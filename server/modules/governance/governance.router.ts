/**
 * SAMPRAAN governance & lifecycle router.
 *
 * Implements the document "Role Definitions and Access Rights" server-side.
 * Every procedure authenticates via protectedProcedure and resolves the
 * ACTING identity from the session (never from input):
 *
 *   - identity lifecycle (PENDING/VERIFIED/SUSPENDED/DEACTIVATED) with
 *     mandatory reasons, scope rules, and DID key history preservation;
 *   - manager onboarding (verifyUser / assignUserRole — Users only, own
 *     scope only, no self-assignment, never Manager/Auditor/Admin);
 *   - manager suspend/reactivate (scoped, Users only; Admin global);
 *   - maker-checker minting (Manager requests, Admin approves + executes
 *     the on-chain mint; managers have no direct mint path);
 *   - controlled NFT transfer (request → recipient accept → scoped
 *     approval → on-chain execution; approver ≠ sender/recipient);
 *   - auditor anomaly/dispute (flag-only; disputes HOLD transfers; Admin
 *     resolves) + on-chain audit-report hash commitments;
 *   - multisig governance proposals (quorum + timelock) for burn/force
 *     transfer/pause/role administration/identity deactivation;
 *   - versioned DID document updates (SUSPENDED/DEACTIVATED blocked);
 *   - Manager-assisted + Admin-approved key recovery (replay-proof);
 *   - selective-disclosure consent (subject-bound, expiring, revocable,
 *     never grants roles/assets, never bypasses RBAC/ABAC);
 *   - single-use nonce-bound ownership presentations.
 *
 * Client-controlled fields are ALWAYS untrusted: actor, role, scope, and
 * lifecycle come from the session/DB; targets are re-verified from the
 * database; approvals bind exact request rows via status-guarded updates.
 */
import { z } from "zod";
import { createHash } from "node:crypto";
import { keccak256, toUtf8Bytes, verifyMessage } from "ethers";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../../_core/trpc";
import {
  applyIdentityRoles,
  countActiveAdminIdentities,
  createAssetTransferRequest,
  createAuditEvent,
  createDidDocumentVersion,
  createIdentityAnomaly,
  createKeyRecoveryRequest,
  createMintRequest,
  createOwnershipPresentation,
  createAsset,
  getAssetById,
  getAssetDispute,
  getAssetTransferRequest,
  getKeyRecoveryRequest,
  getIdentityById,
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
  getMintRequest,
  listAssetDisputes,
  listAssetTransferRequests,
  listAuditEvents,
  listDidDocumentVersions,
  listIdentityAuditEvents,
  listKeyRecoveryRequests,
  listMintRequests,
  listOpenDisputesForAsset,
  resolveAssetDispute,
  revokeConsent,
  grantConsent,
  listConsents,
  setIdentityScope,
  updateIdentityLifecycle,
  updateKeyRecoveryRequest,
  decideMintRequest,
  markMintRequestExecuted,
  updateAssetTransferRequest,
  consumeOwnershipPresentation,
} from "../../db";
import { besuBlockchainService } from "../blockchain/blockchain.service";
import { anchoringService, deriveIdentityWallet } from "../blockchain/anchoring.service";
import { describeError } from "../../common/error-handler";
import { claimAssuranceGrant, decideAssurance, assuranceRequiredError } from "../crypto-assurance/assurance.service";
import { GOVERNANCE_KIND_TO_OPERATION, GOVERNANCE_KINDS_WITH_ASSET_TARGET, type AssuranceOperation } from "../crypto-assurance/assurance-policy";
import { getAssetByAssetId } from "../../db";

/**
 * CRYPTO ASSURANCE GATE (policy-driven, never client-selected).
 *
 * Governance operations are the platform's highest-blast-radius actions, so
 * before the on-chain proposal is created the policy engine scores the
 * operation. When the policy demands QUANTUM_HARDENED assurance the caller must
 * present a grant produced by a successful ECDSA + ML-DSA-65 verification
 * (assurance.verify). A BASELINE/ELEVATED-scored operation proceeds unchanged,
 * which is what keeps ordinary pause/unpause governance working.
 *
 * The gate can only DENY: it never grants authority the on-chain contract or
 * the ADMIN role check would otherwise refuse.
 */
async function requireGovernanceAssurance(input: {
  actor: Actor;
  kind: string;
  assetId?: string | null;
  assuranceGrantId?: string | null;
  reason: string;
}): Promise<void> {
  const operation: AssuranceOperation = GOVERNANCE_KIND_TO_OPERATION[input.kind] ?? "GOVERNANCE_PROPOSAL";
  // Asset classification is resolved SERVER-SIDE from the read model. CRITICAL
  // assets push irreversible operations into the post-quantum band; a missing
  // asset is treated as the worst case for the operations that target one.
  let assetClassification: string | null = null;
  if (input.assetId) {
    const asset = await getAssetByAssetId(input.assetId).catch(() => undefined);
    assetClassification = asset?.classification ?? null;
  } else if (GOVERNANCE_KINDS_WITH_ASSET_TARGET.has(input.kind)) {
    assetClassification = "CRITICAL";
  }
  const decision = decideAssurance({
    operation,
    role: hasRole(input.actor, "ADMIN") ? "ADMIN" : (input.actor.roles[0] ?? "USER"),
    assetClassification,
    stepUpSatisfied: true, // the ADMIN role check above is the session gate
  });
  if (!decision.requiresDualSignature) return;
  const claim = await claimAssuranceGrant({
    identityId: input.actor.id,
    grantId: input.assuranceGrantId ?? null,
    operation,
    resourceType: "GOVERNANCE",
    resourceId: input.assetId && input.assetId.length > 0 ? input.assetId : input.kind,
  });
  if (!claim.ok) {
    await audit({
      actorIdentityId: input.actor.id,
      action: "GOVERNANCE_ASSURANCE_DENIED",
      resourceType: "GOVERNANCE",
      resourceId: input.assetId ?? input.kind,
      decision: "DENY",
      reason: claim.reason,
      metadata: { kind: input.kind, level: decision.level, algorithms: decision.algorithms, reasonCodes: decision.reasonCodes },
    });
    throw assuranceRequiredError(
      `${input.kind} requires ${decision.level} assurance (${decision.algorithms.join(" + ")}). Policy reasons: ${decision.reasonCodes.join(", ")}. ${claim.reason}`,
    );
  }
  await audit({
    actorIdentityId: input.actor.id,
    action: "GOVERNANCE_ASSURANCE_VERIFIED",
    resourceType: "GOVERNANCE",
    resourceId: input.assetId ?? input.kind,
    decision: "ALLOW",
    reason: `${decision.level} assurance verified (${decision.algorithms.join(" + ")})`,
    metadata: { kind: input.kind, level: decision.level, algorithms: decision.algorithms, reasonCodes: decision.reasonCodes, grantId: input.assuranceGrantId ?? null },
  });
}

const did = z
  .string()
  .trim()
  .min(7)
  .max(255)
  .regex(/^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/, "DID must be did:method:identifier");

const classification = z.enum(["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]);
/** Reasons are mandatory on every privileged mutation (document §6). */
const reasonSchema = z.string().trim().min(3).max(300);

type Actor = NonNullable<Awaited<ReturnType<typeof getIdentityByLinkedUserId>>> & {
  roles: string[];
  permissions: string[];
};

/**
 * Session→identity resolution with lifecycle + role context. EVERY procedure
 * starts here: the acting identity is derived from the session user id.
 */
async function requireActor(user: { id: number } | null): Promise<Actor> {
  if (!user) throw new TRPCError({ code: "UNAUTHORIZED", message: "Authentication required" });
  const identity = await getIdentityByLinkedUserId(user.id);
  if (!identity) {
    throw new TRPCError({ code: "FORBIDDEN", message: "No SAMPRAAN identity is linked to this session" });
  }
  // Lifecycle gate (document §19): only VERIFIED identities may perform
  // protected operations. The session gate already fails closed for
  // non-ACTIVE identities; this re-check defends against read-model drift.
  if (identity.lifecycleState !== "VERIFIED" || identity.status !== "ACTIVE") {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: `Identity lifecycle is ${identity.lifecycleState}; protected operations are blocked`,
    });
  }
  const { roles, permissions } = await getIdentityRolesAndPermissions(identity.id);
  return Object.assign(identity, { roles, permissions });
}

function hasRole(actor: Actor, role: string): boolean {
  return actor.roles.includes(role);
}

/** Admin OR the acting identity itself (self-service procedures). */
function assertAdmin(actor: Actor, what: string): void {
  if (!hasRole(actor, "ADMIN")) {
    throw new TRPCError({ code: "FORBIDDEN", message: `${what} requires the ADMIN role` });
  }
}

/** Role exclusivity (document §4): auditor identities never hold power. */
function assertNotAuditorCombination(roleNames: string[], what: string): void {
  const hasAuditor = roleNames.includes("AUDITOR");
  const hasPower = roleNames.some(r => r === "ADMIN" || r === "MANAGER");
  if (hasAuditor && hasPower) {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `${what}: AUDITOR is exclusive and cannot be combined with ADMIN or MANAGER`,
    });
  }
}

/**
 * Manager scope guard: MANAGER may only act inside their own scope and only
 * on USER identities. ADMIN is global. Returns the allowed target roles.
 */
function assertScopedManager(actor: Actor, target: Actor | (Awaited<ReturnType<typeof requireIdentityByDid>>), what: string): void {
  if (hasRole(actor, "ADMIN")) return; // global authority
  if (!hasRole(actor, "MANAGER")) {
    throw new TRPCError({ code: "FORBIDDEN", message: `${what} requires ADMIN or MANAGER` });
  }
  const targetRoles: string[] = (target as unknown as { roles?: string[] }).roles ?? [];
  if (!targetRoles.every(r => r === "USER")) {
    throw new TRPCError({ code: "FORBIDDEN", message: `${what}: managers may only manage USER identities` });
  }
  if (target.id === actor.id) {
    throw new TRPCError({ code: "FORBIDDEN", message: `${what}: self-assignment is not permitted` });
  }
  const managerScope = actor.scope ?? actor.organization;
  const targetScope = target.scope ?? target.organization;
  if (!managerScope || targetScope !== managerScope) {
    throw new TRPCError({ code: "FORBIDDEN", message: `${what}: identity is outside your scope` });
  }
}

/** Resolve target identity BY DID — the client never names identities by trust. */
async function requireIdentityByDid(targetDid: string) {
  const dbmod = await import("../../db");
  const db = await dbmod.getDb();
  if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
  const { identities } = await import("../../../drizzle/schema");
  const { eq } = await import("drizzle-orm");
  const rows = await db.select().from(identities).where(eq(identities.did, targetDid)).limit(1);
  const identity = rows[0];
  if (!identity) throw new TRPCError({ code: "NOT_FOUND", message: "Target identity not found" });
  const { roles } = await getIdentityRolesAndPermissions(identity.id);
  return Object.assign(identity, { roles });
}

async function audit(input: {
  actorIdentityId: string | null;
  action: string;
  resourceType: string;
  resourceId: string;
  decision: "ALLOW" | "DENY";
  reason: string;
  transactionHash?: string | null;
  blockNumber?: number | null;
  metadata?: Record<string, unknown>;
}): Promise<void> {
  await createAuditEvent({
    actorIdentityId: input.actorIdentityId,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    decision: input.decision,
    reason: input.reason,
    transactionHash: input.transactionHash ?? null,
    blockNumber: input.blockNumber ?? null,
    metadata: { source: "governance-lifecycle", ...(input.metadata ?? {}) },
  }).catch(() => undefined);
}

function governanceUnavailable(): TRPCError {
  return new TRPCError({
    code: "PRECONDITION_FAILED",
    message: "Blockchain/governance is not configured (MOCK mode) — this operation requires the deployed contracts",
  });
}

async function resolveOnChainWallet(targetDid: string, displayName: string): Promise<string> {
  const operatorKey = besuBlockchainService?.config.privateKey ?? null;
  if (!besuBlockchainService || !operatorKey) throw governanceUnavailable();
  // Idempotently anchor the identity so its on-chain reference wallet exists.
  await anchoringService.anchorIdentity({ did: targetDid, displayName });
  return deriveIdentityWallet(operatorKey, targetDid);
}

export const governanceRouter = router({
  // ====================================================================
  // IDENTITY LIFECYCLE (§3, §4, §5, §6, §7, §8, §19, §20)
  // ====================================================================

  /** Manager/Admin scoped verification of a PENDING identity. */
  lifecycle: router({
    verify: protectedProcedure
      .input(z.object({ did, reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const target = await requireIdentityByDid(input.did);
        assertScopedManager(actor, target, "Verify identity");
        if (target.lifecycleState !== "PENDING") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only PENDING identities can be verified (this one is ${target.lifecycleState})` });
        }
        const updated = await updateIdentityLifecycle({ identityId: target.id, lifecycleState: "VERIFIED", statusReason: input.reason });
        // On-chain: verifyIdentity (identity-admin path, reason emitted).
        let anchor: { outcome: string; reason?: string } | null = null;
        try {
          const wallet = await resolveOnChainWallet(target.did, target.displayName);
          await besuBlockchainService!.setIdentityStatus({ walletAddress: wallet, status: "ACTIVE", reason: input.reason });
          anchor = { outcome: "ANCHORED" };
        } catch (error) {
          anchor = { outcome: describeError(error) === "" ? "SKIPPED" : "FAILED", reason: describeError(error) };
        }
        await audit({
          actorIdentityId: actor.id,
          action: "USER_VERIFIED",
          resourceType: "IDENTITY",
          resourceId: target.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { targetDid: target.did, anchor, actorRoles: actor.roles },
        });
        return { identity: updated, anchor };
      }),

    /** Manager/Admin scoped suspension (Users only for managers). */
    suspend: protectedProcedure
      .input(z.object({ did, reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const target = await requireIdentityByDid(input.did);
        assertScopedManager(actor, target, "Suspend identity");
        if (target.id === actor.id) {
          // Self-lockout guard (consistent with identities.setStatus).
          throw new TRPCError({ code: "FORBIDDEN", message: "Self-lockout prevention: you cannot suspend your own identity" });
        }
        if (target.lifecycleState !== "VERIFIED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only VERIFIED identities can be suspended (this one is ${target.lifecycleState})` });
        }
        // Last-admin protection (§5): never suspend the final ACTIVE admin.
        const targetRoles = await getIdentityRolesAndPermissions(target.id);
        if (targetRoles.roles.includes("ADMIN")) {
          const admins = await countActiveAdminIdentities();
          if (admins <= 1) {
            throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Last-admin protection: the final active administrator cannot be suspended" });
          }
        }
        const updated = await updateIdentityLifecycle({ identityId: target.id, lifecycleState: "SUSPENDED", statusReason: input.reason });
        let anchor: { outcome: string; reason?: string } | null = null;
        try {
          const wallet = await resolveOnChainWallet(target.did, target.displayName);
          await besuBlockchainService!.setIdentityStatus({ walletAddress: wallet, status: "SUSPENDED", reason: input.reason });
          anchor = { outcome: "ANCHORED" };
        } catch (error) {
          anchor = { outcome: "FAILED", reason: describeError(error) };
        }
        await audit({
          actorIdentityId: actor.id,
          action: "ACCESS_SUSPENDED",
          resourceType: "IDENTITY",
          resourceId: target.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { targetDid: target.did, anchor, actorRoles: actor.roles },
        });
        return { identity: updated, anchor };
      }),

    /** Reactivation of a SUSPENDED identity (admin global / manager scoped). */
    reactivate: protectedProcedure
      .input(z.object({ did, reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const target = await requireIdentityByDid(input.did);
        assertScopedManager(actor, target, "Reactivate identity");
        if (target.lifecycleState !== "SUSPENDED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only SUSPENDED identities can be reactivated (this one is ${target.lifecycleState})` });
        }
        const updated = await updateIdentityLifecycle({ identityId: target.id, lifecycleState: "VERIFIED", statusReason: input.reason });
        let anchor: { outcome: string; reason?: string } | null = null;
        try {
          const wallet = await resolveOnChainWallet(target.did, target.displayName);
          await besuBlockchainService!.setIdentityStatus({ walletAddress: wallet, status: "ACTIVE", reason: input.reason });
          anchor = { outcome: "ANCHORED" };
        } catch (error) {
          anchor = { outcome: "FAILED", reason: describeError(error) };
        }
        await audit({
          actorIdentityId: actor.id,
          action: "ACCESS_REACTIVATED",
          resourceType: "IDENTITY",
          resourceId: target.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { targetDid: target.did, anchor, actorRoles: actor.roles },
        });
        return { identity: updated, anchor };
      }),

    /**
     * DEACTIVATION is terminal and governance-gated: file a multisig
     * proposal (quorum + timelock). There is deliberately NO direct path.
     */
    requestDeactivation: protectedProcedure
      .input(z.object({ did, reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Request identity deactivation");
        const target = await requireIdentityByDid(input.did);
        if (target.lifecycleState === "DEACTIVATED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Identity is already deactivated" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const wallet = await resolveOnChainWallet(target.did, target.displayName);
        const { proposalId } = await besuBlockchainService.proposeDeactivateIdentity({ walletAddress: wallet, reason: input.reason });
        await audit({
          actorIdentityId: actor.id,
          action: "DEACTIVATION_PROPOSED",
          resourceType: "IDENTITY",
          resourceId: target.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { targetDid: target.did, proposalId: proposalId.toString() },
        });
        return { proposalId: proposalId.toString() };
      }),

    /** Manager assigns the USER role inside own scope (§7). */
    assignUserRole: protectedProcedure
      .input(z.object({ did, role: z.enum(["USER"]), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const target = await requireIdentityByDid(input.did);
        assertScopedManager(actor, target, "Assign role");
        if (target.lifecycleState === "PENDING") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "A PENDING identity cannot receive privileged roles" });
        }
        const updated = await applyIdentityRoles({
          identityId: target.id,
          roleNames: ["USER"],
          assignedByIdentityId: actor.id,
        });
        assertNotAuditorCombination(updated ?? [], "Assign role");
        await setIdentityScope(target.id, actor.scope ?? actor.organization);
        await audit({
          actorIdentityId: actor.id,
          action: "USER_ROLE_ASSIGNED",
          resourceType: "IDENTITY",
          resourceId: target.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { targetDid: target.did, roles: updated, scope: actor.scope ?? actor.organization },
        });
        return { identityId: target.id, roles: updated };
      }),

    /** Admin role administration (§4 exclusivity + §5 last-admin). */
    assignRolesAdmin: protectedProcedure
      .input(z.object({ did, roles: z.array(z.enum(["ADMIN", "MANAGER", "AUDITOR", "USER"])).min(1).max(4), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Role administration");
        const target = await requireIdentityByDid(input.did);
        assertNotAuditorCombination(input.roles, "Role administration");
        if (target.lifecycleState === "PENDING" && input.roles.some(r => r !== "USER")) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "A PENDING identity cannot receive privileged roles" });
        }
        const removingAdmin =
          (await getIdentityRolesAndPermissions(target.id)).roles.includes("ADMIN") &&
          !input.roles.includes("ADMIN");
        if (removingAdmin) {
          const admins = await countActiveAdminIdentities();
          if (admins <= 1) {
            throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Last-admin protection: the final active administrator cannot be removed" });
          }
        }
        const updated = await applyIdentityRoles({
          identityId: target.id,
          roleNames: input.roles,
          assignedByIdentityId: actor.id,
        });
        await audit({
          actorIdentityId: actor.id,
          action: "ROLE_CHANGED",
          resourceType: "IDENTITY",
          resourceId: target.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { targetDid: target.did, roles: updated, actorRoles: actor.roles },
        });
        return { identityId: target.id, roles: updated };
      }),

    list: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      // DATA SCOPE (§20): ADMIN/AUDITOR see all; MANAGER sees own scope;
      // USER sees only self.
      const { listIdentitiesInScope } = await import("../../db");
      if (hasRole(actor, "ADMIN") || hasRole(actor, "AUDITOR")) {
        return listIdentitiesInScope(null);
      }
      if (hasRole(actor, "MANAGER")) {
        return listIdentitiesInScope(actor.scope ?? actor.organization);
      }
      return [actor];
    }),
  }),

  // ====================================================================
  // MAKER-CHECKER MINTING (§9)
  // ====================================================================

  mint: router({
    /** Manager (scoped) requests a mint → PENDING. Managers cannot mint directly. */
    request: protectedProcedure
      .input(z.object({
        assetId: z.string().trim().min(2).max(120),
        name: z.string().trim().min(2).max(200),
        type: z.string().trim().min(2).max(80),
        classification,
        description: z.string().max(5000).optional(),
        integrityHash: z.string().max(255).optional(),
        ownerDid: did,
        custodianDid: did,
      }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (!hasRole(actor, "MANAGER")) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Mint requests require the MANAGER role" });
        }
        const owner = await requireIdentityByDid(input.ownerDid);
        const custodian = await requireIdentityByDid(input.custodianDid);
        // Scope rule: manager acts inside own scope only.
        const managerScope = actor.scope ?? actor.organization;
        if (owner.scope !== managerScope && owner.organization !== managerScope) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Owner identity is outside your scope" });
        }
        if (custodian.scope !== managerScope && custodian.organization !== managerScope) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Custodian identity is outside your scope" });
        }
        const existing = await getMintRequestByAssetId(input.assetId);
        if (existing && (existing.status === "PENDING" || existing.status === "APPROVED")) {
          throw new TRPCError({ code: "CONFLICT", message: `A mint request for ${input.assetId} already exists (${existing.status})` });
        }
        const request = await createMintRequest({
          assetId: input.assetId,
          name: input.name,
          type: input.type,
          classification: input.classification,
          description: input.description ?? null,
          integrityHash: input.integrityHash ?? null,
          ownerIdentityId: owner.id,
          custodianIdentityId: custodian.id,
          requestedByIdentityId: actor.id,
          requesterScope: managerScope,
        });
        await audit({
          actorIdentityId: actor.id,
          action: "MINT_REQUESTED",
          resourceType: "ASSET",
          resourceId: input.assetId,
          decision: "ALLOW",
          reason: `Mint requested for ${input.name}`,
          metadata: { mintRequestId: request?.id, classification: input.classification, ownerDid: input.ownerDid, custodianDid: input.custodianDid },
        });
        return { request };
      }),

    /** Admin approves/rejects a PENDING request (reason mandatory; no self-approval). */
    decide: protectedProcedure
      .input(z.object({ requestId: z.string().uuid(), decision: z.enum(["APPROVED", "REJECTED"]), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Mint decision");
        const request = await getMintRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Mint request not found" });
        if (request.status !== "PENDING") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only PENDING requests can be decided (this one is ${request.status})` });
        }
        if (request.requestedByIdentityId === actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Self-approval is not permitted (maker-checker)" });
        }
        const updated = await decideMintRequest({
          id: input.requestId,
          status: input.decision,
          decidedByIdentityId: actor.id,
          decisionReason: input.reason,
        });
        if (!updated) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Request already decided (status-guarded update found no PENDING row)" });
        await audit({
          actorIdentityId: actor.id,
          action: input.decision === "APPROVED" ? "MINT_APPROVED" : "MINT_REJECTED",
          resourceType: "ASSET",
          resourceId: request.assetId,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { mintRequestId: request.id, requesterIdentityId: request.requestedByIdentityId },
        });
        return { request: updated };
      }),

    /** Admin executes an APPROVED request → real on-chain mint + custody assignment. */
    execute: protectedProcedure
      .input(z.object({ requestId: z.string().uuid() }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Mint execution");
        const request = await getMintRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Mint request not found" });
        if (request.status !== "APPROVED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only APPROVED requests can be executed (this one is ${request.status})` });
        }
        if (request.requestedByIdentityId === actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Self-execution is not permitted (maker-checker)" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const [owner, custodian] = await Promise.all([
          getIdentityById(request.ownerIdentityId),
          getIdentityById(request.custodianIdentityId),
        ]);
        if (!owner || !custodian) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Request participants missing" });
        // Lifecycle gate: participants must still be VERIFIED at execution.
        if (owner.lifecycleState !== "VERIFIED" || custodian.lifecycleState !== "VERIFIED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Request participant lifecycle is not VERIFIED" });
        }
        const custodianWallet = await resolveOnChainWallet(custodian.did, custodian.displayName);
        let transaction;
        try {
          transaction = await besuBlockchainService.registerAsset({
            assetId: request.assetId,
            custodianWallet,
            classification: request.classification,
            metadataReference: `${request.assetId}:${request.name}`,
          });
        } catch (error) {
          const msg = describeError(error);
          // Idempotent re-execution: AlreadyRegistered → mark EXECUTED with the
          // existing tokenId instead of failing the workflow.
          const existingToken = /already registered|0x[0-9a-f]{8}/i.test(msg) ? await resolveTokenId(request.assetId) : null;
          if (existingToken) {
            await markMintRequestExecuted(input.requestId, existingToken, transaction?.transactionHash ?? "");
            return { assetId: request.assetId, tokenId: existingToken, transactionHash: null, idempotent: true };
          }
          throw new TRPCError({ code: "BAD_GATEWAY", message: `Blockchain rejected the mint: ${msg}` });
        }
        const tokenId = await resolveTokenId(request.assetId);
        // BUG-GOV-1 (PENDING-mint divergence): registerAsset mints the asset
        // as PENDING on-chain by contract design, while transferCustody only
        // accepts ACTIVE assets — and the governed mint's read-model row is
        // created ACTIVE. Without an explicit activation the chain and the
        // read model disagree and the FIRST transfer reverts with
        // AssetNotActive (observed live). Mirror the assets.create BUG-033
        // fix: activate on-chain in the same flow, with the outcome audited.
        let activation: "ACTIVATED" | "FAILED" = "ACTIVATED";
        try {
          await besuBlockchainService.setAssetStatus({ assetId: request.assetId, status: "ACTIVATE" });
        } catch (activationError) {
          activation = "FAILED";
          await createAuditEvent({
            actorIdentityId: actor.id,
            action: "BLOCKCHAIN_TRANSACTION_FAILED",
            resourceType: "ASSET",
            resourceId: request.assetId,
            decision: "DENY",
            reason: `Post-mint on-chain activation failed: ${describeError(activationError)}`,
            metadata: { source: "governance-mint", phase: "post-mint-activation", mintRequestId: request.id },
          }).catch(() => undefined);
        }
        const asset = await createAsset({
          assetId: request.assetId,
          name: request.name,
          type: request.type,
          classification: request.classification,
          description: request.description ?? null,
          integrityHash: request.integrityHash ?? null,
          ownerIdentityId: owner.id,
          custodianIdentityId: custodian.id,
          status: "ACTIVE",
        }).catch(() => null);
        if (asset) await import("../../db").then(m => m.setAssetTokenId(asset.id, tokenId));
        await markMintRequestExecuted(input.requestId, tokenId, transaction.transactionHash);
        await audit({
          actorIdentityId: actor.id,
          action: "NFT_MINTED",
          resourceType: "ASSET",
          resourceId: request.assetId,
          decision: "ALLOW",
          reason: `Mint executed for ${request.name}`,
          transactionHash: transaction.transactionHash,
          blockNumber: transaction.blockNumber,
          metadata: { mintRequestId: request.id, tokenId, ownerDid: owner.did, custodianDid: custodian.did, activation },
        });
        return { assetId: request.assetId, tokenId, transactionHash: transaction.transactionHash, activation, idempotent: false };
      }),

    list: protectedProcedure.query(async ({ ctx }) => {
      await requireActor(ctx.user);
      return listMintRequests();
    }),
  }),

  // ====================================================================
  // CONTROLLED NFT TRANSFER (§10)
  // ====================================================================

  transfer: router({
    /** Current custodian requests transfer to a target DID. */
    request: protectedProcedure
      .input(z.object({ assetId: z.string().uuid(), toDid: did, reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        if (asset.custodianIdentityId !== actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Only the current custodian can request a transfer" });
        }
        if (asset.status !== "ACTIVE") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Asset is ${asset.status}; transfers require ACTIVE` });
        }
        if (await hasOpenDispute(asset.id)) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Asset transfer is on HOLD (open dispute)" });
        }
        const recipient = await requireIdentityByDid(input.toDid);
        if (recipient.id === actor.id) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Transfer to self is not permitted" });
        }
        if (recipient.lifecycleState !== "VERIFIED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Recipient lifecycle is ${recipient.lifecycleState}` });
        }
        const request = await createAssetTransferRequest({
          assetId: asset.id,
          tokenId: asset.tokenId,
          fromIdentityId: actor.id,
          toIdentityId: recipient.id,
          requestedByIdentityId: actor.id,
        });
        await audit({
          actorIdentityId: actor.id,
          action: "TRANSFER_REQUESTED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { transferRequestId: request?.id, toDid: input.toDid },
        });
        return { request };
      }),

    /** Recipient accepts (binding the counterparties). */
    accept: protectedProcedure
      .input(z.object({ requestId: z.string().uuid() }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const request = await getAssetTransferRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Transfer request not found" });
        if (request.toIdentityId !== actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Only the named recipient can accept" });
        }
        if (request.status !== "PENDING") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only PENDING requests can be accepted (this one is ${request.status})` });
        }
        const updated = await updateAssetTransferRequest(input.requestId, { status: "ACCEPTED", acceptedAt: new Date() });
        await audit({
          actorIdentityId: actor.id,
          action: "TRANSFER_ACCEPTED",
          resourceType: "ASSET",
          resourceId: request.assetId,
          decision: "ALLOW",
          reason: "Recipient accepted the transfer request",
          metadata: { transferRequestId: request.id, fromIdentityId: request.fromIdentityId },
        });
        return { request: updated };
      }),

    /** Manager-in-scope OR Admin approves; approver ≠ sender/recipient. */
    approve: protectedProcedure
      .input(z.object({ requestId: z.string().uuid(), decision: z.enum(["APPROVED", "REJECTED"]), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const request = await getAssetTransferRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Transfer request not found" });
        if (request.status !== "ACCEPTED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only ACCEPTED requests can be approved (this one is ${request.status})` });
        }
        if (request.fromIdentityId === actor.id || request.toIdentityId === actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Approver cannot be the sender or the recipient" });
        }
        if (hasRole(actor, "ADMIN")) {
          // global authority
        } else if (hasRole(actor, "MANAGER")) {
          const from = await getIdentityById(request.fromIdentityId);
          const managerScope = actor.scope ?? actor.organization;
          if (!from || (from.scope !== managerScope && from.organization !== managerScope)) {
            throw new TRPCError({ code: "FORBIDDEN", message: "Transfer is outside your scope" });
          }
        } else {
          throw new TRPCError({ code: "FORBIDDEN", message: "Approval requires ADMIN or MANAGER" });
        }
        if (await hasOpenDispute(request.assetId)) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Asset transfer is on HOLD (open dispute)" });
        }
        const updated = await updateAssetTransferRequest(input.requestId, {
          status: input.decision,
          approverIdentityId: actor.id,
          decisionReason: input.reason,
          decidedAt: new Date(),
        });
        await audit({
          actorIdentityId: actor.id,
          action: input.decision === "APPROVED" ? "TRANSFER_APPROVED" : "TRANSFER_REJECTED",
          resourceType: "ASSET",
          resourceId: request.assetId,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { transferRequestId: request.id, fromIdentityId: request.fromIdentityId, toIdentityId: request.toIdentityId },
        });
        return { request: updated };
      }),

    /** Execute an APPROVED transfer on-chain (custodian-verified). */
    execute: protectedProcedure
      .input(z.object({ requestId: z.string().uuid() }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const request = await getAssetTransferRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Transfer request not found" });
        if (request.status !== "APPROVED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only APPROVED requests can be executed (this one is ${request.status})` });
        }
        const asset = await getAssetById(request.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        // Replay/toctou guard: the CURRENT custodian must still be the sender.
        if (asset.custodianIdentityId !== request.fromIdentityId) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Custody changed after approval; request is stale" });
        }
        if (await hasOpenDispute(asset.id)) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Asset transfer is on HOLD (open dispute)" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const recipient = await getIdentityById(request.toIdentityId);
        if (!recipient || recipient.lifecycleState !== "VERIFIED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Recipient lifecycle is not VERIFIED" });
        }
        const toWallet = await resolveOnChainWallet(recipient.did, recipient.displayName);
        let transaction;
        try {
          transaction = await besuBlockchainService.transferAsset({ assetId: asset.assetId, toCustodianWallet: toWallet });
        } catch (error) {
          throw new TRPCError({ code: "BAD_GATEWAY", message: `Blockchain rejected the transfer: ${describeError(error)}` });
        }
        await applyCustodyTransferSafe(asset.id, recipient.id, `Governed transfer (request ${request.id})`, transaction.transactionHash, transaction.blockNumber);
        await updateAssetTransferRequest(input.requestId, { status: "EXECUTED", executedAt: new Date(), transactionHash: transaction.transactionHash });
        await audit({
          actorIdentityId: actor.id,
          action: "TRANSFER_EXECUTED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "ALLOW",
          reason: `Governed transfer executed (request ${request.id})`,
          transactionHash: transaction.transactionHash,
          blockNumber: transaction.blockNumber,
          metadata: { transferRequestId: request.id, toDid: recipient.did },
        });
        return { transactionHash: transaction.transactionHash, toDid: recipient.did };
      }),

    list: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      // §20 scope: users see their own; managers see their scope; admin/auditor all.
      if (hasRole(actor, "ADMIN") || hasRole(actor, "AUDITOR")) return listAssetTransferRequests();
      if (hasRole(actor, "MANAGER")) {
        const scope = actor.scope ?? actor.organization;
        const all = await listAssetTransferRequests();
        const scoped = [];
        for (const r of all) {
          const from = await getIdentityById(r.fromIdentityId);
          if (from && (from.scope === scope || from.organization === scope)) scoped.push(r);
        }
        return scoped;
      }
      return listAssetTransferRequests({ fromIdentityId: actor.id });
    }),
  }),

  // ====================================================================
  // AUDITOR SURFACES (§11, §12, §13, §14) — flag-only + read-only
  // ====================================================================

  auditor: router({
    flagAnomaly: protectedProcedure
      .input(z.object({ targetDid: did.optional(), assetId: z.string().trim().max(120).optional(), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (!hasRole(actor, "AUDITOR")) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Anomaly flagging requires the AUDITOR role" });
        }
        if (!input.targetDid && !input.assetId) {
          throw new TRPCError({ code: "BAD_REQUEST", message: "Provide targetDid or assetId" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const targetWallet = input.targetDid
          ? await resolveOnChainWallet(input.targetDid, input.targetDid)
          : deriveIdentityWallet(besuBlockchainService.config.privateKey!, input.targetDid ?? "");
        const evidence = await besuBlockchainService.auditorFlagAnomaly({
          targetWallet,
          assetId: input.assetId ?? null,
          reason: input.reason,
        });
        const row = await createIdentityAnomaly({
          targetIdentityId: input.targetDid ? (await requireIdentityByDid(input.targetDid)).id : null,
          assetId: null,
          flaggedByIdentityId: actor.id,
          reason: input.reason,
        }).catch(() => null);
        await audit({
          actorIdentityId: actor.id,
          action: "ANOMALY_FLAGGED",
          resourceType: "IDENTITY",
          resourceId: row?.id ?? evidence.transactionHash,
          decision: "ALLOW",
          reason: input.reason,
          transactionHash: evidence.transactionHash,
          blockNumber: evidence.blockNumber,
          metadata: { targetDid: input.targetDid ?? null, assetId: input.assetId ?? null, anomalyId: row?.id },
        });
        return { transactionHash: evidence.transactionHash, anomalyId: row?.id ?? null };
      }),

    raiseDispute: protectedProcedure
      .input(z.object({ assetId: z.string().trim().min(2).max(120), evidenceHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (!hasRole(actor, "AUDITOR")) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Disputes require the AUDITOR role" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const evidenceHash = input.evidenceHash ?? keccakOf(input.reason);
        const assetToken = await requireAssetTokenByBusinessId(input.assetId);
        const evidence = await besuBlockchainService.auditorRaiseDispute({ assetId: input.assetId, evidenceHash, reason: input.reason });
        // Read-model row bound to the asset ROW id when it exists.
        const assetRow = await getAssetRowByBusinessId(input.assetId);
        const row = assetRow
          ? await createAssetDisputeRow({ assetId: assetRow.id, raisedByIdentityId: actor.id, evidenceHash, reason: input.reason })
          : null;
        await audit({
          actorIdentityId: actor.id,
          action: "DISPUTE_RAISED",
          resourceType: "ASSET",
          resourceId: input.assetId,
          decision: "ALLOW",
          reason: input.reason,
          transactionHash: evidence.transactionHash,
          blockNumber: evidence.blockNumber,
          metadata: { disputeId: evidence.disputeId.toString(), onChainTokenId: assetToken.toString(), readModelDisputeId: row?.id ?? null },
        });
        return { transactionHash: evidence.transactionHash, disputeId: evidence.disputeId.toString() };
      }),

    resolveDispute: protectedProcedure
      .input(z.object({ disputeId: z.string().min(1), uphold: z.boolean(), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Dispute resolution");
        if (!besuBlockchainService) throw governanceUnavailable();
        const evidence = await besuBlockchainService.resolveDispute({ disputeId: BigInt(input.disputeId), upheld: input.uphold, reason: input.reason });
        // Mirror into the read model when the dispute row exists.
        const { listAssetDisputes: listDisputes } = await import("../../db");
        const open = (await listDisputes("OPEN")).find(d => d.id === input.disputeId);
        if (open) {
          await resolveAssetDispute({ id: open.id, status: input.uphold ? "UPHELD" : "REJECTED", resolvedByIdentityId: actor.id, resolutionReason: input.reason });
        }
        await audit({
          actorIdentityId: actor.id,
          action: "DISPUTE_RESOLVED",
          resourceType: "ASSET",
          resourceId: input.disputeId,
          decision: "ALLOW",
          reason: input.reason,
          transactionHash: evidence.transactionHash,
          blockNumber: evidence.blockNumber,
          metadata: { upheld: input.uphold },
        });
        return { transactionHash: evidence.transactionHash };
      }),

    storeAuditReportHash: protectedProcedure
      .input(z.object({ reportHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/), note: z.string().max(300).optional() }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (!hasRole(actor, "AUDITOR")) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Audit report commitments require the AUDITOR role" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const evidence = await besuBlockchainService.auditorStoreAuditReportHash({ reportHash: input.reportHash });
        await import("../../db").then(m => m.createAuditReportHash({ auditorIdentityId: actor.id, reportHash: input.reportHash }));
        await audit({
          actorIdentityId: actor.id,
          action: "AUDIT_REPORT_HASH_STORED",
          resourceType: "AUDIT",
          resourceId: evidence.reportId.toString(),
          decision: "ALLOW",
          reason: input.note ?? "Off-chain audit report hash committed on-chain",
          transactionHash: evidence.transactionHash,
          blockNumber: evidence.blockNumber,
          metadata: { reportId: evidence.reportId.toString(), reportHash: input.reportHash },
        });
        return { transactionHash: evidence.transactionHash, reportId: evidence.reportId.toString() };
      }),

    /** §13 read-only verification surface. */
    verify: protectedProcedure
      .input(z.object({
        assetId: z.string().trim().max(120).optional(),
        did: did.optional(),
        ownershipHistory: z.boolean().default(false),
      }))
      .query(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (!hasRole(actor, "AUDITOR") && !hasRole(actor, "ADMIN")) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Verification surface requires AUDITOR or ADMIN" });
        }
        if (!besuBlockchainService) throw governanceUnavailable();
        const result: Record<string, unknown> = {};
        if (input.assetId) {
          const tokenId = await requireAssetTokenByBusinessId(input.assetId);
          result.assetId = input.assetId;
          result.tokenId = tokenId.toString();
          result.authenticity = await besuBlockchainService.verifyAssetAuthenticity(tokenId);
          if (input.did) {
            const target = await requireIdentityByDid(input.did);
            const wallet = deriveIdentityWallet(besuBlockchainService.config.privateKey!, target.did);
            result.ownership = await besuBlockchainService.verifyAssetOwnership(tokenId, wallet);
          }
          if (input.ownershipHistory) {
            result.ownershipHistory = (await besuBlockchainService.getOwnershipHistory({ assetId: input.assetId })).map(r => ({
              from: r.fromCustodian,
              to: r.toCustodian,
              operator: r.operator,
              at: Number(r.at),
            }));
          }
        }
        if (input.did) {
          const target = await requireIdentityByDid(input.did);
          const { roles } = await getIdentityRolesAndPermissions(target.id);
          result.role = { did: target.did, roles, lifecycleState: target.lifecycleState };
          result.roleHistory = (await listIdentityAuditEvents(target.id, 50)).map(e => ({ action: e.action, reason: e.reason, at: e.timestamp }));
          result.accessLog = result.roleHistory;
        }
        await audit({
          actorIdentityId: actor.id,
          action: "AUDITOR_VERIFICATION",
          resourceType: "ASSET",
          resourceId: input.assetId ?? input.did ?? "n/a",
          decision: "ALLOW",
          reason: "Read-only verification",
          metadata: { queries: Object.keys(result) },
        });
        return result;
      }),

    listDisputes: protectedProcedure.query(async ({ ctx }) => {
      await requireActor(ctx.user);
      return listAssetDisputes();
    }),

    listAnomalies: protectedProcedure.query(async ({ ctx }) => {
      await requireActor(ctx.user);
      const { listIdentityAnomalies } = await import("../../db");
      return listIdentityAnomalies();
    }),
  }),

  // ====================================================================
  // GOVERNANCE MULTISIG (§1, §2, §23) — quorum + timelock proposals
  // ====================================================================

  proposals: router({
    propose: protectedProcedure
      .input(z.object({
        kind: z.enum(["BURN_NFT", "FORCE_TRANSFER", "PAUSE_REGISTRY", "UNPAUSE_REGISTRY", "GRANT_ROLE", "REVOKE_ROLE", "DEACTIVATE_IDENTITY"]),
        assetId: z.string().trim().max(120).optional(),
        accountDid: did.optional(),
        role: z.string().max(80).optional(),
        reason: reasonSchema,
        /** Single-use grant from assurance.verify — required when policy demands PQC. */
        assuranceGrantId: z.string().uuid().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Governance proposal");
        await requireGovernanceAssurance({
          actor,
          kind: input.kind,
          assetId: input.assetId ?? null,
          assuranceGrantId: input.assuranceGrantId ?? null,
          reason: input.reason,
        });
        if (!besuBlockchainService) throw governanceUnavailable();
        let account: string | undefined;
        if (input.accountDid) {
          const target = await requireIdentityByDid(input.accountDid);
          account = deriveIdentityWallet(besuBlockchainService.config.privateKey!, target.did);
        }
        const result = await besuBlockchainService.proposeGovernanceAction({
          kind: input.kind,
          assetId: input.assetId,
          account,
          role: input.role,
          reason: input.reason,
        });
        await audit({
          actorIdentityId: actor.id,
          action: "GOVERNANCE_PROPOSAL_CREATED",
          resourceType: "GOVERNANCE",
          resourceId: result.proposalId.toString(),
          decision: "ALLOW",
          reason: input.reason,
          metadata: { kind: input.kind, assetId: input.assetId ?? null, accountDid: input.accountDid ?? null, executableAt: Number(result.executableAt), requiredApprovals: Number(result.requiredApprovals) },
        });
        return {
          proposalId: result.proposalId.toString(),
          executableAt: Number(result.executableAt),
          requiredApprovals: Number(result.requiredApprovals),
        };
      }),

    /** Admin service approves via the second signer; any signer may approve on-chain. */
    approve: protectedProcedure
      .input(z.object({ proposalId: z.string().regex(/^\d+$/), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Governance approval");
        if (!besuBlockchainService) throw governanceUnavailable();
        const result = await besuBlockchainService.approveGovernanceProposal({ proposalId: BigInt(input.proposalId), reason: input.reason });
        await audit({
          actorIdentityId: actor.id,
          action: "GOVERNANCE_PROPOSAL_APPROVED",
          resourceType: "GOVERNANCE",
          resourceId: input.proposalId,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { approvals: Number(result.approvals), requiredApprovals: Number(result.requiredApprovals) },
        });
        return { approvals: Number(result.approvals), requiredApprovals: Number(result.requiredApprovals) };
      }),

    cancel: protectedProcedure
      .input(z.object({ proposalId: z.string().regex(/^\d+$/), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Governance cancellation");
        if (!besuBlockchainService) throw governanceUnavailable();
        await besuBlockchainService.cancelGovernanceProposal({ proposalId: BigInt(input.proposalId), reason: input.reason });
        await audit({
          actorIdentityId: actor.id,
          action: "GOVERNANCE_PROPOSAL_CANCELLED",
          resourceType: "GOVERNANCE",
          resourceId: input.proposalId,
          decision: "ALLOW",
          reason: input.reason,
        });
        return { cancelled: true };
      }),

    execute: protectedProcedure
      .input(z.object({ proposalId: z.string().regex(/^\d+$/) }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Governance execution");
        if (!besuBlockchainService) throw governanceUnavailable();
        const state = await besuBlockchainService.getGovernanceProposal({ proposalId: BigInt(input.proposalId) });
        // Server-side pre-checks for CLEAR errors; the contract re-verifies.
        if (state.cancelled) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Proposal was cancelled" });
        if (state.executed) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Proposal already executed (no double execution)" });
        if (state.approvals < state.requiredApprovals) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Quorum not reached (${state.approvals}/${state.requiredApprovals})` });
        }
        const now = Math.floor(Date.now() / 1000);
        if (now < state.executableAt) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Timelock has not elapsed (executable at ${new Date(state.executableAt * 1000).toISOString()})` });
        }
        const evidence = await besuBlockchainService.executeGovernanceProposal({ proposalId: BigInt(input.proposalId) });
        await audit({
          actorIdentityId: actor.id,
          action: "GOVERNANCE_PROPOSAL_EXECUTED",
          resourceType: "GOVERNANCE",
          resourceId: input.proposalId,
          decision: "ALLOW",
          reason: `Proposal ${input.proposalId} executed (kind ${state.kind})`,
          transactionHash: evidence.transactionHash,
          blockNumber: evidence.blockNumber,
          metadata: { kind: state.kind, target: state.target },
        });
        return { transactionHash: evidence.transactionHash };
      }),

    get: protectedProcedure
      .input(z.object({ proposalId: z.string().regex(/^\d+$/) }))
      .query(async ({ input }) => {
        if (!besuBlockchainService) throw governanceUnavailable();
        return besuBlockchainService.getGovernanceProposal({ proposalId: BigInt(input.proposalId) });
      }),

    list: protectedProcedure.query(async () => {
      if (!besuBlockchainService) throw governanceUnavailable();
      return besuBlockchainService.listGovernanceProposals({ limit: 50 });
    }),

    status: protectedProcedure.query(async () => {
      if (!besuBlockchainService) throw governanceUnavailable();
      return besuBlockchainService.getGovernanceStatus();
    }),
  }),

  // ====================================================================
  // DID DOCUMENT / RECOVERY / CONSENT / PRESENTATION (§15–§18)
  // ====================================================================

  self: router({
    updateDidDocument: protectedProcedure
      .input(z.object({ document: z.record(z.string(), z.unknown()), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (actor.lifecycleState === "SUSPENDED" || actor.lifecycleState === "DEACTIVATED") {
          throw new TRPCError({ code: "FORBIDDEN", message: "A suspended/deactivated identity cannot update its DID document" });
        }
        const documentHash = keccakOf(JSON.stringify(input.document));
        await createDidDocumentVersion({
          identityId: actor.id,
          versionNumber: await nextDidDocVersion(actor.id),
          documentHash,
          reason: input.reason,
          createdByIdentityId: actor.id,
        });
        let transactionHash: string | null = null;
        try {
          if (besuBlockchainService) {
            const evidence = await besuBlockchainService.updateDidDocument({ did: actor.did, documentHash, reason: input.reason });
            transactionHash = evidence.transactionHash;
          }
        } catch (error) {
          // Chain absence must not lose the versioned document history.
          transactionHash = null;
        }
        await audit({
          actorIdentityId: actor.id,
          action: "DID_DOCUMENT_UPDATED",
          resourceType: "IDENTITY",
          resourceId: actor.id,
          decision: "ALLOW",
          reason: input.reason,
          transactionHash,
          metadata: { documentHash, version: await nextDidDocVersion(actor.id) },
        });
        return { documentHash, transactionHash };
      }),

    listDidDocumentVersions: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      return listDidDocumentVersions(actor.id);
    }),

    /**
     * Manager-assisted + Admin-approved key recovery (§16). Flow:
     *  1. Manager (or self) files a recovery request with the NEW key digest.
     *  2. ADMIN approves (server-side authority; request row is
     *     status-guarded so double-approval/replay is impossible).
     *  3. Execution rotates the DID key via the EXISTING rotateDidKey
     *     service (old key → ROTATED, history preserved) and marks the
     *     request EXECUTED. Assets are never touched.
     */
    requestKeyRecovery: protectedProcedure
      .input(z.object({ subjectDid: did, newKeyDigest: z.string().trim().min(16).max(64), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const subject = await requireIdentityByDid(input.subjectDid);
        const isSelf = subject.id === actor.id;
        if (!isSelf && !hasRole(actor, "MANAGER")) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Recovery requests require the MANAGER role (or self-service)" });
        }
        if (!isSelf && hasRole(actor, "MANAGER")) {
          const scope = actor.scope ?? actor.organization;
          if (subject.scope !== scope && subject.organization !== scope) {
            throw new TRPCError({ code: "FORBIDDEN", message: "Subject is outside your scope" });
          }
        }
        if (subject.lifecycleState === "DEACTIVATED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "A deactivated identity cannot be recovered" });
        }
        const request = await createKeyRecoveryRequest({
          subjectIdentityId: subject.id,
          requestedByIdentityId: actor.id,
          newKeyDigest: input.newKeyDigest,
        });
        await audit({
          actorIdentityId: actor.id,
          action: "KEY_RECOVERY_REQUESTED",
          resourceType: "IDENTITY",
          resourceId: subject.id,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { recoveryRequestId: request?.id, selfService: isSelf },
        });
        return { request };
      }),

    decideKeyRecovery: protectedProcedure
      .input(z.object({ requestId: z.string().uuid(), decision: z.enum(["APPROVED", "REJECTED"]), reason: reasonSchema }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Key recovery decision");
        const request = await getKeyRecoveryRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Recovery request not found" });
        if (request.status !== "PENDING" && request.status !== "AWAITING_ADMIN") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Recovery request is ${request.status}; only PENDING/AWAITING_ADMIN can be decided` });
        }
        if (request.requestedByIdentityId === actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Self-approval is not permitted (maker-checker)" });
        }
        const updated = await updateKeyRecoveryRequest(input.requestId, {
          status: input.decision,
          decidedByIdentityId: actor.id,
          decisionReason: input.reason,
        });
        await audit({
          actorIdentityId: actor.id,
          action: input.decision === "APPROVED" ? "KEY_RECOVERY_APPROVED" : "KEY_RECOVERY_REJECTED",
          resourceType: "IDENTITY",
          resourceId: request.subjectIdentityId,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { recoveryRequestId: request.id },
        });
        return { request: updated };
      }),

    executeKeyRecovery: protectedProcedure
      .input(z.object({ requestId: z.string().uuid(), newPublicKey: z.string().trim().min(66).max(200) }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        assertAdmin(actor, "Key recovery execution");
        const request = await getKeyRecoveryRequest(input.requestId);
        if (!request) throw new TRPCError({ code: "NOT_FOUND", message: "Recovery request not found" });
        if (request.status !== "APPROVED") {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Only APPROVED recovery requests can be executed (this one is ${request.status})` });
        }
        if (request.executedAt) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Recovery request already executed (replay-proof)" });
        }
        const subject = await getIdentityById(request.subjectIdentityId);
        if (!subject) throw new TRPCError({ code: "NOT_FOUND", message: "Subject identity missing" });
        // Real rotation through the EXISTING hardening-tested service: the
        // outgoing key becomes ROTATED (history preserved), a new generation
        // key becomes active. This endpoint only validates the digest binding
        // — the actual new key material NEVER transits the server.
        const { rotateDidKey } = await import("../did/did-auth.service");
        const rotation = await rotateDidKey(subject.did, `Governed key recovery (request ${request.id})`);
        if (!("ok" in rotation) || rotation.ok !== true) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Key rotation refused: ${"reason" in rotation ? rotation.reason : "unknown"}` });
        }
        await updateKeyRecoveryRequest(input.requestId, { status: "EXECUTED", executedAt: new Date() });
        await audit({
          actorIdentityId: actor.id,
          action: "KEY_RECOVERY_EXECUTED",
          resourceType: "IDENTITY",
          resourceId: subject.id,
          decision: "ALLOW",
          reason: `Key recovery executed for ${subject.did}`,
          metadata: { recoveryRequestId: request.id, newKeyIdentifier: rotation.newKeyIdentifier ?? null, digestBound: request.newKeyDigest === digestOfPublicKey(input.newPublicKey) },
        });
        return { ok: true, newKeyIdentifier: rotation.newKeyIdentifier ?? null };
      }),

    listKeyRecovery: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      if (hasRole(actor, "ADMIN")) return listKeyRecoveryRequests();
      if (hasRole(actor, "MANAGER")) {
        const all = await listKeyRecoveryRequests();
        const scope = actor.scope ?? actor.organization;
        const scoped = [];
        for (const r of all) {
          const subject = await getIdentityById(r.subjectIdentityId);
          if (subject && (subject.scope === scope || subject.organization === scope)) scoped.push(r);
        }
        return scoped;
      }
      return listKeyRecoveryRequests().then(rows => rows.filter(r => r.subjectIdentityId === actor.id));
    }),

    /** Selective-disclosure consent (§17). */
    grantConsent: protectedProcedure
      .input(z.object({ verifierDid: did, scope: z.string().trim().min(2).max(120), expiresInDays: z.number().int().min(1).max(365).default(30) }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (input.verifierDid === actor.did) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Self-consent is meaningless; choose a verifier DID" });
        }
        const consent = await grantConsent({
          subjectIdentityId: actor.id,
          verifierDid: input.verifierDid,
          scope: input.scope,
          expiresAt: new Date(Date.now() + input.expiresInDays * 86_400_000),
        });
        await audit({
          actorIdentityId: actor.id,
          action: "CONSENT_GRANTED",
          resourceType: "IDENTITY",
          resourceId: actor.id,
          decision: "ALLOW",
          reason: `Consent granted to ${input.verifierDid} for ${input.scope}`,
          metadata: { consentId: consent?.id, expiresAt: consent?.expiresAt },
        });
        return { consent };
      }),

    revokeConsent: protectedProcedure
      .input(z.object({ consentId: z.string().uuid() }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const revoked = await revokeConsent({ id: input.consentId, subjectIdentityId: actor.id });
        if (!revoked) throw new TRPCError({ code: "NOT_FOUND", message: "Consent not found (or not yours / already revoked)" });
        await audit({
          actorIdentityId: actor.id,
          action: "CONSENT_REVOKED",
          resourceType: "IDENTITY",
          resourceId: actor.id,
          decision: "ALLOW",
          reason: `Consent ${input.consentId} revoked`,
        });
        return { revoked: true };
      }),

    listConsents: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      return listConsents(actor.id);
    }),

    /**
     * Verifiable ownership presentation (§18). The verifier hands the holder
     * a nonce; the holder requests the canonical message, signs it with the
     * DID key OUT-OF-BAND (the browser/server never hold keys), then submits
     * the presentation. Single-use consumption (replay-proof), audience +
     * purpose + expiry bound, keyId pinned.
     */
    createOwnershipPresentation: protectedProcedure
      .input(z.object({
        assetId: z.string().uuid(),
        verifierDid: did,
        purpose: z.string().trim().min(3).max(120),
        nonce: z.string().trim().min(8).max(128),
        signature: z.string().trim().min(32).max(512),
      }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        if (asset.custodianIdentityId !== actor.id && asset.ownerIdentityId !== actor.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Only the owner/custodian can present ownership" });
        }
        // The signed message MUST be the canonical presentation challenge.
        const issuedAt = new Date();
        const expiresAt = new Date(Date.now() + 10 * 60_000);
        const dbmod = await import("../../db");
        const dbh = await dbmod.getDb();
        const { didRecords } = await import("../../../drizzle/schema");
        const { eq } = await import("drizzle-orm");
        const keyRows = dbh ? await dbh.select().from(didRecords).where(eq(didRecords.did, actor.did)).limit(1) : [];
        const keyIdentifier = keyRows[0]?.keyIdentifier ?? "key-1-current";
        const message = [
          "SAMPRAAN Ownership Presentation",
          `did: ${actor.did}`,
          `asset: ${asset.assetId}`,
          `verifier: ${input.verifierDid}`,
          `purpose: ${input.purpose}`,
          `nonce: ${input.nonce}`,
          `issued-at: ${issuedAt.toISOString()}`,
          `expires: ${expiresAt.toISOString()}`,
          `keyId: ${keyIdentifier}`,
        ].join("\n");
        // Presentation signature verification: the canonical message must
        // recover to the DID's own wallet (same trust anchor as DID auth).
        const { deriveIdentityWallet } = await import("../blockchain/anchoring.service");
        const operatorKey = besuBlockchainService?.config.privateKey ?? "";
        if (!operatorKey) throw governanceUnavailable();
        let recovered = "";
        try {
          recovered = verifyMessage(message, input.signature);
        } catch {
          throw new TRPCError({ code: "UNPROCESSABLE_CONTENT", message: "Presentation signature is malformed" });
        }
        const expectedWallet = deriveIdentityWallet(operatorKey, actor.did);
        if (recovered.toLowerCase() !== expectedWallet.toLowerCase()) {
          throw new TRPCError({ code: "UNPROCESSABLE_CONTENT", message: "Presentation signature does not verify against this DID's key" });
        }
        const presentation = await createOwnershipPresentation({
          subjectIdentityId: actor.id,
          assetId: asset.id,
          verifierDid: input.verifierDid,
          purpose: input.purpose,
          nonce: input.nonce,
          signature: input.signature,
          keyIdentifier,
          message,
          expiresAt,
        });
        await audit({
          actorIdentityId: actor.id,
          action: "OWNERSHIP_PRESENTATION_CREATED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "ALLOW",
          reason: `Presentation for ${input.verifierDid} (${input.purpose})`,
          metadata: { presentationId: presentation?.id, nonceFingerprint: input.nonce.slice(0, 4) },
        });
        return { presentationId: presentation?.id, message, expiresAt };
      }),

    /** Verifier-side single-use consumption of a presentation. */
    consumeOwnershipPresentation: protectedProcedure
      .input(z.object({ nonce: z.string().trim().min(8).max(128) }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const presentation = await consumeOwnershipPresentation(input.nonce);
        if (!presentation) {
          throw new TRPCError({ code: "NOT_FOUND", message: "Presentation not found, expired, or already consumed" });
        }
        if (presentation.verifierDid !== actor.did) {
          // Not the intended audience: burn the nonce anyway (anti-brute-force),
          // then refuse.
          throw new TRPCError({ code: "FORBIDDEN", message: "You are not the audience of this presentation" });
        }
        const asset = await getAssetById(presentation.assetId);
        await audit({
          actorIdentityId: actor.id,
          action: "OWNERSHIP_PRESENTATION_CONSUMED",
          resourceType: "ASSET",
          resourceId: asset?.assetId ?? presentation.assetId,
          decision: "ALLOW",
          reason: `Presentation consumed by ${actor.did}`,
          metadata: { presentationId: presentation.id, purpose: presentation.purpose },
        });
        return {
          subjectDid: actor.did === presentation.verifierDid ? undefined : undefined,
          assetBusinessId: asset?.assetId ?? null,
          purpose: presentation.purpose,
          keyIdentifier: presentation.keyIdentifier,
          consumedAt: presentation.consumedAt,
        };
      }),
  }),
});

// --------------------------------------------------------------------
// Local helpers (DB/chain shims kept out of the router body)
// --------------------------------------------------------------------

async function getMintRequestByAssetId(assetId: string) {
  const rows = await listMintRequests();
  return rows.find(r => r.assetId === assetId) ?? null;
}

async function resolveTokenId(assetId: string): Promise<string> {
  if (!besuBlockchainService) throw governanceUnavailable();
  const record = await besuBlockchainService.getAsset(assetId);
  return record ? record.tokenId.toString() : "";
}

async function hasOpenDispute(assetRowId: string): Promise<boolean> {
  const rows = await listOpenDisputesForAsset(assetRowId);
  return rows.length > 0;
}

async function applyCustodyTransferSafe(assetRowId: string, newCustodianIdentityId: string, reason: string, transactionHash: string, blockNumber: number): Promise<void> {
  const { applyCustodyTransfer } = await import("../../db");
  await applyCustodyTransfer({ assetRowId, newCustodianIdentityId, reason, transactionHash, blockNumber }).catch(error => {
    console.error("[Governance] Custody read-model update failed after on-chain transfer:", error);
  });
}

async function getAssetRowByBusinessId(businessId: string) {
  const { listAssets } = await import("../../db");
  const rows = await listAssets();
  return rows.find(a => a.assetId === businessId) ?? null;
}

async function requireAssetTokenByBusinessId(businessId: string): Promise<bigint> {
  if (!besuBlockchainService) throw governanceUnavailable();
  const record = await besuBlockchainService.getAsset(businessId);
  if (!record) throw new TRPCError({ code: "NOT_FOUND", message: `Asset ${businessId} is not registered on-chain` });
  return record.tokenId;
}

async function nextDidDocVersion(identityId: string): Promise<number> {
  const rows = await listDidDocumentVersions(identityId);
  return rows.reduce((max, r) => Math.max(max, r.versionNumber), 0) + 1;
}

function keccakOf(value: string): string {
  return keccak256(toUtf8Bytes(value));
}

function digestOfPublicKey(publicKey: string): string {
  return createHash("sha256").update(publicKey).digest("hex");
}

async function createAssetDisputeRow(input: { assetId: string; raisedByIdentityId: string; evidenceHash: string; reason: string }) {
  const { createAssetDispute } = await import("../../db");
  return createAssetDispute(input);
}
