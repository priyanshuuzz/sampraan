/**
 * SAMPRAAN crypto assurance tRPC surface.
 *
 * Everything here is scoped to the AUTHENTICATED actor: the identity id, DID,
 * role and lifecycle are resolved server-side from the session — none of them
 * can be supplied by the client. The only client-supplied values are the
 * signatures, the nonce, the operation label for a *hypothetical* policy
 * question, and the PUBLIC key being registered.
 *
 * Procedures:
 *   policy.evaluate  — explain the required assurance for an operation (pure)
 *   key.status       — the actor's active ML-DSA-65 key (fingerprint only)
 *   key.register     — register a holder-held public key (signed proof of possession)
 *   key.rotate       — rotate to a new holder-held public key
 *   key.revoke       — disable the actor's PQC key (admin may target a DID)
 *   key.history      — key lifecycle history (audit evidence)
 *   challenge        — issue a policy-scored dual-signature challenge
 *   verify           — submit ECDSA (+ ML-DSA-65) signatures → single-use grant
 *   grants           — the actor's recent challenges/grants
 *   provider         — which PQC provider is active and whether it is prod-safe
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../../_core/trpc";
import {
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
  getActivePqcKeyRecord,
  listPqcKeyRecords,
  registerPqcKeyRecord,
  rotatePqcKeyRecord,
  setPqcKeyStatus,
  listAssuranceChallenges,
  createAuditEvent,
} from "../../db";
import {
  ML_DSA_65_ALGORITHM,
  parsePublicKey,
  isDegeneratePublicKey,
  pqcKeyIdentifierFor,
  generationOf,
  verifyMessageSignature,
} from "./ml-dsa";
import { describePqcProvider, resolvePqcKeyProvider } from "./pqc-key-provider";
import { decideAssurance, issueAssuranceChallenge, verifyAssuranceChallenge, ASSURANCE_GRANT_VALIDITY_MS, assuranceAudience } from "./assurance.service";
import { ASSURANCE_REASON_CODES } from "./assurance-policy";

const operationSchema = z.enum([
  "ASSET_VIEW",
  "CONTENT_ACCESS",
  "CONTENT_UPLOAD",
  "ASSET_MINT",
  "ASSET_ASSIGN",
  "ASSET_TRANSFER",
  "ASSET_FORCE_TRANSFER",
  "ASSET_BURN",
  "ASSET_STATUS_CHANGE",
  "IDENTITY_VERIFY",
  "IDENTITY_STATUS_CHANGE",
  "IDENTITY_ROLE_CHANGE",
  "IDENTITY_ROLE_ADMIN",
  "DID_DOCUMENT_UPDATE",
  "DID_KEY_ROTATE",
  "DID_KEY_REVOKE",
  "KEY_RECOVERY_REQUEST",
  "KEY_RECOVERY_APPROVE",
  "KEY_RECOVERY_EXECUTE",
  "GOVERNANCE_PROPOSAL",
  "GOVERNANCE_APPROVE",
  "GOVERNANCE_EXECUTE",
  "GOVERNANCE_CANCEL",
  "GOVERNANCE_CONFIG",
  "PAUSE_REGISTRY",
  "UNPAUSE_REGISTRY",
  "DISPUTE_RESOLVE",
  "AUDIT_REPORT_COMMIT",
  "CONSENT_GRANT",
]);

const classificationSchema = z.enum(["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]);
const riskSchema = z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const custodySchema = z.enum(["CUSTODIAN", "OWNER", "NONE", "ADMIN_OVERRIDE", "NOT_APPLICABLE"]);
const approvalSchema = z.enum(["NOT_REQUIRED", "PENDING", "APPROVED", "REJECTED", "EXECUTED"]);

const base64Url = z.string().trim().min(16).max(20000).regex(/^[A-Za-z0-9_-]+$/, "Expected base64url");

/** Actor resolution: identity, roles and lifecycle, all server-side. */
async function requireActor(user: { id: number } | null) {
  if (!user) throw new TRPCError({ code: "UNAUTHORIZED", message: "Authentication required" });
  const identity = await getIdentityByLinkedUserId(user.id);
  if (!identity) throw new TRPCError({ code: "FORBIDDEN", message: "No SAMPRAAN identity is linked to this session" });
  const { roles, permissions } = await getIdentityRolesAndPermissions(identity.id);
  return { identity, roles, permissions };
}

async function audit(input: {
  actorIdentityId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  decision: "ALLOW" | "DENY";
  reason: string;
  metadata?: Record<string, unknown>;
}) {
  await createAuditEvent({
    actorIdentityId: input.actorIdentityId,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    decision: input.decision,
    reason: input.reason,
    metadata: { source: "crypto-assurance", ...(input.metadata ?? {}) },
  }).catch(() => undefined);
}

/** Canonical proof-of-possession payload for PQC key registration. */
function buildKeyRegistrationMessage(fields: {
  did: string;
  keyIdentifier: string;
  algorithm: string;
  publicKeyFingerprint: string;
  audience: string;
  generation: number;
}): string {
  return [
    "SAMPRAAN PQC Key Registration",
    "version: 1",
    `did: ${fields.did}`,
    `keyId: ${fields.keyIdentifier}`,
    `algorithm: ${fields.algorithm}`,
    `public-key-sha256: ${fields.publicKeyFingerprint}`,
    `generation: ${fields.generation}`,
    `audience: ${fields.audience}`,
    "Signing this message proves possession of the ML-DSA-65 secret key for this DID.",
  ].join("\n");
}

export const assuranceRouter = router({
  /** Explain the required assurance for an operation. Pure, side-effect free. */
  policy: protectedProcedure
    .input(
      z.object({
        operation: operationSchema,
        assetClassification: classificationSchema.optional(),
        riskLevel: riskSchema.optional(),
        riskScore: z.number().int().min(0).max(100).optional(),
        custodyRelation: custodySchema.optional(),
        approvalStatus: approvalSchema.optional(),
        stepUpSatisfied: z.boolean().optional(),
      }),
    )
    .query(async ({ input, ctx }) => {
      const actor = await requireActor(ctx.user);
      // The ROLE always comes from the session, never from the client — a
      // client could otherwise ask "what does ADMIN require?" and mislead.
      const decision = decideAssurance({
        operation: input.operation,
        role: actor.roles[0] ?? "USER",
        assetClassification: input.assetClassification ?? null,
        riskLevel: input.riskLevel ?? null,
        riskScore: input.riskScore ?? null,
        custodyRelation: input.custodyRelation ?? null,
        approvalStatus: input.approvalStatus ?? null,
        stepUpSatisfied: input.stepUpSatisfied,
      });
      return {
        ...decision,
        // Full vocabulary so the UI can explain ANY code it is shown.
        reasonCodeVocabulary: ASSURANCE_REASON_CODES,
        grantValidityMs: ASSURANCE_GRANT_VALIDITY_MS,
      };
    }),

  /** Which PQC provider is active (never returns key material). */
  provider: protectedProcedure.query(async () => describePqcProvider()),

  key: router({
    status: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      const record = await getActivePqcKeyRecord(actor.identity.did);
      return {
        did: actor.identity.did,
        registered: Boolean(record),
        algorithm: record?.algorithm ?? ML_DSA_65_ALGORITHM,
        keyIdentifier: record?.keyIdentifier ?? null,
        publicKeyFingerprint: record?.publicKeyFingerprint ?? null,
        keySource: record?.keySource ?? null,
        status: record?.status ?? null,
      };
    }),

    /**
     * Register the actor's ML-DSA-65 PUBLIC key.
     *
     * PROOF OF POSSESSION IS MANDATORY: the caller must sign the canonical
     * registration message with the matching secret key. Without it, anyone who
     * saw a public key could bind it to their own identity and then pass
     * dual-signature checks they cannot actually satisfy.
     */
    register: protectedProcedure
      .input(
        z.object({
          publicKey: base64Url,
          /** ML-DSA-65 signature over the canonical registration message. */
          proofOfPossession: base64Url,
          note: z.string().trim().max(200).optional(),
        }),
      )
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        if (actor.identity.status !== "ACTIVE" || actor.identity.lifecycleState !== "VERIFIED") {
          throw new TRPCError({ code: "FORBIDDEN", message: `Identity is ${actor.identity.lifecycleState} — a PQC key cannot be registered` });
        }
        const parsed = parsePublicKey(input.publicKey);
        if (!parsed) {
          throw new TRPCError({ code: "BAD_REQUEST", message: `publicKey must be a base64url ML-DSA-65 public key (1952 bytes)` });
        }
        if (isDegeneratePublicKey(parsed.bytes)) {
          throw new TRPCError({ code: "BAD_REQUEST", message: "Refusing to register an all-zero public key" });
        }
        const existing = await getActivePqcKeyRecord(actor.identity.did);
        const generation = existing ? generationOf(existing.keyIdentifier) + 1 : 1;
        const keyIdentifier = pqcKeyIdentifierFor(actor.identity.did, generation);
        const message = buildKeyRegistrationMessage({
          did: actor.identity.did,
          keyIdentifier,
          algorithm: ML_DSA_65_ALGORITHM,
          publicKeyFingerprint: parsed.fingerprint,
          audience: assuranceAudience(),
          generation,
        });
        const possessed = verifyMessageSignature({
          message,
          publicKey: input.publicKey,
          signature: input.proofOfPossession,
        });
        if (!possessed) {
          await audit({
            actorIdentityId: actor.identity.id,
            action: "PQC_KEY_REGISTRATION_REJECTED",
            resourceType: "IDENTITY",
            resourceId: actor.identity.id,
            decision: "DENY",
            reason: "ML-DSA-65 proof of possession failed",
            metadata: { keyIdentifier, publicKeyFingerprint: parsed.fingerprint },
          });
          throw new TRPCError({ code: "BAD_REQUEST", message: "Proof of possession failed — the signature must verify against the submitted public key" });
        }

        const record = existing
          ? await rotatePqcKeyRecord({
              identityId: actor.identity.id,
              did: actor.identity.did,
              previousKeyIdentifier: existing.keyIdentifier,
              newKeyIdentifier: keyIdentifier,
              algorithm: ML_DSA_65_ALGORITHM,
              publicKey: input.publicKey,
              publicKeyFingerprint: parsed.fingerprint,
              keySource: "REGISTERED",
              registeredByIdentityId: actor.identity.id,
              note: input.note ?? null,
            })
          : await registerPqcKeyRecord({
              identityId: actor.identity.id,
              did: actor.identity.did,
              keyIdentifier,
              algorithm: ML_DSA_65_ALGORITHM,
              publicKey: input.publicKey,
              publicKeyFingerprint: parsed.fingerprint,
              keySource: "REGISTERED",
              registeredByIdentityId: actor.identity.id,
              note: input.note ?? null,
            });
        if (!record) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });

        await audit({
          actorIdentityId: actor.identity.id,
          action: existing ? "PQC_KEY_ROTATED" : "PQC_KEY_REGISTERED",
          resourceType: "DID",
          resourceId: actor.identity.did,
          decision: "ALLOW",
          reason: `${ML_DSA_65_ALGORITHM} key ${existing ? "rotated" : "registered"} (generation ${generation})`,
          metadata: {
            keyIdentifier,
            previousKeyIdentifier: existing?.keyIdentifier ?? null,
            algorithm: ML_DSA_65_ALGORITHM,
            publicKeyFingerprint: parsed.fingerprint,
            keySource: "REGISTERED",
          },
        });

        return {
          keyIdentifier: record.keyIdentifier,
          algorithm: record.algorithm,
          publicKeyFingerprint: record.publicKeyFingerprint,
          rotatedFrom: existing?.keyIdentifier ?? null,
        };
      }),

    /**
     * Disable the actor's PQC key. An ADMIN may target another DID, because a
     * compromised holder key must be revocable by the platform — this is
     * deliberately narrow (a revocation, never a registration on behalf of
     * someone else) and is audited with the reason.
     */
    revoke: protectedProcedure
      .input(z.object({ did: z.string().trim().max(255).optional(), reason: z.string().trim().min(3).max(300) }))
      .mutation(async ({ input, ctx }) => {
        const actor = await requireActor(ctx.user);
        const isAdmin = actor.roles.includes("ADMIN");
        let targetDid = actor.identity.did;
        if (input.did && input.did !== actor.identity.did) {
          if (!isAdmin) throw new TRPCError({ code: "FORBIDDEN", message: "Revoking another DID's PQC key requires the ADMIN role" });
          targetDid = input.did;
        }
        const active = await getActivePqcKeyRecord(targetDid);
        if (!active) throw new TRPCError({ code: "NOT_FOUND", message: "No ACTIVE ML-DSA-65 key for this DID" });
        await setPqcKeyStatus(targetDid, "REVOKED", input.reason);
        await audit({
          actorIdentityId: actor.identity.id,
          action: "PQC_KEY_REVOKED",
          resourceType: "DID",
          resourceId: targetDid,
          decision: "ALLOW",
          reason: input.reason,
          metadata: { keyIdentifier: active.keyIdentifier, targetedBy: isAdmin ? "ADMIN" : "SELF" },
        });
        return { revoked: true, did: targetDid, keyIdentifier: active.keyIdentifier };
      }),

    history: protectedProcedure.query(async ({ ctx }) => {
      const actor = await requireActor(ctx.user);
      const rows = await listPqcKeyRecords(actor.identity.did);
      // Fingerprints and ids only — the stored public key is never returned in
      // bulk history (it is available through key.status for the active key).
      return rows.map(row => ({
        keyIdentifier: row.keyIdentifier,
        algorithm: row.algorithm,
        publicKeyFingerprint: row.publicKeyFingerprint,
        status: row.status,
        keySource: row.keySource,
        supersededByKeyIdentifier: row.supersededByKeyIdentifier,
        note: row.note,
        createdAt: row.createdAt,
        deactivatedAt: row.deactivatedAt,
      }));
    }),
  }),

  /** Issue a policy-scored assurance challenge for a concrete operation. */
  challenge: protectedProcedure
    .input(
      z.object({
        operation: operationSchema,
        resourceType: z.string().trim().min(1).max(100),
        resourceId: z.string().trim().min(1).max(160),
        assetClassification: classificationSchema.optional(),
        riskLevel: riskSchema.optional(),
        riskScore: z.number().int().min(0).max(100).optional(),
        custodyRelation: custodySchema.optional(),
        approvalStatus: approvalSchema.optional(),
      }),
    )
    .mutation(async ({ input, ctx }) => {
      const actor = await requireActor(ctx.user);
      const result = await issueAssuranceChallenge({
        identityId: actor.identity.id,
        did: actor.identity.did,
        identityStatus: actor.identity.status,
        lifecycleState: actor.identity.lifecycleState,
        role: actor.roles[0] ?? "USER",
        operation: input.operation,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        policyInput: {
          assetClassification: input.assetClassification ?? null,
          riskLevel: input.riskLevel ?? null,
          riskScore: input.riskScore ?? null,
          custodyRelation: input.custodyRelation ?? null,
          approvalStatus: input.approvalStatus ?? null,
          stepUpSatisfied: false,
        },
      });
      if (!result.ok) throw new TRPCError({ code: "PRECONDITION_FAILED", message: `${result.code}: ${result.reason}` });
      return result;
    }),

  /** Submit the signature(s). Success returns a single-use grant id. */
  verify: protectedProcedure
    .input(
      z.object({
        nonce: z.string().trim().length(48),
        ecdsaSignature: z.string().trim().min(16).max(500),
        pqcSignature: base64Url.optional(),
      }),
    )
    .mutation(async ({ input, ctx }) => {
      const actor = await requireActor(ctx.user);
      const operatorKey = process.env.BLOCKCHAIN_PRIVATE_KEY ?? "";
      if (!operatorKey) {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Blockchain operator key is not configured — DID signature verification is unavailable" });
      }
      const result = await verifyAssuranceChallenge({
        identityId: actor.identity.id,
        nonce: input.nonce,
        ecdsaSignature: input.ecdsaSignature,
        pqcSignature: input.pqcSignature ?? null,
        operatorKey,
      });
      if (!result.ok) throw new TRPCError({ code: "PRECONDITION_FAILED", message: `${result.code}: ${result.reason}` });
      return result;
    }),

  /** The actor's recent assurance challenges/grants (audit evidence). */
  grants: protectedProcedure.query(async ({ ctx }) => {
    const actor = await requireActor(ctx.user);
    const rows = await listAssuranceChallenges(actor.identity.id);
    return rows.map(row => ({
      id: row.id,
      operation: row.operation,
      resourceType: row.resourceType,
      resourceId: row.resourceId,
      assuranceLevel: row.assuranceLevel,
      requiredAlgorithms: row.requiredAlgorithms,
      reasonCodes: row.reasonCodes,
      ecdsaVerified: row.ecdsaVerified,
      pqcVerified: row.pqcVerified,
      consumedAt: row.consumedAt,
      executedAt: row.executedAt,
      expiresAt: row.expiresAt,
      createdAt: row.createdAt,
    }));
  }),

  /**
   * DEV HELPER — sign a challenge with the server-derived DID key so the demo
   * flow is executable without a PQC-capable client. Refused in production
   * (the provider returns null there, and this procedure answers 403).
   */
  devSign: protectedProcedure
    .input(z.object({ nonce: z.string().trim().length(48) }))
    .mutation(async ({ input, ctx }) => {
      const provider = resolvePqcKeyProvider();
      if (provider.name !== "local-dev") {
        throw new TRPCError({ code: "FORBIDDEN", message: "devSign is available only with the local-dev PQC key provider" });
      }
      const actor = await requireActor(ctx.user);
      const row = (await listAssuranceChallenges(actor.identity.id)).find(item => item.nonce === input.nonce);
      if (!row) throw new TRPCError({ code: "NOT_FOUND", message: "Challenge not found for this identity" });
      const signature = await provider.signWithDerivedKey(actor.identity.did, row.message);
      if (!signature) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Active provider cannot sign (registered keys are holder-held)" });
      return { pqcSignature: signature, keyIdentifier: row.pqcKeyIdentifier };
    }),
});
