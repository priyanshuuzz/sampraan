import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { authorizationService } from "./modules/authorization/authorization.service";
import { blockchainService, besuBlockchainService } from "./modules/blockchain/blockchain.service";
import {
  applyAssetStatusChange,
  applyCustodyTransfer,
  applyIdentityStatusChange,
  createAsset,
  createAuditEvent,
  createAuthorizationDecision,
  createDidRecord,
  createIdentity,
  getAssetById,
  getIdentityById,
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
  listAssets,
  listAuditEvents,
  listIdentities,
  listSecurityAlerts,
  revokePlatformSession,
} from "./db";
import { anchoringService, deriveIdentityWallet } from "./modules/blockchain/anchoring.service";
import { isDuplicateEntryError } from "./modules/db/db-errors";

const identityStatus = z.enum(["ACTIVE", "REVOKED", "SUSPENDED"]);
const assetStatus = z.enum(["ACTIVE", "REVOKED", "PENDING"]);
// Classifications the authorization engine reasons about. Values outside this
// set cannot appear in the DB via the API, so POLICY-HIGH-SENS-TRANSFER can
// never be sidestepped by an ad-hoc classification string.
const assetClassification = z.enum(["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]);
// W3C DID Core generic syntax: did:method:name (method = lowercase
// alphanumeric). Constrained so arbitrary strings can't masquerade as DIDs.
const did = z
  .string()
  .min(8)
  .max(255)
  .regex(/^did:[a-z][a-z0-9]*:[A-Za-z0-9._\-]+$/, "Invalid DID format (expected did:method:identifier)")

export const appRouter = router({
  system: systemRouter,
  health: publicProcedure.query(async () => ({ api: "OK" as const, database: process.env.DATABASE_URL ? "CONFIGURED" as const : "NOT_CONFIGURED" as const, blockchain: await blockchainService.getNetworkStatus() })),
  observatory: publicProcedure.query(async () => { const [identities, assets, audit, alerts, blockchain] = await Promise.all([listIdentities(), listAssets(), listAuditEvents(200), listSecurityAlerts(), blockchainService.getNetworkStatus()]); return { identityCount: identities.length, assetCount: assets.length, auditEventCount: audit.length, openAlertCount: alerts.filter(alert => alert.status === "OPEN").length, blockchain }; }),
  demo: router({
    identities: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listIdentities(); }),
    assets: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listAssets(); }),
    audit: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listAuditEvents(200); }),
    alerts: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listSecurityAlerts(); }),
  }),
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      // QA #5: logout must also revoke the tracked platform session
      // server-side, so a stolen copy of the token cannot be replayed after
      // the legitimate user logged out.
      const bearer = ctx.req.headers.authorization;
      const token =
        typeof bearer === "string" && bearer.startsWith("Bearer ")
          ? bearer.slice(7)
          : null;
      if (token) {
        revokePlatformSession(token).catch((error: unknown) => {
          console.error("[Auth] Failed to revoke platform session on logout:", error);
        });
      }
      return { success: true } as const;
    }),
  }),
  identities: router({
    list: protectedProcedure.query(() => listIdentities()),
    // SECURITY: minting identities into the trust registry is an
    // administrative act — a regular authenticated user must not be able to
    // create identity records that the authorization engine then trusts.
    create: adminProcedure.input(z.object({ displayName: z.string().min(2).max(160), organization: z.string().min(2).max(180), did, status: identityStatus.default("ACTIVE") })).mutation(async ({ input }) => {
      const identity = await createIdentity(input).catch((error: unknown) => {
        // identities.did is UNIQUE; a duplicate DID must surface as a clear
        // client error instead of a masked 500. NOTE (QA #1 regression): the
        // mysql2 error lives in error.cause after drizzle wraps it, so the
        // old message-only regex never matched — duplicates returned 500.
        if (isDuplicateEntryError(error)) {
          throw new TRPCError({ code: "CONFLICT", message: "An identity with this DID already exists" });
        }
        throw error;
      });
      // REVOKED/SUSPENDED identities must never be created pre-revoked with an
      // active DID document: force the DID record status to match the identity.
      if (!identity) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Identity could not be created" });
      await createDidRecord({
        identityId: identity.id,
        did: input.did,
        method: input.did.split(":")[1] ?? "unknown",
        subject: input.did,
        document: { id: input.did, verificationMethod: [] },
        status: input.status === "ACTIVE" ? "ACTIVE" : "REVOKED",
      }).catch(() => { /* DID record is derived material; the identity itself was created. */ });
      // BUG-003 (QA #3): anchor the identity reference on the Besu chain so
      // its lifecycle is tamper-evident from birth. Best-effort: the chain
      // being down must not make identity creation impossible, but every
      // attempt (anchored / skipped / failed) is audited.
      const anchor = await anchoringService.anchorIdentity({
        did: input.did,
        displayName: input.displayName,
      });
      return { ...identity, anchor };
    }),
    /**
     * Identity lifecycle management (admin only). Updating the status
     * updates the read model, revokes the derived DID record, anchors the
     * status change on the Besu chain when configured, and — through the
     * session gate in sdk.authenticateRequest — immediately strips platform
     * privileges from any session bound to a REVOKED/SUSPENDED identity
     * (BUG-007 / QA #4).
     */
    setStatus: adminProcedure.input(z.object({ identityId: z.string().uuid(), status: identityStatus })).mutation(async ({ input }) => {
      const identity = await getIdentityById(input.identityId);
      if (!identity) throw new TRPCError({ code: "NOT_FOUND", message: "Identity not found" });
      if (identity.status === input.status) {
        return { ...identity, changed: false as const };
      }
      const updated = await applyIdentityStatusChange({
        identityId: input.identityId,
        status: input.status,
      });

      // Anchor the status change on-chain when a real chain is configured.
      // The status call targets the identity's deterministic on-chain reference
      // wallet — never the shared operator wallet, which would move every
      // identity's status at once.
      let anchor: { outcome: string; reason?: string } | null = null;
      if (besuBlockchainService) {
        try {
          const operatorKey = besuBlockchainService.config.privateKey;
          const walletAddress = operatorKey
            ? deriveIdentityWallet(operatorKey, identity.did)
            : null;
          if (!walletAddress) {
            anchor = { outcome: "SKIPPED", reason: "Operator key not configured; status change not anchored on-chain" };
          } else {
            // The wallet must exist on-chain before its status can change.
            // Seed-created identities may never have been anchored; anchor
            // idempotently first (AlreadyRegistered is handled as a skip).
            await anchoringService.anchorIdentity({
              did: identity.did,
              displayName: identity.displayName,
            });
            try {
              const evidence = await besuBlockchainService.setIdentityStatus({
                walletAddress,
                status: input.status,
              });
              anchor = { outcome: "ANCHORED", reason: evidence.transactionHash };
            } catch (statusError) {
              const reason = statusError instanceof Error ? statusError.message : String(statusError);
              // BUG-031: the contract reverts SameStatus() (0x24904fe5) when
              // the on-chain status already equals the target — e.g. after a
              // prior chain call failed and the DB/chain drifted, or a
              // re-assertion of the same lifecycle state. An already-in-sync
              // chain is the DESIRED end state, not a failure.
              if (reason.includes("0x24904fe5") || /same status/i.test(reason)) {
                anchor = { outcome: "SKIPPED", reason: "On-chain status already matches the requested status" };
              } else {
                throw statusError;
              }
            }
          }
        } catch (error) {
          anchor = {
            outcome: "FAILED",
            reason: error instanceof Error ? error.message : String(error),
          };
        }
      }

      await createAuditEvent({
        actorIdentityId: identity.id,
        action: input.status === "REVOKED" ? "IDENTITY_REVOKED" : input.status === "SUSPENDED" ? "IDENTITY_SUSPENDED" : "IDENTITY_REACTIVATED",
        resourceType: "IDENTITY",
        resourceId: identity.id,
        decision: "ALLOW",
        reason: `Identity status set to ${input.status} by an administrator`,
        transactionHash: anchor?.outcome === "ANCHORED" ? anchor.reason ?? null : null,
        metadata: { source: "identity-administration", previousStatus: identity.status, newStatus: input.status, anchorOutcome: anchor?.outcome ?? "SKIPPED" },
      }).catch(() => { /* evidence best-effort */ });

      return { ...(updated ?? identity), changed: true as const, anchor };
    }),
  }),
  assets: router({
    list: protectedProcedure.query(() => listAssets()),
    // SECURITY: same reasoning — registering assets (and especially their
    // classification, which drives POLICY-HIGH-SENS-TRANSFER) is
    // administrative. Users must not mint low-classification records to
    // smuggle assets past the transfer policy.
    create: adminProcedure.input(z.object({ assetId: z.string().min(2).max(120), name: z.string().min(2).max(200), type: z.string().min(2).max(80), classification: assetClassification, description: z.string().max(5000).optional(), ownerIdentityId: z.string().uuid(), custodianIdentityId: z.string().uuid(), integrityHash: z.string().max(255).optional(), tokenId: z.string().max(160).optional(), status: assetStatus.default("PENDING") })).mutation(async ({ input }) => {
      const asset = await createAsset(input).catch((error: unknown) => {
        // assets.assetId is UNIQUE; surface duplicates as a clear client
        // error. Same cause-chain handling as identities.create (QA #1).
        if (isDuplicateEntryError(error)) {
          throw new TRPCError({ code: "CONFLICT", message: "An asset with this assetId already exists" });
        }
        throw error;
      });
      // BUG-003 (QA #3): anchor the asset on the Besu chain (controlled mint)
      // so ownership/custody provenance starts on-chain. Best-effort with a
      // full audit trail of the anchor outcome.
      const anchor = await anchoringService.anchorAsset({
        assetId: input.assetId,
        classification: input.classification,
        integrityHash: input.integrityHash ?? null,
      });
      return { ...asset, anchor };
    }),
    /**
     * Asset lifecycle management (admin only). BUG-028: assets were created
     * PENDING with NO way to ever activate them, making every API-created
     * asset permanently untransferable. This transitions the read-model
     * status and mirrors the lifecycle on-chain (ACTIVATE/SUSPEND/RESTORE/
     * REVOKE) when a real chain is configured, with full audit evidence.
     */
    setStatus: adminProcedure.input(z.object({ assetId: z.string().uuid(), status: assetStatus })).mutation(async ({ input }) => {
      const asset = await getAssetById(input.assetId);
      if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
      if (asset.status === input.status) {
        return { ...asset, changed: false as const };
      }
      const updated = await applyAssetStatusChange({
        assetRowId: asset.id,
        status: input.status,
      });

      // Mirror the lifecycle change on-chain when configured.
      let anchor: { outcome: string; reason?: string } | null = null;
      if (besuBlockchainService) {
        const chainStatus =
          input.status === "ACTIVE" ? "ACTIVATE" :
          input.status === "REVOKED" ? "REVOKE" : "SUSPEND";
        try {
          const evidence = await besuBlockchainService.setAssetStatus({
            assetId: asset.assetId,
            status: chainStatus as "ACTIVATE" | "SUSPEND" | "RESTORE" | "REVOKE",
          });
          anchor = { outcome: "ANCHORED", reason: evidence.transactionHash };
        } catch (error) {
          anchor = {
            outcome: "FAILED",
            reason: error instanceof Error ? error.message : String(error),
          };
        }
      }

      await createAuditEvent({
        actorIdentityId: null,
        action: input.status === "ACTIVE" ? "ASSET_ACTIVATED" : input.status === "REVOKED" ? "ASSET_REVOKED" : "ASSET_SUSPENDED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "ALLOW",
        reason: `Asset status set to ${input.status} by an administrator`,
        transactionHash: anchor?.outcome === "ANCHORED" ? anchor.reason ?? null : null,
        metadata: { source: "asset-administration", previousStatus: asset.status, newStatus: input.status, anchorOutcome: anchor?.outcome ?? "SKIPPED" },
      }).catch(() => { /* evidence best-effort */ });

      return { ...(updated ?? asset), changed: true as const, anchor };
    }),
    // SECURITY: classification and step-up state come exclusively from
    // server-side state. The client may only name the asset; it can never
    // assert its own classification, role, permissions, or step-up state.
    authorizeTransfer: protectedProcedure.input(z.object({ assetId: z.string().uuid() })).mutation(async ({ ctx, input }) => {
      const asset = await getAssetById(input.assetId);
      if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });

      // SECURITY: the asset must be ACTIVE before any policy evaluation; a
      // revoked or suspended asset can never be transferred.
      if (asset.status !== "ACTIVE") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Asset is ${asset.status.toLowerCase()} and cannot be transferred` });
      }

      // SECURITY: resolve the real SAMPRAAN identity linked to the authenticated
      // platform user. The frontend never supplies role/status/permissions —
      // they are derived server-side from the session and the trust domain.
      // An actor without a registered SAMPRAAN identity never evaluates as
      // ACTIVE: the engine denies.
      const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
      const { roles, permissions } = actorIdentity
        ? await getIdentityRolesAndPermissions(actorIdentity.id)
        : { roles: [] as string[], permissions: [] as string[] };

      // SECURITY: the owner identity status is resolved from the database,
      // never asserted by the caller. An asset whose owner identity is
      // suspended or revoked (or unknown) cannot be transferred, even when the
      // actor is an administrator — defense in depth on top of the actor
      // identity check below.
      const ownerIdentity = await getIdentityById(asset.ownerIdentityId);
      const ownerStatus = ownerIdentity?.status ?? "SUSPENDED";
      if (ownerStatus !== "ACTIVE") {
        const reason = `Owner identity is ${ownerStatus.toLowerCase()}`;
        const decision = {
          decision: "DENY" as const,
          decisionId: crypto.randomUUID(),
          reason,
          policyId: undefined,
          timestamp: new Date().toISOString(),
        };
        // The denial is evidence: persist the audit event with the actor
        // attribution (never the resource owner) before returning.
        await createAuditEvent({ actorIdentityId: actorIdentity?.id ?? null, action: "AUTHORIZATION_DENIED", resourceType: "ASSET", resourceId: asset.assetId, decision: "DENY", reason, metadata: { source: "authorization-engine", policyId: null, actorOpenId: ctx.user.openId, actorUserRole: ctx.user.role, actorUserOpenId: ctx.user.openId, ownerStatus } });
        return { ...decision, transaction: null };
      }

      const result = authorizationService.evaluate({
        identityStatus: actorIdentity?.status ?? "UNREGISTERED",
        // Platform admin maps to the ADMIN role and gains administration:manage;
        // both are still subject to the engine's identity-status check above.
        role: ctx.user.role === "admin" ? "ADMIN" : roles[0] ?? "USER",
        permissions: ctx.user.role === "admin" ? Array.from(new Set([...permissions, "administration:manage"])) : permissions,
        resourceType: "asset",
        action: "TRANSFER",
        // SECURITY: classification always comes from the database record,
        // never from a client-supplied value. No client step-up state is
        // forwarded: there is no server-side step-up mechanism, so
        // HIGHLY_SENSITIVE transfers CHALLENGE instead of silently ALLOWing.
        assetClassification: asset.classification,
      });

      // SECURITY: audit and decision records always attribute the ACTOR —
      // the requesting identity — never the resource owner.
      // authorization_decisions.actorIdentityId is NOT NULL, so unregistered
      // actors (no SAMPRAAN identity) cannot have a decision row; their
      // attempts are still captured by the nullable-actor audit event below.
      // authorization_decisions.policyId is FK-bound to policies.id (UUID),
      // but the engine's inline policy labels (POLICY-*) are not UUIDs, so
      // they are recorded in the audit metadata instead of the FK column.
      const auditAction = result.decision === "DENY" ? "AUTHORIZATION_DENIED" : result.decision === "CHALLENGE" ? "AUTHORIZATION_CHALLENGED" : "AUTHORIZATION_ALLOWED";
      // SECURITY: audit metadata records BOTH acting-account coordinates
      // (Manus openId/role) and the actor's SAMPRAAN identity id, so a denial
      // can never be misattributed to the resource owner.
      const actingUser = { actorUserOpenId: ctx.user.openId, actorUserRole: ctx.user.role };
      const auditMetadata: Record<string, unknown> = { source: "authorization-engine", policyId: result.policyId ?? null, actorOpenId: ctx.user.openId, ...actingUser };

      if (actorIdentity) {
        await createAuthorizationDecision({
          id: result.decisionId,
          actorIdentityId: actorIdentity.id,
          resourceType: "ASSET",
          resourceId: asset.assetId,
          action: "TRANSFER",
          decision: result.decision,
          reason: result.reason,
          policyId: null,
          timestamp: new Date(result.timestamp),
        }).catch((error: unknown) => {
          // The decision is evidence: a persistence failure must surface, not
          // silently drop the audit trail.
          console.error("[Authorization] Failed to persist decision:", error);
        });
      }

      const persistAudit = (extra: { transactionHash?: string; blockNumber?: number } = {}) =>
        createAuditEvent({
          actorIdentityId: actorIdentity?.id ?? null,
          action: auditAction,
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: result.decision,
          reason: result.reason,
          metadata: auditMetadata,
          ...extra,
        }).catch((error: unknown) => {
          console.error("[Authorization] Failed to persist audit event:", error);
        });

      if (result.decision !== "ALLOW") {
        await persistAudit();
        return { ...result, transaction: null };
      }

      // Policy ALLOWed the request. The smart contract now INDEPENDENTLY
      // re-verifies role, identity status, and asset state on-chain; only a
      // successful receipt produces a confirmed transaction record.
      //
      // BUG-029: the transfer target must be the ACTING identity's on-chain
      // reference wallet — not the shared operator wallet. Assets anchored at
      // creation already sit with the operator wallet, so transferring
      // "to the operator" reverts with SameAssetStatus() (0x27479240) and the
      // custody never moves. Each identity's wallet is derived
      // deterministically from its DID, so custody flows to the authorized
      // actor exactly as the policy engine decided.
      const operatorKey = besuBlockchainService?.config.privateKey ?? null;
      const toCustodianWallet = actorIdentity && operatorKey
        ? deriveIdentityWallet(operatorKey, actorIdentity.did)
        : blockchainService.operatorAddress;
      // The contract requires the RECIPIENT identity to be ACTIVE on-chain
      // (RecipientNotActive). An actor identity that exists in the read model
      // but was never anchored would fail the transfer; anchor it now —
      // idempotent, best-effort, and audited exactly like creation.
      if (actorIdentity && operatorKey && blockchainService.mode === "BESU") {
        await anchoringService.anchorIdentity({
          did: actorIdentity.did,
          displayName: actorIdentity.displayName,
        });
      }
      if (blockchainService.mode === "BESU" && !toCustodianWallet) {
        // A real-chain custody transfer needs a custodian wallet on the
        // contract call; without it the transfer cannot happen. Record the
        // failure evidence — never the ALLOW audit — and fail closed.
        await createAuditEvent({
          actorIdentityId: actorIdentity?.id ?? null,
          action: "BLOCKCHAIN_TRANSACTION_FAILED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "DENY",
          reason: "Blockchain custodian wallet is not configured",
          metadata: { source: "blockchain-evidence", ...actingUser },
        }).catch((persistError: unknown) => {
          console.error("[Authorization] Failed to persist chain-failure audit event:", persistError);
        });
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Blockchain custodian wallet is not configured" });
      }
      // BUG-032: when the asset's on-chain custodian is ALREADY the acting
      // identity's wallet (e.g. re-running the SIH demo transfer twice), the
      // contract correctly reverts SameAssetStatus() (0x27479240). That is
      // not a failure — the requested custody state already holds on-chain.
      // Read the chain state and short-circuit with an evidence-backed
      // "already in custody" result instead of a confusing BAD_GATEWAY error.
      if (besuBlockchainService && toCustodianWallet) {
        const onChainAsset = await besuBlockchainService
          .getAsset(asset.assetId)
          .catch(() => null);
        if (onChainAsset && onChainAsset.custodian.toLowerCase() === toCustodianWallet.toLowerCase()) {
          await createAuditEvent({
            actorIdentityId: actorIdentity?.id ?? null,
            action: "ASSET_CUSTODY_UNCHANGED",
            resourceType: "ASSET",
            resourceId: asset.assetId,
            decision: "ALLOW",
            reason: "Requested custodian already holds custody on-chain",
            metadata: { source: "blockchain-evidence", custodianWallet: toCustodianWallet, chainMode: blockchainService.mode, ...actingUser },
          }).catch(() => { /* best-effort evidence */ });
          return {
            ...result,
            reason: "Requested custodian already holds custody on-chain — no transfer needed",
            transaction: null,
            custodyUnchanged: true as const,
          };
        }
      }
      let transaction;
      try {
        transaction = await blockchainService.submitTransaction({
          action: "ASSET_TRANSFER",
          payload: { assetId: asset.assetId, toCustodianWallet, actor: ctx.user.openId },
        });
      } catch (error) {
        // The chain rejected or reverted the operation: never claim success.
        // The authorization decision is evidence and is recorded alongside a
        // BLOCKCHAIN_TRANSACTION_FAILED audit event with the failure reason.
        const reason = error instanceof Error ? error.message : String(error);
        // BUG-032 (race safety): if the custodian moved between our read and
        // the submit, SameAssetStatus() still means "already in the requested
        // custody" — return the honest unchanged state, not an error.
        if (reason.includes("0x27479240") || /same asset status/i.test(reason)) {
          await createAuditEvent({
            actorIdentityId: actorIdentity?.id ?? null,
            action: "ASSET_CUSTODY_UNCHANGED",
            resourceType: "ASSET",
            resourceId: asset.assetId,
            decision: "ALLOW",
            reason: "Requested custodian already holds custody on-chain",
            metadata: { source: "blockchain-evidence", custodianWallet: toCustodianWallet, ...actingUser },
          }).catch(() => { /* best-effort evidence */ });
          return {
            ...result,
            reason: "Requested custodian already holds custody on-chain — no transfer needed",
            transaction: null,
            custodyUnchanged: true as const,
          };
        }
        await createAuditEvent({
          actorIdentityId: actorIdentity?.id ?? null,
          action: "BLOCKCHAIN_TRANSACTION_FAILED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "DENY",
          reason,
          metadata: { source: "blockchain-evidence", ...actingUser },
        }).catch((persistError: unknown) => {
          console.error("[Authorization] Failed to persist chain-failure audit event:", persistError);
        });
        console.error("[Authorization] Blockchain submission failed after ALLOW:", error);
        throw new TRPCError({ code: "BAD_GATEWAY", message: `Blockchain rejected the transfer: ${reason}` });
      }
      await createAuditEvent({
        actorIdentityId: actorIdentity?.id ?? null,
        action: "ASSET_TRANSFERRED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "ALLOW",
        reason: "Custody transfer confirmed on-chain",
        transactionHash: transaction.transactionHash,
        blockNumber: transaction.blockNumber,
        metadata: { source: "blockchain-evidence", blockHash: transaction.blockHash, gasUsed: transaction.gasUsed, chainMode: blockchainService.mode, events: transaction.events, ...actingUser },
      }).catch((persistError: unknown) => {
        console.error("[Authorization] Failed to persist transfer audit event:", persistError);
      });

      // BUG-006: the chain is authoritative, but the read model must agree
      // with it. After a CONFIRMED transfer, move the DB custodian + custody
      // history to the acting (authorized) identity. If the DB write fails,
      // record the drift explicitly — never silently leave the two layers
      // disagreeing.
      const custodianUpdate = await applyCustodyTransfer({
        assetRowId: asset.id,
        newCustodianIdentityId: actorIdentity?.id ?? null,
        reason: `On-chain custody transfer confirmed in tx ${transaction.transactionHash}`,
        transactionHash: transaction.transactionHash,
        blockNumber: transaction.blockNumber,
      }).catch((dbError: unknown) => {
        console.error("[Authorization] Custody read-model update failed after on-chain transfer:", dbError);
        return null;
      });
      if (!custodianUpdate) {
        await createAuditEvent({
          actorIdentityId: actorIdentity?.id ?? null,
          action: "CUSTODY_SYNC_FAILED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "CHALLENGE",
          reason: "On-chain transfer confirmed but the database custodian could not be updated",
          transactionHash: transaction.transactionHash,
          blockNumber: transaction.blockNumber,
          metadata: { source: "blockchain-evidence", ...actingUser },
        }).catch(() => { /* best-effort evidence */ });
      }

      return { ...result, transaction };

    }),
  }),
  audit: router({ list: protectedProcedure.input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional()).query(({ input }) => listAuditEvents(input?.limit ?? 50)) }),
  alerts: router({ list: protectedProcedure.query(() => listSecurityAlerts()) }),
  blockchain: router({
    status: publicProcedure.query(() => blockchainService.getNetworkStatus()),
    latestBlock: publicProcedure.query(() => blockchainService.getLatestBlock()),
    transaction: protectedProcedure.input(z.object({ transactionHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) })).query(({ input }) => blockchainService.getTransaction(input.transactionHash)),
    events: protectedProcedure.input(z.object({ fromBlock: z.number().int().min(0).optional(), toBlock: z.number().int().min(0).optional() }).optional().refine(input => !input || input.fromBlock === undefined || input.toBlock === undefined || input.toBlock >= input.fromBlock, { message: "toBlock must be greater than or equal to fromBlock" })).query(async ({ input }) => {
      // BUG-005 (QA #6): large/invalid ranges previously produced raw driver
      // errors. Validate and clamp the window, and surface a clear error when
      // the chain cannot serve the request.
      if (input && input.fromBlock !== undefined && input.toBlock !== undefined) {
        const span = input.toBlock - input.fromBlock;
        if (span > 10_000) {
          throw new TRPCError({ code: "BAD_REQUEST", message: `Block range too large (${span} blocks). Query at most 10,000 blocks per request.` });
        }
      }
      try {
        return await blockchainService.getEvents(input);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        throw new TRPCError({ code: "BAD_GATEWAY", message: `Blockchain event query failed: ${reason}` });
      }
    }),
  }),
});

export type AppRouter = typeof appRouter;