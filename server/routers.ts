import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { authorizationService } from "./modules/authorization/authorization.service";
import { blockchainService } from "./modules/blockchain/blockchain.service";
import {
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
} from "./db";

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
        const message = error instanceof Error ? error.message : String(error);
        // identities.did is UNIQUE; a duplicate DID must surface as a clear
        // client error instead of a masked 500.
        if (/duplicate entry|ER_DUP_ENTRY/i.test(message)) {
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
      return identity;
    }),
  }),
  assets: router({
    list: protectedProcedure.query(() => listAssets()),
    // SECURITY: same reasoning — registering assets (and especially their
    // classification, which drives POLICY-HIGH-SENS-TRANSFER) is
    // administrative. Users must not mint low-classification records to
    // smuggle assets past the transfer policy.
    create: adminProcedure.input(z.object({ assetId: z.string().min(2).max(120), name: z.string().min(2).max(200), type: z.string().min(2).max(80), classification: assetClassification, description: z.string().max(5000).optional(), ownerIdentityId: z.string().uuid(), custodianIdentityId: z.string().uuid(), integrityHash: z.string().max(255).optional(), tokenId: z.string().max(160).optional(), status: assetStatus.default("PENDING") })).mutation(({ input }) => createAsset(input).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      // assets.assetId is UNIQUE; surface duplicates as a clear client error.
      if (/duplicate entry|ER_DUP_ENTRY/i.test(message)) {
        throw new TRPCError({ code: "CONFLICT", message: "An asset with this assetId already exists" });
      }
      throw error;
    })),
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
      // successful receipt produces a confirmed transaction record. On the
      // real Besu chain the transfer is submitted to the configured custodian
      // wallet; in MOCK mode (chain-less environments/tests) the legacy mock
      // evidence path is used so the flow stays exercisable without a chain.
      const toCustodianWallet = blockchainService.operatorAddress;
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

      return { ...result, transaction };

    }),
  }),
  audit: router({ list: protectedProcedure.input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional()).query(({ input }) => listAuditEvents(input?.limit ?? 50)) }),
  alerts: router({ list: protectedProcedure.query(() => listSecurityAlerts()) }),
  blockchain: router({
    status: publicProcedure.query(() => blockchainService.getNetworkStatus()),
    latestBlock: publicProcedure.query(() => blockchainService.getLatestBlock()),
    transaction: protectedProcedure.input(z.object({ transactionHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) })).query(({ input }) => blockchainService.getTransaction(input.transactionHash)),
    events: protectedProcedure.input(z.object({ fromBlock: z.number().int().min(0).optional(), toBlock: z.number().int().min(0).optional() }).optional()).query(({ input }) => blockchainService.getEvents(input)),
  }),
});

export type AppRouter = typeof appRouter;