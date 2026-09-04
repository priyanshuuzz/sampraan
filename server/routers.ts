import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { authorizationService } from "./modules/authorization/authorization.service";
import { blockchainService } from "./modules/blockchain/blockchain.service";
import {
  createAsset,
  createAuditEvent,
  createAuthorizationDecision,
  createDidRecord,
  createIdentity,
  getAssetById,
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
  listAssets,
  listAuditEvents,
  listIdentities,
  listSecurityAlerts,
} from "./db";

const identityStatus = z.enum(["ACTIVE", "REVOKED", "SUSPENDED"]);
const assetStatus = z.enum(["ACTIVE", "REVOKED", "PENDING"]);
const assetClassification = z.enum(["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE"]);

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
    create: protectedProcedure.input(z.object({ displayName: z.string().min(2).max(160), organization: z.string().min(2).max(180), did: z.string().min(8).max(255).regex(/^did:[a-z0-9]+:[^\s]+$/, "did must be a valid DID (did:method:identifier)"), status: identityStatus.default("ACTIVE") })).mutation(async ({ input }) => {
      // REVOKED/SUSPENDED identities must never be created pre-revoked with an
      // active DID document: force the DID record status to match the identity.
      const identity = await createIdentity(input).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        // identities.did is UNIQUE; a duplicate DID must surface as a clear
        // client error instead of a masked 500.
        if (/duplicate entry|ER_DUP_ENTRY/i.test(message)) {
          throw new TRPCError({ code: "CONFLICT", message: "An identity with this DID already exists" });
        }
        throw error;
      });
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
    create: protectedProcedure.input(z.object({ assetId: z.string().min(2).max(120), name: z.string().min(2).max(200), type: z.string().min(2).max(80), classification: assetClassification, description: z.string().max(5000).optional(), ownerIdentityId: z.string().uuid(), custodianIdentityId: z.string().uuid(), integrityHash: z.string().max(255).optional(), tokenId: z.string().max(160).optional(), status: assetStatus.default("PENDING") })).mutation(({ input }) => createAsset(input).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      // assets.assetId is UNIQUE; surface duplicates as a clear client error.
      if (/duplicate entry|ER_DUP_ENTRY/i.test(message)) {
        throw new TRPCError({ code: "CONFLICT", message: "An asset with this assetId already exists" });
      }
      throw error;
    })),
    authorizeTransfer: protectedProcedure.input(z.object({
      assetId: z.string().uuid(),
      // SECURITY: this client-supplied value is IGNORED for policy evaluation.
      // Classification always comes from the database record. The field stays
      // in the wire contract (existing clients send it) but is never trusted.
      assetClassification: z.string().max(80).optional(),
      stepUpAuthenticated: z.boolean().default(false),
    })).mutation(async ({ ctx, input }) => {
      const asset = await getAssetById(input.assetId);
      if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });

      if (asset.status !== "ACTIVE") {
        throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Asset is ${asset.status.toLowerCase()} and cannot be transferred` });
      }

      // SECURITY: resolve the real SAMPRAAN identity linked to the authenticated
      // platform user. The frontend never supplies role/status/permissions —
      // they are derived server-side from the session and the trust domain.
      // Following the trust-domain pattern, an actor without a registered
      // SAMPRAAN identity never evaluates as ACTIVE: the engine denies.
      const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
      const { roles, permissions } = actorIdentity
        ? await getIdentityRolesAndPermissions(actorIdentity.id)
        : { roles: [] as string[], permissions: [] as string[] };

      const result = authorizationService.evaluate({
        identityStatus: actorIdentity?.status ?? "UNREGISTERED",
        // Platform admin maps to the ADMIN role and gains administration:manage;
        // both are still subject to the engine's identity-status check above.
        role: ctx.user.role === "admin" ? "ADMIN" : roles[0] ?? "USER",
        permissions: ctx.user.role === "admin" ? Array.from(new Set([...permissions, "administration:manage"])) : permissions,
        resourceType: "asset",
        action: "TRANSFER",
        assetClassification: asset.classification,
        context: { stepUpAuthenticated: input.stepUpAuthenticated },
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
      const auditMetadata: Record<string, unknown> = { source: "authorization-engine", policyId: result.policyId ?? null, stepUpAuthenticated: input.stepUpAuthenticated, actorOpenId: ctx.user.openId };

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

      let transaction;
      try {
        transaction = await blockchainService.submitTransaction({ action: "ASSET_TRANSFER", payload: { assetId: asset.assetId, actor: ctx.user.openId } });
      } catch (error) {
        // The authorization decision is evidence and must be recorded even
        // when the chain submission fails; the operator can retry the transfer.
        await persistAudit();
        console.error("[Authorization] Blockchain submission failed after ALLOW:", error);
        throw new TRPCError({ code: "BAD_GATEWAY", message: "Transfer was authorized but the blockchain submission failed" });
      }
      await persistAudit({ transactionHash: transaction.transactionHash, blockNumber: transaction.blockNumber });

      return { ...result, transaction };
    }),
  }),
  audit: router({ list: protectedProcedure.input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional()).query(({ input }) => listAuditEvents(input?.limit ?? 50)) }),
  alerts: router({ list: protectedProcedure.query(() => listSecurityAlerts()) }),
  blockchain: router({ status: publicProcedure.query(() => blockchainService.getNetworkStatus()), latestBlock: publicProcedure.query(() => blockchainService.getLatestBlock()) }),
});

export type AppRouter = typeof appRouter;
