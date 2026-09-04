import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { authorizationService } from "./modules/authorization/authorization.service";
import { blockchainService } from "./modules/blockchain/blockchain.service";
import { createAsset, createAuditEvent, createAuthorizationDecision, createDidRecord, createIdentity, getAssetById, listAssets, listAuditEvents, listIdentities, listSecurityAlerts } from "./db";

const identityStatus = z.enum(["ACTIVE", "REVOKED", "SUSPENDED"]);
const assetStatus = z.enum(["ACTIVE", "REVOKED", "PENDING"]);

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
    create: protectedProcedure.input(z.object({ displayName: z.string().min(2).max(160), organization: z.string().min(2).max(180), did: z.string().min(8).max(255), status: identityStatus.default("ACTIVE") })).mutation(async ({ input }) => { const identity = await createIdentity(input); if (!identity) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Identity could not be created" }); await createDidRecord({ identityId: identity.id, did: input.did, method: input.did.split(":")[1] ?? "unknown", subject: input.did, document: { id: input.did, verificationMethod: [] }, status: "ACTIVE" }); return identity; }),
  }),
  assets: router({
    list: protectedProcedure.query(() => listAssets()),
    create: protectedProcedure.input(z.object({ assetId: z.string().min(2).max(120), name: z.string().min(2).max(200), type: z.string().min(2).max(80), classification: z.string().min(2).max(80), description: z.string().max(5000).optional(), ownerIdentityId: z.string().uuid(), custodianIdentityId: z.string().uuid(), integrityHash: z.string().max(255).optional(), tokenId: z.string().max(160).optional(), status: assetStatus.default("PENDING") })).mutation(({ input }) => createAsset(input)),
    authorizeTransfer: protectedProcedure.input(z.object({ assetId: z.string().uuid(), assetClassification: z.string().optional(), stepUpAuthenticated: z.boolean().default(false) })).mutation(async ({ ctx, input }) => {
      const asset = await getAssetById(input.assetId);
      if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
      const role = ctx.user.role === "admin" ? "ADMIN" : "USER";
      const result = authorizationService.evaluate({ identityStatus: "ACTIVE", role, permissions: role === "ADMIN" ? ["asset:transfer", "administration:manage"] : ["asset:read"], resourceType: "asset", action: "TRANSFER", assetClassification: input.assetClassification ?? asset.classification, context: { stepUpAuthenticated: input.stepUpAuthenticated } });
      await createAuthorizationDecision({ id: result.decisionId, actorIdentityId: asset.ownerIdentityId, resourceType: "ASSET", resourceId: asset.assetId, action: "TRANSFER", decision: result.decision, reason: result.reason, policyId: result.policyId, timestamp: new Date(result.timestamp) });
      await createAuditEvent({ actorIdentityId: asset.ownerIdentityId, action: result.decision === "DENY" ? "AUTHORIZATION_DENIED" : result.decision === "CHALLENGE" ? "AUTHORIZATION_CHALLENGED" : "AUTHORIZATION_ALLOWED", resourceType: "ASSET", resourceId: asset.assetId, decision: result.decision, reason: result.reason, metadata: { source: "authorization-engine" } });
      if (result.decision !== "ALLOW") return { ...result, transaction: null };
      // Policy ALLOWed the request. The smart contract now INDEPENDENTLY
      // re-verifies role, identity status, and asset state on-chain; only a
      // successful receipt produces a confirmed transaction record.
      try {
        const toCustodianWallet = blockchainService.operatorAddress;
        if (!toCustodianWallet) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Blockchain operator is not configured" });
        const transaction = await blockchainService.submitTransaction({ action: "ASSET_TRANSFER", payload: { assetId: asset.assetId, toCustodianWallet, actor: ctx.user.openId } });
        await createAuditEvent({ actorIdentityId: asset.ownerIdentityId, action: "ASSET_TRANSFERRED", resourceType: "ASSET", resourceId: asset.assetId, decision: "ALLOW", reason: "Custody transfer confirmed on-chain", transactionHash: transaction.transactionHash, blockNumber: transaction.blockNumber, metadata: { source: "blockchain-evidence", blockHash: transaction.blockHash, gasUsed: transaction.gasUsed, chainMode: blockchainService.mode, events: transaction.events } });
        return { ...result, transaction };
      } catch (error) {
        // The chain rejected or reverted the operation: never claim success.
        const reason = error instanceof Error ? error.message : String(error);
        await createAuditEvent({ actorIdentityId: asset.ownerIdentityId, action: "BLOCKCHAIN_TRANSACTION_FAILED", resourceType: "ASSET", resourceId: asset.assetId, decision: "DENY", reason, metadata: { source: "blockchain-evidence" } });
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: `Blockchain rejected the transfer: ${reason}` });
      }
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