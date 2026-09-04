import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { authorizationService } from "./modules/authorization/authorization.service";
import { blockchainService } from "./modules/blockchain/blockchain.service";
import { createAsset, createAuditEvent, createAuthorizationDecision, createDidRecord, createIdentity, getAssetById, getIdentityById, listAssets, listAuditEvents, listIdentities, listSecurityAlerts } from "./db";

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
  .regex(/^did:[a-z][a-z0-9]*:[A-Za-z0-9._\-]+$/, "Invalid DID format (expected did:method:identifier)");

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
    create: adminProcedure.input(z.object({ displayName: z.string().min(2).max(160), organization: z.string().min(2).max(180), did, status: identityStatus.default("ACTIVE") })).mutation(async ({ input }) => { const identity = await createIdentity(input); if (!identity) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Identity could not be created" }); await createDidRecord({ identityId: identity.id, did: input.did, method: input.did.split(":")[1] ?? "unknown", subject: input.did, document: { id: input.did, verificationMethod: [] }, status: "ACTIVE" }); return identity; }),
  }),
  assets: router({
    list: protectedProcedure.query(() => listAssets()),
    // SECURITY: same reasoning — registering assets (and especially their
    // classification, which drives POLICY-HIGH-SENS-TRANSFER) is
    // administrative. Users must not mint low-classification records to
    // smuggle assets past the transfer policy.
    create: adminProcedure.input(z.object({ assetId: z.string().min(2).max(120), name: z.string().min(2).max(200), type: z.string().min(2).max(80), classification: assetClassification, description: z.string().max(5000).optional(), ownerIdentityId: z.string().uuid(), custodianIdentityId: z.string().uuid(), integrityHash: z.string().max(255).optional(), tokenId: z.string().max(160).optional(), status: assetStatus.default("PENDING") })).mutation(({ input }) => createAsset(input)),
    // SECURITY: classification and step-up state come exclusively from
    // server-side state. The client may only name the asset; it can never
    // assert its own classification, role, permissions, or step-up state.
    authorizeTransfer: protectedProcedure.input(z.object({ assetId: z.string().uuid() })).mutation(async ({ ctx, input }) => {
      const asset = await getAssetById(input.assetId);
      if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
      const ownerIdentity = await getIdentityById(asset.ownerIdentityId);
      // Owner identity status is resolved from the database, never asserted by
      // the caller. Unknown/missing identities evaluate as SUSPENDED (deny).
      const identityStatus = ownerIdentity?.status ?? "SUSPENDED";
      const role = ctx.user.role === "admin" ? "ADMIN" : "USER";
      const result = authorizationService.evaluate({ identityStatus, role, permissions: role === "ADMIN" ? ["asset:transfer", "administration:manage"] : ["asset:read"], resourceType: "asset", action: "TRANSFER", assetClassification: asset.classification });
      // The schema links decisions to identity records, not user accounts;
      // the acting account is recorded in metadata so audit trails can never
      // misattribute a denial to the asset's owner.
      const actingUser = { actorUserOpenId: ctx.user.openId, actorUserRole: ctx.user.role };
      await createAuthorizationDecision({ id: result.decisionId, actorIdentityId: asset.ownerIdentityId, resourceType: "ASSET", resourceId: asset.assetId, action: "TRANSFER", decision: result.decision, reason: result.reason, policyId: result.policyId, timestamp: new Date(result.timestamp) });
      await createAuditEvent({ actorIdentityId: asset.ownerIdentityId, action: result.decision === "DENY" ? "AUTHORIZATION_DENIED" : result.decision === "CHALLENGE" ? "AUTHORIZATION_CHALLENGED" : "AUTHORIZATION_ALLOWED", resourceType: "ASSET", resourceId: asset.assetId, decision: result.decision, reason: result.reason, metadata: { source: "authorization-engine", ...actingUser } });
      if (result.decision !== "ALLOW") return { ...result, transaction: null };
      const transaction = await blockchainService.submitTransaction({ action: "ASSET_TRANSFER", payload: { assetId: asset.assetId, actor: ctx.user.openId } });
      return { ...result, transaction };
    }),
  }),
  audit: router({ list: protectedProcedure.input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional()).query(({ input }) => listAuditEvents(input?.limit ?? 50)) }),
  alerts: router({ list: protectedProcedure.query(() => listSecurityAlerts()) }),
  blockchain: router({ status: publicProcedure.query(() => blockchainService.getNetworkStatus()), latestBlock: publicProcedure.query(() => blockchainService.getLatestBlock()) }),
});

export type AppRouter = typeof appRouter;
