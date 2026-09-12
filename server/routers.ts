import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME, SESSION_TTL_MS } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { sdk } from "./_core/sdk";
import { systemRouter } from "./_core/systemRouter";
import { adminProcedure, protectedProcedure, publicProcedure, router } from "./_core/trpc";
import { authorizationService } from "./modules/authorization/authorization.service";
import { blockchainService, besuBlockchainService } from "./modules/blockchain/blockchain.service";
import type { BesuBlockchainService as BesuService } from "./modules/blockchain/besu-blockchain.service";
import {
  createAssetApproval,
  getActiveAssetApproval,
  getAssetApproval,
  listAssetApprovals,
  markAssetApprovalExecuted,
  updateAssetApprovalStatus,
  applyAssetStatusChange,
  applyCustodyTransfer,
  applyIdentityRoles,
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
  getUserByEmail,
  getIdentitiesWithRoles,
  listAssetAuditEvents,
  listAssetCustody,
  listAssets,
  listAuditEvents,
  listIdentityAuditEvents,
  listIdentities,
  listPermissions,
  listPolicies,
  listRolesWithPermissions,
  listSecurityAlerts,
  revokePlatformSession,
  updateAlertStatus,
} from "./db";
import { anchoringService, deriveIdentityWallet } from "./modules/blockchain/anchoring.service";
import {
  createDidChallenge,
  verifyDidChallenge,
  rotateDidKey,
  setDidKeyStatus,
  createStepUpChallenge,
  verifyStepUpChallenge,
  hasValidStepUp,
  fingerprintNonce,
} from "./modules/did/did-auth.service";
import { buildAssetProvenance } from "./modules/provenance/provenance.service";
import { graphQueryService } from "./modules/graph/graph.service";
import { isDuplicateEntryError } from "./modules/db/db-errors";
import { describeError } from "./common/error-handler";
import { verifyPassword } from "./auth/password";
import {
  recordIntelligenceScanEvidence,
  scheduleIntelligenceScan,
  securityIntelligenceService,
} from "./modules/security-intelligence/intelligence.service";
import { parse as parseCookieHeader } from "cookie";

/** Extract the session token from a raw Cookie header (null when absent). */
function extractSessionCookie(cookieHeader: unknown): string | null {
  if (typeof cookieHeader !== "string" || cookieHeader.length === 0) return null;
  const parsed = parseCookieHeader(cookieHeader);
  const value = parsed[COOKIE_NAME];
  return typeof value === "string" && value.length > 0 ? value : null;
}

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
  /**
   * DID authentication (LOOP 2) + key lifecycle (LOOP 3).
   * Challenge-response: server issues a single-use expiring nonce bound to
   * the DID; the caller signs it with the DID key; the server verifies the
   * signature recovers to the DID's on-chain reference wallet. Revoked or
   * rotated keys fail closed BEFORE any signature work.
   */
  did: router({
    requestChallenge: publicProcedure
      .input(z.object({ did: z.string().min(8).max(255) }))
      .mutation(async ({ input }) => {
        const result = await createDidChallenge(input.did.trim());
        if (!result.ok) {
          await createAuditEvent({ actorIdentityId: null, action: "DID_CHALLENGE_REQUESTED", resourceType: "IDENTITY", resourceId: input.did, decision: "DENY", reason: result.reason, metadata: { source: "did-auth", code: result.code } }).catch(() => undefined);
          throw new TRPCError({ code: result.code === "DID_NOT_FOUND" ? "NOT_FOUND" : "FORBIDDEN", message: result.reason });
        }
        await createAuditEvent({ actorIdentityId: null, action: "DID_CHALLENGE_REQUESTED", resourceType: "IDENTITY", resourceId: input.did, decision: "ALLOW", reason: "Challenge issued", metadata: { source: "did-auth", nonceFingerprint: fingerprintNonce(result.challenge.nonce), expiresAt: result.challenge.expiresAt } }).catch(() => undefined);
        return result.challenge;
      }),
    verifyChallenge: publicProcedure
      .input(z.object({ did: z.string().min(8).max(255), nonce: z.string().min(16).max(128), signature: z.string().min(32).max(255) }))
      .mutation(async ({ input }) => {
        const operatorKey = besuBlockchainService?.config.privateKey ?? null;
        if (!operatorKey) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Blockchain operator key is not configured — DID verification unavailable" });
        const result = await verifyDidChallenge({ did: input.did.trim(), nonce: input.nonce, signature: input.signature, operatorKey });
        if (!result.ok) {
          await createAuditEvent({ actorIdentityId: null, action: "DID_AUTH_FAILED", resourceType: "IDENTITY", resourceId: input.did, decision: "DENY", reason: result.reason, metadata: { source: "did-auth", code: result.code } }).catch(() => undefined);
          scheduleIntelligenceScan();
          throw new TRPCError({ code: "UNAUTHORIZED", message: result.reason });
        }
        // DID authentication mints the SAME server-tracked session the
        // password path uses; roles still come from the database per request.
        let sessionToken: string | null = null;
        if (result.linkedUserId) {
          const db = await import("./db").then(m => m.getDb());
          const linkedUser = await (async () => {
            if (!db) return null;
            const { users } = await import("../drizzle/schema");
            const { eq } = await import("drizzle-orm");
            const rows = await db.select().from(users).where(eq(users.id, result.linkedUserId!)).limit(1);
            return rows[0] ?? null;
          })();
          if (linkedUser) {
            sessionToken = await sdk.createSessionToken(linkedUser.openId, { name: linkedUser.name ?? "", expiresInMs: SESSION_TTL_MS });
            const { trackPlatformSession } = await import("./db");
            await trackPlatformSession({ sessionToken, linkedUserId: linkedUser.id, expiresAt: new Date(Date.now() + SESSION_TTL_MS) });
          }
        }
        const identity = await getIdentityById(result.identityId);
        await createAuditEvent({ actorIdentityId: result.identityId, action: "DID_AUTH_SUCCEEDED", resourceType: "IDENTITY", resourceId: result.did, decision: "ALLOW", reason: "Challenge signature verified against the DID reference wallet", metadata: { source: "did-auth", recoveredAddress: result.recoveredAddress, sessionIssued: Boolean(sessionToken) } }).catch(() => undefined);
        return { ok: true as const, identityId: result.identityId, did: result.did, displayName: identity?.displayName ?? null, identityStatus: identity?.status ?? null, sessionToken };
      }),
    /** Key lifecycle read model. */
    keyStatus: protectedProcedure.input(z.object({ did: z.string().min(8).max(255) })).query(async ({ input }) => {
      const db = await import("./db").then(m => m.getDb());
      if (!db) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Database unavailable" });
      const { didRecords } = await import("../drizzle/schema");
      const { eq } = await import("drizzle-orm");
      const rows = await db.select({ status: didRecords.status, keyStatus: didRecords.keyStatus, rotatedAt: didRecords.rotatedAt, revokedAt: didRecords.revokedAt }).from(didRecords).where(eq(didRecords.did, input.did)).limit(1);
      if (!rows[0]) throw new TRPCError({ code: "NOT_FOUND", message: "DID not found" });
      return rows[0];
    }),
    /** Rotate the current key: the old key immediately stops authenticating. */
    rotateKey: protectedProcedure.input(z.object({ did: z.string().min(8).max(255) })).mutation(async ({ input, ctx }) => {
      const result = await rotateDidKey(input.did);
      if (!result.ok) throw new TRPCError({ code: "BAD_REQUEST", message: result.reason });
      const actor = await getIdentityByLinkedUserId(ctx.user.id);
      await createAuditEvent({ actorIdentityId: actor?.id ?? null, action: "DID_KEY_ROTATED", resourceType: "IDENTITY", resourceId: input.did, decision: "ALLOW", reason: "Key marked ROTATED — previous key cannot authenticate", metadata: { source: "did-lifecycle" } }).catch(() => undefined);
      return result;
    }),
    /** Explicit key activation or revocation (admin only). */
    setKeyStatus: adminProcedure.input(z.object({ did: z.string().min(8).max(255), keyStatus: z.enum(["ACTIVE", "REVOKED"]) })).mutation(async ({ input, ctx }) => {
      const result = await setDidKeyStatus(input.did, input.keyStatus);
      if (!result.ok) throw new TRPCError({ code: "BAD_REQUEST", message: result.reason });
      const actor = await getIdentityByLinkedUserId(ctx.user.id);
      await createAuditEvent({ actorIdentityId: actor?.id ?? null, action: input.keyStatus === "REVOKED" ? "DID_KEY_REVOKED" : "DID_KEY_ACTIVATED", resourceType: "IDENTITY", resourceId: input.did, decision: "ALLOW", reason: `Key status set to ${input.keyStatus}`, metadata: { source: "did-lifecycle" } }).catch(() => undefined);
      return result;
    }),
  }),
  /**
   * Server-verified step-up authentication (LOOP 5). A CHALLENGE policy
   * decision for a HIGHLY_SENSITIVE transfer is only satisfied by consuming
   * a signature-verified step-up bound to (identity, purpose).
   */
  stepup: router({
    requestChallenge: protectedProcedure
      .input(z.object({ assetId: z.string().uuid() }))
      .mutation(async ({ ctx, input }) => {
        const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
        if (!actorIdentity) throw new TRPCError({ code: "FORBIDDEN", message: "No SAMPRAAN identity is linked to this session" });
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        const purpose = `transfer:${asset.assetId}`;
        const challenge = await createStepUpChallenge(actorIdentity.id, purpose);
        if (!("nonce" in challenge)) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: challenge.reason });
        await createAuditEvent({ actorIdentityId: actorIdentity.id, action: "STEP_UP_CHALLENGE_ISSUED", resourceType: "ASSET", resourceId: asset.assetId, decision: "CHALLENGE", reason: `Step-up challenge issued for ${purpose}`, metadata: { source: "step-up", nonceFingerprint: fingerprintNonce(challenge.nonce) } }).catch(() => undefined);
        return challenge;
      }),
    verify: protectedProcedure
      .input(z.object({ assetId: z.string().uuid(), nonce: z.string().min(16).max(128), signature: z.string().min(32).max(255) }))
      .mutation(async ({ ctx, input }) => {
        const operatorKey = besuBlockchainService?.config.privateKey ?? null;
        if (!operatorKey) throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Blockchain operator key is not configured" });
        const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
        if (!actorIdentity) throw new TRPCError({ code: "FORBIDDEN", message: "No SAMPRAAN identity is linked to this session" });
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        const purpose = `transfer:${asset.assetId}`;
        const result = await verifyStepUpChallenge({ identityId: actorIdentity.id, purpose, nonce: input.nonce, signature: input.signature, operatorKey });
        if (!result.ok) {
          await createAuditEvent({ actorIdentityId: actorIdentity.id, action: "STEP_UP_FAILED", resourceType: "ASSET", resourceId: asset.assetId, decision: "DENY", reason: result.reason, metadata: { source: "step-up", code: result.code } }).catch(() => undefined);
          scheduleIntelligenceScan();
          throw new TRPCError({ code: "UNAUTHORIZED", message: result.reason });
        }
        await createAuditEvent({ actorIdentityId: actorIdentity.id, action: "STEP_UP_SUCCEEDED", resourceType: "ASSET", resourceId: asset.assetId, decision: "ALLOW", reason: "Step-up signature verified server-side", metadata: { source: "step-up", purpose } }).catch(() => undefined);
        return { ok: true as const, purpose, validForMs: 10 * 60 * 1000 };
      }),
  }),
  health: publicProcedure.query(async () => ({ api: "OK" as const, database: process.env.DATABASE_URL ? "CONFIGURED" as const : "NOT_CONFIGURED" as const, blockchain: await blockchainService.getNetworkStatus() })),
  observatory: publicProcedure.query(async () => { const [identities, assets, audit, alerts, blockchain] = await Promise.all([listIdentities(), listAssets(), listAuditEvents(200), listSecurityAlerts(), blockchainService.getNetworkStatus()]); return { identityCount: identities.length, assetCount: assets.length, auditEventCount: audit.length, openAlertCount: alerts.filter(alert => alert.status === "OPEN").length, blockchain }; }),
  demo: router({
    identities: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listIdentities(); }),
    assets: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listAssets(); }),
    audit: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listAuditEvents(200); }),
    alerts: publicProcedure.query(async () => { if (process.env.NODE_ENV !== "development") throw new TRPCError({ code: "FORBIDDEN", message: "Demo data is available only in development" }); return listSecurityAlerts(); }),
  }),
  auth: router({
    // SECURITY: the session identity payload must never include the local
    // password hash — scrypt material is server-only (verified against, never
    // returned). The browser only needs id/openId/name/email/role.
    me: publicProcedure.query(opts => {
      if (!opts.ctx.user) return null;
      const { passwordHash: _serverOnly, ...safeUser } = opts.ctx.user;
      return safeUser;
    }),
    /**
     * LOCAL LOGIN (development / team-demonstration auth path).
     *
     * The production auth path is OAuth (see _core/oauth.ts) and remains
     * fully intact. When no external IdP is configured (local runs, judges'
     * laptops), this procedure authenticates seed/admin-provisioned local
     * accounts against a server-side scrypt hash, then issues the SAME
     * session token mechanism the OAuth flow uses (sdk.createSessionToken +
     * server-side session tracking + httpOnly cookie). Roles are loaded from
     * the database on every request — never from the client.
     *
     * Anti-enumeration: invalid email and invalid password are both
     * "Invalid email or password" with equalized timing.
     */
    login: publicProcedure
      .input(
        z.object({
          email: z.string().trim().toLowerCase().email(),
          password: z.string().min(8).max(128),
        }),
      )
      .mutation(async ({ input, ctx }) => {
        const { burnPasswordTiming } = await import("./auth/password");
        const user = await getUserByEmail(input.email).catch(() => undefined);
        let authenticated = false;
        if (user?.passwordHash) {
          authenticated = await verifyPassword(input.password, user.passwordHash);
        } else {
          await burnPasswordTiming();
        }
        if (!user || !authenticated) {
          await createAuditEvent({
            actorIdentityId: null,
            action: "LOGIN_FAILED",
            resourceType: "SESSION",
            resourceId: input.email.replace(/(.{2}).*(@.*)/, "$1***$2"),
            decision: "DENY",
            reason: "Invalid email or password",
            metadata: { source: "local-auth", attemptedEmailDomain: input.email.split("@")[1] ?? null },
          }).catch(() => undefined);
          scheduleIntelligenceScan();
          throw new TRPCError({ code: "UNAUTHORIZED", message: "Invalid email or password" });
        }

        const sessionToken = await sdk.createSessionToken(user.openId, {
          name: user.name ?? "",
          expiresInMs: SESSION_TTL_MS,
        });
        const { trackPlatformSession } = await import("./db");
        await trackPlatformSession({
          sessionToken,
          linkedUserId: user.id,
          expiresAt: new Date(Date.now() + SESSION_TTL_MS),
        });
        const cookieOptions = getSessionCookieOptions(ctx.req);
        ctx.res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: SESSION_TTL_MS });

        await createAuditEvent({
          actorIdentityId: null,
          action: "LOGIN_SUCCEEDED",
          resourceType: "SESSION",
          resourceId: user.openId,
          decision: "ALLOW",
          reason: "Local password authentication succeeded",
          metadata: { source: "local-auth", loginMethod: "password" },
        }).catch(() => undefined);

        return { user: { id: user.id, openId: user.openId, name: user.name, email: user.email, role: user.role } };
      }),
    /** Which auth modes the UI should offer for this deployment. */
    config: publicProcedure.query(() => ({
      localLoginEnabled: true,
      oauthConfigured: Boolean(process.env.OAUTH_SERVER_URL && process.env.VITE_OAUTH_PORTAL_URL),
    })),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      // QA #5: logout must revoke the tracked platform session server-side,
      // so a stolen copy of the token cannot be replayed after the
      // legitimate user logged out. BOTH delivery channels are covered:
      // the Authorization bearer header AND the session cookie — a
      // logout that only cleared the cookie left bearer replay open.
      const bearer = ctx.req.headers.authorization;
      const bearerToken =
        typeof bearer === "string" && bearer.startsWith("Bearer ")
          ? bearer.slice(7)
          : null;
      const cookieHeader = ctx.req.headers.cookie;
      const cookieToken = extractSessionCookie(cookieHeader);
      for (const token of new Set([bearerToken, cookieToken].filter((t): t is string => Boolean(t)))) {
        revokePlatformSession(token).catch((error: unknown) => {
          console.error("[Auth] Failed to revoke platform session on logout:", error);
        });
      }
      return { success: true } as const;
    }),
  }),
  identities: router({
    /**
     * Enriched registry: every identity WITH its role names, so the workspace
     * can show roles and permissions without a second round trip. The roles
     * come from the database (identity_roles), never from the client.
     */
    list: protectedProcedure.query(() => getIdentitiesWithRoles()),
    /** Single identity with roles, permissions, and its DID record. */
    detail: protectedProcedure.input(z.object({ identityId: z.string().uuid() })).query(async ({ input }) => {
      const identity = await getIdentityById(input.identityId);
      if (!identity) throw new TRPCError({ code: "NOT_FOUND", message: "Identity not found" });
      const { roles: roleNames, permissions } = await getIdentityRolesAndPermissions(identity.id);
      // Resolve the on-chain identity reference when a real chain is bound.
      let onChain: Awaited<ReturnType<BesuService["getIdentity"]>> | null = null;
      if (besuBlockchainService) {
        const service = besuBlockchainService;
        try {
          const status = await service.getNetworkStatus();
          const key = status.connected ? service.config.privateKey : null;
          if (key) {
            const wallet = deriveIdentityWallet(key, identity.did);
            onChain = await service.getIdentity(wallet);
          }
        } catch {
          onChain = null;
        }
      }
      return { identity, roles: roleNames, permissions, onChain };
    }),
    /** Audit history for one identity (actor or target). */
    history: protectedProcedure.input(z.object({ identityId: z.string().uuid(), limit: z.number().int().min(1).max(200).default(50) }).optional()).query(({ input }) => listIdentityAuditEvents(input?.identityId ?? "", input?.limit ?? 50)),
    /** RBAC catalog: roles with their permission keys (read-only). */
    roles: protectedProcedure.query(() => listRolesWithPermissions()),
    permissions: protectedProcedure.query(() => listPermissions()),
    /**
     * RBAC WRITE PATH (admin only): replace an identity's role set.
     *
     * SECURITY: role changes are server-side only, audited with the ACTING
     * administrator attributed, and — because permissions are re-resolved
     * from identity_roles on every authorizeTransfer call — take effect on
     * the very next operation. The linked platform account's role is NOT
     * touched: platform users.role only gates admin-vs-user API procedures;
     * SAMPRAAN domain authorization uses these identity roles.
     */
    assignRoles: adminProcedure
      .input(
        z.object({
          identityId: z.string().uuid(),
          roleNames: z.array(z.enum(["ADMIN", "MANAGER", "AUDITOR", "USER"])).min(1).max(4),
        }),
      )
      .mutation(async ({ input, ctx }) => {
        const identity = await getIdentityById(input.identityId);
        if (!identity) throw new TRPCError({ code: "NOT_FOUND", message: "Identity not found" });
        const actingAdminIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
        const updatedRoles = await applyIdentityRoles({
          identityId: identity.id,
          roleNames: input.roleNames,
          assignedByIdentityId: actingAdminIdentity?.id ?? null,
        });
        if (!updatedRoles) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Role update could not be persisted" });
        await createAuditEvent({
          actorIdentityId: actingAdminIdentity?.id ?? null,
          action: "ROLE_CHANGED",
          resourceType: "IDENTITY",
          resourceId: identity.id,
          decision: "ALLOW",
          reason: `Roles for ${identity.displayName} set to ${updatedRoles.join(", ")}`,
          metadata: {
            source: "rbac-administration",
            targetIdentityId: identity.id,
            targetDid: identity.did,
            roles: updatedRoles,
            actorUserOpenId: ctx.user?.openId ?? null,
            actorUserRole: ctx.user?.role ?? null,
          },
        }).catch(() => { /* evidence best-effort */ });
        scheduleIntelligenceScan();
        return { identityId: identity.id, roles: updatedRoles };
      }),
    // SECURITY: minting identities into the trust registry is an
    // administrative act — a regular authenticated user must not be able to
    // create identity records that the authorization engine then trusts.
    create: adminProcedure.input(z.object({ displayName: z.string().min(2).max(160), organization: z.string().min(2).max(180), did, status: identityStatus.default("ACTIVE") })).mutation(async ({ input, ctx }) => {
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
      // IDENTITY_CREATED audit attributed to the ACTING administrator — the
      // admin who registered the identity, never the identity itself.
      const actingAdminIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
      await createAuditEvent({
        actorIdentityId: actingAdminIdentity?.id ?? null,
        action: "IDENTITY_CREATED",
        resourceType: "IDENTITY",
        resourceId: identity.id,
        decision: "ALLOW",
        reason: `Identity ${identity.displayName} (${identity.did}) registered`,
        transactionHash: anchor.outcome === "ANCHORED" ? anchor.transactionHash ?? null : null,
        blockNumber: anchor.outcome === "ANCHORED" ? anchor.blockNumber ?? null : null,
        metadata: {
          source: "identity-administration",
          anchorOutcome: anchor.outcome,
          anchorReason: anchor.reason ?? null,
          targetIdentityId: identity.id,
          actorUserOpenId: ctx.user?.openId ?? null,
          actorUserRole: ctx.user?.role ?? null,
        },
      }).catch(() => { /* evidence best-effort */ });
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
    setStatus: adminProcedure.input(z.object({ identityId: z.string().uuid(), status: identityStatus })).mutation(async ({ input, ctx }) => {
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
            reason: describeError(error),
          };
        }
      }

      // SECURITY: audit evidence must attribute the ACTING administrator —
      // resolved server-side from the session — never the target identity.
      // (The previous implementation recorded actorIdentityId = identity.id,
      //  i.e. the identity whose status changed, so a revocation looked like a
      //  self-revocation in the evidence trail.)
      const actingAdminIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
      await createAuditEvent({
        actorIdentityId: actingAdminIdentity?.id ?? null,
        action: input.status === "REVOKED" ? "IDENTITY_REVOKED" : input.status === "SUSPENDED" ? "IDENTITY_SUSPENDED" : "IDENTITY_REACTIVATED",
        resourceType: "IDENTITY",
        resourceId: identity.id,
        decision: "ALLOW",
        reason: `Identity status set to ${input.status} by an administrator`,
        transactionHash: anchor?.outcome === "ANCHORED" ? anchor.reason ?? null : null,
        metadata: { source: "identity-administration", previousStatus: identity.status, newStatus: input.status, anchorOutcome: anchor?.outcome ?? "SKIPPED", targetIdentityId: identity.id, actorUserOpenId: ctx.user?.openId ?? null, actorUserRole: ctx.user?.role ?? null },
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
    create: adminProcedure.input(z.object({ assetId: z.string().min(2).max(120), name: z.string().min(2).max(200), type: z.string().min(2).max(80), classification: assetClassification, description: z.string().max(5000).optional(), ownerIdentityId: z.string().uuid(), custodianIdentityId: z.string().uuid(), integrityHash: z.string().max(255).optional(), tokenId: z.string().max(160).optional(), status: assetStatus.default("PENDING") })).mutation(async ({ input, ctx }) => {
      // Validate the referenced identities BEFORE writing: owner and
      // custodian must exist and be ACTIVE (the on-chain mint enforces the
      // same rule — CustodianNotActive — so fail early with a clear message).
      const owner = await getIdentityById(input.ownerIdentityId);
      const custodian = await getIdentityById(input.custodianIdentityId);
      if (!owner) throw new TRPCError({ code: "BAD_REQUEST", message: "Owner identity not found" });
      if (!custodian) throw new TRPCError({ code: "BAD_REQUEST", message: "Custodian identity not found" });
      if (owner.status !== "ACTIVE" || custodian.status !== "ACTIVE") {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Owner and custodian identities must be ACTIVE to register an asset" });
      }
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
      // Persist the token id (on-chain NFT id) into the read model when the
      // mint actually confirmed, so the UI can show the REAL token id.
      // BUG-033: registerAsset mints PENDING by contract design, while
      // transferCustody only accepts ACTIVE assets. An asset registered with
      // status ACTIVE must be activated on-chain in the same flow — otherwise
      // the read model and the chain disagree and the first transfer reverts
      // with AssetNotActive (the exact failure that made minting unusable).
      let activation: { transactionHash?: string; error?: string } | null = null;
      if (anchor.outcome === "ANCHORED" && besuBlockchainService) {
        const onChain = await besuBlockchainService.getAsset(input.assetId).catch(() => null);
        if (onChain && onChain.tokenId) {
          const { setAssetTokenId } = await import("./db");
          await setAssetTokenId(asset.id, onChain.tokenId.toString()).catch(() => undefined);
          (asset as { tokenId?: string | null }).tokenId = onChain.tokenId.toString();
        }
        if (input.status === "ACTIVE") {
          try {
            const activationTx = await besuBlockchainService.setAssetStatus({
              assetId: input.assetId,
              status: "ACTIVATE",
            });
            activation = { transactionHash: activationTx.transactionHash };
          } catch (activationError) {
            activation = { error: describeError(activationError) };
            await createAuditEvent({
              actorIdentityId: null,
              action: "BLOCKCHAIN_TRANSACTION_FAILED",
              resourceType: "ASSET",
              resourceId: asset.assetId,
              decision: "DENY",
              reason: `Post-mint on-chain activation failed: ${activation.error}`,
              metadata: { source: "asset-administration", phase: "post-mint-activation" },
            }).catch(() => { /* evidence best-effort */ });
          }
        }
      }
      // ASSET_CREATED audit event attributed to the ACTING administrator.
      const actingAdminIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
      await createAuditEvent({
        actorIdentityId: actingAdminIdentity?.id ?? null,
        action: "ASSET_CREATED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "ALLOW",
        reason: `Asset ${asset.name} registered (${asset.classification})`,
        transactionHash: anchor.outcome === "ANCHORED" ? anchor.transactionHash ?? null : null,
        blockNumber: anchor.outcome === "ANCHORED" ? anchor.blockNumber ?? null : null,
        metadata: {
          source: "asset-administration",
          anchorOutcome: anchor.outcome,
          anchorReason: anchor.reason ?? null,
          activationTransactionHash: activation?.transactionHash ?? null,
          activationError: activation?.error ?? null,
          ownerIdentityId: input.ownerIdentityId,
          custodianIdentityId: input.custodianIdentityId,
          actorUserOpenId: ctx.user?.openId ?? null,
          actorUserRole: ctx.user?.role ?? null,
        },
      }).catch(() => { /* evidence best-effort */ });
      scheduleIntelligenceScan();
      return { ...asset, anchor, activation };
    }),
    /** Asset detail with custody history, audit provenance, and on-chain state. */
    detail: protectedProcedure.input(z.object({ assetId: z.string().uuid() })).query(async ({ input }) => {
      const asset = await getAssetById(input.assetId);
      if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
      const [custody, auditEvents] = await Promise.all([
        listAssetCustody(asset.id),
        listAssetAuditEvents(asset.assetId, 100),
      ]);
      const onChain = besuBlockchainService
        ? await besuBlockchainService.getAsset(asset.assetId).catch(() => null)
        : null;
      return { asset, custody, auditEvents, onChain };
    }),
    /**
     * ASSIGNMENT workflow (admin only): place an asset in the custody of a
     * chosen identity. The smart contract's assignAsset() independently
     * re-verifies the operator role and that the recipient identity is
     * ACTIVE on-chain; the read model mirrors the confirmed transition and
     * the custody history row is recorded.
     */
    assign: adminProcedure
      .input(z.object({ assetId: z.string().uuid(), custodianIdentityId: z.string().uuid() }))
      .mutation(async ({ input, ctx }) => {
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        if (asset.status === "REVOKED") throw new TRPCError({ code: "PRECONDITION_FAILED", message: "A revoked asset cannot be reassigned" });
        const custodian = await getIdentityById(input.custodianIdentityId);
        if (!custodian) throw new TRPCError({ code: "NOT_FOUND", message: "Custodian identity not found" });
        if (custodian.status !== "ACTIVE") throw new TRPCError({ code: "PRECONDITION_FAILED", message: `Custodian identity is ${custodian.status.toLowerCase()}` });
        const actingAdminIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
        const actingUser = { actorUserOpenId: ctx.user?.openId ?? null, actorUserRole: ctx.user?.role ?? null };

        const operatorKey = besuBlockchainService?.config.privateKey ?? null;
        if (!besuBlockchainService || !operatorKey) {
          throw new TRPCError({ code: "PRECONDITION_FAILED", message: "Blockchain is not configured (MOCK mode) — on-chain assignment is unavailable" });
        }
        // The recipient's on-chain reference wallet must be registered and
        // ACTIVE on-chain before assignAsset can succeed (RecipientNotActive).
        await anchoringService.anchorIdentity({ did: custodian.did, displayName: custodian.displayName });
        const custodianWallet = deriveIdentityWallet(operatorKey, custodian.did);
        let transaction;
        try {
          transaction = await blockchainService.submitTransaction({
            action: "ASSET_ASSIGN",
            payload: { assetId: asset.assetId, custodianWallet, actor: ctx.user?.openId ?? "admin" },
          });
        } catch (error) {
          const reason = describeError(error);
          await createAuditEvent({
            actorIdentityId: actingAdminIdentity?.id ?? null,
            action: "BLOCKCHAIN_TRANSACTION_FAILED",
            resourceType: "ASSET",
            resourceId: asset.assetId,
            decision: "DENY",
            reason: `Assignment rejected by the chain: ${reason}`,
            metadata: { source: "blockchain-evidence", ...actingUser },
          }).catch(() => undefined);
          scheduleIntelligenceScan();
          throw new TRPCError({ code: "BAD_GATEWAY", message: `Blockchain rejected the assignment: ${reason}` });
        }
        const custodyUpdate = await applyCustodyTransfer({
          assetRowId: asset.id,
          newCustodianIdentityId: custodian.id,
          reason: `Custody assigned by administrator (tx ${transaction.transactionHash})`,
          transactionHash: transaction.transactionHash,
          blockNumber: transaction.blockNumber,
        }).catch(error => {
          console.error("[Assets] Custody read-model update failed after on-chain assignment:", error);
          return null;
        });
        await createAuditEvent({
          actorIdentityId: actingAdminIdentity?.id ?? null,
          action: "ASSET_ASSIGNED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "ALLOW",
          reason: `Custody assigned to ${custodian.displayName} (${custodian.did})`,
          transactionHash: transaction.transactionHash,
          blockNumber: transaction.blockNumber,
          metadata: { source: "blockchain-evidence", blockHash: transaction.blockHash, gasUsed: transaction.gasUsed, chainMode: blockchainService.mode, events: transaction.events, newCustodianIdentityId: custodian.id, readModelSynced: Boolean(custodyUpdate), ...actingUser },
        }).catch(() => { /* evidence best-effort */ });
        return { asset: custodyUpdate ?? asset, transaction, custodianIdentityId: custodian.id };
      }),
    /**
     * Asset lifecycle management (admin only). BUG-028: assets were created
     * PENDING with NO way to ever activate them, making every API-created
     * asset permanently untransferable. This transitions the read-model
     * status and mirrors the lifecycle on-chain (ACTIVATE/SUSPEND/RESTORE/
     * REVOKE) when a real chain is configured, with full audit evidence.
     */
    setStatus: adminProcedure.input(z.object({ assetId: z.string().uuid(), status: assetStatus })).mutation(async ({ input, ctx }) => {
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
            reason: describeError(error),
          };
        }
      }

      // SECURITY: attribute the ACTING administrator, resolved server-side
      // from the session — never null and never the resource owner.
      const actingAdminIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
      await createAuditEvent({
        actorIdentityId: actingAdminIdentity?.id ?? null,
        action: input.status === "ACTIVE" ? "ASSET_ACTIVATED" : input.status === "REVOKED" ? "ASSET_REVOKED" : "ASSET_SUSPENDED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "ALLOW",
        reason: `Asset status set to ${input.status} by an administrator`,
        transactionHash: anchor?.outcome === "ANCHORED" ? anchor.reason ?? null : null,
        metadata: { source: "asset-administration", previousStatus: asset.status, newStatus: input.status, anchorOutcome: anchor?.outcome ?? "SKIPPED", actorUserOpenId: ctx.user?.openId ?? null, actorUserRole: ctx.user?.role ?? null },
      }).catch(() => { /* evidence best-effort */ });

      return { ...(updated ?? asset), changed: true as const, anchor };
    }),
    // SECURITY: classification and step-up state come exclusively from
    // server-side state. The client may only name the asset; it can never
    // assert its own classification, role, permissions, or step-up state.
    authorizeTransfer: protectedProcedure.input(z.object({ assetId: z.string().uuid(), recipientIdentityId: z.string().uuid().optional() })).mutation(async ({ ctx, input }) => {
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

      // RECIPIENT RESOLUTION (server-side only): when the caller names a
      // recipient identity, custody moves to THAT identity; otherwise (legacy
      // behavior preserved) it moves to the ACTING identity. The client only
      // ever passes an identity id — status and wallet are resolved here.
      const recipientIdentity = input.recipientIdentityId
        ? await getIdentityById(input.recipientIdentityId)
        : actorIdentity;
      const recipient = recipientIdentity ?? null;
      if (input.recipientIdentityId && !recipient) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Recipient identity not found" });
      }

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
      }      // ABAC CONTEXT (server-resolved only, LOOP 4/5/6):
      //  - custody: current custodian identity from the DATABASE read model
      //  - step-up: a server-verified step-up session for this exact asset
      //  - approval: the requester's active approval row for this operation
      //  - risk: advisory level from the security-intelligence rule engine
      // The client can influence NONE of these values.
      const role = ctx.user.role === "admin" ? "ADMIN" : roles[0] ?? "USER";
      const purpose = `transfer:${asset.assetId}`;
      const [stepUpValid, approvalRow, riskLevel] = await Promise.all([
        actorIdentity ? hasValidStepUp(actorIdentity.id, purpose) : Promise.resolve(false),
        actorIdentity ? getActiveAssetApproval({ assetId: asset.id, requesterIdentityId: actorIdentity.id, action: "TRANSFER" }) : Promise.resolve(undefined),
        securityIntelligenceService.assessRisk({ identityId: actorIdentity?.id ?? null, action: "TRANSFER", classification: asset.classification }),
      ]);
      const sensitive = asset.classification === "HIGHLY_SENSITIVE" || asset.classification === "CRITICAL";
      const result = authorizationService.evaluate({
        identityStatus: actorIdentity?.status ?? "UNREGISTERED",
        // Platform admin maps to the ADMIN role and gains administration:manage;
        // both are still subject to the engine's identity-status check above.
        role,
        permissions: ctx.user.role === "admin" ? Array.from(new Set([...permissions, "administration:manage"])) : permissions,
        resourceType: "asset",
        action: "TRANSFER",
        // SECURITY: classification always comes from the database record,
        // never from a client-supplied value. Step-up state comes from the
        // server-verified step-up session store only.
        assetClassification: asset.classification,
        actorIdentityId: actorIdentity?.id,
        currentCustodianIdentityId: asset.custodianIdentityId,
        approvalStatus: approvalRow?.status,
        riskLevel,
        context: {
          stepUpAuthenticated: stepUpValid,
          approvalRequired: sensitive,
        },
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
      // (platform openId/role) and the actor's SAMPRAAN identity id, so a denial
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
        // Denied/challenged requests feed the advisory intelligence engine.
        scheduleIntelligenceScan();
        return { ...result, transaction: null };
      }

      // Policy ALLOWed the request. The smart contract now INDEPENDENTLY
      // re-verifies role, identity status, and asset state on-chain; only a
      // successful receipt produces a confirmed transaction record.
      //
      // BUG-029: the transfer target must be the RECIPIENT identity's on-chain
      // reference wallet — not the shared operator wallet. Assets anchored at
      // creation already sit with the operator wallet, so transferring
      // "to the operator" reverts with SameAssetStatus() (0x27479240) and the
      // custody never moves. Each identity's wallet is derived
      // deterministically from its DID, so custody flows to the authorized
      // recipient exactly as the policy engine decided. When no recipient was
      // named, the acting identity is the recipient (legacy SIH demo behavior).
      const operatorKey = besuBlockchainService?.config.privateKey ?? null;
      const toCustodianWallet = recipient && operatorKey
        ? deriveIdentityWallet(operatorKey, recipient.did)
        : blockchainService.operatorAddress;
      // The contract requires the RECIPIENT identity to be ACTIVE on-chain
      // (RecipientNotActive). A recipient identity that exists in the read
      // model but was never anchored would fail the transfer; anchor it now —
      // idempotent, best-effort, and audited exactly like creation.
      if (recipient && operatorKey && blockchainService.mode === "BESU") {
        await anchoringService.anchorIdentity({
          did: recipient.did,
          displayName: recipient.displayName,
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
        const reason = describeError(error);
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
        metadata: { source: "blockchain-evidence", blockHash: transaction.blockHash, gasUsed: transaction.gasUsed, chainMode: blockchainService.mode, events: transaction.events, recipientIdentityId: recipient?.id ?? null, recipientDid: recipient?.did ?? null, recipientWallet: toCustodianWallet, ...actingUser },
      }).catch((persistError: unknown) => {
        console.error("[Authorization] Failed to persist transfer audit event:", persistError);
      });

      // BUG-006: the chain is authoritative, but the read model must agree
      // with it. After a CONFIRMED transfer, move the DB custodian + custody
      // history to the RECIPIENT identity (the acting identity when no
      // recipient was named). If the DB write fails, record the drift
      // explicitly — never silently leave the two layers disagreeing.
      // LOOP 6: a consumed approval is marked EXECUTED so the same approval
      // can never authorize a second transfer (execution revalidated policy
      // above before the chain call).
      if (approvalRow && approvalRow.status === "APPROVED") {
        await markAssetApprovalExecuted(approvalRow.id).catch(() => undefined);
      }
      const custodianUpdate = await applyCustodyTransfer({
        assetRowId: asset.id,
        newCustodianIdentityId: recipient?.id ?? null,
        reason: `On-chain custody transfer to ${recipient?.displayName ?? "recipient"} confirmed in tx ${transaction.transactionHash}`,
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
  audit: router({
    list: protectedProcedure.input(z.object({ limit: z.number().int().min(1).max(200).default(50) }).optional()).query(({ input }) => listAuditEvents(input?.limit ?? 50)),
    /** Audit events for one asset's provenance view. */
    forAsset: protectedProcedure.input(z.object({ assetId: z.string().min(2).max(160) })).query(({ input }) => listAssetAuditEvents(input.assetId)),
  }),
  alerts: router({
    list: protectedProcedure.query(() => listSecurityAlerts()),
    /** Investigator workflow: advance an advisory alert's status. */
    setStatus: protectedProcedure
      .input(z.object({ alertId: z.string().uuid(), status: z.enum(["OPEN", "INVESTIGATING", "RESOLVED"]) }))
      .mutation(async ({ input, ctx }) => {
        const alert = await updateAlertStatus(input);
        if (!alert) throw new TRPCError({ code: "NOT_FOUND", message: "Alert not found" });
        const actingIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
        await createAuditEvent({
          actorIdentityId: actingIdentity?.id ?? null,
          action: "SECURITY_ALERT_UPDATED",
          resourceType: "SECURITY",
          resourceId: input.alertId,
          decision: "ALLOW",
          reason: `Alert status set to ${input.status} (advisory workflow only)`,
          metadata: { source: "security-intelligence", alertStatus: input.status, advisory: true, actorUserOpenId: ctx.user?.openId ?? null },
        }).catch(() => { /* best-effort */ });
        return alert;
      }),
  }),
  /**
   * Security intelligence (ADVISORY ONLY — never part of authorization).
   * Rules-first evaluation of REAL audit events into security_alerts rows.
   */
  intelligence: router({
    /** Run the advisory rule scan on demand (idempotent per day). */
    scan: protectedProcedure.mutation(async ({ ctx }) => {
      const result = await securityIntelligenceService.scan();
      await recordIntelligenceScanEvidence(result);
      const actingIdentity = ctx.user ? await getIdentityByLinkedUserId(ctx.user.id) : undefined;
      if (result.created > 0 && actingIdentity) {
        await createAuditEvent({
          actorIdentityId: actingIdentity.id,
          action: "SECURITY_INTELLIGENCE_RUN",
          resourceType: "SECURITY",
          resourceId: "intelligence-engine",
          decision: "ALLOW",
          reason: `Advisory rule scan run by ${actingIdentity.displayName}`,
          metadata: { source: "security-intelligence", advisory: true, ...result },
        }).catch(() => { /* best-effort */ });
      }
      return result;
    }),
  }),
  /**
   * Policy management/inspection surface. The authorization SERVICE remains
   * the single source of truth for evaluation; this router exposes the policy
   * catalog (policies table) for inspection plus a DRY-RUN evaluation that
   * explains an ALLOW/DENY/CHALLENGE decision WITHOUT executing anything.
   */
  policies: router({
    /** Policy catalog as stored (subjectRole x resourceType x action x classification x effect). */
    list: protectedProcedure.query(() => listPolicies()),
    /**
     * Dry-run policy evaluation for an asset transfer. Explains the decision
     * the engine WOULD make for the CURRENT session actor and a chosen asset:
     * which checks passed, which failed, and what the smart contract would
     * independently re-verify. Persists the decision + audit row exactly like
     * the real path (labelled as a dry run) but performs NO chain submission.
     */
    evaluateTransfer: protectedProcedure
      .input(z.object({ assetId: z.string().uuid() }))
      .mutation(async ({ ctx, input }) => {
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
        const { roles, permissions } = actorIdentity
          ? await getIdentityRolesAndPermissions(actorIdentity.id)
          : { roles: [] as string[], permissions: [] as string[] };
        const ownerIdentity = await getIdentityById(asset.ownerIdentityId);
        const ownerStatus = ownerIdentity?.status ?? "SUSPENDED";
        const result = authorizationService.evaluate({
          identityStatus: actorIdentity?.status ?? "UNREGISTERED",
          role: ctx.user.role === "admin" ? "ADMIN" : roles[0] ?? "USER",
          permissions: ctx.user.role === "admin" ? Array.from(new Set([...permissions, "administration:manage"])) : permissions,
          resourceType: "asset",
          action: "TRANSFER",
          assetClassification: asset.classification,
        });
        const actingUser = { actorUserOpenId: ctx.user.openId, actorUserRole: ctx.user.role };
        if (actorIdentity) {
          await createAuthorizationDecision({
            id: result.decisionId,
            actorIdentityId: actorIdentity.id,
            resourceType: "ASSET",
            resourceId: asset.assetId,
            action: "TRANSFER_DRY_RUN",
            decision: result.decision,
            reason: result.reason,
            policyId: null,
            timestamp: new Date(result.timestamp),
          }).catch(() => undefined);
        }
        await createAuditEvent({
          actorIdentityId: actorIdentity?.id ?? null,
          action: "AUTHORIZATION_DRY_RUN",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: result.decision,
          reason: result.reason,
          metadata: { source: "authorization-engine", dryRun: true, policyId: result.policyId ?? null, ownerStatus, ...actingUser },
        }).catch(() => undefined);
        // Contract-side checks that would independently re-verify this call.
        const contractChecks = [
          { check: "Caller holds ASSET_MANAGER_ROLE", note: "Re-verified on-chain by SampraanAssetRegistry.transferCustody" },
          { check: `Asset status is ACTIVE (current: ${asset.status})`, note: "Suspended/revoked assets are frozen on-chain" },
          { check: `Owner identity ACTIVE (current: ${ownerStatus})`, note: "Server-side defense in depth" },
          { check: `Recipient identity registered and ACTIVE`, note: "RecipientNotActive revert otherwise" },
        ];
        return { ...result, asset: { id: asset.id, assetId: asset.assetId, name: asset.name, classification: asset.classification, status: asset.status }, actor: { identity: actorIdentity ? { id: actorIdentity.id, displayName: actorIdentity.displayName, status: actorIdentity.status } : null, roles, permissions }, ownerStatus, contractChecks, dryRun: true as const };
      }),
  }),
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
        const reason = describeError(error);
        throw new TRPCError({ code: "BAD_GATEWAY", message: `Blockchain event query failed: ${reason}` });
      }
    }),
  }),
  /**
   * Sensitive-asset approval workflow (LOOP 6). Approvals gate sensitive
   * TRANSFER operations at the application layer; the smart contract still
   * independently re-verifies every state transition.
   */
  approvals: router({
    list: protectedProcedure.input(z.object({ assetId: z.string().uuid() })).query(({ input }) => listAssetApprovals(input.assetId)),
    /** Request approval for a sensitive transfer (requester = current session identity). */
    request: protectedProcedure
      .input(z.object({ assetId: z.string().uuid(), action: z.literal("TRANSFER").default("TRANSFER"), targetIdentityId: z.string().uuid().optional(), reason: z.string().max(300).optional() }))
      .mutation(async ({ ctx, input }) => {
        const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
        if (!actorIdentity) throw new TRPCError({ code: "FORBIDDEN", message: "No SAMPRAAN identity is linked to this session" });
        const asset = await getAssetById(input.assetId);
        if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
        const existing = await getActiveAssetApproval({ assetId: asset.id, requesterIdentityId: actorIdentity.id, action: input.action });
        if (existing) return existing;
        const approval = await createAssetApproval({
          assetId: asset.id,
          requesterIdentityId: actorIdentity.id,
          action: input.action,
          targetIdentityId: input.targetIdentityId ?? null,
          reason: input.reason ?? null,
        });
        if (!approval) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Approval could not be persisted" });
        await createAuditEvent({ actorIdentityId: actorIdentity.id, action: "APPROVAL_REQUESTED", resourceType: "ASSET", resourceId: asset.assetId, decision: "CHALLENGE", reason: `Approval requested for ${input.action} of ${asset.classification} asset`, metadata: { source: "approval-workflow", approvalId: approval.id } }).catch(() => undefined);
        return approval;
      }),
    /** Approve/reject — ADMIN (or approval-holder role per policy) only. */
    decide: protectedProcedure
      .input(z.object({ approvalId: z.string().uuid(), decision: z.enum(["APPROVED", "REJECTED"]), reason: z.string().max(300).optional() }))
      .mutation(async ({ ctx, input }) => {
        const actorIdentity = await getIdentityByLinkedUserId(ctx.user.id);
        if (!actorIdentity) throw new TRPCError({ code: "FORBIDDEN", message: "No SAMPRAAN identity is linked to this session" });
        const approval = await getAssetApproval(input.approvalId);
        if (!approval) throw new TRPCError({ code: "NOT_FOUND", message: "Approval not found" });
        const { roles } = await getIdentityRolesAndPermissions(actorIdentity.id);
        const role = ctx.user.role === "admin" ? "ADMIN" : roles[0] ?? "USER";
        // Only ADMIN (or an identity holding administration:manage) may approve.
        const { permissions } = await getIdentityRolesAndPermissions(actorIdentity.id);
        const canApprove = role === "ADMIN" || permissions.includes("administration:manage");
        if (!canApprove) {
          await createAuditEvent({ actorIdentityId: actorIdentity.id, action: "APPROVAL_DENIED", resourceType: "ASSET", resourceId: approval.id, decision: "DENY", reason: `Role ${role} may not decide approvals`, metadata: { source: "approval-workflow" } }).catch(() => undefined);
          throw new TRPCError({ code: "FORBIDDEN", message: "Only administrators may decide approvals" });
        }
        if (approval.requesterIdentityId === actorIdentity.id) {
          throw new TRPCError({ code: "FORBIDDEN", message: "Separation of duties: the requester may not approve their own request" });
        }
        const updated = await updateAssetApprovalStatus({ approvalId: input.approvalId, status: input.decision, approverIdentityId: actorIdentity.id });
        if (!updated) throw new TRPCError({ code: "CONFLICT", message: "Approval is no longer pending" });
        await createAuditEvent({ actorIdentityId: actorIdentity.id, action: input.decision === "APPROVED" ? "APPROVAL_GRANTED" : "APPROVAL_REJECTED", resourceType: "ASSET", resourceId: approval.id, decision: input.decision === "APPROVED" ? "ALLOW" : "DENY", reason: input.reason ?? `Approval ${input.decision.toLowerCase()} by ${actorIdentity.displayName}`, metadata: { source: "approval-workflow", assetId: approval.assetId, requesterIdentityId: approval.requesterIdentityId } }).catch(() => undefined);
        return updated;
      }),
  }),
  /** Complete asset provenance (LOOP 9): real chain evidence + custody read model. */
  provenance: protectedProcedure.input(z.object({ assetId: z.string().uuid() })).query(async ({ input }) => {
    const asset = await getAssetById(input.assetId);
    if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
    const operatorKey = besuBlockchainService?.config.privateKey ?? null;
    let onChain: { custodian: string | null; status: string | null } | null = null;
    if (besuBlockchainService) {
      const record = await besuBlockchainService.getAsset(asset.assetId).catch(() => null);
      if (record) onChain = { custodian: record.custodian ?? null, status: String(record.status ?? "") || null };
    }
    return buildAssetProvenance({
      assetRowId: asset.id,
      onChain,
      deriveWallet: operatorKey ? (did: string) => deriveIdentityWallet(operatorKey, did) : undefined,
    });
  }),
  /**
   * Policy simulator (LOOP 10): runs the SAME authorization engine on a
   * hypothetical input without executing anything. ADMIN-only to prevent
   * policy probing by unprivileged roles; the result is clearly labelled a
   * dry run and persists NO decision rows.
   */
  simulator: adminProcedure
    .input(z.object({
      role: z.enum(["ADMIN", "MANAGER", "AUDITOR", "USER"]),
      identityStatus: z.enum(["ACTIVE", "SUSPENDED", "REVOKED"]).default("ACTIVE"),
      assetClassification: z.enum(["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]),
      action: z.enum(["TRANSFER", "CREATE_ASSET", "READ"]),
      stepUpAuthenticated: z.boolean().default(false),
      approvalStatus: z.enum(["PENDING", "APPROVED", "REJECTED", "EXECUTED"]).optional(),
      riskLevel: z.enum(["LOW", "MEDIUM", "HIGH"]).optional(),
      custodyMatch: z.boolean().default(true),
    }))
    .mutation(async ({ input }) => {
      const permissionFor = (action: string) => ({ READ: "asset:read", TRANSFER: "asset:transfer", CREATE_ASSET: "asset:create" })[action] ?? "asset:read";
      const rolePermissions: Record<string, string[]> = {
        ADMIN: ["administration:manage"],
        MANAGER: [permissionFor(input.action)],
        AUDITOR: ["asset:read"],
        USER: ["asset:read"],
      };
      const result = authorizationService.evaluate({
        identityStatus: input.identityStatus,
        role: input.role,
        permissions: rolePermissions[input.role] ?? [],
        resourceType: "asset",
        action: input.action,
        assetClassification: input.assetClassification,
        actorIdentityId: "simulated-actor",
        currentCustodianIdentityId: input.custodyMatch ? "simulated-actor" : "other-custodian",
        approvalStatus: input.approvalStatus,
        riskLevel: input.riskLevel,
        context: { stepUpAuthenticated: input.stepUpAuthenticated, approvalRequired: input.assetClassification === "HIGHLY_SENSITIVE" || input.assetClassification === "CRITICAL" },
      });
      await createAuditEvent({ actorIdentityId: null, action: "POLICY_SIMULATED", resourceType: "POLICY", resourceId: result.decisionId, decision: result.decision, reason: `Simulated ${input.role}/${input.action}/${input.assetClassification} → ${result.decision}`, metadata: { source: "policy-simulator", dryRun: true, input } }).catch(() => undefined);
      return { ...result, input, dryRun: true as const };
    }),
  /**
   * The Graph query layer (LOOP 11) — READ-ONLY indexing/query surface over
   * REAL contract events. NEVER consulted for authorization decisions; the
   * core application works identically when unavailable.
   */
  graph: router({
    status: protectedProcedure.query(() => graphQueryService.status()),
    asset: protectedProcedure.input(z.object({ assetId: z.string().min(2).max(160) })).query(({ input }) => graphQueryService.getAsset(input.assetId)),
    provenance: protectedProcedure.input(z.object({ assetId: z.string().min(2).max(160) })).query(({ input }) => graphQueryService.getProvenance(input.assetId)),
    identity: protectedProcedure.input(z.object({ wallet: z.string().regex(/^0x[0-9a-fA-F]{40}$/) })).query(({ input }) => graphQueryService.getIdentity(input.wallet)),
    roleEvents: protectedProcedure.query(() => graphQueryService.getRoleEvents()),
  }),
});

export type AppRouter = typeof appRouter;