import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../../_core/trpc";
import {
  createAssetContentVersion,
  createAssetAccessGrant,
  createAuditEvent,
  getAssetById,
  getAssetContentVersionById,
  getAssetIdForGrant,
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
  listActiveAssetAccessGrants,
  listAssetAccessGrants,
  listAssetContentVersions,
  getNextAssetVersionNumber,
  revokeAssetAccessGrant,
} from "../../db";
import { besuBlockchainService } from "../blockchain/blockchain.service";
import { anchoringService } from "../blockchain/anchoring.service";
import { hasValidStepUp } from "../did/did-auth.service";
import { describeError } from "../../common/error-handler";
import { scheduleIntelligenceScan } from "../security-intelligence/intelligence.service";
import {
  ContentValidationError,
  MAX_UPLOAD_BYTES,
  encryptAndStore,
  evaluateContentAccess,
  loadVersionPlaintext,
  sanitizeFilename,
  validateUpload,
  verifyVersionIntegrity,
  type ContentActor,
  type ContentResource,
} from "./content.service";
import { assetFilePolicy } from "./file-policy";

/**
 * Controlled asset content router.
 *
 * REAL digital-asset content behind the EXISTING security model: every
 * procedure authenticates via protectedProcedure, then authorizes through
 * evaluateContentAccess with ALL security inputs resolved server-side
 * (identity status, role, permissions, classification, ownership/custody,
 * grants, step-up). The client can name an asset and a version — nothing
 * else it sends is trusted.
 *
 * There is deliberately NO download procedure and NO public file URL:
 * content reaches an authorized browser only through the authenticated
 * streaming view below, and the storage layer is never exposed.
 */

const contentAction = z.enum(["VIEW", "EDIT", "UPLOAD", "MANAGE_ACCESS"]);
/**
 * Purpose token for step-up challenges and probes. MUST be the single
 * composer of this string on the server: stepup.requestChallenge binds its
 * challenges to `content-<action>:<asset row id>` and the content gate
 * probes with the exact same token, so a challenge issued by this product
 * can actually satisfy the gate it was issued for (and nothing else —
 * identity + purpose + audience + keyId stay bound).
 */
export const stepUpPurposeFor = (action: "VIEW" | "EDIT" | "UPLOAD" | "MANAGE_ACCESS" | "TRANSFER", assetRowId: string) =>
  `content-${action.toLowerCase()}:${assetRowId}`;

/** Resolve the session's SAMPRAAN identity + RBAC envelope (server-side only). */
async function resolveActor(ctx: { user: { id: number; openId: string; role: string } }): Promise<ContentActor> {
  const identity = await getIdentityByLinkedUserId(ctx.user.id);
  const { roles, permissions } = identity
    ? await getIdentityRolesAndPermissions(identity.id)
    : { roles: [], permissions: [] };
  return {
    platformUserId: ctx.user.id,
    openId: ctx.user.openId,
    platformRole: ctx.user.role === "admin" ? "admin" : "user",
    identity: identity
      ? {
          id: identity.id,
          did: identity.did,
          status: identity.status as ContentActor["identity"] extends null ? never : "ACTIVE" | "SUSPENDED" | "REVOKED",
          lifecycleState: identity.lifecycleState,
        }
      : null,
    roles,
    permissions: ctx.user.role === "admin" ? Array.from(new Set([...permissions, "administration:manage"])) : permissions,
  };
}

function toContentResource(asset: NonNullable<Awaited<ReturnType<typeof getAssetById>>>): ContentResource {
  return {
    id: asset.id,
    assetId: asset.assetId,
    classification: asset.classification,
    status: asset.status,
    ownerIdentityId: asset.ownerIdentityId,
    custodianIdentityId: asset.custodianIdentityId,
  };
}

/**
 * Shared authorization gate. Loads the asset, resolves the actor from the
 * session, evaluates content access server-side, and persists an audit row
 * for EVERY decision (including denials — denials are evidence).
 */
async function authorizeContentOperation(input: {
  ctx: { user: { id: number; openId: string; role: string } };
  assetId: string;
  action: z.infer<typeof contentAction>;
  versionId?: string;
}): Promise<{
  actor: ContentActor;
  asset: NonNullable<Awaited<ReturnType<typeof getAssetById>>>;
  decision: Awaited<ReturnType<typeof evaluateContentAccess>>;
}> {
  const asset = await getAssetById(input.assetId);
  if (!asset) throw new TRPCError({ code: "NOT_FOUND", message: "Asset not found" });
  const actor = await resolveActor(input.ctx);
  // Purpose must be computed over the asset's ROW id (uuid) — the same id the
  // step-up router resolves and binds challenges to. Never the business key.
  const purpose = stepUpPurposeFor(input.action, asset.id);
  const decision = await evaluateContentAccess({
    actor,
    asset: toContentResource(asset),
    action: input.action,
    purpose,
    stepUpProbe: (identityId: string, purpose: string) => hasValidStepUp(identityId, purpose),
    grantProbe: (assetRowId: string, identityId: string) => listActiveAssetAccessGrants(assetRowId, identityId).then(rows => rows.map(row => row.permission)),
  });

  const auditDecision = decision.decision;
  await createAuditEvent({
    actorIdentityId: actor.identity?.id ?? null,
    action: auditDecision === "ALLOW" ? `ASSET_CONTENT_${input.action}_AUTHORIZED` : "ASSET_CONTENT_ACCESS_DENIED",
    resourceType: "ASSET",
    resourceId: asset.assetId,
    decision: auditDecision,
    reason: decision.reason,
    metadata: {
      source: "asset-content",
      requestedAction: input.action,
      versionId: input.versionId ?? null,
      baseline: decision.baseline,
      stepUpPurpose: purpose,
      actorOpenId: input.ctx.user.openId,
      actorUserRole: input.ctx.user.role,
      identityDid: actor.identity?.did ?? null,
    },
  }).catch((error: unknown) => {
    console.error("[AssetContent] Failed to persist access audit event:", error);
  });
  if (decision.decision !== "ALLOW") scheduleIntelligenceScan();

  if (decision.decision === "DENY") {
    throw new TRPCError({ code: "FORBIDDEN", message: decision.reason });
  }
  if (decision.decision === "CHALLENGE") {
    throw new TRPCError({
      code: "PRECONDITION_FAILED",
      message: `STEP_UP_REQUIRED: ${decision.reason}`,
    });
  }
  return { actor, asset, decision };
}

/** Version rows are safe to expose: NEVER includes the encryption envelope. */
function toPublicVersion(version: Awaited<ReturnType<typeof listAssetContentVersions>>[number]) {
  return {
    id: version.id,
    assetId: version.assetId,
    versionNumber: version.versionNumber,
    filename: version.filename,
    originalFilename: version.originalFilename,
    mimeType: version.mimeType,
    sizeBytes: Number(version.sizeBytes),
    contentHash: version.contentHash,
    storageProvider: version.storageProvider,
    createdByIdentityId: version.createdByIdentityId,
    changeNote: version.changeNote,
    createdTxHash: version.createdTxHash,
    createdBlockNumber: version.createdBlockNumber,
    createdAt: version.createdAt,
  };
}

export const assetContentRouter = router({
  /** Version list + workspace metadata for one asset (authorized VIEWers). */
  list: protectedProcedure
    .input(z.object({ assetId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      await authorizeContentOperation({ ctx, assetId: input.assetId, action: "VIEW" });
      const versions = await listAssetContentVersions(input.assetId);
      return { versions: versions.map(toPublicVersion) };
    }),

  /**
   * Metadata for one version (authorized VIEWers). Integrity is NOT claimed
   * here — verification is an explicit operation the actor must run.
   */
  detail: protectedProcedure
    .input(z.object({ versionId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const version = await getAssetContentVersionById(input.versionId);
      if (!version) throw new TRPCError({ code: "NOT_FOUND", message: "Content version not found" });
      await authorizeContentOperation({ ctx, assetId: version.assetId, action: "VIEW", versionId: version.id });
      return { version: toPublicVersion(version) };
    }),

  /**
   * Controlled content view. Streams the DECRYPTED plaintext to an
   * authorized session ONLY, as a data: URL payload (the tRPC channel) —
   * there is no cacheable file URL, no download endpoint, and the storage
   * reference/paths never leave the server. Browsers render it inside the
   * asset workspace; nothing about this response grants persistence rights.
   */
  view: protectedProcedure
    .input(z.object({ versionId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const version = await getAssetContentVersionById(input.versionId);
      if (!version) throw new TRPCError({ code: "NOT_FOUND", message: "Content version not found" });
      const { actor } = await authorizeContentOperation({ ctx, assetId: version.assetId, action: "VIEW", versionId: version.id });

      try {
        const plaintext = await loadVersionPlaintext(version);
        await createAuditEvent({
          // FINAL-AUDIT FIX (attribution): the VIEWED event carried a null
          // actor — the authorized actor was already resolved by the gate
          // above, so attributing a controlled-content disclosure to nobody
          // left the most security-sensitive read operation unattributable.
          actorIdentityId: actor.identity?.id ?? null,
          action: "ASSET_CONTENT_VIEWED",
          resourceType: "ASSET",
          resourceId: version.assetId,
          decision: "ALLOW",
          reason: `Content v${version.versionNumber} streamed to an authorized session`,
          metadata: { source: "asset-content", versionId: version.id, mimeType: version.mimeType, sizeBytes: Number(version.sizeBytes), actorOpenId: ctx.user.openId, identityDid: actor.identity?.did ?? null },
        }).catch(() => undefined);
        return {
          version: toPublicVersion(version),
          contentBase64: plaintext.toString("base64"),
          // View-only contract: the client is told (and the audit shows) this
          // is a controlled in-workspace view, not a download.
          disposition: "view" as const,
        };
      } catch (error) {
        await createAuditEvent({
          actorIdentityId: null,
          action: "ASSET_CONTENT_UNAVAILABLE",
          resourceType: "ASSET",
          resourceId: version.assetId,
          decision: "DENY",
          reason: `Content could not be retrieved: ${describeError(error)}`,
          metadata: { source: "asset-content", versionId: version.id },
        }).catch(() => undefined);
        throw new TRPCError({ code: "NOT_FOUND", message: "Stored content is unavailable" });
      }
    }),

  /**
   * Create a NEW version (authorized EDITors). Historical versions are
   * preserved — content is never overwritten. The version number is
   * allocated atomically; the (assetId, versionNumber) UNIQUE constraint
   * makes concurrent creations safe (one loses, cleanly).
   */
  createVersion: protectedProcedure
    .input(
      z.object({
        assetId: z.string().uuid(),
        // Single-file upload through the tRPC channel (1 MB body cap is
        // lifted for THIS route by the express raw-body handler).
        filename: z.string().min(1).max(255),
        clientMimeType: z.string().max(127).nullable().default(null),
        dataBase64: z.string().min(4),
        changeNote: z.string().max(300).optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const { actor, asset } = await authorizeContentOperation({ ctx, assetId: input.assetId, action: "EDIT" });

      const decoded = Buffer.from(input.dataBase64, "base64");
      if (decoded.byteLength === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Upload payload is empty" });
      }
      if (decoded.byteLength > MAX_UPLOAD_BYTES) {
        throw new TRPCError({ code: "PAYLOAD_TOO_LARGE", message: `File exceeds the ${Math.floor(MAX_UPLOAD_BYTES / (1024 * 1024))} MiB limit` });
      }

      let validated;
      try {
        validated = validateUpload({
          originalFilename: input.filename,
          clientMimeType: input.clientMimeType,
          data: decoded,
        });
      } catch (error) {
        if (error instanceof ContentValidationError) {
          await createAuditEvent({
            actorIdentityId: actor.identity?.id ?? null,
            action: "ASSET_CONTENT_UPLOAD_REJECTED",
            resourceType: "ASSET",
            resourceId: asset.assetId,
            decision: "DENY",
            reason: error.message,
            metadata: { source: "asset-content", filename: sanitizeFilename(input.filename), actorOpenId: ctx.user.openId },
          }).catch(() => undefined);
          throw new TRPCError({ code: "BAD_REQUEST", message: error.message });
        }
        throw error;
      }

      const stored = await encryptAndStore(validated);
      const versionNumber = await getNextAssetVersionNumber(asset.id);
      try {
        const version = await createAssetContentVersion({
          assetId: asset.id,
          versionNumber,
          filename: stored.filename,
          originalFilename: stored.originalFilename,
          mimeType: stored.mimeType,
          sizeBytes: stored.sizeBytes,
          contentHash: stored.contentHash,
          storageProvider: stored.storageProvider,
          storageReference: stored.storageReference,
          encryption: stored.encryption,
          createdByIdentityId: actor.identity!.id,
          changeNote: input.changeNote ?? null,
        });
        if (!version) throw new Error("Database unavailable");

        // Blockchain provenance for durable version events (best-effort, like
        // all anchoring): the on-chain metadata digest of the asset is
        // refreshed to bind the latest content hash into chain evidence.
        let anchor: { outcome: string; transactionHash?: string; blockNumber?: number; reason?: string } = {
          outcome: "SKIPPED",
          reason: "Blockchain is not configured (MOCK mode)",
        };
        if (besuBlockchainService) {
          try {
            const evidence = await anchoringService.anchorAssetVersion({ assetId: asset.assetId, contentHash: validated.contentHash, versionNumber });
            if (evidence) anchor = evidence;
          } catch (error) {
            anchor = { outcome: "FAILED", reason: describeError(error) };
          }
        }
        await createAuditEvent({
          actorIdentityId: actor.identity!.id,
          action: "ASSET_VERSION_CREATED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "ALLOW",
          reason: `Version ${versionNumber} created (${stored.filename}, ${stored.mimeType}, sha256 ${validated.contentHash.slice(0, 12)}…)`,
          transactionHash: anchor.outcome === "ANCHORED" ? anchor.transactionHash ?? null : null,
          blockNumber: anchor.outcome === "ANCHORED" ? anchor.blockNumber ?? null : null,
          metadata: {
            source: "asset-content",
            versionId: version.id,
            versionNumber,
            contentHash: validated.contentHash,
            storageProvider: stored.storageProvider,
            anchorOutcome: anchor.outcome,
            anchorReason: anchor.reason ?? null,
            actorOpenId: ctx.user.openId,
          },
        }).catch(() => undefined);

        return { version: toPublicVersion(version), anchor };
      } catch (error) {
        // Version row write failed AFTER the object was stored: record the
        // orphaned object for cleanup instead of pretending success.
        await createAuditEvent({
          actorIdentityId: actor.identity?.id ?? null,
          action: "ASSET_VERSION_PERSIST_FAILED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "DENY",
          reason: `Content stored but the version row failed: ${describeError(error)}`,
          metadata: { source: "asset-content", storageReference: stored.storageReference, contentHash: stored.contentHash },
        }).catch(() => undefined);
        if (error instanceof Error && /Duplicate entry/i.test(error.message)) {
          throw new TRPCError({ code: "CONFLICT", message: "A version was just created for this asset — reload and retry" });
        }
        throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Version could not be persisted" });
      }
    }),

  /**
   * Verify Integrity — recomputes the plaintext hash from STORED ciphertext
   * through the storage abstraction and compares against the recorded hash.
   * The result states exactly what was verified; no blind success.
   */
  verifyIntegrity: protectedProcedure
    .input(z.object({ versionId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const version = await getAssetContentVersionById(input.versionId);
      if (!version) throw new TRPCError({ code: "NOT_FOUND", message: "Content version not found" });
      const { actor } = await authorizeContentOperation({ ctx, assetId: version.assetId, action: "VIEW", versionId: version.id });

      const result = await verifyVersionIntegrity({
        storageProvider: version.storageProvider,
        storageReference: version.storageReference,
        sizeBytes: Number(version.sizeBytes),
        contentHash: version.contentHash,
        encryption: version.encryption,
      });
      await createAuditEvent({
        // FINAL-AUDIT FIX (attribution): same actor-resolution as the view
        // event — an integrity verdict (especially a MISMATCH, which is a
        // potential tamper signal) must name WHO ran the verification.
        actorIdentityId: actor.identity?.id ?? null,
        action: result.state === "INTEGRITY_VERIFIED" ? "ASSET_INTEGRITY_VERIFIED" : result.state === "INTEGRITY_MISMATCH" ? "ASSET_INTEGRITY_MISMATCH" : "ASSET_INTEGRITY_ERROR",
        resourceType: "ASSET",
        resourceId: version.assetId,
        decision: result.state === "INTEGRITY_VERIFIED" ? "ALLOW" : result.state === "INTEGRITY_MISMATCH" ? "DENY" : "CHALLENGE",
        reason:
          result.state === "INTEGRITY_VERIFIED"
            ? `Integrity verified for v${version.versionNumber} (sha256 recomputed from stored ciphertext)`
            : result.state === "INTEGRITY_MISMATCH"
              ? `Integrity MISMATCH for v${version.versionNumber}: recorded ${version.contentHash.slice(0, 12)}…, computed ${result.computedHash?.slice(0, 12) ?? "n/a"}…`
              : `Integrity check could not complete: ${result.detail ?? result.state}`,
        metadata: { source: "asset-content", versionId: version.id, state: result.state, actorOpenId: ctx.user.openId, identityDid: actor.identity?.did ?? null },
      }).catch(() => undefined);
      if (result.state === "INTEGRITY_MISMATCH") scheduleIntelligenceScan();
      return result;
    }),

  /** Manage Access — grants extend VIEW/EDIT beyond owner/custodian (admin/owner). */
  grants: protectedProcedure
    .input(z.object({ assetId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      // The grants list IS access-control metadata (grantee identities,
      // permissions, reasons), so it is gated like the rest of Manage Access —
      // admin/owner only. Gating it as VIEW both let non-managers enumerate
      // the ACL and dragged the sensitive-content step-up requirement onto a
      // management read, breaking programmatic grant reconciliation with a
      // 412 that had nothing to do with content access.
      await authorizeContentOperation({ ctx, assetId: input.assetId, action: "MANAGE_ACCESS" });
      const rows = await listAssetAccessGrants(input.assetId);
      return { grants: rows };
    }),

  grant: protectedProcedure
    .input(z.object({ assetId: z.string().uuid(), granteeIdentityId: z.string().uuid(), permission: z.enum(["VIEW", "EDIT"]), reason: z.string().max(300).optional() }))
    .mutation(async ({ ctx, input }) => {
      const { actor } = await authorizeContentOperation({ ctx, assetId: input.assetId, action: "MANAGE_ACCESS" });
      const grant = await createAssetAccessGrant({
        assetId: input.assetId,
        granteeIdentityId: input.granteeIdentityId,
        permission: input.permission,
        grantedByIdentityId: actor.identity!.id,
        reason: input.reason ?? null,
      }).catch((error: unknown) => {
        // The UNIQUE (assetId, grantee, permission) constraint is what makes
        // racing grants safe, so a grant that is ALREADY LIVE is a genuine
        // conflict. It used to escape as an untyped exception, which the tRPC
        // error formatter masked into a generic 500 "The request could not be
        // completed safely." — leaving Manage Access undiagnosable. A conflict
        // the caller can fix is a CONFLICT, with a safe, actionable message
        // (a REVOKED grant is revived atomically by createAssetAccessGrant and
        // never reaches here).
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("DUPLICATE_ACTIVE_GRANT")) {
          throw new TRPCError({
            code: "CONFLICT",
            message: `${input.permission} access is already granted to this identity on this asset. Revoke the active grant before re-issuing it.`,
          });
        }
        throw error;
      });
      if (!grant) throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Grant could not be persisted" });
      await createAuditEvent({
        actorIdentityId: actor.identity!.id,
        action: "ASSET_ACCESS_POLICY_CHANGED",
        resourceType: "ASSET",
        resourceId: input.assetId,
        decision: "ALLOW",
        reason: `Access grant ${input.permission} issued`,
        metadata: { source: "asset-content", grantId: grant.id, granteeIdentityId: input.granteeIdentityId, permission: input.permission, actorOpenId: ctx.user.openId },
      }).catch(() => undefined);
      return grant;
    }),

  revokeGrant: protectedProcedure
    .input(z.object({ grantId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      // Load the grant through its asset to scope authorization correctly.
      const target = await getAssetIdForGrant(input.grantId);
      if (!target) throw new TRPCError({ code: "NOT_FOUND", message: "Grant not found" });
      const { actor } = await authorizeContentOperation({ ctx, assetId: target.assetId, action: "MANAGE_ACCESS" });
      const revoked = await revokeAssetAccessGrant(input.grantId);
      if (!revoked) throw new TRPCError({ code: "CONFLICT", message: "Grant is no longer active" });
      await createAuditEvent({
        actorIdentityId: actor.identity!.id,
        action: "ASSET_ACCESS_POLICY_CHANGED",
        resourceType: "ASSET",
        resourceId: target.assetId,
        decision: "ALLOW",
        reason: `Access grant revoked (${target.permission})`,
        metadata: { source: "asset-content", grantId: input.grantId, granteeIdentityId: target.granteeIdentityId, permission: target.permission, actorOpenId: ctx.user.openId },
      }).catch(() => undefined);
      return { ok: true as const };
    }),

  /** Upload policy for the workspace UI (limits + accepted types). */
  policy: protectedProcedure.query(() => ({
    maxBytes: MAX_UPLOAD_BYTES,
    allowedMimeTypes: assetFilePolicy.allowedMimeTypes(),
  })),
});
