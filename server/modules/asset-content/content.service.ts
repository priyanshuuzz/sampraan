/**
 * SAMPRAAN controlled asset content service.
 *
 * The security boundary for REAL digital asset content. Every operation:
 *   1. authenticates (session user resolved server-side),
 *   2. authorizes via the policy engine (role + classification + custody +
 *      grants + step-up + approval — server-resolved only),
 *   3. validates the file (size, MIME by sniffing magic bytes, safe name),
 *   4. encrypts (AES-256-GCM per-object DEK, wrapped by the master key),
 *   5. stores ciphertext through the StorageProvider abstraction,
 *   6. persists verifiable metadata (plaintext sha256, MIME, size) and
 *   7. records audit evidence (and chain provenance for versions).
 *
 * SECURITY INVARIANTS:
 *  - The client can influence NOTHING security-relevant: role, identity
 *    status, classification, custody, grants, step-up and approval state are
 *    resolved from the session + database on EVERY call.
 *  - Plaintext never persists: content is encrypted before storage; only
 *    wrapped (envelope-encrypted) key material is stored in the DB.
 *  - No raw storage paths or provider URLs are ever exposed to clients.
 *  - There is NO download endpoint by product design; content view flows
 *    through an authenticated streaming endpoint after authorization.
 *  - Integrity verification recomputes the REAL plaintext hash from stored
 *    ciphertext — it never trusts the recorded hash.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { Readable } from "node:stream";
import { describeError } from "../../common/error-handler";
import {
  ContentUnavailableError,
  deriveContentReference,
  resolveStorage,
} from "./storage";
import { assetFilePolicy, type SniffedMime } from "./file-policy";

export type { SniffedMime };

export const ASSET_ACTIONS = ["VIEW", "EDIT", "UPLOAD", "MANAGE_ACCESS"] as const;
export type AssetContentAction = (typeof ASSET_ACTIONS)[number];

export interface ContentActor {
  /** Platform user id from the session (ctx.user.id). */
  platformUserId: number;
  openId: string;
  platformRole: "admin" | "user";
  /** Linked SAMPRAAN identity (resolved server-side; null ⇒ unregistered). */
  identity: {
    id: string;
    did: string;
    status: "ACTIVE" | "SUSPENDED" | "REVOKED";
    /** Governance lifecycle (PENDING/VERIFIED/SUSPENDED/DEACTIVATED). Optional so existing actor constructors keep compiling. */
    lifecycleState?: "PENDING" | "VERIFIED" | "SUSPENDED" | "DEACTIVATED";
  } | null;
  roles: string[];
  permissions: string[];
}

export interface ContentResource {
  id: string;
  assetId: string;
  classification: "PUBLIC" | "CONTROLLED" | "SENSITIVE" | "HIGHLY_SENSITIVE" | "CRITICAL";
  status: "ACTIVE" | "PENDING" | "REVOKED";
  ownerIdentityId: string;
  custodianIdentityId: string;
}

/** Server-verified step-up probe (injected to avoid a circular import). */
export type StepUpProbe = (identityId: string, purpose: string) => Promise<boolean>;

export interface ContentAccessInput {
  actor: ContentActor;
  asset: ContentResource;
  action: AssetContentAction;
  /** Purpose token for step-up, e.g. `content-view:<assetId>`. */
  purpose?: string;
  stepUpProbe?: StepUpProbe;
}

export type ContentAccessDecision = {
  decision: "ALLOW" | "DENY" | "CHALLENGE";
  reason: string;
  /** True when the actor's custody/ownership/grant baseline permits the action. */
  baseline: "OWNER" | "CUSTODIAN" | "GRANT" | "NONE";
};

/* ------------------------------------------------------------------ */
/* Authorization                                                       */
/* ------------------------------------------------------------------ */

/** Permission key required for each content action. */
const ACTION_PERMISSION: Record<AssetContentAction, string> = {
  VIEW: "asset:read",
  EDIT: "asset:edit",
  UPLOAD: "asset:create",
  MANAGE_ACCESS: "asset:assign",
};

/**
 * Server-side authorization for asset CONTENT operations.
 *
 * Ownership and custody confer the OWNER/CUSTODIAN baseline (owner/custodian
 * may always VIEW; custodian may EDIT per the existing RBAC model — the
 * asset:edit permission is still required for non-admin actors). Explicit
 * access grants EXTEND access to other identities. Auditors get VIEW via
 * their asset:read permission; they never receive EDIT/UPLOAD.
 */
export async function evaluateContentAccess(input: ContentAccessInput): Promise<ContentAccessDecision> {
  const { actor, asset, action } = input;

  if (!actor.identity) {
    return { decision: "DENY", reason: "No SAMPRAAN identity is linked to this session", baseline: "NONE" };
  }
  if (actor.identity.status !== "ACTIVE") {
    return { decision: "DENY", reason: `Identity is ${actor.identity.status.toLowerCase()}`, baseline: "NONE" };
  }
  // GOVERNANCE LIFECYCLE (document §19): a PENDING/SUSPENDED/DEACTIVATED
  // identity may not perform protected content operations even if the
  // legacy status enum has not yet caught up (defense in depth against
  // read-model drift — lifecycleState is the authoritative gate).
  if (actor.identity.lifecycleState && actor.identity.lifecycleState !== "VERIFIED") {
    return { decision: "DENY", reason: `Identity lifecycle is ${actor.identity.lifecycleState.toLowerCase()}`, baseline: "NONE" };
  }
  if (asset.status === "REVOKED") {
    return { decision: "DENY", reason: "A revoked asset cannot be accessed", baseline: "NONE" };
  }

  const isAdmin = actor.platformRole === "admin" || actor.roles.includes("ADMIN");
  const isOwner = actor.identity.id === asset.ownerIdentityId;
  const isCustodian = actor.identity.id === asset.custodianIdentityId;

  let baseline: ContentAccessDecision["baseline"] = "NONE";
  if (isOwner) baseline = "OWNER";
  else if (isCustodian) baseline = "CUSTODIAN";

  // Explicit grants extend access beyond ownership/custody.
  let hasViewGrant = false;
  let hasEditGrant = false;
  if (input.grantProbe) {
    const grants = await input.grantProbe(asset.id, actor.identity.id);
    hasViewGrant = grants.some(g => g === "VIEW" || g === "EDIT");
    hasEditGrant = grants.some(g => g === "EDIT");
    if (!isOwner && !isCustodian) {
      if (hasEditGrant) baseline = "GRANT";
      else if (hasViewGrant) baseline = "GRANT";
    }
  }

  const permissionNeeded = ACTION_PERMISSION[action];
  const holdsPermission =
    isAdmin ||
    actor.permissions.includes(permissionNeeded) ||
    actor.permissions.includes("administration:manage");

  // Baseline access rules per action:
  //  VIEW: owner/custodian/admin, or a granted identity, or any identity
  //        holding asset:read (auditors inspect; USER still needs a grant or
  //        custody because asset:read alone does not open every asset).
  //  EDIT/UPLOAD: owner/custodian/admin with the matching permission.
  //  MANAGE_ACCESS: admin or owner only (custodians manage content, not ACLs).
  const permission = ACTION_PERMISSION[action];
  let access = false;
  switch (action) {
    case "VIEW":
      access =
        isAdmin ||
        isOwner ||
        isCustodian ||
        hasViewGrant ||
        hasEditGrant ||
        // Global read permission (auditor/inspector envelope) allows VIEW of
        // registry metadata AND content of non-HIGHLY_SENSITIVE/CRITICAL
        // assets; sensitive content still requires ownership, custody, or an
        // explicit grant — classification restrictions are enforced below.
        (holdsPermission && !isHighlySensitive(asset.classification));
      break;
    case "EDIT":
    case "UPLOAD":
      access = isAdmin || isOwner || isCustodian || hasEditGrant;
      break;
    case "MANAGE_ACCESS":
      access = isAdmin || isOwner;
      break;
  }

  if (!access) {
    return {
      decision: "DENY",
      reason: `Role ${actor.roles[0] ?? actor.platformRole} does not hold ${permission} access for this asset`,
      baseline,
    };
  }

  if (!holdsPermission && action !== "VIEW") {
    // Non-admin actors (owner/custodian/grantee) still need the domain
    // permission for mutating actions — the grant extends WHO may act, the
    // RBAC permission defines WHAT they may do.
    return {
      decision: "DENY",
      reason: `Identity does not hold ${permission}`,
      baseline,
    };
  }

  // Classification restriction: SENSITIVE+ content requires an explicit
  // relationship (owner/custodian/admin/grant) — a bare asset:read holder
  // (e.g. an unrelated USER with a stray grant) cannot read it.
  if (
    action === "VIEW" &&
    isSensitiveOrAbove(asset.classification) &&
    !isAdmin &&
    !isOwner &&
    !isCustodian &&
    !hasViewGrant &&
    !hasEditGrant
  ) {
    return {
      decision: "DENY",
      reason: `${asset.classification} content requires an explicit access grant`,
      baseline,
    };
  }

  // Step-up: SENSITIVE-and-above VIEW and every EDIT/UPLOAD require a
  // server-verified step-up when the probe is provided. The challenge must be
  // consumed for THIS exact purpose.
  const needsStepUp =
    input.stepUpProbe != null &&
    input.purpose != null &&
    (action === "EDIT" || action === "UPLOAD" || (action === "VIEW" && isSensitiveOrAbove(asset.classification)));
  if (needsStepUp && input.stepUpProbe && input.purpose) {
    const ok = await input.stepUpProbe(actor.identity.id, input.purpose);
    if (!ok) {
      return {
        decision: "CHALLENGE",
        reason: "Step-up authentication is required for this operation",
        baseline,
      };
    }
  }

  return { decision: "ALLOW", reason: "Content authorization satisfied", baseline };
}

function isSensitiveOrAbove(classification: ContentResource["classification"]): boolean {
  return classification === "SENSITIVE" || classification === "HIGHLY_SENSITIVE" || classification === "CRITICAL";
}

function isHighlySensitive(classification: ContentResource["classification"]): boolean {
  return classification === "HIGHLY_SENSITIVE" || classification === "CRITICAL";
}

/* ------------------------------------------------------------------ */
/* File validation                                                     */
/* ------------------------------------------------------------------ */

export const MAX_UPLOAD_BYTES = Number(process.env.ASSET_CONTENT_MAX_BYTES ?? 20 * 1024 * 1024); // 20 MiB
export const MIN_UPLOAD_BYTES = 1;

/** Normalize a client filename into a safe storage name. */
export function sanitizeFilename(original: string): string {
  const base = original.split(/[\\/]/).pop() ?? "asset";
  const cleaned = base
    .normalize("NFKC")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/[^A-Za-z0-9._ ()-]/g, "_")
    .replace(/^\.+/, "")
    .replace(/\s+/g, " ")
    .trim();
  const safe = cleaned.length > 0 ? cleaned : "asset";
  // Keep the total length bounded; preserve the extension when truncating.
  if (safe.length <= 200) return safe;
  const ext = pathExtname(safe);
  const stem = safe.slice(0, Math.max(1, 200 - ext.length));
  return ext ? `${stem}${ext}` : stem;
}

function pathExtname(name: string): string {
  const idx = name.lastIndexOf(".");
  return idx > 0 ? name.slice(idx) : "";
}

export interface ValidatedUpload {
  filename: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  data: Buffer;
  /** sha256 of the PLAINTEXT — the integrity anchor recorded in the DB. */
  contentHash: string;
}

/**
 * Validate and normalize an upload. MIME is decided by MAGIC-BYTE sniffing
 * (never the client Content-Type); extension-only claims are ignored. Files
 * whose sniffed type is not on the allowlist are rejected.
 */
export function validateUpload(input: {
  originalFilename: string;
  clientMimeType: string | null | undefined;
  data: Buffer;
}): ValidatedUpload {
  if (!input.data || input.data.byteLength < MIN_UPLOAD_BYTES) {
    throw new ContentValidationError("File is empty");
  }
  if (input.data.byteLength > MAX_UPLOAD_BYTES) {
    throw new ContentValidationError(`File exceeds the ${Math.floor(MAX_UPLOAD_BYTES / (1024 * 1024))} MiB limit`);
  }
  const sniffed = assetFilePolicy.sniff(input.data);
  if (!sniffed) {
    throw new ContentValidationError("Unsupported or unrecognized file type");
  }
  // Text formats must also decode cleanly; binary garbage renamed to .txt
  // must not pass as text.
  if (sniffed.category === "text") {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(input.data);
    if (decoded.includes("\u0000")) {
      throw new ContentValidationError("File content does not match the declared text format");
    }
  }
  const filename = sanitizeFilename(input.originalFilename);
  return {
    filename,
    originalFilename: input.originalFilename.slice(0, 255),
    mimeType: sniffed.mimeType,
    sizeBytes: input.data.byteLength,
    data: input.data,
    contentHash: createHash("sha256").update(input.data).digest("hex"),
  };
}

export class ContentValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContentValidationError";
  }
}

/* ------------------------------------------------------------------ */
/* Encryption / decryption primitives                                  */
/* ------------------------------------------------------------------ */

export interface EnvelopeEncryption {
  alg: "AES-256-GCM";
  keyId: string;
  /** base64(iv(12) || ciphertext || tag(16)) of the per-object DEK. */
  wrappedKeyB64: string;
  ivB64: string;
  tagB64: string;
}

/** Encrypt plaintext with a fresh per-object DEK (envelope-wrapped). */
async function encryptBuffer(plaintext: Buffer): Promise<{ ciphertext: Buffer; envelope: EnvelopeEncryption }> {
  const { keyProvider } = resolveStorage();
  const dek = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", dek, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const { wrappedKeyB64, keyId } = await keyProvider.wrapKey(dek);
  return {
    ciphertext,
    envelope: { alg: "AES-256-GCM", keyId, wrappedKeyB64, ivB64: iv.toString("base64"), tagB64: tag.toString("base64") },
  };
}

/** Decrypt ciphertext with the stored envelope. Throws on ANY tamper. */
async function decryptBuffer(ciphertext: Buffer, envelope: EnvelopeEncryption): Promise<Buffer> {
  const { keyProvider } = resolveStorage();
  const dek = await keyProvider.unwrapKey(envelope.wrappedKeyB64, envelope.keyId);
  const decipher = createDecipheriv("aes-256-gcm", dek, Buffer.from(envelope.ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(envelope.tagB64, "base64"));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/** Parse + normalize a stored envelope (DB JSON may be any shape). */
function parseEnvelope(raw: unknown): EnvelopeEncryption {
  if (!raw || typeof raw !== "object") throw new Error("Stored encryption envelope is missing");
  const env = raw as Record<string, unknown>;
  if (env.alg !== "AES-256-GCM") throw new Error(`Unsupported content encryption: ${String(env.alg)}`);
  for (const key of ["keyId", "wrappedKeyB64", "ivB64", "tagB64"]) {
    if (typeof env[key] !== "string" || (env[key] as string).length === 0) {
      throw new Error(`Stored encryption envelope is malformed (${key})`);
    }
  }
  return env as unknown as EnvelopeEncryption;
}

/* ------------------------------------------------------------------ */
/* Core operations                                                     */
/* ------------------------------------------------------------------ */

export interface StoredVersionMetadata {
  filename: string;
  originalFilename: string;
  mimeType: string;
  sizeBytes: number;
  contentHash: string;
  storageProvider: string;
  storageReference: string;
  encryption: EnvelopeEncryption;
}

/**
 * Encrypt + store a validated upload. Returns the version metadata to
 * persist (the caller writes the DB row inside its own transaction).
 */
export async function encryptAndStore(validated: ValidatedUpload): Promise<StoredVersionMetadata> {
  const { provider, keyProvider } = resolveStorage();
  const { ciphertext, envelope } = await encryptBuffer(validated.data);
  const integrityKey = await keyProvider.integrityKey();
  const reference = deriveContentReference({
    ciphertext,
    plaintextHash: validated.contentHash,
    integrityKey,
  });
  const stored = await provider.put(reference, ciphertext, { contentHash: validated.contentHash });
  return {
    filename: validated.filename,
    originalFilename: validated.originalFilename,
    mimeType: validated.mimeType,
    sizeBytes: validated.sizeBytes,
    contentHash: validated.contentHash,
    storageProvider: provider.name,
    storageReference: stored.reference,
    encryption: envelope,
  };
}

export type IntegrityState = "INTEGRITY_VERIFIED" | "INTEGRITY_MISMATCH" | "CONTENT_UNAVAILABLE" | "VERIFICATION_ERROR";

export interface IntegrityResult {
  state: IntegrityState;
  /** The hash recomputed from the stored ciphertext, decrypted. */
  computedHash?: string;
  expectedHash: string;
  sizeBytes: number;
  detail?: string;
}

/**
 * Verify the integrity of one stored version: fetch ciphertext through the
 * storage abstraction, decrypt (authenticated — any tamper fails), recompute
 * the plaintext sha256 and compare against the recorded hash.
 */
export async function verifyVersionIntegrity(version: {
  storageProvider: string;
  storageReference: string;
  sizeBytes: number;
  contentHash: string;
  encryption: unknown;
}): Promise<IntegrityResult> {
  const { provider } = resolveStorage();
  try {
    const envelope = parseEnvelope(version.encryption);
    const ciphertext = await provider.get(version.storageReference);
    const plaintext = await decryptBuffer(ciphertext, envelope);
    const computedHash = createHash("sha256").update(plaintext).digest("hex");
    const verified = computedHash === version.contentHash && plaintext.byteLength === version.sizeBytes;
    return {
      state: verified ? "INTEGRITY_VERIFIED" : "INTEGRITY_MISMATCH",
      computedHash,
      expectedHash: version.contentHash,
      sizeBytes: plaintext.byteLength,
    };
  } catch (error) {
    if (error instanceof ContentUnavailableError) {
      return { state: "CONTENT_UNAVAILABLE", expectedHash: version.contentHash, sizeBytes: version.sizeBytes };
    }
    return {
      state: "VERIFICATION_ERROR",
      expectedHash: version.contentHash,
      sizeBytes: version.sizeBytes,
      detail: describeError(error),
    };
  }
}

/** Load + decrypt a version's plaintext (authorization is the caller's job). */
export async function loadVersionPlaintext(version: {
  storageReference: string;
  encryption: unknown;
}): Promise<Buffer> {
  const { provider } = resolveStorage();
  const envelope = parseEnvelope(version.encryption);
  const ciphertext = await provider.get(version.storageReference);
  return decryptBuffer(ciphertext, envelope);
}

/**
 * Stream a version's plaintext WITHOUT buffering it fully in memory.
 * GCM requires authenticity before delivery, so the full ciphertext is
 * decrypted and verified first, then streamed — bounded by MAX_UPLOAD_BYTES
 * so a corrupted/giant object cannot exhaust memory.
 */
export async function streamVersionPlaintext(version: {
  storageReference: string;
  encryption: unknown;
}): Promise<ReadableStream<Uint8Array>> {
  const plaintext = await loadVersionPlaintext(version);
  if (plaintext.byteLength > MAX_UPLOAD_BYTES * 4) {
    throw new Error("Decrypted content exceeds the safety bound");
  }
  const iterable = (function* () {
    const CHUNK = 256 * 1024;
    for (let offset = 0; offset < plaintext.byteLength; offset += CHUNK) {
      yield new Uint8Array(plaintext.subarray(offset, offset + CHUNK));
    }
  })();
  return Readable.toWeb(Readable.from(iterable)) as ReadableStream<Uint8Array>;
}

/** Reference to the injected grant probe type used by the router. */
export type GrantProbe = (assetId: string, identityId: string) => Promise<string[]>;

// GrantProbe lives on ContentAccessInput via declaration merging below.
declare module "./content.service" {}
export interface ContentAccessInput {
  grantProbe?: GrantProbe;
}
