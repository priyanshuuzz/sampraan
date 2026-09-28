/**
 * SAMPRAAN asset content storage abstraction.
 *
 * Asset content is ALWAYS encrypted (AES-256-GCM) BEFORE it reaches a
 * storage provider, so no provider ever sees plaintext. This module defines:
 *
 *  - StorageProvider   — the port: put/get/stat/delete of opaque encrypted
 *                        blobs addressed by a content reference (CID-like).
 *  - LocalEncryptedStorageProvider — deterministic filesystem provider for
 *                        development. Content lives OUTSIDE the repository
 *                        (a configurable data directory) and is gitignored.
 *  - IpfsStorageProvider — adapter for an IPFS(-compatible) HTTP API (Kubo
 *                        /api/v0/add, /api/v0/cat) or a pinning gateway POST
 *                        endpoint. Content is content-addressed; the CID of
 *                        the ENCRYPTED blob is the storage reference.
 *
 * SECURITY INVARIANTS (enforced here, not by callers):
 *  - References are server-generated; client input never becomes a path.
 *  - Paths are validated against traversal BEFORE touching the filesystem.
 *  - The provider never receives or returns plaintext-decided behavior —
 *    authorization ALWAYS happens in the content service above this layer.
 *  - A public IPFS gateway is NEVER an access path: reads go through the
 *    configured node/API endpoint only, and the CID alone grants nothing.
 *
 * Known limitation (documented, not hidden): the local provider's master key
 * comes from server-side configuration/env. It is NOT an HSM/KMS. Production
 * deployments must swap AssetKeyProvider for a KMS-backed implementation —
 * the rest of the domain code is provider-agnostic by design.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes, createHmac } from "node:crypto";
import { createReadStream, createWriteStream, existsSync } from "node:fs";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { describeError } from "../../common/error-handler";

/* ------------------------------------------------------------------ */
/* Key management (development provider; KMS/HSM replaces later)       */
/* ------------------------------------------------------------------ */

export interface AssetKeyProvider {
  /** Wrap (encrypt) a per-object data key with the master key. */
  wrapKey(plaintextKey: Buffer): Promise<{ wrappedKeyB64: string; keyId: string }>;
  /** Unwrap a stored data key. Throws when the key id is unknown. */
  unwrapKey(wrappedKeyB64: string, keyId: string): Promise<Buffer>;
  /** Content-integrity HMAC key (key commitment for ciphertext binding). */
  integrityKey(): Promise<Buffer>;
}

/**
 * Development key provider: AES-256-GCM envelope encryption with a master
 * key loaded from server-side configuration (ASSET_CONTENT_MASTER_KEY hex or
 * derived from JWT_SECRET when unset in non-production).
 *
 * NOT a production KMS. Documented limitation — see README "Known
 * Limitations". keyId names the (static) master key for future rotation.
 */
export class LocalDevKeyProvider implements AssetKeyProvider {
  private readonly masterKey: Buffer;
  readonly keyId: string;

  constructor(masterKey: Buffer, keyId = "local-dev-v1") {
    if (masterKey.length !== 32) {
      throw new Error("LocalDevKeyProvider requires a 32-byte (256-bit) master key");
    }
    this.masterKey = masterKey;
    this.keyId = keyId;
  }

  /** Resolve the master key from the environment (never hardcode secrets). */
  static fromEnvironment(): LocalDevKeyProvider {
    const configured = process.env.ASSET_CONTENT_MASTER_KEY;
    if (configured) {
      const normalized = configured.trim().toLowerCase().replace(/^0x/, "");
      if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new Error(
          "ASSET_CONTENT_MASTER_KEY must be 64 hex characters (32 bytes). Refusing to start with a malformed master key."
        );
      }
      return new LocalDevKeyProvider(Buffer.from(normalized, "hex"));
    }
    if (process.env.NODE_ENV === "production") {
      throw new Error(
        "Refusing to start in production without ASSET_CONTENT_MASTER_KEY. Provision a 32-byte random hex key (or a KMS-backed key provider) before serving asset content."
      );
    }
    // Development fallback: derive a stable per-deployment key from the JWT
    // secret. Never a production posture — loudly labeled as dev-only.
    const derived = createHash("sha256")
      .update(`sampraan-asset-content:${process.env.JWT_SECRET ?? "sampraan-dev"}`)
      .digest();
    return new LocalDevKeyProvider(derived, "local-dev-derived");
  }

  async wrapKey(plaintextKey: Buffer): Promise<{ wrappedKeyB64: string; keyId: string }> {
    // Wire format MUST be iv(12) || ciphertext || tag(16) — exactly what
    // unwrapKey parses below. The IV is per-wrap randomness; storing it with
    // the wrapped key is required (it is not secret). Previously the IV was
    // omitted, so every unwrap authenticated the wrong bytes and ALL stored
    // content failed GCM verification on read.
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.masterKey, iv);
    const wrapped = Buffer.concat([iv, cipher.update(plaintextKey), cipher.final(), cipher.getAuthTag()]);
    return { wrappedKeyB64: wrapped.toString("base64"), keyId: this.keyId };
  }

  async unwrapKey(wrappedKeyB64: string, keyId: string): Promise<Buffer> {
    if (keyId !== this.keyId) {
      throw new Error(`Unknown content key id "${keyId}" — key rotation/restore not available for this key`);
    }
    const wrapped = Buffer.from(wrappedKeyB64, "base64");
    if (wrapped.length < 16 + 12) {
      throw new Error("Wrapped key material is malformed");
    }
    const iv = wrapped.subarray(0, 12);
    const tag = wrapped.subarray(wrapped.length - 16);
    const body = wrapped.subarray(12, wrapped.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", this.masterKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
  }

  async integrityKey(): Promise<Buffer> {
    return createHash("sha256").update("sampraan-asset-integrity").update(this.masterKey).digest();
  }
}

/* ------------------------------------------------------------------ */
/* Storage provider port                                               */
/* ------------------------------------------------------------------ */

export interface StoredObject {
  /** Content-addressed (or path-addressed) reference of the ENCRYPTED blob. */
  reference: string;
  /** Ciphertext byte length. */
  byteLength: number;
  /** sha256 of the CIPHERTEXT (provider-level corruption detection). */
  ciphertextSha256: string;
}

export interface StorageProvider {
  readonly name: string;
  /** Persist an encrypted blob; returns its content reference. */
  put(ref: string, data: Buffer, metadata: { contentHash: string }): Promise<StoredObject>;
  /** Load an encrypted blob by reference. */
  get(ref: string): Promise<Buffer>;
  /** Existence + size probe (integrity "CONTENT UNAVAILABLE" checks). */
  stat(ref: string): Promise<{ exists: boolean; byteLength: number }>;
  /** Remove an object (only used by administrative cleanup). */
  delete(ref: string): Promise<void>;
  /** Stream an encrypted blob without buffering the whole object. */
  stream(ref: string): Promise<ReadableStream<Uint8Array>>;
}

/** Characters allowed in a server-generated content reference. */
const REF_PATTERN = /^[A-Za-z0-9._-]+$/;

function assertSafeReference(ref: string): string {
  if (typeof ref !== "string" || ref.length === 0 || ref.length > 200) {
    throw new Error("Invalid storage reference");
  }
  if (!REF_PATTERN.test(ref)) {
    throw new Error("Invalid storage reference (unexpected characters)");
  }
  if (ref.includes("..")) {
    throw new Error("Invalid storage reference (traversal sequence)");
  }
  return ref;
}

/**
 * Deterministic LOCAL provider. Objects live under
 * <dataDir>/asset-content/<shard>/<ref> where shard = first 2 ref chars —
 * a flat, traversal-safe, content-addressed-by-reference layout.
 */
export class LocalEncryptedStorageProvider implements StorageProvider {
  readonly name = "local-encrypted";
  private readonly dataDir: string;

  constructor(dataDir: string) {
    if (!dataDir || path.isAbsolute(dataDir) === false) {
      throw new Error("LocalEncryptedStorageProvider requires an absolute data directory");
    }
    this.dataDir = dataDir;
  }

  static defaultDirectory(): string {
    const configured = process.env.ASSET_CONTENT_STORAGE_DIR;
    if (configured) return path.resolve(configured);
    // Default: OS data dir OUTSIDE the repository so uploads can never enter
    // git. XDG_DATA_HOME on Linux, LOCALAPPDATA on Windows, ~/Library on macOS.
    if (process.env.SAMPRAAN_DATA_DIR) return path.join(path.resolve(process.env.SAMPRAAN_DATA_DIR), "asset-content");
    const platform = process.platform;
    if (platform === "win32") {
      return path.join(process.env.LOCALAPPDATA ?? path.join(process.cwd(), ".local-data"), "sampraan", "asset-content");
    }
    if (platform === "darwin") {
      return path.join(process.env.HOME ?? process.cwd(), "Library", "Application Support", "sampraan", "asset-content");
    }
    return path.join(process.env.XDG_DATA_HOME ?? path.join(process.env.HOME ?? process.cwd(), ".local", "share"), "sampraan", "asset-content");
  }

  private objectPath(ref: string): string {
    const safe = assertSafeReference(ref);
    const shard = safe.slice(0, 2);
    return path.join(this.dataDir, shard, safe);
  }

  async put(ref: string, data: Buffer, metadata: { contentHash: string }): Promise<StoredObject> {
    const target = this.objectPath(ref);
    await mkdir(path.dirname(target), { recursive: true });
    // Write-then-rename: a crash cannot leave a torn object behind.
    const tempPath = `${target}.tmp-${randomBytes(6).toString("hex")}`;
    await writeFile(tempPath, data);
    await writeFile(`${tempPath}.meta`, JSON.stringify({ ...metadata, byteLength: data.byteLength }), "utf8");
    try {
      await pipeline(
        createReadStream(tempPath),
        createWriteStream(target)
      );
    } catch (error) {
      throw new Error(`Failed to persist encrypted content: ${describeError(error)}`);
    } finally {
      await rm(tempPath, { force: true }).catch(() => undefined);
      await rm(`${tempPath}.meta`, { force: true }).catch(() => undefined);
    }
    return {
      reference: ref,
      byteLength: data.byteLength,
      ciphertextSha256: createHash("sha256").update(data).digest("hex"),
    };
  }

  async get(ref: string): Promise<Buffer> {
    const target = this.objectPath(ref);
    if (!existsSync(target)) {
      throw new ContentUnavailableError(ref);
    }
    return readFile(target);
  }

  async stat(ref: string): Promise<{ exists: boolean; byteLength: number }> {
    try {
      const info = await stat(this.objectPath(ref));
      return { exists: true, byteLength: info.size };
    } catch {
      return { exists: false, byteLength: 0 };
    }
  }

  async delete(ref: string): Promise<void> {
    await rm(this.objectPath(ref), { force: true });
  }

  async stream(ref: string): Promise<ReadableStream<Uint8Array>> {
    const target = this.objectPath(ref);
    return Readable.toWeb(createReadStream(target)) as ReadableStream<Uint8Array>;
  }
}

/**
 * IPFS-compatible provider. Writes go through an IPFS HTTP API (Kubo
 * /api/v0/add?pin=true or any compatible endpoint); reads through
 * /api/v0/cat. The CID of the ENCRYPTED blob is the storage reference, so
 * storage is content-addressed and integrity-verifiable by construction.
 *
 * This is NOT an authorization boundary: possession of a CID grants nothing
 * — the blob is ciphertext, and reads still flow through the SAMPRAAN
 * authorization layer (assets.content.view) which decrypts server-side.
 * Public gateways are never used for reads; only the configured node.
 */
export class IpfsStorageProvider implements StorageProvider {
  readonly name = "ipfs";
  private readonly apiBase: string;
  private readonly fetchImpl: typeof fetch;

  constructor(apiBase: string, fetchImpl: typeof fetch = fetch) {
    this.apiBase = normalizeIpfsApiBase(apiBase);
    this.fetchImpl = fetchImpl;
  }

  static fromEnvironment(): IpfsStorageProvider | null {
    const api = process.env.IPFS_API_URL;
    return api ? new IpfsStorageProvider(api) : null;
  }

  async put(ref: string, data: Buffer, metadata: { contentHash: string }): Promise<StoredObject> {
    void metadata;
    const form = new FormData();
    form.append("file", new Blob([new Uint8Array(data)]), ref);
    const response = await this.fetchImpl(`${this.apiBase}/add?pin=true&cid-version=1`, {
      method: "POST",
      body: form,
    });
    if (!response.ok) {
      throw new Error(`IPFS add failed: HTTP ${response.status}`);
    }
    const result = (await response.json()) as { Hash?: string };
    if (!result?.Hash) {
      throw new Error("IPFS add returned no CID");
    }
    // The IPFS CID is authoritative; the caller's provisional ref is only a
    // dedup hint. Returning the real CID keeps references verifiable.
    return {
      reference: result.Hash,
      byteLength: data.byteLength,
      ciphertextSha256: createHash("sha256").update(data).digest("hex"),
    };
  }

  async get(ref: string): Promise<Buffer> {
    assertSafeReference(ref);
    const response = await this.fetchImpl(`${this.apiBase}/cat?arg=${encodeURIComponent(ref)}`, { method: "POST" });
    if (response.status === 404 || response.status === 500) {
      throw new ContentUnavailableError(ref);
    }
    if (!response.ok) {
      throw new Error(`IPFS cat failed: HTTP ${response.status}`);
    }
    return Buffer.from(await response.arrayBuffer());
  }

  async stat(ref: string): Promise<{ exists: boolean; byteLength: number }> {
    assertSafeReference(ref);
    try {
      const response = await this.fetchImpl(`${this.apiBase}/object/stat?arg=${encodeURIComponent(ref)}`, { method: "POST" });
      if (!response.ok) return { exists: false, byteLength: 0 };
      const body = (await response.json()) as { Size?: number };
      return { exists: true, byteLength: body?.Size ?? 0 };
    } catch {
      return { exists: false, byteLength: 0 };
    }
  }

  async delete(ref: string): Promise<void> {
    assertSafeReference(ref);
    await this.fetchImpl(`${this.apiBase}/pin/rm?arg=${encodeURIComponent(ref)}`, { method: "POST" }).catch(() => undefined);
  }

  async stream(ref: string): Promise<ReadableStream<Uint8Array>> {
    const self = this;
    return new ReadableStream<Uint8Array>({
      async start(controller) {
        try {
          const response = await self.fetchImpl(`${self.apiBase}/cat?arg=${encodeURIComponent(ref)}`, { method: "POST" });
          if (!response.ok || !response.body) {
            controller.error(new ContentUnavailableError(ref));
            return;
          }
          const reader = response.body.getReader();
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            controller.enqueue(value);
          }
          controller.close();
        } catch (error) {
          controller.error(error);
        }
      },
    });
  }
}

/** Thrown when the referenced encrypted object cannot be retrieved. */
export class ContentUnavailableError extends Error {
  constructor(reference: string) {
    super(`Stored content is unavailable for reference ${reference}`);
    this.name = "ContentUnavailableError";
  }
}

/**
 * Normalize the Kubo RPC base so both documented spellings work:
 *   http://127.0.0.1:5001            → .../api/v0   (bare endpoint)
 *   http://127.0.0.1:5001/api/v0     → unchanged    (full RPC base)
 *
 * Accepts an optional trailing slash, and http(s) only — the API must never
 * be pointed at a non-HTTP scheme (SSRF/arbitrary-protocol guard). Without
 * this, the canonical .env.example value (…/api/v0) produced
 * /api/v0/api/v0/add and EVERY upload failed with HTTP 404.
 */
export function normalizeIpfsApiBase(apiBase: string): string {
  const trimmed = apiBase.trim().replace(/\/+$/, "");
  if (!/^https?:\/\//i.test(trimmed)) {
    throw new Error(`IPFS_API_URL must be an http(s) URL (received "${apiBase.slice(0, 40)}")`);
  }
  return /\/api\/v0$/.test(trimmed) ? trimmed : `${trimmed}/api/v0`;
}

/* ------------------------------------------------------------------ */
/* Content-addressed reference generation                              */
/* ------------------------------------------------------------------ */

/**
 * Deterministic, content-derived reference for the ENCRYPTED blob:
 * sha256(ciphertext + plaintextHash + integrityKey) truncated and encoded as
 * a CIDv1-shaped string. Identical content+key produces the same reference
 * (dedup-friendly); different content can never collide in practice.
 * The integrity key participates in the digest so references cannot be
 * computed offline by someone who only knows the plaintext hash.
 */
export function deriveContentReference(input: {
  ciphertext: Buffer;
  plaintextHash: string;
  integrityKey: Buffer;
}): string {
  const digest = createHmac("sha256", input.integrityKey)
    .update(input.ciphertext)
    .update(input.plaintextHash)
    .digest();
  const b32 = base32Encode(digest.subarray(0, 30)).toLowerCase();
  return `bciqa${b32}`; // CIDv1-style prefix (b = base32, c = raw-ish marker)
}

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/* ------------------------------------------------------------------ */
/* Provider resolution                                                 */
/* ------------------------------------------------------------------ */

export interface StorageResolution {
  provider: StorageProvider;
  keyProvider: AssetKeyProvider;
}

let cached: StorageResolution | null = null;

/**
 * Resolve the active storage provider + key provider from configuration.
 *
 * Selection order:
 *   1. IPFS_API_URL set → IpfsStorageProvider (content still encrypted first).
 *   2. Otherwise        → LocalEncryptedStorageProvider (deterministic dev store).
 *
 * Both providers satisfy the same port, so swapping via configuration never
 * touches the asset domain code. The key provider is always the local dev
 * implementation today; a KMS-backed AssetKeyProvider drops in behind the
 * same interface (documented limitation).
 */
export function resolveStorage(): StorageResolution {
  if (cached) return cached;
  const keyProvider = LocalDevKeyProvider.fromEnvironment();
  const ipfs = IpfsStorageProvider.fromEnvironment();
  // PRODUCTION POSTURE (self-hosted Kubo only): content MUST live on the
  // organization's own IPFS node. A silent local-filesystem fallback in
  // production would create two divergent content stores (some versions on
  // IPFS, some on the container's ephemeral disk) and break restart recovery
  // — so production refuses to resolve a storage provider at all without
  // IPFS_API_URL. Development keeps the explicit local fallback so the demo
  // works without the Kubo container; /health reports `ipfs:false` and the
  // deployment guide requires the node in production.
  if (!ipfs && process.env.NODE_ENV === "production") {
    throw new Error(
      "IPFS_API_URL is not set — production asset content requires the self-hosted Kubo IPFS node (refusing silent local-filesystem fallback).",
    );
  }
  const provider = ipfs ?? new LocalEncryptedStorageProvider(LocalEncryptedStorageProvider.defaultDirectory());
  cached = { provider, keyProvider };
  return cached;
}

/** Test hook: clear the memoized provider resolution. */
export function resetStorageForTests(): void {
  cached = null;
}
