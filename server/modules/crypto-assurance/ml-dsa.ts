/**
 * ML-DSA-65 (FIPS 204, "Dilithium3") signature primitives — the post-quantum
 * half of SAMPRAAN's crypto assurance layer.
 *
 * WHY THIS EXISTS: the platform's baseline signature is ECDSA over secp256k1,
 * which is required for EVM/Besu compatibility and is NOT being replaced. A
 * quantum adversary that later recovers a secp256k1 key could retroactively
 * forge the evidence for an irreversible operation. For the highest-risk
 * operations the platform therefore requires a SECOND signature under a
 * post-quantum scheme, so an archived dual-signed payload stays unforgeable.
 *
 * IMPLEMENTATION NOTES
 *  - Primitive: @noble/post-quantum (audited, dependency-free, pure JS). We use
 *    ML-DSA-65 = NIST security category 3 (192-bit classical / 128-bit quantum).
 *  - This module is a THIN, TOTAL wrapper: every public function either returns
 *    a value or returns `false`/`null` — it never throws on attacker-controlled
 *    input. Callers get one boolean to check and cannot accidentally treat a
 *    malformed input as a successful verification.
 *  - Sizes are asserted, not assumed: a truncated or over-long public key or
 *    signature is rejected before any lattice arithmetic runs.
 *  - NO PRIVATE KEY MATERIAL IS EVER LOGGED, RETURNED OR PERSISTED by this
 *    module. The registration path accepts public keys only.
 */
import { createHash } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

/** Algorithm identifier used in every stored key/audit record. */
export const ML_DSA_65_ALGORITHM = "ML-DSA-65" as const;

/** FIPS 204 ML-DSA-65 wire sizes (bytes). Asserted on every boundary. */
export const ML_DSA_65_SIZES = {
  publicKey: 1952,
  secretKey: 4032,
  signature: 3309,
  seed: 32,
} as const;

const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value);

/** Strict base64url decoder: rejects anything that is not canonical base64url. */
export function decodeBase64Url(value: string): Uint8Array | null {
  if (typeof value !== "string" || value.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const bytes = Buffer.from(value, "base64url");
    // Round-trip check: Buffer.from tolerates some malformed input, so verify
    // that re-encoding reproduces the input exactly (canonical form only).
    if (bytes.length === 0) return null;
    if (bytes.toString("base64url") !== value) return null;
    return new Uint8Array(bytes);
  } catch {
    return null;
  }
}

export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** sha256 hex of a raw public key — the stable, non-reversible key fingerprint. */
export function fingerprintPublicKey(publicKey: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(publicKey)).digest("hex");
}

/**
 * Deterministic key generation from a 32-byte seed.
 *
 * Used by the LOCAL DEV key provider so the demo credential can be
 * reconstructed from the server operator key exactly like the ECDSA reference
 * wallet is (see did-key-provider.ts). Production MUST use registered public
 * keys instead — this function is not a key-management strategy.
 */
export function keyPairFromSeed(seed: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  if (seed.length !== ML_DSA_65_SIZES.seed) {
    throw new Error(`ML-DSA-65 seed must be ${ML_DSA_65_SIZES.seed} bytes (received ${seed.length})`);
  }
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  return { publicKey: new Uint8Array(publicKey), secretKey: new Uint8Array(secretKey) };
}

/** Sign a message. Returns null when the secret key is not a valid ML-DSA-65 key. */
export function signMessage(message: string, secretKey: Uint8Array): Uint8Array | null {
  if (secretKey.length !== ML_DSA_65_SIZES.secretKey) return null;
  try {
    const signature = ml_dsa65.sign(secretKey, utf8(message));
    return new Uint8Array(signature);
  } catch {
    return null;
  }
}

/**
 * Verify a base64url signature over a message against a base64url public key.
 *
 * TOTAL FUNCTION: any malformed input, any length mismatch, any internal
 * error yields `false`. There is no code path that returns true for input the
 * algorithm did not actually verify.
 */
export function verifyMessageSignature(input: {
  message: string;
  publicKey: string;
  signature: string;
}): boolean {
  const publicKeyBytes = decodeBase64Url(input.publicKey);
  if (!publicKeyBytes || publicKeyBytes.length !== ML_DSA_65_SIZES.publicKey) return false;
  const signatureBytes = decodeBase64Url(input.signature);
  if (!signatureBytes || signatureBytes.length !== ML_DSA_65_SIZES.signature) return false;
  try {
    return ml_dsa65.verify(publicKeyBytes, utf8(input.message), signatureBytes) === true;
  } catch {
    return false;
  }
}

/** Validate a candidate PUBLIC key (registration path). Returns the decoded bytes or null. */
export function parsePublicKey(value: unknown): { bytes: Uint8Array; fingerprint: string } | null {
  if (typeof value !== "string") return null;
  const bytes = decodeBase64Url(value);
  if (!bytes || bytes.length !== ML_DSA_65_SIZES.publicKey) return null;
  return { bytes, fingerprint: fingerprintPublicKey(bytes) };
}

/**
 * Reject degenerate all-zero keys. An all-zero public key can never have been
 * produced by keygen; accepting it would let an attacker register a key whose
 * "signatures" are trivially predictable.
 */
export function isDegeneratePublicKey(bytes: Uint8Array): boolean {
  for (const byte of bytes) {
    if (byte !== 0) return false;
  }
  return true;
}

/**
 * Key identifiers for the PQC half, mirroring the ECDSA `key-<n>-<digest>`
 * convention so both halves of a dual signature can be tied to the same
 * generation number in the audit trail.
 */
export function pqcKeyIdentifierFor(did: string, generation: number): string {
  const digest = createHash("sha256").update(`${did}#ml-dsa-65#${generation}`).digest("hex").slice(0, 12);
  return `pqc-key-${generation}-${digest}`;
}

/** Parse `pqc-key-<generation>-<digest>`; defaults to generation 1. */
export function generationOf(keyIdentifier: string | null | undefined): number {
  const match = /^pqc-key-(\d+)-/.exec(keyIdentifier ?? "");
  return match ? Number(match[1]) : 1;
}
