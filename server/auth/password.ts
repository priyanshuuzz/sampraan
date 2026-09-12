/**
 * SAMPRAAN local password hashing (development / team demonstration auth).
 *
 * Uses Node's built-in scrypt (memory-hard, no native deps) with a per-user
 * random salt. Hash format: scrypt$N$r$p$saltB64$hashB64 — self-describing so
 * parameters can be raised later without invalidating existing hashes.
 *
 * The production auth path remains OAuth (see _core/sdk.ts); this module backs
 * the local login flow used when no external IdP is configured. Passwords are
 * never logged, never returned by any API, and comparisons run in constant
 * time.
 */
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

// promisify loses the options overload; declare the exact shape we need.
const scryptAsync = promisify(scrypt) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options?: { N?: number; r?: number; p?: number; maxmem?: number },
) => Promise<Buffer>;

// OWASP-aligned interactive-login parameters (scrypt N=2^15, r=8, p=1).
const N = 32_768;
const R = 8;
const P = 1;
const KEYLEN = 64;
// Node's default maxmem (32 MB) is just below what N=2^15, r=8 needs; raise it explicitly.
const MAXMEM = 128 * N * R * 2;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = (await scryptAsync(password.normalize("NFKC"), salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM })) as Buffer;
  return ["scrypt", N, R, P, salt.toString("base64url"), derived.toString("base64url")].join("$");
}

export async function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean> {
  if (typeof stored !== "string" || !stored.startsWith("scrypt$")) return false;
  const parts = stored.split("$");
  if (parts.length !== 6) return false;
  const [, nStr, rStr, pStr, saltB64, hashB64] = parts;
  const n = Number(nStr);
  const r = Number(rStr);
  const p = Number(pStr);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (n < 1024 || n > 1_048_576 || r < 1 || r > 64 || p < 1 || p > 8) return false;
  try {
    const salt = Buffer.from(saltB64, "base64url");
    const expected = Buffer.from(hashB64, "base64url");
    const derived = (await scryptAsync(password.normalize("NFKC"), salt, expected.length, { N: n, r, p, maxmem: 128 * n * r * 2 })) as Buffer;
    return derived.length === expected.length && timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

/** Cheap dummy verification to equalize timing when the user does not exist. */
const DUMMY_HASH = ["scrypt", N, R, P, Buffer.alloc(16).toString("base64url"), Buffer.alloc(64).toString("base64url")].join("$");
export async function burnPasswordTiming(): Promise<void> {
  await verifyPassword("timing-equalizer", DUMMY_HASH).catch(() => undefined);
}
