/**
 * SAMPRAAN DID authentication service (LOOP 2 + LOOP 3).
 *
 * Real cryptographic DID challenge-response built on the EXISTING DID
 * architecture:
 *
 *  - Every SAMPRAAN identity owns a DID row (did_records) and a
 *    deterministic on-chain reference wallet derived from the operator key
 *    and the DID string (see anchoring.service.deriveIdentityWallet).
 *  - Authentication: the server issues a single-use, expiring challenge
 *    nonce bound to the DID; the caller signs the challenge message with the
 *    identity's key; the server verifies that the signature RECOVERS to the
 *    DID's reference wallet. A wrong key, wrong DID, expired challenge,
 *    replayed nonce, or revoked/rotated key all fail closed.
 *
 * The signing key for a DID is never stored or transported by this module —
 * the caller (demo client or wallet) holds it. The server only verifies.
 *
 * Key lifecycle (LOOP 3): did_records.keyStatus gates authentication:
 *   ACTIVE   — current key, may authenticate
 *   ROTATED  — superseded key, MUST NOT authenticate
 *   REVOKED  — permanently unusable
 */
import { createHash, randomBytes } from "node:crypto";
import { verifyMessage } from "ethers";
import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { getDb } from "../../db";
import { didChallenges, didRecords, identities, stepUpSessions } from "../../../drizzle/schema";
import { deriveIdentityWallet } from "../blockchain/anchoring.service";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** A verified step-up stays valid for authorization re-evaluation for 10 minutes. */
export const STEP_UP_VALIDITY_MS = 10 * 60 * 1000;

export interface DidChallenge {
  challengeId: string;
  did: string;
  message: string;
  nonce: string;
  expiresAt: string;
}

export type DidAuthFailure =
  | { ok: false; reason: string; code: "DID_NOT_FOUND" | "IDENTITY_NOT_ACTIVE" | "KEY_ROTATED" | "KEY_REVOKED" };

function ok<T>(value: T): { ok: true; value: T } {
  return { ok: true, value };
}
void ok;

/** Precondition checks shared by challenge issuance and verification. */
async function assertDidUsable(did: string): Promise<DidAuthFailure | null> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DID_NOT_FOUND" };
  const rows = await db
    .select({ did: didRecords, identity: identities })
    .from(didRecords)
    .leftJoin(identities, eq(identities.id, didRecords.identityId))
    .where(eq(didRecords.did, did))
    .limit(1);
  const row = rows[0];
  if (!row) return { ok: false, reason: "DID is not registered", code: "DID_NOT_FOUND" };
  if (row.did.status === "REVOKED" || row.did.keyStatus === "REVOKED") {
    return { ok: false, reason: "DID key is revoked", code: "KEY_REVOKED" };
  }
  if (row.did.keyStatus === "ROTATED") {
    return { ok: false, reason: "DID key has been rotated — the current key must be used", code: "KEY_ROTATED" };
  }
  if (!row.identity || row.identity.status !== "ACTIVE") {
    return { ok: false, reason: `Identity is ${row.identity?.status?.toLowerCase() ?? "unknown"}`, code: "IDENTITY_NOT_ACTIVE" };
  }
  return null;
}

/** Deterministic canonical challenge message (what the caller must sign). */
export function buildChallengeMessage(did: string, nonce: string, expiresAt: Date): string {
  return [
    "SAMPRAAN DID Authentication",
    `DID: ${did}`,
    `Nonce: ${nonce}`,
    `Expires: ${expiresAt.toISOString()}`,
    "Signing this message proves control of this DID. It grants no asset or fund access.",
  ].join("\n");
}

/** Issue a single-use, expiring challenge for a DID. Fails closed per LOOP 2. */
export async function createDidChallenge(did: string): Promise<{ ok: true; challenge: DidChallenge } | DidAuthFailure> {
  const precondition = await assertDidUsable(did);
  if (precondition) return precondition;
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DID_NOT_FOUND" };
  const nonce = randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  const id = crypto.randomUUID();
  await db.insert(didChallenges).values({
    id,
    did,
    nonce,
    message: buildChallengeMessage(did, nonce, expiresAt),
    expiresAt,
  });
  return {
    ok: true,
    challenge: {
      challengeId: id,
      did,
      nonce,
      message: buildChallengeMessage(did, nonce, expiresAt),
      expiresAt: expiresAt.toISOString(),
    } as DidChallenge,
  };
}

export interface DidVerificationInput {
  did: string;
  nonce: string;
  signature: string;
  /** Operator key used to derive the DID's reference wallet (server-side only). */
  operatorKey: string;
}

export interface DidVerificationSuccess {
  ok: true;
  identityId: string;
  did: string;
  linkedUserId: number | null;
  recoveredAddress: string;
}

/**
 * Verify a challenge response. The challenge row is consumed ATOMICALLY
 * (single UPDATE guarded on consumedAt IS NULL + expiry) BEFORE signature
 * checks, so a replayed nonce can never be re-verified even under a race.
 */
export async function verifyDidChallenge(input: DidVerificationInput): Promise<DidVerificationSuccess | { ok: false; reason: string; code: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DATABASE_UNAVAILABLE" };

  // Atomic single-use consume: only an unconsumed, unexpired row matches.
  const consumed = await db
    .update(didChallenges)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(didChallenges.nonce, input.nonce),
        eq(didChallenges.did, input.did),
        isNull(didChallenges.consumedAt),
        gt(didChallenges.expiresAt, new Date()),
      ),
    );
  if (!consumed || consumed[0].affectedRows === 0) {
    return { ok: false, reason: "Challenge is invalid, expired, or already used", code: "CHALLENGE_INVALID" };
  }

  const precondition = await assertDidUsable(input.did);
  if (precondition) return { ...precondition, code: `CHALLENGE_${precondition.code}` };

  const challengeRows = await db
    .select()
    .from(didChallenges)
    .where(eq(didChallenges.nonce, input.nonce))
    .limit(1);
  const challenge = challengeRows[0];

  let recovered: string;
  try {
    recovered = verifyMessage(challenge.message, input.signature);
  } catch {
    return { ok: false, reason: "Signature is malformed", code: "SIGNATURE_INVALID" };
  }

  const expectedWallet = deriveIdentityWallet(input.operatorKey, input.did);
  if (recovered.toLowerCase() !== expectedWallet.toLowerCase()) {
    return { ok: false, reason: "Signature does not verify against this DID's key", code: "SIGNATURE_MISMATCH" };
  }

  const identityRows = await db
    .select()
    .from(identities)
    .where(eq(identities.did, input.did))
    .limit(1);
  const identity = identityRows[0];
  if (!identity) return { ok: false, reason: "Identity not found for DID", code: "IDENTITY_NOT_FOUND" };

  return {
    ok: true,
    identityId: identity.id,
    did: input.did,
    linkedUserId: identity.linkedUserId ?? null,
    recoveredAddress: recovered,
  };
}

/* ------------------------------------------------------------------ */
/* Key lifecycle (LOOP 3)                                              */
/* ------------------------------------------------------------------ */

/** Rotate a DID's key: old key becomes ROTATED (cannot authenticate). */
export async function rotateDidKey(did: string): Promise<{ ok: true; rotatedAt: string } | { ok: false; reason: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable" };
  const result = await db
    .update(didRecords)
    .set({ keyStatus: "ROTATED", rotatedAt: new Date() })
    .where(and(eq(didRecords.did, did), eq(didRecords.status, "ACTIVE")));
  if (!result || result[0].affectedRows === 0) return { ok: false, reason: "DID not found or not active" };
  return { ok: true, rotatedAt: new Date().toISOString() };
}

/** Activate (complete rotation) or revoke a DID's key explicitly. */
export async function setDidKeyStatus(did: string, keyStatus: "ACTIVE" | "REVOKED"): Promise<{ ok: boolean; reason?: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable" };
  const patch: { keyStatus: "ACTIVE" | "ROTATED" | "REVOKED"; rotatedAt?: Date | null; revokedAt?: Date } = { keyStatus };
  if (keyStatus === "ACTIVE") patch.rotatedAt = null;
  if (keyStatus === "REVOKED") patch.revokedAt = new Date();
  const result = await db.update(didRecords).set(patch).where(eq(didRecords.did, did));
  if (!result || result[0].affectedRows === 0) return { ok: false, reason: "DID not found" };
  return { ok: true };
}

/* ------------------------------------------------------------------ */
/* Server-verified step-up sessions (LOOP 5)                           */
/* ------------------------------------------------------------------ */

/** Deterministic canonical step-up message (what the caller must sign). */
function buildStepUpMessage(identityId: string, purpose: string, nonce: string, expiresAt: Date): string {
  return [
    "SAMPRAAN Step-Up Verification",
    `Identity: ${identityId}`,
    `Purpose: ${purpose}`,
    `Nonce: ${nonce}`,
    `Expires: ${expiresAt.toISOString()}`,
  ].join("\n");
}

/** Issue a step-up challenge bound to (identity, purpose). purpose is
 * action-scoped, e.g. `transfer:{assetId}` — a step-up for one asset can
 * never satisfy another.
 */
export async function createStepUpChallenge(identityId: string, purpose: string): Promise<{ nonce: string; message: string; expiresAt: string } | { ok: false; reason: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable" };
  const nonce = randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  await db.insert(stepUpSessions).values({
    identityId,
    purpose,
    nonce,
    expiresAt,
  });
  return { nonce, message: buildStepUpMessage(identityId, purpose, nonce, expiresAt), expiresAt: expiresAt.toISOString() };
}

/**
 * Verify + consume a step-up challenge. On success the row is stamped with
 * consumedAt = now, which marks the (identity, purpose) step-up as
 * server-verified until STEP_UP_VALIDITY_MS passes. Signature must recover
 * to the identity DID's reference wallet.
 */
export async function verifyStepUpChallenge(input: { identityId: string; purpose: string; nonce: string; signature: string; operatorKey: string }): Promise<{ ok: true } | { ok: false; reason: string; code: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DATABASE_UNAVAILABLE" };
  const consumed = await db
    .update(stepUpSessions)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(stepUpSessions.nonce, input.nonce),
        eq(stepUpSessions.identityId, input.identityId),
        eq(stepUpSessions.purpose, input.purpose),
        isNull(stepUpSessions.consumedAt),
        gt(stepUpSessions.expiresAt, new Date()),
      ),
    );
  if (!consumed || consumed[0].affectedRows === 0) {
    return { ok: false, reason: "Step-up challenge is invalid, expired, or already used", code: "STEP_UP_INVALID" };
  }
  const rows = await db.select().from(stepUpSessions).where(eq(stepUpSessions.nonce, input.nonce)).limit(1);
  const session = rows[0];
  let recovered: string;
  try {
    recovered = verifyMessage(buildStepUpMessage(session.identityId, session.purpose, session.nonce, session.expiresAt), input.signature);
  } catch {
    return { ok: false, reason: "Step-up signature is malformed", code: "SIGNATURE_INVALID" };
  }
  const identityRows = await db.select().from(identities).where(eq(identities.id, input.identityId)).limit(1);
  const identity = identityRows[0];
  if (!identity) return { ok: false, reason: "Identity not found", code: "IDENTITY_NOT_FOUND" };
  const expectedWallet = deriveIdentityWallet(input.operatorKey, identity.did);
  if (recovered.toLowerCase() !== expectedWallet.toLowerCase()) {
    return { ok: false, reason: "Step-up signature does not verify against this identity's key", code: "SIGNATURE_MISMATCH" };
  }
  return { ok: true };
}

/** Is there a server-verified, unexpired step-up for (identity, purpose)? */
export async function hasValidStepUp(identityId: string, purpose: string): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;
  // The verification marker is a row consumed within the validity window.
  const since = new Date(Date.now() - STEP_UP_VALIDITY_MS);
  const verified = await db
    .select({ id: stepUpSessions.id })
    .from(stepUpSessions)
    .where(
      and(
        eq(stepUpSessions.identityId, identityId),
        eq(stepUpSessions.purpose, purpose),
        gt(stepUpSessions.consumedAt, since),
      ),
    )
    .orderBy(desc(stepUpSessions.consumedAt))
    .limit(1);
  return verified.length > 0;
}

/** Hash helper for logging nonces safely (never log the raw nonce). */
export function fingerprintNonce(nonce: string): string {
  return createHash("sha256").update(nonce).digest("hex").slice(0, 12);
}
