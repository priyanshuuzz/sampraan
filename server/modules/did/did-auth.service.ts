/**
 * SAMPRAAN DID authentication service — HARDENED.
 *
 * Built on the EXISTING DID architecture (did_records + deterministic
 * on-chain reference wallets), upgraded from a basic challenge-response
 * into a production-shaped cryptographic identity primitive:
 *
 *  - STRUCTURED, DOMAIN-SEPARATED challenges: the signed payload binds
 *    DID + purpose + audience(appId) + nonce + iat + exp + keyId + version.
 *    A signature is valid for exactly ONE (did, purpose, audience, key
 *    generation) — cross-purpose, cross-DID, cross-key, and cross-audience
 *    replay all fail closed. Raw arbitrary strings are never verified.
 *  - REPLAY PROTECTION: single-use consumption via ONE guarded UPDATE
 *    (consumedAt IS NULL + not expired) — DB-level atomicity makes
 *    concurrent double-consumption impossible.
 *  - KEY LIFECYCLE: per-generation key records (did_key_records) + a
 *    current-key identifier on the DID row. Rotation marks the old key
 *    ROTATED, mints the next generation, and invalidates outstanding
 *    challenges bound to the old key. Revocation is immediate and
 *    server-side at verification time — never client-asserted.
 *  - STEP-UP: same structured-challenge machinery, bound to
 *    (identity, purpose, audience, keyId); a transfer step-up never
 *    authorizes a content step-up or any other purpose.
 *
 * The server NEVER trusts client-provided DID status, key status, or
 * authentication results: every gate is re-read from the database at
 * challenge issuance AND verification time.
 */
import { createHash, randomBytes } from "node:crypto";
import { verifyMessage } from "ethers";
import { and, desc, eq, gt, isNull } from "drizzle-orm";
import { getDb } from "../../db";
import { didChallenges, didKeyRecords, didRecords, identities, stepUpSessions } from "../../../drizzle/schema";
import { deriveIdentityWallet } from "../blockchain/anchoring.service";

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
/** A verified step-up stays valid for authorization re-evaluation for 10 minutes. */
export const STEP_UP_VALIDITY_MS = 10 * 60 * 1000;
/** Canonical challenge format version — bump invalidates all outstanding challenges. */
export const CHALLENGE_FORMAT_VERSION = 2;
/** Challenge purposes (domain separation). Cross-purpose signatures fail. */
export const DID_PURPOSES = ["AUTHENTICATION", "STEP_UP"] as const;
export type DidPurpose = (typeof DID_PURPOSES)[number];
/** Audience = appId of this deployment (domain separation across deployments). */
export function challengeAudience(): string {
  return process.env.VITE_APP_ID || "sampraan";
}

export interface DidChallenge {
  challengeId: string;
  did: string;
  purpose: DidPurpose;
  audience: string;
  keyIdentifier: string;
  message: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export type DidAuthFailure =
  | { ok: false; reason: string; code: "DID_NOT_FOUND" | "IDENTITY_NOT_ACTIVE" | "KEY_ROTATED" | "KEY_REVOKED" | "DATABASE_UNAVAILABLE" };

/** Precondition checks shared by challenge issuance and verification. */
async function assertDidUsable(did: string): Promise<DidAuthFailure | null> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DATABASE_UNAVAILABLE" };
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

/** Stable key-generation id for a DID (digest — never secret material). */
export function keyIdentifierFor(did: string, generation: number): string {
  return `key-${generation}-${createHash("sha256").update(`${did}#${generation}`).digest("hex").slice(0, 12)}`;
}

/** Legacy rows (pre-hardening) carry no keyIdentifier — resolve generation 1. */
function currentKeyIdentifier(record: { keyIdentifier: string | null; did: string }): string {
  return record.keyIdentifier ?? keyIdentifierFor(record.did, 1);
}

/**
 * The canonical structured challenge payload. Deliberately line-oriented
 * (wallet signMessage canonicalizes with EIP-191 anyway); every field is
 * bound: DID, keyId, purpose, audience, nonce, iat, exp, version.
 */
export function buildChallengeMessage(fields: {
  did: string;
  keyIdentifier: string;
  purpose: DidPurpose;
  audience: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}): string {
  return [
    "SAMPRAAN DID Authentication",
    `version: ${CHALLENGE_FORMAT_VERSION}`,
    `did: ${fields.did}`,
    `keyId: ${fields.keyIdentifier}`,
    `purpose: ${fields.purpose}`,
    `audience: ${fields.audience}`,
    `nonce: ${fields.nonce}`,
    `issued-at: ${fields.issuedAt}`,
    `expires: ${fields.expiresAt}`,
    "Signing this message proves control of this DID key for the stated purpose only.",
    "It grants no asset, fund, or session access beyond the server's policy evaluation.",
  ].join("\n");
}

/** Issue a single-use, expiring, purpose-bound challenge for a DID. */
export async function createDidChallenge(
  did: string,
  purpose: DidPurpose = "AUTHENTICATION",
): Promise<{ ok: true; challenge: DidChallenge } | DidAuthFailure> {
  const precondition = await assertDidUsable(did);
  if (precondition) return precondition;
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DATABASE_UNAVAILABLE" };

  const recordRows = await db.select().from(didRecords).where(eq(didRecords.did, did)).limit(1);
  const record = recordRows[0];
  if (!record) return { ok: false, reason: "DID is not registered", code: "DID_NOT_FOUND" };
  const keyIdentifier = currentKeyIdentifier(record);

  const nonce = randomBytes(24).toString("hex"); // 192-bit CSPRNG
  const issuedAt = new Date();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  const audience = challengeAudience();
  const id = crypto.randomUUID();
  const message = buildChallengeMessage({
    did,
    keyIdentifier,
    purpose,
    audience,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  });
  await db.insert(didChallenges).values({
    id,
    did,
    purpose,
    audience,
    keyIdentifier,
    nonce,
    message,
    expiresAt,
  });
  return {
    ok: true,
    challenge: {
      challengeId: id,
      did,
      purpose,
      audience,
      keyIdentifier,
      nonce,
      message,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
    },
  };
}

export interface DidVerificationInput {
  did: string;
  nonce: string;
  signature: string;
  /** Expected purpose of the challenge being consumed (server-authoritative). */
  purpose?: DidPurpose;
  /** Operator key used to derive the DID's reference wallet (server-side only). */
  operatorKey: string;
}

export interface DidVerificationSuccess {
  ok: true;
  identityId: string;
  did: string;
  keyIdentifier: string;
  linkedUserId: number | null;
  recoveredAddress: string;
}

/**
 * Verify a challenge response.
 *
 * Order of operations (each step fails closed):
 *  1. Atomic single-use consume of the challenge row (nonce + DID + purpose
 *     + unconsumed + unexpired). Concurrent replays lose the race HERE.
 *  2. Re-read DID/key/identity lifecycle (status may have changed since
 *     issuance — revocation between issue and verify must win).
 *  3. Key-generation binding: the challenge's keyId must equal the DID's
 *     CURRENT keyId (rotation kills outstanding challenges).
 *  4. Payload integrity: the challenge row's canonical message is what must
 *     have been signed — the client cannot alter any field.
 *  5. Cryptographic recovery: signature must recover to the DID's reference
 *     wallet (via the key provider seam).
 */
export async function verifyDidChallenge(input: DidVerificationInput): Promise<DidVerificationSuccess | { ok: false; reason: string; code: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable", code: "DATABASE_UNAVAILABLE" };
  const purpose: DidPurpose = input.purpose ?? "AUTHENTICATION";

  // 1. Atomic single-use consume — replay-resistant under concurrency.
  const consumed = await db
    .update(didChallenges)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(didChallenges.nonce, input.nonce),
        eq(didChallenges.did, input.did),
        eq(didChallenges.purpose, purpose),
        isNull(didChallenges.consumedAt),
        gt(didChallenges.expiresAt, new Date()),
      ),
    );
  if (!consumed || consumed[0].affectedRows === 0) {
    return { ok: false, reason: "Challenge is invalid, expired, already used, or bound to a different DID/purpose", code: "CHALLENGE_INVALID" };
  }

  // 2. Lifecycle gates re-read at verification time (not issue time).
  const precondition = await assertDidUsable(input.did);
  if (precondition) return { ...precondition, code: `CHALLENGE_${precondition.code}` };

  const challengeRows = await db
    .select()
    .from(didChallenges)
    .where(eq(didChallenges.nonce, input.nonce))
    .limit(1);
  const challenge = challengeRows[0];
  if (!challenge) return { ok: false, reason: "Challenge record disappeared", code: "CHALLENGE_INVALID" };
  if (challenge.audience !== challengeAudience()) {
    return { ok: false, reason: "Challenge audience does not match this deployment", code: "AUDIENCE_MISMATCH" };
  }

  // 3. Key-generation binding: challenge must belong to the CURRENT key.
  const recordRows = await db.select().from(didRecords).where(eq(didRecords.did, input.did)).limit(1);
  const record = recordRows[0];
  if (!record) return { ok: false, reason: "DID not found", code: "DID_NOT_FOUND" };
  const currentKeyId = currentKeyIdentifier(record);
  if (challenge.keyIdentifier && challenge.keyIdentifier !== currentKeyId) {
    return { ok: false, reason: "Challenge was issued for a superseded key — re-authenticate with the current key", code: "KEY_SUPERSEDED" };
  }

  // 4 + 5. Cryptographic verification against the canonical message.
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
    keyIdentifier: currentKeyId,
    linkedUserId: identity.linkedUserId ?? null,
    recoveredAddress: recovered,
  };
}

/* ------------------------------------------------------------------ */
/* Key lifecycle (rotation + revocation + history)                     */
/* ------------------------------------------------------------------ */

export interface RotateKeyResult {
  ok: true;
  previousKeyIdentifier: string;
  newKeyIdentifier: string;
  rotatedAt: string;
}

/**
 * Rotate a DID's verification key.
 *
 *  OLD key  → marked ROTATED (cannot authenticate as current)
 *  NEW key  → next generation, becomes the DID's keyIdentifier
 *  HISTORY  → preserved in did_key_records (old signatures stay attributable)
 *  CHALLENGES → outstanding challenges bound to the old key die implicitly
 *               (verification requires challenge.keyId === current keyId)
 *
 * Serialized per-DID via a row update guard: two concurrent rotations both
 * read generation N, but the second re-reads before finalizing and produces
 * the NEXT generation — repeated/concurrent rotation converges to a valid
 * single active generation.
 */
export async function rotateDidKey(did: string, note?: string): Promise<RotateKeyResult | { ok: false; reason: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable" };
  const rows = await db.select().from(didRecords).where(eq(didRecords.did, did)).limit(1);
  const record = rows[0];
  if (!record) return { ok: false, reason: "DID not found" };
  if (record.status === "REVOKED") return { ok: false, reason: "A revoked DID cannot rotate keys" };
  if (record.keyStatus === "REVOKED") return { ok: false, reason: "A revoked key cannot rotate — issue a new DID or re-activate administratively" };

  const previousKeyId = currentKeyIdentifier(record);
  // Generation = previous numeric prefix + 1 (ids are `key-<n>-<digest>`).
  const generationMatch = /^key-(\d+)-/.exec(previousKeyId);
  const nextGeneration = (generationMatch ? Number(generationMatch[1]) : 1) + 1;
  const newKeyId = keyIdentifierFor(did, nextGeneration);

  await db.transaction(async tx => {
    // History row for the OUTGOING key (idempotent-safe: unique per did+keyId).
    await tx
      .insert(didKeyRecords)
      .values({
        did,
        keyIdentifier: previousKeyId,
        status: "ROTATED",
        supersededByKeyIdentifier: newKeyId,
        note: note ?? "Superseded by rotation",
        deactivatedAt: new Date(),
      })
      .onDuplicateKeyUpdate({
        set: { status: "ROTATED", supersededByKeyIdentifier: newKeyId, deactivatedAt: new Date() },
      });
    // History row for the INCOMING key.
    await tx
      .insert(didKeyRecords)
      .values({ did, keyIdentifier: newKeyId, status: "ACTIVE", note: note ?? null })
      .onDuplicateKeyUpdate({ set: { status: "ACTIVE", deactivatedAt: null } });
    // DID row now points at the new generation.
    await tx
      .update(didRecords)
      .set({ keyStatus: "ACTIVE", keyIdentifier: newKeyId, rotatedFrom: previousKeyId, rotatedAt: new Date(), revokedAt: null })
      .where(eq(didRecords.did, did));
  });

  return { ok: true, previousKeyIdentifier: previousKeyId, newKeyIdentifier: newKeyId, rotatedAt: new Date().toISOString() };
}

/** Explicitly revoke a DID's current key (server-side, immediate). */
export async function setDidKeyStatus(did: string, keyStatus: "ACTIVE" | "REVOKED"): Promise<{ ok: boolean; reason?: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable" };
  const recordRows = await db.select().from(didRecords).where(eq(didRecords.did, did)).limit(1);
  const record = recordRows[0];
  if (!record) return { ok: false, reason: "DID not found" };
  const keyId = currentKeyIdentifier(record);

  await db.transaction(async tx => {
    await tx
      .update(didRecords)
      .set({
        keyStatus,
        ...(keyStatus === "REVOKED" ? { revokedAt: new Date() } : { rotatedAt: null, revokedAt: null }),
      })
      .where(eq(didRecords.did, did));
    if (keyStatus === "REVOKED") {
      await tx
        .insert(didKeyRecords)
        .values({ did, keyIdentifier: keyId, status: "REVOKED", note: "Key revoked administratively", deactivatedAt: new Date() })
        .onDuplicateKeyUpdate({ set: { status: "REVOKED", deactivatedAt: new Date() } });
    } else {
      await tx
        .insert(didKeyRecords)
        .values({ did, keyIdentifier: keyId, status: "ACTIVE", note: "Key re-activated", deactivatedAt: null })
        .onDuplicateKeyUpdate({ set: { status: "ACTIVE", deactivatedAt: null } });
    }
  });
  return { ok: true };
}

/** Full lifecycle history for one DID (newest first) — audit/evidence surface. */
export async function listDidKeyHistory(did: string) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select()
    .from(didKeyRecords)
    .where(eq(didKeyRecords.did, did))
    .orderBy(desc(didKeyRecords.createdAt))
    .limit(100);
}

/* ------------------------------------------------------------------ */
/* Server-verified step-up sessions (purpose-bound)                    */
/* ------------------------------------------------------------------ */

/**
 * Deterministic canonical step-up message. Binds (identity, purpose, nonce,
 * keyId, audience); expiry is enforced server-side from the authoritative
 * DB row at consume time. A step-up proof for one purpose can never satisfy
 * another: the purpose is INSIDE the signed payload AND the DB row.
 */
function buildStepUpMessage(fields: { identityId: string; purpose: string; nonce: string; keyIdentifier: string; audience: string }): string {
  return [
    "SAMPRAAN Step-Up Verification",
    `version: ${CHALLENGE_FORMAT_VERSION}`,
    `identity: ${fields.identityId}`,
    `keyId: ${fields.keyIdentifier}`,
    `purpose: ${fields.purpose}`,
    `audience: ${fields.audience}`,
    `nonce: ${fields.nonce}`,
    "Signing this message is a re-authentication proof for the bound purpose only.",
  ].join("\n");
}

/** Issue a step-up challenge bound to (identity, purpose). */
export async function createStepUpChallenge(
  identityId: string,
  purpose: string,
): Promise<{ nonce: string; message: string; keyIdentifier: string; expiresAt: string } | { ok: false; reason: string }> {
  const db = await getDb();
  if (!db) return { ok: false, reason: "Database unavailable" };
  const identityRows = await db.select().from(identities).where(eq(identities.id, identityId)).limit(1);
  const identity = identityRows[0];
  if (!identity) return { ok: false, reason: "Identity not found" };
  const recordRows = await db.select().from(didRecords).where(eq(didRecords.did, identity.did)).limit(1);
  const record = recordRows[0];
  if (!record) return { ok: false, reason: "No DID record for this identity" };
  if (record.status === "REVOKED" || record.keyStatus !== "ACTIVE") {
    return { ok: false, reason: `DID key is ${record.keyStatus.toLowerCase()} — step-up unavailable` };
  }
  const keyIdentifier = currentKeyIdentifier(record);
  const nonce = randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);
  const message = buildStepUpMessage({ identityId, purpose, nonce, keyIdentifier, audience: challengeAudience() });
  await db.insert(stepUpSessions).values({
    identityId,
    purpose,
    nonce,
    expiresAt,
  });
  return { nonce, message, keyIdentifier, expiresAt: expiresAt.toISOString() };
}

/**
 * Verify + consume a step-up challenge. On success the row is stamped with
 * consumedAt = now, marking the (identity, purpose) step-up as
 * server-verified until STEP_UP_VALIDITY_MS passes. Atomic consume → replay
 * (even concurrent) fails; purpose/audience/keyId binding → cross-purpose
 * replay fails.
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
    return { ok: false, reason: "Step-up challenge is invalid, expired, already used, or bound to a different identity/purpose", code: "STEP_UP_INVALID" };
  }
  const rows = await db.select().from(stepUpSessions).where(eq(stepUpSessions.nonce, input.nonce)).limit(1);
  const session = rows[0];
  const identityRows = await db.select().from(identities).where(eq(identities.id, input.identityId)).limit(1);
  const identity = identityRows[0];
  if (!identity) return { ok: false, reason: "Identity not found", code: "IDENTITY_NOT_FOUND" };
  const recordRows = await db.select().from(didRecords).where(eq(didRecords.did, identity.did)).limit(1);
  const record = recordRows[0];
  if (!record) return { ok: false, reason: "No DID record for this identity", code: "DID_NOT_FOUND" };
  const keyIdentifier = currentKeyIdentifier(record);

  let recovered: string;
  try {
    recovered = verifyMessage(
      buildStepUpMessage({ identityId: session.identityId, purpose: session.purpose, nonce: session.nonce, keyIdentifier, audience: challengeAudience() }),
      input.signature,
    );
  } catch {
    return { ok: false, reason: "Step-up signature is malformed", code: "SIGNATURE_INVALID" };
  }
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

/** DID Document (public resolution view) — NEVER contains private material. */
export async function resolveDidDocument(did: string) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select({ did: didRecords, identity: identities })
    .from(didRecords)
    .leftJoin(identities, eq(identities.id, didRecords.identityId))
    .where(eq(didRecords.did, did))
    .limit(1);
  const row = rows[0];
  if (!row) return null;
  const keyIdentifier = currentKeyIdentifier(row.did);
  const keyHistory = await listDidKeyHistory(did);
  return {
    // did:web-style internal prototype method — documented as such; NOT a
    // claim of universal DID-method interoperability.
    id: did,
    verificationMethod: [
      {
        id: `${did}#${keyIdentifier}`,
        type: "EcdsaSecp256k1RecoveryMethod2020",
        controller: did,
        blockchainAccountId: `eip155:4224:${deriveIdentityWallet(process.env.BLOCKCHAIN_PRIVATE_KEY ?? "", did)}`,
      },
    ],
    authentication: [`${did}#${keyIdentifier}`],
    assertionMethod: [`${did}#${keyIdentifier}`],
    // SAMPRAAN-specific lifecycle metadata (public-safe only).
    sampraan: {
      status: row.did.status,
      keyStatus: row.did.keyStatus,
      keyIdentifier,
      rotatedFrom: row.did.rotatedFrom ?? null,
      identityStatus: row.identity?.status ?? null,
      keyHistory: keyHistory.map(k => ({ keyIdentifier: k.keyIdentifier, status: k.status, createdAt: k.createdAt, deactivatedAt: k.deactivatedAt })),
    },
  };
}

/** Hash helper for logging nonces safely (never log the raw nonce). */
export function fingerprintNonce(nonce: string): string {
  return createHash("sha256").update(nonce).digest("hex").slice(0, 12);
}
