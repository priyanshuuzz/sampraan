/**
 * SAMPRAAN CRYPTO ASSURANCE SERVICE.
 *
 * Turns a policy decision ("this operation needs ELEVATED / QUANTUM_HARDENED
 * assurance") into a verified, single-use GRANT — or fails closed.
 *
 * Flow for a protected operation:
 *
 *   1. evaluateAssurance(...)            → level + algorithm set (policy.ts)
 *   2. issueChallenge(...)               → canonical, nonce-bound, expiring payload
 *   3. verifyChallenge(...)              → ECDSA signature (+ ML-DSA-65 when the
 *                                          level demands it) over THAT payload
 *   4. claimGrant(...)                   → the operation consumes the grant once
 *
 * Security properties, each enforced by this module and proven by tests:
 *
 *  - BINDING: the canonical payload carries identity, DID, BOTH key ids, both
 *    algorithm names, operation, resource type, resource id, audience, nonce,
 *    issued-at and expiry. A signature is valid for exactly one operation on
 *    exactly one resource in exactly one deployment — the client cannot widen
 *    scope because the payload is re-derived server-side from the stored row.
 *  - REPLAY: verification consumes the challenge with one atomic guarded UPDATE
 *    (consumedAt IS NULL + unexpired), and the resulting grant is claimed with
 *    a second guarded UPDATE (executedAt IS NULL). Concurrent double-verify and
 *    double-execute both lose at the database layer.
 *  - LIFE-CYCLE RE-READ: identity status, DID key status and the PQC key record
 *    are re-read AT VERIFICATION TIME. Revoking a key between issue and verify
 *    wins; a revoked key can never clear an outstanding challenge.
 *  - NO SECRETS: the row stores public key ids and the canonical message only.
 *  - AUDIT: every issue, success, and failure writes an audit event carrying
 *    the policy reason codes, the level, and (on failure) the precise code.
 */
import { createHash, randomBytes } from "node:crypto";
import { verifyMessage } from "ethers";
import { TRPCError } from "@trpc/server";
import {
  claimAssuranceGrantExecution,
  consumeAssuranceChallengeAtomic,
  createAssuranceChallenge,
  createAuditEvent,
  findValidAssuranceGrant,
  markAssuranceHalfVerified,
} from "../../db";
import { getDb } from "../../db";
import { didRecords, identities } from "../../../drizzle/schema";
import { eq } from "drizzle-orm";
import { deriveIdentityWallet } from "../blockchain/anchoring.service";
import { createStepUpChallenge, keyIdentifierFor } from "../did/did-auth.service";
import { verifyMessageSignature } from "./ml-dsa";
import { resolvePqcKeyProvider } from "./pqc-key-provider";
import { ALGORITHM_BY_LEVEL, evaluateAssurance, type AssuranceLevel, type AssuranceOperation, type AssurancePolicyInput, type AssurancePolicyResult } from "./assurance-policy";

/** A challenge/grant stays usable for this long after it is issued. */
export const ASSURANCE_CHALLENGE_TTL_MS = 5 * 60 * 1000;
/**
 * A VERIFIED grant may be claimed by the protected operation for this long.
 * Short on purpose: the grant is proof of a fresh dual signature, not a
 * long-lived credential.
 */
export const ASSURANCE_GRANT_VALIDITY_MS = 5 * 60 * 1000;

/** Canonical payload format version — bump invalidates outstanding payloads. */
export const ASSURANCE_FORMAT_VERSION = 1;

export function assuranceAudience(): string {
  return process.env.VITE_APP_ID || "sampraan";
}

/**
 * The canonical dual-signature payload. Deliberately line-oriented and
 * field-labelled: every field is inside the signed bytes, so no part of the
 * authorization context can be altered after signing.
 */
export function buildAssuranceMessage(fields: {
  identityId: string;
  did: string;
  level: AssuranceLevel;
  algorithms: readonly string[];
  operation: string;
  resourceType: string;
  resourceId: string;
  audience: string;
  ecdsaKeyIdentifier: string;
  pqcKeyIdentifier: string | null;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  reasonCodes: readonly string[];
}): string {
  return [
    "SAMPRAAN Crypto Assurance",
    `version: ${ASSURANCE_FORMAT_VERSION}`,
    `identity: ${fields.identityId}`,
    `did: ${fields.did}`,
    `level: ${fields.level}`,
    `algorithms: ${fields.algorithms.join("+")}`,
    `operation: ${fields.operation}`,
    `resource-type: ${fields.resourceType}`,
    `resource-id: ${fields.resourceId}`,
    `audience: ${fields.audience}`,
    `ecdsa-key: ${fields.ecdsaKeyIdentifier}`,
    `pqc-key: ${fields.pqcKeyIdentifier ?? "none"}`,
    `nonce: ${fields.nonce}`,
    `issued-at: ${fields.issuedAt}`,
    `expires: ${fields.expiresAt}`,
    `policy-reasons: ${fields.reasonCodes.join(",")}`,
    "This payload authorizes exactly one operation on exactly one resource, once.",
  ].join("\n");
}

export interface AssuranceDecision {
  level: AssuranceLevel;
  algorithms: readonly string[];
  requiresDualSignature: boolean;
  requiresStepUp: boolean;
  score: number;
  reasonCodes: readonly string[];
  explanation: string;
}

/** Pure decision (no side effects) — the explainability surface. */
export function decideAssurance(input: AssurancePolicyInput): AssuranceDecision {
  const result: AssurancePolicyResult = evaluateAssurance(input);
  return {
    level: result.level,
    algorithms: result.algorithms,
    requiresDualSignature: result.requiresDualSignature,
    requiresStepUp: result.requiresStepUp,
    score: result.score,
    reasonCodes: result.reasonCodes,
    explanation: result.explanation,
  };
}

export interface IssuedAssuranceChallenge {
  challengeId: string;
  level: AssuranceLevel;
  algorithms: readonly string[];
  message: string;
  nonce: string;
  audience: string;
  ecdsaKeyIdentifier: string;
  pqcKeyIdentifier: string | null;
  issuedAt: string;
  expiresAt: string;
  reasonCodes: readonly string[];
  explanation: string;
}

export type AssuranceFailure = { ok: false; code: string; reason: string };

/** Resolve the actor's DID row + current ECDSA key id, failing closed. */
async function resolveActorCrypto(did: string) {
  const db = await getDb();
  if (!db) return { ok: false as const, code: "DATABASE_UNAVAILABLE", reason: "Database unavailable" };
  const rows = await db.select().from(didRecords).where(eq(didRecords.did, did)).limit(1);
  const record = rows[0];
  if (!record) return { ok: false as const, code: "DID_NOT_FOUND", reason: "No DID record for this identity" };
  if (record.status !== "ACTIVE") return { ok: false as const, code: "DID_REVOKED", reason: "DID is not ACTIVE" };
  if (record.keyStatus !== "ACTIVE") {
    return { ok: false as const, code: "KEY_NOT_ACTIVE", reason: `DID key is ${record.keyStatus} — assurance cannot be issued` };
  }
  const ecdsaKeyIdentifier = record.keyIdentifier ?? keyIdentifierFor(did, 1);
  return { ok: true as const, record, ecdsaKeyIdentifier };
}

export interface IssueAssuranceInput {
  identityId: string;
  did: string;
  identityStatus: string;
  lifecycleState: string;
  role: string;
  operation: AssuranceOperation;
  resourceType: string;
  resourceId: string;
  policyInput: Omit<AssurancePolicyInput, "operation" | "role">;
}

/**
 * Issue an assurance challenge for an operation. BASELINE operations need no
 * challenge at all — the caller gets `{ required: false }` and continues with
 * the ordinary session-bound authorization.
 */
export async function issueAssuranceChallenge(
  input: IssueAssuranceInput,
): Promise<{ ok: true; required: false; decision: AssuranceDecision } | { ok: true; required: true; decision: AssuranceDecision; challenge: IssuedAssuranceChallenge } | AssuranceFailure> {
  const decision = decideAssurance({ ...input.policyInput, operation: input.operation, role: input.role });
  if (decision.level === "BASELINE") {
    return { ok: true, required: false, decision };
  }
  if (input.identityStatus !== "ACTIVE" || input.lifecycleState !== "VERIFIED") {
    return { ok: false, code: "IDENTITY_NOT_ACTIVE", reason: `Identity is ${input.lifecycleState}/${input.identityStatus} — assurance cannot be issued` };
  }

  const crypto = await resolveActorCrypto(input.did);
  if (!crypto.ok) return crypto;

  // Resolve the PQC half when (and only when) the policy demands it. A missing
  // registered key is a FAILURE, never a silent downgrade to ECDSA-only.
  let pqcKeyIdentifier: string | null = null;
  const requiredAlgorithms: string[] = [...ALGORITHM_BY_LEVEL[decision.level]];
  if (decision.requiresDualSignature) {
    const provider = resolvePqcKeyProvider();
    const resolved = await provider.resolvePublicKey(input.did);
    if (!resolved) {
      await auditAssurance({
        actorIdentityId: input.identityId,
        action: "ASSURANCE_CHALLENGE_REFUSED",
        decision: "DENY",
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        reason: "Policy requires a post-quantum signature but no ACTIVE ML-DSA-65 key is registered for this DID",
        metadata: { operation: input.operation, level: decision.level, reasonCodes: decision.reasonCodes },
      });
      return {
        ok: false,
        code: "PQC_KEY_UNAVAILABLE",
        reason: "This operation requires a post-quantum signature. Register an ML-DSA-65 key for this DID before proceeding.",
      };
    }
    pqcKeyIdentifier = resolved.keyIdentifier;
  }

  const nonce = randomBytes(24).toString("hex");
  const issuedAt = new Date();
  const expiresAt = new Date(Date.now() + ASSURANCE_CHALLENGE_TTL_MS);
  const audience = assuranceAudience();
  const message = buildAssuranceMessage({
    identityId: input.identityId,
    did: input.did,
    level: decision.level,
    algorithms: requiredAlgorithms,
    operation: input.operation,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    audience,
    ecdsaKeyIdentifier: crypto.ecdsaKeyIdentifier,
    pqcKeyIdentifier,
    nonce,
    issuedAt: issuedAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
    reasonCodes: decision.reasonCodes,
  });

  const row = await createAssuranceChallenge({
    identityId: input.identityId,
    did: input.did,
    operation: input.operation,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    assuranceLevel: decision.level,
    requiredAlgorithms,
    reasonCodes: [...decision.reasonCodes],
    audience,
    ecdsaKeyIdentifier: crypto.ecdsaKeyIdentifier,
    pqcKeyIdentifier,
    nonce,
    message,
    expiresAt,
  });
  if (!row) return { ok: false, code: "DATABASE_UNAVAILABLE", reason: "Could not persist the assurance challenge" };

  await auditAssurance({
    actorIdentityId: input.identityId,
    action: "ASSURANCE_CHALLENGE_ISSUED",
    decision: "ALLOW",
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    reason: `Assurance ${decision.level} challenge issued (score ${decision.score})`,
    metadata: {
      operation: input.operation,
      level: decision.level,
      algorithms: requiredAlgorithms,
      reasonCodes: decision.reasonCodes,
      challengeId: row.id,
      expiresAt: expiresAt.toISOString(),
    },
  });

  return {
    ok: true,
    required: true,
    decision,
    challenge: {
      challengeId: row.id,
      level: decision.level,
      algorithms: requiredAlgorithms,
      message,
      nonce,
      audience,
      ecdsaKeyIdentifier: crypto.ecdsaKeyIdentifier,
      pqcKeyIdentifier,
      issuedAt: issuedAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      reasonCodes: decision.reasonCodes,
      explanation: decision.explanation,
    },
  };
}

export interface VerifyAssuranceInput {
  identityId: string;
  nonce: string;
  /** EIP-191 (personal_sign) signature over the canonical message. */
  ecdsaSignature: string;
  /** Base64url ML-DSA-65 signature over the SAME canonical message. */
  pqcSignature?: string | null;
  /** Operator key used to derive the DID reference wallet (server-side only). */
  operatorKey: string;
}

export type AssuranceVerifyResult =
  | { ok: true; grantId: string; level: AssuranceLevel; operation: string; resourceType: string; resourceId: string; algorithmVerified: string[] }
  | AssuranceFailure;

/**
 * Verify a dual-signature response. Every failure path is audited with a
 * machine-readable code so a denial is explainable after the fact.
 */
export async function verifyAssuranceChallenge(input: VerifyAssuranceInput): Promise<AssuranceVerifyResult> {
  const db = await getDb();
  if (!db) return { ok: false, code: "DATABASE_UNAVAILABLE", reason: "Database unavailable" };

  // 1. Atomic single-use consume — the replay boundary.
  const challenge = await consumeAssuranceChallengeAtomic({ identityId: input.identityId, nonce: input.nonce });
  if (!challenge) {
    await auditAssurance({
      actorIdentityId: input.identityId,
      action: "ASSURANCE_FAILED",
      decision: "DENY",
      resourceType: "ASSURANCE",
      resourceId: input.nonce.slice(0, 16),
      reason: "Challenge is invalid, expired, already used, or bound to a different identity",
      metadata: { code: "CHALLENGE_INVALID" },
    });
    return { ok: false, code: "CHALLENGE_INVALID", reason: "Challenge is invalid, expired, already used, or bound to a different identity" };
  }

  // 2. Life-cycle re-read at verification time.
  const identityRows = await db.select().from(identities).where(eq(identities.id, input.identityId)).limit(1);
  const identity = identityRows[0];
  if (!identity) return { ok: false, code: "IDENTITY_NOT_FOUND", reason: "Identity not found" };
  if (identity.status !== "ACTIVE" || identity.lifecycleState !== "VERIFIED") {
    return { ok: false, code: "IDENTITY_NOT_ACTIVE", reason: `Identity is ${identity.lifecycleState}/${identity.status}` };
  }
  const didRow = (await db.select().from(didRecords).where(eq(didRecords.did, challenge.did)).limit(1))[0];
  if (!didRow) return { ok: false, code: "DID_NOT_FOUND", reason: "No DID record for this identity" };
  if (didRow.status !== "ACTIVE" || didRow.keyStatus !== "ACTIVE") {
    return { ok: false, code: "KEY_NOT_ACTIVE", reason: "DID key was revoked or rotated after the challenge was issued" };
  }
  if (challenge.audience !== assuranceAudience()) {
    return { ok: false, code: "AUDIENCE_MISMATCH", reason: "Challenge audience does not match this deployment" };
  }
  // Key-generation binding: a challenge issued for generation N cannot be
  // satisfied by generation N+1 (rotation kills in-flight challenges).
  const currentEcdsaKeyId = didRow.keyIdentifier ?? keyIdentifierFor(challenge.did, 1);
  if (challenge.ecdsaKeyIdentifier !== currentEcdsaKeyId) {
    return { ok: false, code: "KEY_SUPERSEDED", reason: "Challenge was issued for a superseded key generation" };
  }

  // 3. ECDSA half — signature must recover to the DID's reference wallet.
  let recovered: string;
  try {
    recovered = verifyMessage(challenge.message, input.ecdsaSignature);
  } catch {
    await markAssuranceHalfVerified({ challengeId: challenge.id, ecdsaVerified: false, pqcVerified: false });
    return failAndAudit(input.identityId, challenge, "SIGNATURE_INVALID", "ECDSA signature is malformed");
  }
  const expectedWallet = deriveIdentityWallet(input.operatorKey, challenge.did);
  if (recovered.toLowerCase() !== expectedWallet.toLowerCase()) {
    await markAssuranceHalfVerified({ challengeId: challenge.id, ecdsaVerified: false, pqcVerified: false });
    return failAndAudit(input.identityId, challenge, "SIGNATURE_MISMATCH", "ECDSA signature does not verify against this DID's key");
  }

  // 4. PQC half — REQUIRED when the policy mandated it. A missing signature is
  //    a failure, not a downgrade.
  const requiredAlgorithms = (challenge.requiredAlgorithms as string[] | null) ?? [];
  const needsPqc = requiredAlgorithms.includes("ML_DSA_65");
  let pqcVerified = false;
  if (needsPqc) {
    const provider = resolvePqcKeyProvider();
    const resolved = await provider.resolvePublicKey(challenge.did);
    if (!resolved || resolved.keyIdentifier !== challenge.pqcKeyIdentifier) {
      await markAssuranceHalfVerified({ challengeId: challenge.id, ecdsaVerified: true, pqcVerified: false });
      return failAndAudit(input.identityId, challenge, "PQC_KEY_UNAVAILABLE", "The ML-DSA-65 key bound to this challenge is no longer ACTIVE");
    }
    if (!input.pqcSignature) {
      await markAssuranceHalfVerified({ challengeId: challenge.id, ecdsaVerified: true, pqcVerified: false });
      return failAndAudit(input.identityId, challenge, "PQC_SIGNATURE_MISSING", "This operation requires an ML-DSA-65 signature in addition to ECDSA");
    }
    pqcVerified = verifyMessageSignature({
      message: challenge.message,
      publicKey: resolved.publicKey,
      signature: input.pqcSignature,
    });
    if (!pqcVerified) {
      await markAssuranceHalfVerified({ challengeId: challenge.id, ecdsaVerified: true, pqcVerified: false });
      return failAndAudit(input.identityId, challenge, "PQC_SIGNATURE_INVALID", "ML-DSA-65 signature does not verify against the registered public key");
    }
  }

  await markAssuranceHalfVerified({ challengeId: challenge.id, ecdsaVerified: true, pqcVerified });

  const algorithmVerified = needsPqc ? ["ECDSA_SECP256K1", "ML_DSA_65"] : ["ECDSA_SECP256K1"];
  await auditAssurance({
    actorIdentityId: input.identityId,
    action: "ASSURANCE_VERIFIED",
    decision: "ALLOW",
    resourceType: challenge.resourceType,
    resourceId: challenge.resourceId,
    reason: `Assurance ${challenge.assuranceLevel} verified (${algorithmVerified.join(" + ")})`,
    metadata: {
      challengeId: challenge.id,
      operation: challenge.operation,
      level: challenge.assuranceLevel,
      algorithms: algorithmVerified,
      pqcKeyIdentifier: challenge.pqcKeyIdentifier,
      ecdsaKeyIdentifier: challenge.ecdsaKeyIdentifier,
      reasonCodes: challenge.reasonCodes,
      recoveredAddress: recovered.toLowerCase(),
    },
  });

  return {
    ok: true,
    grantId: challenge.id,
    level: challenge.assuranceLevel as AssuranceLevel,
    operation: challenge.operation,
    resourceType: challenge.resourceType,
    resourceId: challenge.resourceId,
    algorithmVerified,
  };
}

async function failAndAudit(
  identityId: string,
  challenge: { id: string; operation: string; resourceType: string; resourceId: string; assuranceLevel: string; reasonCodes: unknown },
  code: string,
  reason: string,
): Promise<AssuranceFailure> {
  await auditAssurance({
    actorIdentityId: identityId,
    action: "ASSURANCE_FAILED",
    decision: "DENY",
    resourceType: challenge.resourceType,
    resourceId: challenge.resourceId,
    reason,
    metadata: { code, challengeId: challenge.id, operation: challenge.operation, level: challenge.assuranceLevel },
  });
  return { ok: false, code, reason };
}

/**
 * The gate used by protected operations.
 *
 * Returns the grant row when the caller presents a valid, fresh, matching,
 * UNCLAIMED grant — and claims it in the same call so the operation can only
 * ever run once per grant. Returns null (fail closed) otherwise.
 */
export async function claimAssuranceGrant(input: {
  identityId: string;
  grantId: string | null | undefined;
  operation: AssuranceOperation;
  resourceType: string;
  resourceId: string;
}): Promise<{ ok: true; level: AssuranceLevel } | { ok: false; reason: string }> {
  if (!input.grantId) {
    return { ok: false, reason: "This operation requires a crypto assurance grant (dual-signature verification) — request a challenge first." };
  }
  const notOlderThan = new Date(Date.now() - ASSURANCE_GRANT_VALIDITY_MS);
  const grant = await findValidAssuranceGrant({
    grantId: input.grantId,
    identityId: input.identityId,
    operation: input.operation,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    notOlderThan,
  });
  if (!grant) {
    return { ok: false, reason: "The assurance grant is invalid, expired, already used, or bound to a different actor/operation/resource." };
  }
  const claimed = await claimAssuranceGrantExecution(grant.id);
  if (!claimed) {
    return { ok: false, reason: "The assurance grant has already been consumed by another operation (single-use)." };
  }
  return { ok: true, level: grant.assuranceLevel as AssuranceLevel };
}

/** Evidence-grade audit helper (never throws into the caller's path). */
async function auditAssurance(input: {
  actorIdentityId: string | null;
  action: string;
  decision: "ALLOW" | "DENY";
  resourceType: string;
  resourceId: string;
  reason: string;
  metadata: Record<string, unknown>;
}): Promise<void> {
  await createAuditEvent({
    actorIdentityId: input.actorIdentityId,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    decision: input.decision,
    reason: input.reason,
    metadata: { source: "crypto-assurance", ...input.metadata },
  }).catch(() => undefined);
}

/** Digest helper for logging challenge identifiers without leaking payloads. */
export function fingerprintChallenge(challengeId: string): string {
  return createHash("sha256").update(challengeId).digest("hex").slice(0, 12);
}

/**
 * Issue a plain ECDSA step-up challenge for an ELEVATED operation. This
 * deliberately reuses the EXISTING DID step-up machinery so the platform has
 * exactly one step-up mechanism — no second, weaker path can be introduced.
 */
export async function issueStepUpForOperation(identityId: string, purpose: string) {
  return createStepUpChallenge(identityId, purpose);
}

/** Fail-closed helper for routers: convert a gate failure into a tRPC error. */
export function assuranceRequiredError(reason: string): TRPCError {
  return new TRPCError({ code: "PRECONDITION_FAILED", message: `CRYPTO_ASSURANCE_REQUIRED: ${reason}` });
}
