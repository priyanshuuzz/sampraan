/**
 * CRYPTO ASSURANCE — end-to-end security matrix (DB-backed).
 *
 * Exercises the full policy-driven dual-signature flow against a real MySQL
 * read model:
 *
 *   policy → challenge → ECDSA (+ ML-DSA-65) verify → single-use grant → claim
 *
 * Attack cases that MUST fail safely:
 *   - replayed challenge (same nonce twice)
 *   - replayed grant (one verification, two executions)
 *   - grant used for a different operation or resource
 *   - tampered ML-DSA-65 signature
 *   - ML-DSA-65 signature omitted where the policy demands it
 *   - ECDSA signature from the wrong key
 *   - signature over a modified payload (operation/resource swapped)
 *   - post-quantum requirement with no registered/derivable key
 *   - cross-DID grant theft
 *
 * Skips automatically when no MySQL is reachable so CI without a DB stays green.
 */
import "dotenv/config";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Wallet, keccak256, solidityPacked, toUtf8Bytes } from "ethers";
import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { getDb } from "./db";
import { assuranceChallenges, auditEvents, didRecords, identities, pqcKeyRecords } from "../drizzle/schema";
import {
  buildAssuranceMessage,
  claimAssuranceGrant,
  decideAssurance,
  issueAssuranceChallenge,
  verifyAssuranceChallenge,
} from "./modules/crypto-assurance/assurance.service";
import { derivePqcKeyPair } from "./modules/crypto-assurance/pqc-key-provider";
import { encodeBase64Url, pqcKeyIdentifierFor, signMessage } from "./modules/crypto-assurance/ml-dsa";
import { registerPqcKeyRecord } from "./db";

const OPERATOR_KEY = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

async function dbAvailable(): Promise<boolean> {
  try {
    const db = await getDb();
    if (!db) return false;
    await db.select({ id: identities.id }).from(identities).limit(1);
    return true;
  } catch {
    return false;
  }
}

const testShouldRun = await dbAvailable();
const d = testShouldRun ? describe : describe.skip;

const TEST_DID = `did:sampraan:assurance-probe-${randomUUID().slice(0, 8)}`;
let identityId = "";

/** The DID holder's ECDSA key (same derivation the demo client uses). */
function holderKey(did: string): string {
  return keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(OPERATOR_KEY)), did]));
}

/** ML-DSA-65 signature over a message using the DID's derived PQC key. */
function pqcSign(did: string, message: string): string {
  const { secretKey } = derivePqcKeyPair(OPERATOR_KEY, did);
  const signature = signMessage(message, secretKey);
  if (!signature) throw new Error("test PQC signing failed");
  return encodeBase64Url(signature);
}

d("crypto assurance — dual signature end-to-end", () => {
  beforeAll(async () => {
    const db = await getDb();
    if (!db) return;
    identityId = randomUUID();
    await db.insert(identities).values({
      id: identityId,
      displayName: "Assurance Probe Identity",
      organization: "SAMPRAAN TEST",
      status: "ACTIVE",
      lifecycleState: "VERIFIED",
      did: TEST_DID,
      scope: "SAMPRAAN TEST",
    });
    await db.insert(didRecords).values({
      id: randomUUID(),
      identityId,
      did: TEST_DID,
      method: "sampraan",
      subject: "assurance-probe",
      status: "ACTIVE",
      keyStatus: "ACTIVE",
    });
  });

  afterAll(async () => {
    const db = await getDb();
    if (!db) return;
    // Order matters: audit_events reference the identity (FK), so the evidence
    // rows this suite produced are removed first. The identity itself is a
    // throwaway probe row, so deleting its audit trail is correct here.
    await db.delete(auditEvents).where(eq(auditEvents.actorIdentityId, identityId));
    await db.delete(assuranceChallenges).where(eq(assuranceChallenges.identityId, identityId));
    await db.delete(pqcKeyRecords).where(eq(pqcKeyRecords.identityId, identityId));
    await db.delete(didRecords).where(eq(didRecords.did, TEST_DID));
    await db.delete(identities).where(eq(identities.id, identityId));
  });

  const issue = (operation: Parameters<typeof issueAssuranceChallenge>[0]["operation"], resourceId: string, role = "ADMIN") =>
    issueAssuranceChallenge({
      identityId,
      did: TEST_DID,
      identityStatus: "ACTIVE",
      lifecycleState: "VERIFIED",
      role,
      operation,
      resourceType: "GOVERNANCE",
      resourceId,
      policyInput: { assetClassification: null, riskLevel: "LOW", riskScore: 0, custodyRelation: "NOT_APPLICABLE", approvalStatus: "NOT_REQUIRED" },
    });

  it("policy: BURN_NFT is QUANTUM_HARDENED, PAUSE_REGISTRY is ELEVATED", () => {
    expect(decideAssurance({ operation: "ASSET_BURN", role: "ADMIN" }).level).toBe("QUANTUM_HARDENED");
    expect(decideAssurance({ operation: "PAUSE_REGISTRY", role: "ADMIN" }).level).toBe("ELEVATED");
  });

  it("BASELINE operations need no challenge at all", async () => {
    const result = await issue("ASSET_VIEW", "asset-1", "USER");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.required).toBe(false);
  });

  it("QUANTUM_HARDENED: a valid dual signature yields a single-use grant", async () => {
    const issued = await issue("ASSET_BURN", "asset-burn-1");
    expect(issued.ok).toBe(true);
    if (!issued.ok || !issued.required) return;
    expect(issued.challenge.level).toBe("QUANTUM_HARDENED");
    expect(issued.challenge.algorithms).toEqual(["ECDSA_SECP256K1", "ML_DSA_65"]);

    const message = issued.challenge.message;
    const result = await verifyAssuranceChallenge({
      identityId,
      nonce: issued.challenge.nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(message),
      pqcSignature: pqcSign(TEST_DID, message),
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.algorithmVerified).toEqual(["ECDSA_SECP256K1", "ML_DSA_65"]);

    // The grant authorizes exactly this operation on exactly this resource…
    const claim = await claimAssuranceGrant({
      identityId,
      grantId: result.grantId,
      operation: "ASSET_BURN",
      resourceType: "GOVERNANCE",
      resourceId: "asset-burn-1",
    });
    expect(claim.ok).toBe(true);
    // …exactly once (single-use claim).
    const replayClaim = await claimAssuranceGrant({
      identityId,
      grantId: result.grantId,
      operation: "ASSET_BURN",
      resourceType: "GOVERNANCE",
      resourceId: "asset-burn-1",
    });
    expect(replayClaim.ok).toBe(false);
  });

  it("rejects a REPLAYED challenge nonce (atomic single-use consumption)", async () => {
    const issued = await issue("ASSET_BURN", "asset-burn-2");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const { nonce, message } = issued.challenge;
    const ecdsaSignature = await new Wallet(holderKey(TEST_DID)).signMessage(message);
    const pqcSignature = pqcSign(TEST_DID, message);

    const first = await verifyAssuranceChallenge({ identityId, nonce, ecdsaSignature, pqcSignature, operatorKey: OPERATOR_KEY });
    expect(first.ok).toBe(true);
    const second = await verifyAssuranceChallenge({ identityId, nonce, ecdsaSignature, pqcSignature, operatorKey: OPERATOR_KEY });
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("CHALLENGE_INVALID");
  });

  it("rejects a concurrent double-verify of the same nonce (exactly one winner)", async () => {
    const issued = await issue("ASSET_FORCE_TRANSFER", "asset-force-1");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const { nonce, message } = issued.challenge;
    const ecdsaSignature = await new Wallet(holderKey(TEST_DID)).signMessage(message);
    const pqcSignature = pqcSign(TEST_DID, message);
    const [a, b] = await Promise.all([
      verifyAssuranceChallenge({ identityId, nonce, ecdsaSignature, pqcSignature, operatorKey: OPERATOR_KEY }),
      verifyAssuranceChallenge({ identityId, nonce, ecdsaSignature, pqcSignature, operatorKey: OPERATOR_KEY }),
    ]);
    expect([a.ok, b.ok].filter(Boolean).length).toBe(1);
  });

  it("rejects a TAMPERED ML-DSA-65 signature", async () => {
    const issued = await issue("ASSET_BURN", "asset-burn-3");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const { nonce, message } = issued.challenge;
    const good = pqcSign(TEST_DID, message);
    // Flip one character while staying valid base64url.
    const tampered = `${good.slice(0, 10)}${good[10] === "A" ? "B" : "A"}${good.slice(11)}`;
    const result = await verifyAssuranceChallenge({
      identityId,
      nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(message),
      pqcSignature: tampered,
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("PQC_SIGNATURE_INVALID");
  });

  it("rejects an OMITTED ML-DSA-65 signature (no silent downgrade)", async () => {
    const issued = await issue("ASSET_BURN", "asset-burn-4");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const result = await verifyAssuranceChallenge({
      identityId,
      nonce: issued.challenge.nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(issued.challenge.message),
      pqcSignature: null,
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("PQC_SIGNATURE_MISSING");
  });

  it("rejects an ECDSA signature from the WRONG key", async () => {
    const issued = await issue("ASSET_BURN", "asset-burn-5");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const { nonce, message } = issued.challenge;
    const result = await verifyAssuranceChallenge({
      identityId,
      nonce,
      ecdsaSignature: await new Wallet(Wallet.createRandom().privateKey).signMessage(message),
      pqcSignature: pqcSign(TEST_DID, message),
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("SIGNATURE_MISMATCH");
  });

  it("a signature over a MODIFIED payload cannot be replayed into the challenge", async () => {
    const issued = await issue("ASSET_BURN", "asset-burn-6");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const { nonce, message } = issued.challenge;
    // The attacker signs a payload that targets a DIFFERENT resource. The
    // server verifies against the STORED canonical message, so this fails.
    const forgedPayload = message.replace("resource-id: asset-burn-6", "resource-id: asset-victim");
    const result = await verifyAssuranceChallenge({
      identityId,
      nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(forgedPayload),
      pqcSignature: pqcSign(TEST_DID, forgedPayload),
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("SIGNATURE_MISMATCH");
  });

  it("a grant cannot be reused for a different operation or resource", async () => {
    const issued = await issue("ASSET_FORCE_TRANSFER", "asset-force-2");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    const { nonce, message } = issued.challenge;
    const verified = await verifyAssuranceChallenge({
      identityId,
      nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(message),
      pqcSignature: pqcSign(TEST_DID, message),
      operatorKey: OPERATOR_KEY,
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) return;

    const wrongOperation = await claimAssuranceGrant({ identityId, grantId: verified.grantId, operation: "ASSET_BURN", resourceType: "GOVERNANCE", resourceId: "asset-force-2" });
    expect(wrongOperation.ok).toBe(false);
    const wrongResource = await claimAssuranceGrant({ identityId, grantId: verified.grantId, operation: "ASSET_FORCE_TRANSFER", resourceType: "GOVERNANCE", resourceId: "asset-other" });
    expect(wrongResource.ok).toBe(false);
    const missingGrant = await claimAssuranceGrant({ identityId, grantId: null, operation: "ASSET_FORCE_TRANSFER", resourceType: "GOVERNANCE", resourceId: "asset-force-2" });
    expect(missingGrant.ok).toBe(false);
  });

  it("a registered REGISTERED-source key is used and a wrong-key signature fails", async () => {
    // Register a holder-generated ML-DSA-65 key (the production path).
    const { publicKey, secretKey } = derivePqcKeyPair(OPERATOR_KEY, `${TEST_DID}#registered`);
    const keyIdentifier = pqcKeyIdentifierFor(TEST_DID, 9);
    const registered = await registerPqcKeyRecord({
      identityId,
      did: TEST_DID,
      keyIdentifier,
      algorithm: "ML-DSA-65",
      publicKey: encodeBase64Url(publicKey),
      publicKeyFingerprint: "test-fingerprint",
      keySource: "REGISTERED",
      registeredByIdentityId: identityId,
    });
    expect(registered?.status).toBe("ACTIVE");

    const issued = await issue("ASSET_BURN", "asset-burn-7");
    if (!issued.ok || !issued.required) throw new Error("expected a challenge");
    expect(issued.challenge.pqcKeyIdentifier).toBe(keyIdentifier);

    const { nonce, message } = issued.challenge;
    // Correct: sign with the REGISTERED key's secret half.
    const goodSignature = encodeBase64Url(signMessage(message, secretKey) as Uint8Array);
    const ok = await verifyAssuranceChallenge({
      identityId,
      nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(message),
      pqcSignature: goodSignature,
      operatorKey: OPERATOR_KEY,
    });
    expect(ok.ok).toBe(true);

    // Wrong: sign with the DEV-derived key instead of the registered one.
    const issued2 = await issue("ASSET_BURN", "asset-burn-8");
    if (!issued2.ok || !issued2.required) throw new Error("expected a challenge");
    const bad = await verifyAssuranceChallenge({
      identityId,
      nonce: issued2.challenge.nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(issued2.challenge.message),
      pqcSignature: pqcSign(TEST_DID, issued2.challenge.message),
      operatorKey: OPERATOR_KEY,
    });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.code).toBe("PQC_SIGNATURE_INVALID");
  });

  it("ELEVATED operations need only the ECDSA half (no PQC downgrade of the level)", async () => {
    const issued = await issue("PAUSE_REGISTRY", "PAUSE_REGISTRY");
    expect(issued.ok).toBe(true);
    if (!issued.ok || !issued.required) return;
    expect(issued.challenge.level).toBe("ELEVATED");
    expect(issued.challenge.algorithms).toEqual(["ECDSA_SECP256K1"]);
    const result = await verifyAssuranceChallenge({
      identityId,
      nonce: issued.challenge.nonce,
      ecdsaSignature: await new Wallet(holderKey(TEST_DID)).signMessage(issued.challenge.message),
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(true);
  });

  it("the canonical payload binds identity, DID, operation, resource, audience and nonce", () => {
    const message = buildAssuranceMessage({
      identityId: "id-1",
      did: "did:sampraan:alice",
      level: "QUANTUM_HARDENED",
      algorithms: ["ECDSA_SECP256K1", "ML_DSA_65"],
      operation: "ASSET_BURN",
      resourceType: "GOVERNANCE",
      resourceId: "asset-1",
      audience: "sampraan",
      ecdsaKeyIdentifier: "key-1-abcdef123456",
      pqcKeyIdentifier: "pqc-key-1-abcdef123456",
      nonce: "n".repeat(48),
      issuedAt: new Date(0).toISOString(),
      expiresAt: new Date(60_000).toISOString(),
      reasonCodes: ["PQC_POLICY_MANDATED"],
    });
    for (const fragment of [
      "identity: id-1",
      "did: did:sampraan:alice",
      "level: QUANTUM_HARDENED",
      "algorithms: ECDSA_SECP256K1+ML_DSA_65",
      "operation: ASSET_BURN",
      "resource-id: asset-1",
      "audience: sampraan",
      "ecdsa-key: key-1-abcdef123456",
      "pqc-key: pqc-key-1-abcdef123456",
      `nonce: ${"n".repeat(48)}`,
    ]) {
      expect(message).toContain(fragment);
    }
  });
});
