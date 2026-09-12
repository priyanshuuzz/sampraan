/**
 * LOOP 2+3+5 — DB-backed DID challenge-response, key lifecycle, and step-up
 * tests. Skipped automatically when no MySQL is reachable so `pnpm test`
 * stays green on machines without the dev DB.
 */
import "dotenv/config";
import { describe, expect, it } from "vitest";
import { Wallet } from "ethers";
import {
  createDidChallenge,
  verifyDidChallenge,
  rotateDidKey,
  setDidKeyStatus,
  createStepUpChallenge,
  verifyStepUpChallenge,
  hasValidStepUp,
} from "./did-auth.service";
import { getDb } from "../../db";
import { didRecords } from "../../../drizzle/schema";
import { eq } from "drizzle-orm";

/** Deterministic test operator key — never a real secret. */
const OPERATOR_KEY = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";
const DEMO_DID = "did:sampraan:dev-user-riya";

async function dbAvailable(): Promise<boolean> {
  try {
    const db = await getDb();
    if (!db) return false;
    await db.select({ id: didRecords.id }).from(didRecords).limit(1);
    return true;
  } catch {
    return false;
  }
}

const testShouldRun = await dbAvailable();
const d = testShouldRun ? describe : describe.skip;

/** Sign a message exactly as a demo client would. */
async function sign(message: string, key: string): Promise<string> {
  return new Wallet(key).signMessage(message);
}

d("DID challenge-response (LOOP 2)", () => {
  it("rejects an unknown DID at challenge time", async () => {
    const result = await createDidChallenge("did:sampraan:does-not-exist");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("DID_NOT_FOUND");
  });

  it("issues a challenge for a valid DID and verifies a correct signature", async () => {
    const challenge = await createDidChallenge(DEMO_DID);
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const { nonce, message } = challenge.challenge;
    // Recompute the DID's signing seed exactly as deriveIdentityWallet does
    // (keccak256(keccak256(operatorKey), did)) — the honest holder of the
    // DID key can always do this; the server only stores the ADDRESS.
    const { keccak256, toUtf8Bytes, solidityPacked } = await import("ethers");
    const seed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(OPERATOR_KEY)), DEMO_DID]));
    const signature = await sign(message, seed);
    const result = await verifyDidChallenge({ did: DEMO_DID, nonce, signature, operatorKey: OPERATOR_KEY });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.did).toBe(DEMO_DID);
      const { deriveIdentityWallet } = await import("../blockchain/anchoring.service");
      expect(result.recoveredAddress.toLowerCase()).toBe(deriveIdentityWallet(OPERATOR_KEY, DEMO_DID).toLowerCase());
    }
  });

  it("rejects an invalid signature (wrong key)", async () => {
    const challenge = await createDidChallenge(DEMO_DID);
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const { nonce, message } = challenge.challenge;
    const wrongKey = Wallet.createRandom().privateKey;
    const signature = await sign(message, wrongKey);
    const result = await verifyDidChallenge({ did: DEMO_DID, nonce, signature, operatorKey: OPERATOR_KEY });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe("SIGNATURE_MISMATCH");
  });

  it("rejects a replayed nonce (single-use enforcement)", async () => {
    const challenge = await createDidChallenge(DEMO_DID);
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const { nonce, message } = challenge.challenge;
    const { keccak256, toUtf8Bytes, solidityPacked } = await import("ethers");
    const seed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(OPERATOR_KEY)), DEMO_DID]));
    const signature = await sign(message, seed);
    const first = await verifyDidChallenge({ did: DEMO_DID, nonce, signature, operatorKey: OPERATOR_KEY });
    expect(first.ok).toBe(true);
    const second = await verifyDidChallenge({ did: DEMO_DID, nonce, signature, operatorKey: OPERATOR_KEY });
    // The challenge row was consumed by the first verification — the second
    // attempt MUST fail as a replay even with a valid signature.
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe("CHALLENGE_INVALID");
  });

  it("rejects a nonce that was never issued", async () => {
    const result = await verifyDidChallenge({
      did: DEMO_DID,
      nonce: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      signature: "0x" + "00".repeat(65),
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(false);
  });
});

d("Key lifecycle (LOOP 3)", () => {
  it("rotated key cannot authenticate (challenge issuance fails with KEY_ROTATED)", async () => {
    const rows = await (await getDb())!.select().from(didRecords).where(eq(didRecords.did, DEMO_DID)).limit(1);
    const original = rows[0]?.keyStatus ?? "ACTIVE";
    try {
      await rotateDidKey(DEMO_DID);
      const challenge = await createDidChallenge(DEMO_DID);
      expect(challenge.ok).toBe(false);
      if (!challenge.ok) expect(challenge.code).toBe("KEY_ROTATED");
    } finally {
      await setDidKeyStatus(DEMO_DID, original === "ACTIVE" ? "ACTIVE" : "ACTIVE");
    }
  });

  it("revoked key fails closed", async () => {
    try {
      await setDidKeyStatus(DEMO_DID, "REVOKED");
      const challenge = await createDidChallenge(DEMO_DID);
      expect(challenge.ok).toBe(false);
      if (!challenge.ok) expect(challenge.code).toBe("KEY_REVOKED");
    } finally {
      await setDidKeyStatus(DEMO_DID, "ACTIVE");
    }
  });

  it("re-activated key authenticates again (challenge issues)", async () => {
    await setDidKeyStatus(DEMO_DID, "ACTIVE");
    const challenge = await createDidChallenge(DEMO_DID);
    expect(challenge.ok).toBe(true);
  });
});

d("Step-up sessions (LOOP 5)", () => {
  it("hasValidStepUp is false before any verification", async () => {
    const identityId = "00000000-0000-0000-0000-00000000000x" as string;
    // A non-existent identity simply has no valid step-up.
    const valid = await hasValidStepUp(identityId, "transfer:none");
    expect(valid).toBe(false);
  });

  it("rejects a step-up nonce that was never issued", async () => {
    const identityRows = await (await getDb())!.select().from(didRecords).where(eq(didRecords.did, DEMO_DID)).limit(1);
    const identityId = identityRows[0]?.identityId;
    if (!identityId) return;
    const result = await verifyStepUpChallenge({
      identityId,
      purpose: "transfer:test",
      nonce: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      signature: "0x" + "00".repeat(65),
      operatorKey: OPERATOR_KEY,
    });
    expect(result.ok).toBe(false);
  });
});
