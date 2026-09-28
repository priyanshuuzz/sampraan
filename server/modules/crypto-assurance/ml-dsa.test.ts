/**
 * ML-DSA-65 primitive wrapper — security unit tests.
 *
 * Proves the properties the assurance layer depends on:
 *  - a valid signature verifies and a tampered message/signature does NOT;
 *  - the verifier is TOTAL: malformed, truncated, empty and non-base64 input
 *    returns false rather than throwing or (worse) returning true;
 *  - key generation is deterministic from a seed (so the local-dev provider is
 *    reproducible) and different seeds produce different keys;
 *  - degenerate all-zero public keys are detectable;
 *  - key identifiers follow the documented generation format.
 */
import { describe, expect, it } from "vitest";
import {
  ML_DSA_65_SIZES,
  decodeBase64Url,
  encodeBase64Url,
  fingerprintPublicKey,
  generationOf,
  isDegeneratePublicKey,
  keyPairFromSeed,
  parsePublicKey,
  pqcKeyIdentifierFor,
  signMessage,
  verifyMessageSignature,
} from "./ml-dsa";
import { derivePqcKeyPair } from "./pqc-key-provider";

const OPERATOR_KEY = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

describe("ML-DSA-65 primitives", () => {
  it("produces FIPS 204 wire sizes", () => {
    const { publicKey, secretKey } = keyPairFromSeed(new Uint8Array(32).fill(3));
    expect(publicKey.length).toBe(ML_DSA_65_SIZES.publicKey);
    expect(secretKey.length).toBe(ML_DSA_65_SIZES.secretKey);
    const signature = signMessage("sampraan", secretKey);
    expect(signature?.length).toBe(ML_DSA_65_SIZES.signature);
  });

  it("verifies a valid signature over the exact message", () => {
    const { publicKey, secretKey } = keyPairFromSeed(new Uint8Array(32).fill(7));
    const message = "SAMPRAAN Crypto Assurance\noperation: ASSET_BURN";
    const signature = signMessage(message, secretKey);
    expect(signature).not.toBeNull();
    expect(
      verifyMessageSignature({
        message,
        publicKey: encodeBase64Url(publicKey),
        signature: encodeBase64Url(signature as Uint8Array),
      }),
    ).toBe(true);
  });

  it("rejects a signature over a TAMPERED message (one byte changed)", () => {
    const { publicKey, secretKey } = keyPairFromSeed(new Uint8Array(32).fill(9));
    const message = "operation: ASSET_BURN\nresource-id: asset-1";
    const signature = encodeBase64Url(signMessage(message, secretKey) as Uint8Array);
    const tampered = message.replace("asset-1", "asset-2");
    expect(
      verifyMessageSignature({ message: tampered, publicKey: encodeBase64Url(publicKey), signature }),
    ).toBe(false);
  });

  it("rejects a signature verified against a DIFFERENT public key", () => {
    const a = keyPairFromSeed(new Uint8Array(32).fill(1));
    const b = keyPairFromSeed(new Uint8Array(32).fill(2));
    const message = "sampraan-dual-signature";
    const signature = encodeBase64Url(signMessage(message, a.secretKey) as Uint8Array);
    expect(
      verifyMessageSignature({ message, publicKey: encodeBase64Url(b.publicKey), signature }),
    ).toBe(false);
  });

  it("is TOTAL on malformed input (never throws, never verifies)", () => {
    const { publicKey, secretKey } = keyPairFromSeed(new Uint8Array(32).fill(5));
    const message = "sampraan";
    const goodSignature = encodeBase64Url(signMessage(message, secretKey) as Uint8Array);
    const goodPublicKey = encodeBase64Url(publicKey);

    const malformedPublicKeys = ["", "not base64!!", "AAAA", encodeBase64Url(new Uint8Array(10))];
    const malformedSignatures = ["", "!!!!", "AAAA", goodSignature.slice(0, 100), `${goodSignature}A`];

    for (const pk of malformedPublicKeys) {
      expect(verifyMessageSignature({ message, publicKey: pk, signature: goodSignature })).toBe(false);
    }
    for (const sig of malformedSignatures) {
      expect(verifyMessageSignature({ message, publicKey: goodPublicKey, signature: sig })).toBe(false);
    }
  });

  it("rejects a TRUNCATED signature of the correct prefix", () => {
    const { publicKey, secretKey } = keyPairFromSeed(new Uint8Array(32).fill(11));
    const message = "truncation";
    const signature = signMessage(message, secretKey) as Uint8Array;
    const truncated = Buffer.from(signature.slice(0, signature.length - 1)).toString("base64url");
    expect(
      verifyMessageSignature({ message, publicKey: encodeBase64Url(publicKey), signature: truncated }),
    ).toBe(false);
  });

  it("is deterministic from a seed and distinct across seeds", () => {
    const a1 = keyPairFromSeed(new Uint8Array(32).fill(4));
    const a2 = keyPairFromSeed(new Uint8Array(32).fill(4));
    const b = keyPairFromSeed(new Uint8Array(32).fill(6));
    expect(Buffer.from(a1.publicKey).equals(Buffer.from(a2.publicKey))).toBe(true);
    expect(Buffer.from(a1.publicKey).equals(Buffer.from(b.publicKey))).toBe(false);
  });

  it("refuses a seed of the wrong length", () => {
    expect(() => keyPairFromSeed(new Uint8Array(31))).toThrow(/32 bytes/);
  });

  it("parses only canonical base64url public keys and detects degenerate keys", () => {
    const { publicKey } = keyPairFromSeed(new Uint8Array(32).fill(8));
    const parsed = parsePublicKey(encodeBase64Url(publicKey));
    expect(parsed).not.toBeNull();
    expect(parsed?.fingerprint).toBe(fingerprintPublicKey(publicKey));
    expect(parsed?.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(parsePublicKey("")).toBeNull();
    expect(parsePublicKey("not-a-key")).toBeNull();
    expect(parsePublicKey(encodeBase64Url(new Uint8Array(ML_DSA_65_SIZES.publicKey)))).not.toBeNull();
    expect(isDegeneratePublicKey(new Uint8Array(ML_DSA_65_SIZES.publicKey))).toBe(true);
    expect(isDegeneratePublicKey(publicKey)).toBe(false);
  });

  it("rejects non-canonical base64url encodings", () => {
    expect(decodeBase64Url("abc=")).toBeNull(); // padding is not base64url-canonical here
    expect(decodeBase64Url("a b")).toBeNull();
    expect(decodeBase64Url("")).toBeNull();
    expect(decodeBase64Url("AAAA")).not.toBeNull();
  });

  describe("key identifiers", () => {
    it("encodes the generation and is scoped to the DID", () => {
      const first = pqcKeyIdentifierFor("did:sampraan:alice", 1);
      const second = pqcKeyIdentifierFor("did:sampraan:alice", 2);
      expect(first).toMatch(/^pqc-key-1-[0-9a-f]{12}$/);
      expect(generationOf(first)).toBe(1);
      expect(generationOf(second)).toBe(2);
      expect(pqcKeyIdentifierFor("did:sampraan:bob", 1)).not.toBe(first);
      expect(generationOf(null)).toBe(1);
      expect(generationOf("garbage")).toBe(1);
    });
  });

  describe("local-dev derivation", () => {
    it("derives a usable keypair per DID and refuses an invalid operator key", () => {
      const a = derivePqcKeyPair(OPERATOR_KEY, "did:sampraan:alice");
      const b = derivePqcKeyPair(OPERATOR_KEY, "did:sampraan:alice");
      const c = derivePqcKeyPair(OPERATOR_KEY, "did:sampraan:bob");
      expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(true);
      expect(Buffer.from(a.publicKey).equals(Buffer.from(c.publicKey))).toBe(false);
      const signature = signMessage("challenge", a.secretKey) as Uint8Array;
      expect(verifyMessageSignature({ message: "challenge", publicKey: encodeBase64Url(a.publicKey), signature: encodeBase64Url(signature) })).toBe(true);
      expect(() => derivePqcKeyPair("nope", "did:sampraan:alice")).toThrow(/32-byte hex/);
    });
  });
});
