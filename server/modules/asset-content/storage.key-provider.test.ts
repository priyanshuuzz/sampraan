/**
 * Regression tests for the asset-content key-provider wire format.
 *
 * BUG THIS PINS: wrapKey once returned body||tag (dropping its own IV)
 * while unwrapKey parsed iv||body||tag — so EVERY stored object failed GCM
 * authentication on read ("Unsupported state or unable to authenticate
 * data"), even moments after being written. These tests pin the contract:
 *
 *   wrapped = iv(12) || ciphertext || tag(16)
 *
 * so the two sides can never drift apart silently again. Pure unit tests —
 * no database, no filesystem.
 */
import { describe, expect, it } from "vitest";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { LocalDevKeyProvider } from "./storage";

const MASTER = randomBytes(32);

describe("LocalDevKeyProvider wire format", () => {
  it("roundtrips a wrapped key through wrapKey → unwrapKey", async () => {
    const provider = new LocalDevKeyProvider(MASTER, "test-key-v1");
    const dek = randomBytes(32);
    const { wrappedKeyB64, keyId } = await provider.wrapKey(dek);
    expect(keyId).toBe("test-key-v1");
    const unwrapped = await provider.unwrapKey(wrappedKeyB64, keyId);
    expect(unwrapped.equals(dek)).toBe(true);
  });

  it("stores the wrap IV as the FIRST 12 bytes of the wrapped blob", async () => {
    const provider = new LocalDevKeyProvider(MASTER, "test-key-v1");
    const dek = randomBytes(32);
    const { wrappedKeyB64 } = await provider.wrapKey(dek);
    const wrapped = Buffer.from(wrappedKeyB64, "base64");
    // 12 (iv) + 32 (dek plaintext) + 16 (tag)
    expect(wrapped.length).toBe(60);
    const iv = wrapped.subarray(0, 12);
    const body = wrapped.subarray(12, wrapped.length - 16);
    const tag = wrapped.subarray(wrapped.length - 16);
    // The recorded IV must actually decrypt the recorded body+tag.
    const decipher = createDecipheriv("aes-256-gcm", MASTER, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
    expect(plaintext.equals(dek)).toBe(true);
  });

  it("uses a fresh IV for every wrap (never a fixed nonce)", async () => {
    const provider = new LocalDevKeyProvider(MASTER, "test-key-v1");
    const dek = randomBytes(32);
    const a = Buffer.from((await provider.wrapKey(dek)).wrappedKeyB64, "base64");
    const b = Buffer.from((await provider.wrapKey(dek)).wrappedKeyB64, "base64");
    expect(a.subarray(0, 12).equals(b.subarray(0, 12))).toBe(false);
  });

  it("fails GCM authentication when the blob is tampered with", async () => {
    const provider = new LocalDevKeyProvider(MASTER, "test-key-v1");
    const { wrappedKeyB64, keyId } = await provider.wrapKey(randomBytes(32));
    const wrapped = Buffer.from(wrappedKeyB64, "base64");
    wrapped[20] ^= 0xff; // flip one bit inside the ciphertext body
    await expect(provider.unwrapKey(wrapped.toString("base64"), keyId)).rejects.toThrow();
  });

  it("refuses a wrapped key whose keyId does not match the provider", async () => {
    const provider = new LocalDevKeyProvider(MASTER, "test-key-v1");
    const { wrappedKeyB64 } = await provider.wrapKey(randomBytes(32));
    await expect(provider.unwrapKey(wrappedKeyB64, "some-other-key")).rejects.toThrow(/Unknown content key id/);
  });

  it("supports the legacy reader contract: an externally-produced iv||body||tag blob unwraps", async () => {
    // This is the shape unwrapKey has always parsed; wrapKey now emits it.
    const provider = new LocalDevKeyProvider(MASTER, "test-key-v1");
    const dek = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", MASTER, iv);
    const legacy = Buffer.concat([iv, cipher.update(dek), cipher.final(), cipher.getAuthTag()]);
    const unwrapped = await provider.unwrapKey(legacy.toString("base64"), "test-key-v1");
    expect(unwrapped.equals(dek)).toBe(true);
  });

  it("deriveContentReference stays deterministic for identical inputs", async () => {
    // Imported lazily to keep this suite focused on the key provider.
    const { deriveContentReference } = await import("./storage");
    const integrityKey = await new LocalDevKeyProvider(MASTER, "k").integrityKey();
    const ciphertext = randomBytes(64);
    const refA = deriveContentReference({ ciphertext, plaintextHash: "abc", integrityKey });
    const refB = deriveContentReference({ ciphertext, plaintextHash: "abc", integrityKey });
    expect(refA).toBe(refB);
    expect(refA.startsWith("bciqa")).toBe(true);
  });

  it("encrypt→store→read→decrypt roundtrip verifies integrity (end-to-end seam)", async () => {
    // The exact scenario that failed before the fix: the full content
    // pipeline in one process, no mocks.
    const { encryptAndStore, verifyVersionIntegrity, validateUpload } = await import("./content.service");
    process.env.ASSET_CONTENT_MASTER_KEY = MASTER.toString("hex");
    const { resetStorageForTests } = await import("./storage");
    resetStorageForTests();
    try {
      const data = Buffer.from("Regression probe content — the seam that silently broke.\n");
      const validated = validateUpload({ originalFilename: "regression.txt", clientMimeType: "text/plain", data });
      const stored = await encryptAndStore(validated);
      const result = await verifyVersionIntegrity({
        storageProvider: stored.storageProvider,
        storageReference: stored.storageReference,
        sizeBytes: stored.sizeBytes,
        contentHash: stored.contentHash,
        encryption: stored.encryption,
      });
      expect(result.state).toBe("INTEGRITY_VERIFIED");
      // Clean up the object written to the real local store.
      const { resolveStorage } = await import("./storage");
      await resolveStorage().provider.delete(stored.storageReference).catch(() => undefined);
    } finally {
      delete process.env.ASSET_CONTENT_MASTER_KEY;
      resetStorageForTests();
    }
  });
});
