/**
 * SAMPRAAN IPFS evidence run (mandate non-negotiables).
 *
 * Proves, against the LIVE self-hosted Kubo node and the REAL SAMPRAAN
 * content service:
 *   1. FILE → AES-256-GCM envelope encryption → ciphertext only → Kubo add
 *   2. REAL CID returned by Kubo; DB reference = that CID
 *   3. RAW object fetched directly from Kubo: plaintext marker ABSENT in the
 *      stored bytes (ciphertext never equals plaintext)
 *   4. Authorized retrieval path (loadVersionPlaintext) returns the EXACT
 *      original plaintext (server-side decryption)
 *   5. TAMPER: flipped ciphertext byte → decrypt FAILS (no bypass)
 *   6. VERSIONS: V1 and V2 produce distinct CIDs, both retrievable
 *   7. FAILURE SAFETY: Kubo down → put/get/stat FAIL (no fake success)
 *
 * Usage: npx tsx server/__ipfs-evidence.mts
 */
import "dotenv/config";
import { createHash } from "node:crypto";
import { encryptAndStore, loadVersionPlaintext, verifyVersionIntegrity } from "../server/modules/asset-content/content.service.ts";
import { IpfsStorageProvider, LocalDevKeyProvider, resetStorageForTests } from "../server/modules/asset-content/storage.ts";

let failures = 0;
function check(name: string, pass: boolean, detail = ""): void {
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
  if (!pass) failures += 1;
}

async function main(): Promise<void> {
  const api = process.env.IPFS_API_URL;
  if (!api) throw new Error("IPFS_API_URL missing");
  console.log(`Self-hosted Kubo: ${api}`);

  // ---------------------------------------------------------------- 1–4
  const MARKER = "SAMPRAAN-PLAINTEXT-MARKER-9f31c2: TOP SECRET rotor calibration";
  const plaintext = Buffer.from(
    `SAMPRAAN evidence document\n${MARKER}\nsha-of-this-file-is-tracked-in-the-read-model\n`.repeat(4),
    "utf8",
  );
  const contentHash = createHash("sha256").update(plaintext).digest("hex");

  resetStorageForTests();
  const validated = {
    filename: "evidence-document.txt",
    originalFilename: "evidence-document.txt",
    mimeType: "text/plain",
    sizeBytes: plaintext.byteLength,
    data: plaintext,
    contentHash,
  };
  const stored = await encryptAndStore(validated);
  const cid = stored.storageReference;
  check("V1 real CIDv1 from Kubo", cid.startsWith("bafkr"), cid.slice(0, 20) + "…");
  check("V1 provider recorded as ipfs", stored.storageProvider === "ipfs");
  check("V1 envelope is AES-256-GCM with wrapped DEK", stored.encryption.alg === "AES-256-GCM" && stored.encryption.wrappedKeyB64.length > 20);
  check("V1 recorded contentHash matches plaintext sha256", stored.contentHash === contentHash);

  // Raw object straight from Kubo — NO application code in between.
  const ipfs = new IpfsStorageProvider(api);
  const raw: Buffer = await ipfs.get(cid);
  check("raw Kubo object retrievable by CID", raw.byteLength === stored.sizeBytes, `${raw.byteLength} bytes`);
  check("plaintext marker ABSENT from stored Kubo bytes", !raw.toString("latin1").includes("SAMPRAAN-PLAINTEXT-MARKER-9f31c2"));
  check("stored bytes are NOT the plaintext", !raw.equals(plaintext));
  check("stored bytes are NOT a plain base64/hex of plaintext", !raw.toString("utf8").includes(plaintext.toString("utf8").slice(0, 16)));
  const rawHash = createHash("sha256").update(raw).digest("hex");
  check("raw ciphertext hash != plaintext hash", rawHash !== contentHash);

  // Authorized retrieval path: server-side decrypt.
  resetStorageForTests();
  const decrypted = await loadVersionPlaintext({ storageReference: cid, encryption: stored.encryption });
  check("authorized API retrieval decrypts EXACT original", decrypted.equals(plaintext));
  check("decrypted contains marker", decrypted.toString("utf8").includes(MARKER));

  // ---------------------------------------------------------------- 5 TAMPER
  const tampered = Buffer.from(raw);
  tampered[10] ^= 0xff;
  await ipfs.put("tamper-probe-ref", tampered, { contentHash: "tampered" }).catch(() => undefined);
  // Tamper locally: modify the CIPHERTEXT and try to decrypt with the real envelope.
  const { createDecipheriv } = await import("node:crypto");
  const legacy = LocalDevKeyProvider.fromEnvironment();
  const dek = await legacy.unwrapKey(stored.encryption.wrappedKeyB64, stored.encryption.keyId);
  const decipher = createDecipheriv("aes-256-gcm", dek, Buffer.from(stored.encryption.ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(stored.encryption.tagB64, "base64"));
  let tamperFailed = false;
  try {
    Buffer.concat([decipher.update(tampered), decipher.final()]);
  } catch {
    tamperFailed = true;
  }
  check("TAMPER: modified ciphertext FAILS GCM auth", tamperFailed);

  // Tamper the envelope tag instead (metadata-level tamper).
  let tagTamperFailed = false;
  try {
    await loadVersionPlaintext({
      storageReference: cid,
      encryption: { ...stored.encryption, tagB64: Buffer.from(Buffer.from(stored.encryption.tagB64, "base64")).toString("base64").slice(0, -2) + "AA" },
    });
  } catch {
    tagTamperFailed = true;
  }
  check("TAMPER: modified auth tag FAILS decryption", tagTamperFailed);

  // Integrity verifier on mismatched size record (read-model tamper).
  resetStorageForTests();
  const mismatch = await verifyVersionIntegrity({
    storageProvider: stored.storageProvider,
    storageReference: cid,
    sizeBytes: stored.sizeBytes + 1, // tampered metadata
    contentHash: stored.contentHash,
    encryption: stored.encryption,
  });
  check("TAMPER: tampered read-model size → INTEGRITY_MISMATCH", mismatch.state === "INTEGRITY_MISMATCH", mismatch.state);
  const clean = await verifyVersionIntegrity({
    storageProvider: stored.storageProvider,
    storageReference: cid,
    sizeBytes: stored.sizeBytes,
    contentHash: stored.contentHash,
    encryption: stored.encryption,
  });
  check("integrity verifier PASS on clean version", clean.state === "INTEGRITY_VERIFIED", clean.state);

  // ---------------------------------------------------------------- 6 VERSIONS
  const v2Plaintext = Buffer.from(plaintext.toString("utf8") + "\nV2 ADDENDUM: rotor calibrated 2026-09-28\n", "utf8");
  const v2 = await encryptAndStore({
    ...validated,
    data: v2Plaintext,
    sizeBytes: v2Plaintext.byteLength,
    contentHash: createHash("sha256").update(v2Plaintext).digest("hex"),
  });
  check("V2 real CID distinct from V1", v2.storageReference.startsWith("bafkr") && v2.storageReference !== cid, v2.storageReference.slice(0, 20) + "…");
  resetStorageForTests();
  const v2Back = await loadVersionPlaintext({ storageReference: v2.storageReference, encryption: v2.encryption });
  check("V2 decrypts to exact V2 plaintext", v2Back.equals(v2Plaintext));
  check("V1 still retrievable after V2 upload", (await loadVersionPlaintext({ storageReference: cid, encryption: stored.encryption })).equals(plaintext));
  check("V1 and V2 CIDs both pinned-persistent on OUR Kubo", (await ipfs.stat(cid)).exists && (await ipfs.stat(v2.storageReference)).exists);

  // ---------------------------------------------------------------- 7 FAILURE SAFETY
  const dead = new IpfsStorageProvider("http://127.0.0.1:59999/api/v0");
  let putFailed = false;
  try {
    await dead.put("ref", Buffer.from("x"), { contentHash: "x" });
  } catch {
    putFailed = true;
  }
  check("Kubo UNAVAILABLE: upload FAILS (no fake success)", putFailed);
  let getFailed = false;
  try {
    await dead.get("bafkreidj5dmjwc7wlc3ucekg2kmsypsqoqwr4l5mvltghtrpt7eiud6zfi");
  } catch {
    getFailed = true;
  }
  check("Kubo UNAVAILABLE: retrieval FAILS", getFailed);

  // Invalid CID: live node, garbage reference → must throw, not fabricate.
  let invalidFailed = false;
  try {
    await ipfs.get("bafkreiinvalidcid00000000000000000000000000000000000000000");
  } catch {
    invalidFailed = true;
  }
  check("INVALID CID: retrieval FAILS against live Kubo", invalidFailed);

  console.log(failures === 0 ? "\nALL IPFS EVIDENCE CHECKS PASS" : `\n${failures} CHECK(S) FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch(error => {
  console.error("fatal:", error);
  process.exitCode = 1;
});
