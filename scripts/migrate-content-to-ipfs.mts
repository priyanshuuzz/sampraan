/**
 * ONE-SHOT content migration: local-encrypted → self-hosted Kubo (IPFS).
 *
 * Every asset_content_versions row stored by the legacy local provider is
 * re-encrypted under the CURRENT master key (fresh per-object DEK), pushed
 * to Kubo, verified by full decrypt-back + sha256 comparison, and only then
 * updated in the read model. A row that cannot be decrypted (tamper/missing
 * key) is LEFT UNTOUCHED and reported — data-safe by construction.
 *
 * Idempotent: rows already on the ipfs provider are skipped, so re-running
 * after a partial migration processes only the remainder.
 *
 * Usage: npx tsx server/__migrate-content-to-ipfs.mts
 */
import "dotenv/config";
import { createHash, createDecipheriv, createCipheriv } from "node:crypto";
import mysql from "mysql2/promise";
import {
  IpfsStorageProvider,
  LocalEncryptedStorageProvider,
  LocalDevKeyProvider,
  resetStorageForTests,
} from "./modules/asset-content/storage.ts";
import { encryptAndStore, loadVersionPlaintext } from "./modules/asset-content/content.service.ts";

interface EnvelopeLike {
  alg: "AES-256-GCM";
  keyId: string;
  wrappedKeyB64: string;
  ivB64: string;
  tagB64: string;
}

async function main(): Promise<void> {
  const api = process.env.IPFS_API_URL;
  if (!api) throw new Error("IPFS_API_URL is required — refusing to migrate to an unknown provider");
  const ipfs = new IpfsStorageProvider(api);

  // The legacy rows were wrapped under the JWT-derived dev key ("local-dev-
  // derived"). Construct that provider EXPLICITLY — fromEnvironment() would
  // now return the new ASSET_CONTENT_MASTER_KEY provider instead.
  const legacySecret = process.env.JWT_SECRET ?? "sampraan-dev";
  const legacyKey = createHash("sha256").update(`sampraan-asset-content:${legacySecret}`).digest();
  const legacy = new LocalDevKeyProvider(legacyKey, "local-dev-derived");
  console.log(`[migrate] legacy key provider: ${legacy.keyId}`);

  const legacyDir = LocalEncryptedStorageProvider.defaultDirectory();
  const local = new LocalEncryptedStorageProvider(legacyDir);
  console.log(`[migrate] legacy local dir: ${legacyDir}`);

  const connection = await mysql.createConnection(process.env.DATABASE_URL!);
  const [rows] = await connection.query<mysql.RowDataPacket[]>(
    "SELECT id, assetId, versionNumber, filename, mimeType, sizeBytes, contentHash, storageReference, encryption FROM asset_content_versions WHERE storageProvider <> 'ipfs' ORDER BY createdAt ASC",
  );
  console.log(`[migrate] rows to migrate: ${rows.length}`);

  let ok = 0;
  let failed = 0;
  for (const row of rows) {
    const envelope = (typeof row.encryption === "string" ? JSON.parse(row.encryption) : row.encryption) as EnvelopeLike;
    try {
      // 1. Load legacy ciphertext from the local provider.
      const ciphertext = await local.get(row.storageReference);
      // 2. Decrypt with the legacy dev key (the DEK was wrapped under it).
      const dek = await legacy.unwrapKey(envelope.wrappedKeyB64, envelope.keyId);
      const decipher = createDecipheriv("aes-256-gcm", dek, Buffer.from(envelope.ivB64, "base64"));
      decipher.setAuthTag(Buffer.from(envelope.tagB64, "base64"));
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      // 3. Verify plaintext hash before re-encryption.
      const computed = createHash("sha256").update(plaintext).digest("hex");
      if (computed !== row.contentHash) {
        throw new Error(`plaintext hash mismatch (db ${row.contentHash.slice(0, 12)} vs computed ${computed.slice(0, 12)})`);
      }
      // 4. Re-encrypt with a FRESH per-object DEK under the CURRENT master
      //    key and push to Kubo.
      resetStorageForTests();
      const stored = await encryptAndStore({
        filename: row.filename as string,
        originalFilename: row.filename as string,
        mimeType: row.mimeType as string,
        sizeBytes: plaintext.byteLength,
        data: plaintext,
        contentHash: row.contentHash as string,
      });
      if (stored.storageProvider !== "ipfs" || !stored.storageReference.startsWith("bafkr")) {
        throw new Error(`expected ipfs CIDv1, got ${stored.storageProvider}:${stored.storageReference.slice(0, 12)}`);
      }
      // 5. Decrypt-back verification from IPFS.
      resetStorageForTests();
      const roundTrip = await loadVersionPlaintext({
        storageReference: stored.storageReference,
        encryption: stored.encryption,
      });
      const rtHash = createHash("sha256").update(roundTrip).digest("hex");
      if (rtHash !== row.contentHash || roundTrip.byteLength !== plaintext.byteLength) {
        throw new Error("post-upload decrypt-back verification failed");
      }
      // 6. Update the read model row.
      await connection.execute(
        "UPDATE asset_content_versions SET storageProvider = ?, storageReference = ?, encryption = ?, sizeBytes = ? WHERE id = ?",
        [stored.storageProvider, stored.storageReference, JSON.stringify(stored.encryption), stored.sizeBytes, row.id],
      );
      ok += 1;
      if (ok % 10 === 0) console.log(`[migrate] progress ${ok}/${rows.length}`);
    } catch (error) {
      failed += 1;
      console.warn(`[migrate] FAILED ${row.assetId} v${row.versionNumber} (${row.filename}): ${(error as Error).message} — row left untouched`);
    }
  }

  console.log(`[migrate] done: ${ok} migrated, ${failed} failed/left-untouched`);
  await connection.end();
  resetStorageForTests();
}

main().catch(error => {
  console.error("[migrate] fatal:", error);
  process.exitCode = 1;
});
