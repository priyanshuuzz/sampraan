/**
 * SAMPRAAN deterministic DEVELOPMENT seed.
 *
 * FICTIONAL DATA ONLY — never real BEL personnel or operational data. All
 * names, DIDs, emails, and assets are invented. Passwords below are
 * development placeholders hashed with the same server-side scrypt the
 * local login flow verifies against; they are NOT production credentials.
 *
 * What this seed guarantees (all idempotent — safe to re-run):
 *  - The 4 SAMPRAAN roles (ADMIN, MANAGER, AUDITOR, USER) and the full
 *    permission catalog with a least-privilege matrix.
 *  - 4 identities, one per role, each LINKED to a platform user so the
 *    documented "linkedUserId gap" (docs/integration-notes.md #1) is closed
 *    in dev: every role can be logged in as and immediately exercises its
 *    real authorization envelope.
 *  - 4 local accounts with scrypt password hashes for the local login flow:
 *      admin@sampraan.dev  / SampraanAdmin#2026
 *      manager@sampraan.dev / SampraanManager#2026
 *      auditor@sampraan.dev / SampraanAuditor#2026
 *      user@sampraan.dev    / SampraanUser#2026
 *  - Several assets across classifications with ownership + custody history.
 *  - A seeded HIGH-sensitivity transfer-deny policy row (catalog display).
 *  - Audit history rows describing the seeded state (marked source: seed).
 *
 * Chain linkage: identities/assets are anchored on-chain lazily by the
 * backend on their next operation (anchoring is idempotent) — the seed does
 * not require the chain to be up.
 */
import { randomUUID, scrypt as scryptCb, randomBytes } from "node:crypto";
import { promisify } from "node:util";
import mysql from "mysql2/promise";
// BUG-026: load .env before reading env vars.
import "dotenv/config";
// Real chain anchoring (LOCAL DEMO ONLY — uses the operator key from .env to
// anchor seeded assets on the local Besu QBFT chain; see anchorAssets below).
import { JsonRpcProvider, Contract, Wallet, keccak256, toUtf8Bytes, solidityPacked } from "ethers";

const scrypt = promisify(scryptCb);
const N = 32_768, R = 8, P = 1, KEYLEN = 64;
const MAXMEM = 128 * N * R * 2; // explicit ceiling so N*r fits comfortably
async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password.normalize("NFKC"), salt, KEYLEN, { N, r: R, p: P, maxmem: MAXMEM });
  return ["scrypt", N, R, P, salt.toString("base64url"), derived.toString("base64url")].join("$");
}

const url = process.env.DATABASE_URL;
if (!url) throw new Error("DATABASE_URL is required to run the demo seed (set it in .env or the environment)");
const connection = await mysql.createConnection(url);

/**
 * LOCAL DEMO ONLY — anchor seeded assets on the real local Besu chain.
 *
 * The seed INITIALIZES data; it never fakes blockchain transactions. When a
 * real chain is configured (deployment.json + BLOCKCHAIN_PRIVATE_KEY), each
 * seeded asset is minted through the DEPLOYED SampraanAssetRegistry contract
 * (real QBFT transaction, real NFT token id, real AssetRegistered event) and
 * the read model is updated with the REAL token id and tx hash. When no chain
 * is configured, anchoring is skipped with an explicit audit event — the seed
 * still works without Docker, but nothing pretends to be on-chain.
 *
 * Per-identity derived wallets mirror server/modules/blockchain/anchoring.service.ts
 * (keccak256(keccak256(operatorKey), did)) so chain state matches exactly what
 * the backend derives at request time.
 */
async function anchorAssets(input) {
  const { readFileSync, existsSync } = await import("node:fs");
  const path = await import("node:path");
  const { resolveProjectRoot } = await import("./modules/blockchain/paths.mjs").catch(() => ({}));
  const root = path.resolve(import.meta.dirname, "..");
  const deploymentFile = path.join(root, "blockchain", "deployment.json");
  const artifactFile = path.join(root, "blockchain", "artifacts", "SampraanAssetRegistry.json");
  const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY;
  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL ?? "http://localhost:8545";

  let deployment = null;
  try {
    if (existsSync(deploymentFile)) deployment = JSON.parse(readFileSync(deploymentFile, "utf8"));
  } catch { deployment = null; }
  const contractAddress = deployment?.contracts?.SampraanAssetRegistry;
  const keyIsValid = typeof privateKey === "string" && /^0x[0-9a-fA-F]{64}$/.test(privateKey) && privateKey !== "0x" + "0".repeat(64);
  if (!contractAddress || !keyIsValid || !existsSync(artifactFile)) {
    console.warn("[seed] Chain not configured (deployment.json / BLOCKCHAIN_PRIVATE_KEY missing) — seeded assets are NOT anchored on-chain (MOCK mode). Run the chain + deploy for full fidelity.");
    for (const asset of input.assets) {
      await input.auditSink({
        id: id(`audit-anchor-${asset.assetId}`),
        actorIdentityId: IDN.ADMIN,
        action: "BLOCKCHAIN_ANCHOR_SKIPPED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "CHALLENGE",
        reason: "Seed: blockchain not configured — asset anchored lazily by the backend on its next operation",
        timestamp: new Date(),
        transactionHash: null,
        blockNumber: null,
        metadata: { source: "seed", note: "No chain configured; nothing fake was recorded" },
      });
    }
    return;
  }

  const { abi, bytecode: _bytecode } = JSON.parse(readFileSync(artifactFile, "utf8"));
  const provider = new JsonRpcProvider(rpcUrl, deployment.chainId ?? 4224, { staticNetwork: true });
  const wallet = new Wallet(privateKey, provider);
  const registry = new Contract(contractAddress, abi, wallet);
  const operatorKeyHash = keccak256(toUtf8Bytes(privateKey));
  // Mirrors deriveIdentityWallet() in anchoring.service.ts.
  const deriveWallet = (did) => new Wallet(keccak256(solidityPacked(["bytes32", "string"], [operatorKeyHash, did]))).address;

  // INTEGRITY SWEEP: every asset in the read model must be backed by real
  // chain state. Mint any asset that still lacks a token id (e.g. rows left
  // un-anchored by an earlier session) — never fake one.
  const [unanchored] = await connection.execute(
    "SELECT a.id AS rowId, a.assetId, a.classification, a.integrityHash, a.custodianIdentityId FROM assets a WHERE a.tokenId IS NULL",
  );
  if (unanchored.length > 0) {
    const [identRows] = await connection.execute("SELECT id, displayName, did FROM identities");
    const didById = new Map(identRows.map(r => [r.id, r.did]));
    for (const asset of unanchored) {
      const custodianDid = didById.get(asset.custodianIdentityId);
      if (!custodianDid) { console.warn(`[seed] cannot anchor ${asset.assetId}: custodian identity missing`); continue; }
      try {
        const custodianWallet = deriveWallet(custodianDid);
        const identityRegistryAddress = deployment.contracts.SampraanIdentityRegistry;
        const identityArtifact = JSON.parse(readFileSync(path.join(root, "blockchain", "artifacts", "SampraanIdentityRegistry.json"), "utf8"));
        const identityRegistry = new Contract(identityRegistryAddress, identityArtifact.abi, wallet);
        const identityRecord = await identityRegistry.getIdentity(custodianWallet).catch(() => null);
        if (!identityRecord || identityRecord.status === 0n) {
          const regTx = await identityRegistry.registerIdentity(custodianWallet, keccak256(toUtf8Bytes(custodianDid)), keccak256(toUtf8Bytes(`pk:${custodianDid}`)));
          await regTx.wait();
        }
        const tx = await registry.registerAsset(
          keccak256(toUtf8Bytes(asset.assetId)),
          custodianWallet,
          keccak256(toUtf8Bytes(asset.classification)),
          keccak256(toUtf8Bytes(asset.integrityHash ?? `asset:${asset.assetId}`)),
        );
        const receipt = await tx.wait();
        // Post-mint activation (registerAsset mints PENDING).
        const activateTx = await registry.activateAsset(await registry.resolveAssetId(keccak256(toUtf8Bytes(asset.assetId))));
        await activateTx.wait();
        const resolved = await registry.resolveAssetId(keccak256(toUtf8Bytes(asset.assetId)));
        await connection.execute("UPDATE assets SET tokenId = ? WHERE id = ?", [resolved.toString(), asset.rowId]);
        await input.auditSink({
          id: id(`audit-sweep-${asset.assetId}`),
          actorIdentityId: IDN.ADMIN,
          action: "ASSET_ANCHOR_CONFIRMED",
          resourceType: "ASSET",
          resourceId: asset.assetId,
          decision: "ALLOW",
          reason: `Seed sweep: REAL NFT mint confirmed on the local QBFT chain (token ${resolved}, block ${receipt.blockNumber})`,
          timestamp: new Date(),
          transactionHash: receipt.hash,
          blockNumber: receipt.blockNumber,
          metadata: { source: "seed", contract: contractAddress, tokenId: resolved.toString() },
        });
        console.log(`[seed] sweep-anchored ${asset.assetId}: token ${resolved} tx ${receipt.hash}`);
      } catch (error) {
        console.warn(`[seed] sweep anchor FAILED for ${asset.assetId}: ${error?.reason ?? error?.message ?? error}`);
      }
    }
  }

  for (const asset of input.assets) {
    const assetDigest = keccak256(toUtf8Bytes(asset.assetId));
    try {
      const existingToken = await registry.resolveAssetId(assetDigest);
      if (existingToken !== 0n) {
        // Already anchored (re-seed): reconcile the read model with the chain.
        const record = await registry.getAsset(existingToken);
        // Keep the FIRST confirmation evidence when it already exists; only
        // write a reconciliation row on a fresh database.
        await connection.execute(
          "INSERT IGNORE INTO audit_events (id, actorIdentityId, action, resourceType, resourceId, decision, reason, timestamp, transactionHash, blockNumber, metadata, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'APPLICATION')",
          [id(`audit-anchor-${asset.assetId}`), IDN.ADMIN, "ASSET_ANCHOR_RECONCILED", "ASSET", asset.assetId, "ALLOW", `Seed: asset already minted on-chain (token ${existingToken}) — read model reconciled`, new Date(), null, null, JSON.stringify({ source: "seed", tokenId: existingToken.toString(), contract: contractAddress })],
        );
        continue;
      }
      const custodianDid = input.identityDids.get(asset.custodianIdentityId);
      if (!custodianDid) throw new Error(`No DID for custodian ${asset.custodianIdentityId}`);
      const custodianWallet = deriveWallet(custodianDid);
      // The custodian identity must be registered + ACTIVE on-chain before the
      // mint (CustodianNotActive otherwise) — anchor it idempotently first.
      const identityRegistryAddress = deployment.contracts.SampraanIdentityRegistry;
      const identityArtifact = JSON.parse(readFileSync(path.join(root, "blockchain", "artifacts", "SampraanIdentityRegistry.json"), "utf8"));
      const identityRegistry = new Contract(identityRegistryAddress, identityArtifact.abi, wallet);
      const identityRecord = await identityRegistry.getIdentity(custodianWallet).catch(() => null);
      if (!identityRecord || identityRecord.status === 0n) {
        const didDigest = keccak256(toUtf8Bytes(custodianDid));
        const pkDigest = keccak256(toUtf8Bytes(`pk:${custodianDid}`));
        const regTx = await identityRegistry.registerIdentity(custodianWallet, didDigest, pkDigest);
        await regTx.wait();
      }
      const tx = await registry.registerAsset(
        assetDigest,
        custodianWallet,
        keccak256(toUtf8Bytes(asset.classification)),
        keccak256(toUtf8Bytes(asset.integrityHash ?? `asset:${asset.assetId}`)),
      );
      const receipt = await tx.wait();
      // registerAsset mints PENDING (contract design); seeded assets must be
      // ACTIVE so transfers work immediately — activate on-chain right after
      // the mint.
      const activateTx = await registry.activateAsset(await registry.resolveAssetId(assetDigest));
      await activateTx.wait();
      const resolved = await registry.resolveAssetId(assetDigest);
      await connection.execute("UPDATE assets SET tokenId = ? WHERE id = ?", [resolved.toString(), asset.rowId]);
      await input.auditSink({
        id: id(`audit-anchor-${asset.assetId}`),
        actorIdentityId: IDN.ADMIN,
        action: "ASSET_ANCHOR_CONFIRMED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "ALLOW",
        reason: `Seed: REAL NFT mint confirmed on the local QBFT chain (token ${resolved}, block ${receipt.blockNumber})`,
        timestamp: new Date(),
        transactionHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        metadata: { source: "seed", contract: contractAddress, tokenId: resolved.toString(), operator: wallet.address },
      });
      console.log(`[seed] anchored ${asset.assetId} on-chain: token ${resolved} tx ${receipt.hash}`);
    } catch (error) {
      const reason = error?.reason ?? error?.shortMessage ?? error?.message ?? String(error);
      console.warn(`[seed] anchor FAILED for ${asset.assetId}: ${reason}`);
      await input.auditSink({
        id: id(`audit-anchor-${asset.assetId}`),
        actorIdentityId: IDN.ADMIN,
        action: "BLOCKCHAIN_ANCHOR_FAILED",
        resourceType: "ASSET",
        resourceId: asset.assetId,
        decision: "DENY",
        reason: `Seed: on-chain anchor failed — ${reason}`,
        timestamp: new Date(),
        transactionHash: null,
        blockNumber: null,
        metadata: { source: "seed" },
      });
    }
  }
}

// ---------- deterministic identifiers (stable across re-runs) ----------
//
// Deterministic UUIDs derived from a stable name (keccak-based, v4-shaped per
// RFC 4122). The API schema (and the identities/assets tables' UUID columns)
// validate UUIDs, so "seed-*" string ids made the Register Asset form reject
// every seeded identity with "Invalid UUID". Deriving the uuid from the name
// keeps ids stable across re-runs AND across fresh databases.
const uuidFromName = (name) => {
  const chars = keccak256(toUtf8Bytes("sampraan-seed:" + name)).slice(2, 34).split("");
  chars[12] = "4"; // UUID version 4 nibble
  chars[16] = "8"; // RFC 4122 variant nibble
  const u = chars.join("");
  return `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20, 32)}`;
};
const id = uuidFromName;
// Permission catalog keys (UNIQUE `key` column in permissions).
const PERM_KEYS = ["identity:create","identity:read","identity:update","identity:revoke","asset:create","asset:read","asset:assign","asset:transfer","asset:revoke","audit:read","policy:create","policy:update","administration:manage"];
const IDN = {
  ADMIN: id("identity-admin"), MANAGER: id("identity-manager"),
  AUDITOR: id("identity-auditor"), USER: id("identity-user"),
};
// NOTE: users.id is INT AUTO_INCREMENT (platform schema) — it must NOT be
// supplied; users are keyed deterministically by their UNIQUE openId and the
// generated id is resolved for identities.linkedUserId below.
const USERS = {
  ADMIN: "sampraan-dev-admin", MANAGER: "sampraan-dev-manager",
  AUDITOR: "sampraan-dev-auditor", USER: "sampraan-dev-user",
};
const ASSETS = {
  FIRMWARE: id("asset-DEV-FIRMWARE-001"), INSTRUMENT: id("asset-DEV-INSTRUMENT-002"),
  SPEC: id("asset-DEV-SPEC-003"), KEYMAT: id("asset-DEV-KEYMAT-004"),
};

// ---------- permission matrix (least privilege) ----------

// ---------- helpers ----------
const upsert = async (sql, params) => connection.execute(sql, params);

try {
  await connection.beginTransaction();

  // Roles — keyed by the UNIQUE name. The id is generated/looked up by name
  // (FIX: hard-coded seed-* ids silently collided with rows already created
  // by provisioning scripts with UUID ids; the INSERT hit the UPDATE branch,
  // the seed ids never existed, and every FK into roles/permissions below
  // was silently dropped by INSERT IGNORE — leaving identities with NO
  // roles and the authorization engine denying every non-admin transfer).
  const roleDescriptions = {
    ADMIN: "Full administrative control: identities, roles, assets, policies, audit.",
    MANAGER: "Operate on permitted assets: assign and transfer custody of non-step-up assets.",
    AUDITOR: "Read-only inspection of assets, provenance, and the audit trail. No mutation.",
    USER: "Explicitly permitted operations only (asset:read). No custody mutations.",
  };
  const roleIdByName = {};
  for (const [name, description] of Object.entries(roleDescriptions)) {
    await upsert(
      "INSERT INTO roles (id, name, description) VALUES (UUID(), ?, ?) ON DUPLICATE KEY UPDATE description = VALUES(description)",
      [name, description],
    );
    const [roleRows] = await connection.execute("SELECT id FROM roles WHERE name = ?", [name]);
    if (!roleRows[0]?.id) throw new Error(`Seed failed to resolve roles.id for ${name}`);
    roleIdByName[name] = roleRows[0].id;
  }

  // Permissions — same pattern, keyed by the UNIQUE `key` column.
  const permIdByKey = {};
  for (const key of PERM_KEYS) {
    await upsert(
      "INSERT INTO permissions (id, `key`, description) VALUES (UUID(), ?, ?) ON DUPLICATE KEY UPDATE description = VALUES(description)",
      [key, `Demo permission: ${key}`],
    );
    const [permRows] = await connection.execute("SELECT id FROM permissions WHERE `key` = ?", [key]);
    if (!permRows[0]?.id) throw new Error(`Seed failed to resolve permissions.id for ${key}`);
    permIdByKey[key] = permRows[0].id;
  }

  // Role → permission matrix (least privilege); both sides resolved by name.
  const ROLE_PERMISSIONS = {
    ADMIN: ["identity:create","identity:read","identity:update","identity:revoke","asset:create","asset:read","asset:assign","asset:transfer","asset:revoke","audit:read","policy:create","policy:update","administration:manage"],
    MANAGER: ["identity:read","asset:read","asset:assign","asset:transfer","audit:read"],
    AUDITOR: ["identity:read","asset:read","audit:read"],
    USER: ["asset:read"],
  };
  for (const [roleName, keys] of Object.entries(ROLE_PERMISSIONS)) {
    for (const key of keys) {
      await upsert(
        "INSERT IGNORE INTO role_permissions (roleId, permissionId) SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = ? AND p.`key` = ?",
        [roleName, key],
      );
    }
  }

  // Identities (one per role) — all ACTIVE, with distinct fictional DIDs.
  // A previous seed revision wrote these rows under legacy non-UUID "seed-*"
  // ids, which the API's UUID validation rejects ("Invalid UUID" on the
  // Register Asset form). Assets minted under the legacy ids carry REAL
  // on-chain token ids and must be preserved, so: insert the NEW UUID
  // identities first, re-parent the legacy assets, then delete the legacy
  // identity rows (children cleaned first to satisfy FKs).
  await upsert("DELETE FROM identity_roles WHERE identityId LIKE 'seed-%'");
  await upsert("DELETE FROM asset_custody WHERE custodianIdentityId LIKE 'seed-%'");
  await upsert("DELETE FROM asset_ownership WHERE ownerIdentityId LIKE 'seed-%'");
  await upsert("DELETE FROM did_records WHERE identityId LIKE 'seed-%'");
  await upsert("DELETE FROM sessions WHERE identityId LIKE 'seed-%'");
  await upsert("UPDATE audit_events SET actorIdentityId = NULL WHERE actorIdentityId LIKE 'seed-%'");
  // Break the UNIQUE(did) collision with the legacy rows (their identity ids
  // are referenced by preserved assets, so they cannot be updated in place
  // and their dids must not collide with the new rows below). Idempotent:
  // the rename only matches rows that still carry an original (un-renamed) did.
  await upsert("UPDATE identities SET did = CONCAT('legacy:', did) WHERE id LIKE 'seed-%' AND did LIKE 'did:%'");
  const identityRows = [
    [IDN.ADMIN, "Dev Admin (Aarav Mehta)", "SAMPRAAN DEMO ORGANIZATION", "did:sampraan:dev-admin-aarav", "ACTIVE"],
    [IDN.MANAGER, "Dev Manager (Ananya Rao)", "SAMPRAAN DEMO ORGANIZATION", "did:sampraan:dev-manager-ananya", "ACTIVE"],
    [IDN.AUDITOR, "Dev Auditor (Vikram Singh)", "SAMPRAAN DEMO ORGANIZATION", "did:sampraan:dev-auditor-vikram", "ACTIVE"],
    [IDN.USER, "Dev User (Riya Kulkarni)", "SAMPRAAN DEMO ORGANIZATION", "did:sampraan:dev-user-riya", "ACTIVE"],
  ];
  for (const [identityId, displayName, organization, did, status] of identityRows) {
    await upsert(
      "INSERT INTO identities (id, displayName, organization, status, did) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE displayName = VALUES(displayName), organization = VALUES(organization), status = VALUES(status)",
      [identityId, displayName, organization, status, did],
    );
  }
  // Re-parent legacy-id assets to the new UUID identities, then remove the
  // legacy identity rows (the API can never address "seed-*" ids).
  await upsert("UPDATE assets SET custodianIdentityId = ? WHERE custodianIdentityId LIKE 'seed-%' AND assetId IN ('DEV-FIRMWARE-001','DEV-INSTRUMENT-002')", [IDN.MANAGER]);
  await upsert("UPDATE assets SET custodianIdentityId = ? WHERE custodianIdentityId LIKE 'seed-%' AND assetId = 'DEV-SPEC-003'", [IDN.AUDITOR]);
  await upsert("UPDATE assets SET custodianIdentityId = ?, ownerIdentityId = ? WHERE custodianIdentityId LIKE 'seed-%'", [IDN.ADMIN, IDN.ADMIN]);
  await upsert("UPDATE assets SET ownerIdentityId = ? WHERE ownerIdentityId LIKE 'seed-%'", [IDN.ADMIN]);
  await upsert("DELETE FROM identities WHERE id LIKE 'seed-%'");
  // ---- legacy ASSET id migration (same pattern as identities) ----
  // Assets minted under legacy ids carry REAL on-chain token ids: copy them
  // (including tokenId) into fresh UUID-keyed rows, then drop the legacy rows.
  // Idempotent rename (only un-renamed original assetIds match 'DEV-...').
  await upsert("UPDATE assets SET assetId = CONCAT('legacy:', assetId) WHERE id LIKE 'seed-%' AND assetId LIKE 'DEV-%'");
  for (const legacyAssetId of ["DEV-FIRMWARE-001", "DEV-INSTRUMENT-002", "DEV-SPEC-003", "DEV-KEYMAT-004"]) {
    await upsert(
      "INSERT INTO assets (id, assetId, name, type, classification, description, ownerIdentityId, custodianIdentityId, integrityHash, tokenId, status) " +
      "SELECT ?, ?, name, type, classification, description, ownerIdentityId, custodianIdentityId, integrityHash, tokenId, status FROM assets WHERE assetId = ? " +
      "AND NOT EXISTS (SELECT 1 FROM assets cur WHERE cur.assetId = ?)",
      [id(`asset-${legacyAssetId}`), legacyAssetId, `legacy:${legacyAssetId}`, legacyAssetId],
    );
  }
  await upsert("DELETE FROM asset_ownership WHERE assetId LIKE 'seed-%'");
  await upsert("DELETE FROM asset_custody WHERE assetId LIKE 'seed-%'");
  await upsert("DELETE FROM security_alerts WHERE assetId LIKE 'seed-%'");
  await upsert("DELETE FROM assets WHERE id LIKE 'seed-%'");

  // Platform users with scrypt-hashed local passwords, linked to identities.
  // users.role is the PLATFORM role (admin gates adminProcedure); the SAMPRAAN
  // domain authorization uses identity_roles above. Only the admin account gets
  // platform admin; the others are platform users whose SAMPRAAN identities
  // carry their domain roles.
  const accountSpecs = [
    [USERS.ADMIN, "Dev Admin", "admin@sampraan.dev", "admin", IDN.ADMIN, "SampraanAdmin#2026"],
    [USERS.MANAGER, "Dev Manager", "manager@sampraan.dev", "user", IDN.MANAGER, "SampraanManager#2026"],
    [USERS.AUDITOR, "Dev Auditor", "auditor@sampraan.dev", "user", IDN.AUDITOR, "SampraanAuditor#2026"],
    [USERS.USER, "Dev User", "user@sampraan.dev", "user", IDN.USER, "SampraanUser#2026"],
  ];
  for (const [openId, name, email, role, identityId, password] of accountSpecs) {
    const passwordHash = await hashPassword(password);
    // Upsert by the UNIQUE openId; never write the auto-increment id.
    await upsert(
      "INSERT INTO users (openId, name, email, loginMethod, role, passwordHash) VALUES (?, ?, ?, 'password', ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), email = VALUES(email), role = VALUES(role), passwordHash = VALUES(passwordHash)",
      [openId, name, email, role, passwordHash],
    );
    const [rows] = await connection.execute("SELECT id FROM users WHERE openId = ?", [openId]);
    const linkedUserId = rows[0]?.id;
    if (!linkedUserId) throw new Error(`Seed failed to resolve users.id for ${openId}`);
    await upsert("UPDATE identities SET linkedUserId = ? WHERE id = ?", [linkedUserId, identityId]);
  }

  // Identity roles (resolved by role NAME — see the roles fix above).
  const identityRoleRows = [
    [IDN.ADMIN, "ADMIN"], [IDN.MANAGER, "MANAGER"],
    [IDN.AUDITOR, "AUDITOR"], [IDN.USER, "USER"],
  ];
  for (const [identityId, roleName] of identityRoleRows) {
    await upsert(
      "INSERT IGNORE INTO identity_roles (identityId, roleId) SELECT ?, id FROM roles WHERE name = ?",
      [identityId, roleName],
    );
  }

  // Assets (fictional, varied classifications; owner=admin identity, custodians spread)
  const assetRows = [
    [ASSETS.FIRMWARE, "DEV-FIRMWARE-001", "Restricted Firmware Package (Demo)", "FIRMWARE", "HIGHLY_SENSITIVE", "Fictional firmware artifact for the step-up CHALLENGE demonstration.", IDN.ADMIN, IDN.MANAGER, "sha256:demo-firmware-integrity", "ACTIVE"],
    [ASSETS.INSTRUMENT, "DEV-INSTRUMENT-002", "Environmental Test Instrument (Demo)", "INSTRUMENT", "CONTROLLED", "Fictional test instrument for the ALLOW transfer demonstration.", IDN.ADMIN, IDN.MANAGER, "sha256:demo-instrument-integrity", "ACTIVE"],
    [ASSETS.SPEC, "DEV-SPEC-003", "Radar Interface Specification (Demo)", "DOCUMENT", "SENSITIVE", "Fictional design document; custody with the auditor for review.", IDN.ADMIN, IDN.AUDITOR, "sha256:demo-spec-integrity", "ACTIVE"],
    [ASSETS.KEYMAT, "DEV-KEYMAT-004", "Signing Key Material Reference (Demo)", "KEY_MATERIAL", "CRITICAL", "Fictional key-material reference record (contents never on-chain).", IDN.ADMIN, IDN.ADMIN, "sha256:demo-keymat-integrity", "ACTIVE"],
  ];
  for (const [rowId, assetId, name, type, classification, description, ownerId, custodianId, integrityHash, status] of assetRows) {
    await upsert(
      "INSERT INTO assets (id, assetId, name, type, classification, description, ownerIdentityId, custodianIdentityId, integrityHash, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), status = VALUES(status), custodianIdentityId = VALUES(custodianIdentityId)",
      [rowId, assetId, name, type, classification, description, ownerId, custodianId, integrityHash, status],
    );
  }

  // Ownership + custody history rows (idempotent: only insert when none open)
  await upsert(
    "INSERT INTO asset_ownership (id, assetId, ownerIdentityId) SELECT ?, ?, ? FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM asset_ownership WHERE assetId = ? AND endedAt IS NULL)",
    [id("own-firmware"), ASSETS.FIRMWARE, IDN.ADMIN, ASSETS.FIRMWARE],
  );
  const custodySpecs = [
    ["cust-firmware", ASSETS.FIRMWARE, IDN.MANAGER, "Seed custody: manager holds the firmware package"],
    ["cust-instrument", ASSETS.INSTRUMENT, IDN.MANAGER, "Seed custody: manager holds the test instrument"],
    ["cust-spec", ASSETS.SPEC, IDN.AUDITOR, "Seed custody: auditor reviews the specification"],
    ["cust-keymat", ASSETS.KEYMAT, IDN.ADMIN, "Seed custody: admin retains key material reference"],
  ];
  for (const [custodyId, assetId, custodianId, reason] of custodySpecs) {
    await upsert(
      "INSERT INTO asset_custody (id, assetId, custodianIdentityId, reason) SELECT ?, ?, ?, ? FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM asset_custody WHERE assetId = ? AND endedAt IS NULL)",
      [id(custodyId), assetId, custodianId, reason, assetId],
    );
  }

  // DID records for the identities
  for (const [identityId, , , did] of identityRows) {
    await upsert(
      "INSERT INTO did_records (id, identityId, did, method, subject, document, status) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE') ON DUPLICATE KEY UPDATE status = 'ACTIVE'",
      [id(`did-${did.slice(-6)}`), identityId, did, "sampraan", did, JSON.stringify({ id: did, verificationMethod: [] })],
    );
  }

  // REAL on-chain anchoring of seeded assets (never faked): every seeded asset
  // is minted on the local Besu QBFT chain through the DEPLOYED
  // SampraanAssetRegistry with the operator key from .env. A seeded asset
  // without real chain state would revert the very first transfer with
  // AssetNotRegistered — so the seed anchors each asset once and stores the
  // REAL token id + transaction hash in the read model and the audit trail.
  await anchorAssets({
    assets: assetRows.map(([rowId, assetId, , , classification, , , custodianId, integrityHash]) => ({
      rowId, assetId, classification, custodianIdentityId: custodianId, integrityHash,
    })),
    identityDids: new Map(identityRows.map(row => [row[0], row[3]])),
    identityDisplayNames: new Map(identityRows.map(row => [row[0], row[1]])),
    auditSink: async (event) => {
      await upsert(
        "INSERT INTO audit_events (id, actorIdentityId, action, resourceType, resourceId, decision, reason, timestamp, transactionHash, blockNumber, metadata, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'APPLICATION') ON DUPLICATE KEY UPDATE reason = VALUES(reason), transactionHash = VALUES(transactionHash), blockNumber = VALUES(blockNumber)",
        [event.id, event.actorIdentityId, event.action, event.resourceType, event.resourceId, event.decision, event.reason, event.timestamp, event.transactionHash, event.blockNumber, JSON.stringify(event.metadata)],
      );
    },
  });

  // Policy catalog row (catalog display; the engine's rules are code).
  await upsert(
    "INSERT INTO policies (id, name, description, subjectRole, resourceType, action, assetClassification, effect, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE description = VALUES(description)",
    [id("policy-high-sens"), "Highly sensitive transfer guard (demo catalog)", "Users cannot transfer HIGHLY_SENSITIVE assets; other roles require step-up.", "USER", "ASSET", "TRANSFER", "HIGHLY_SENSITIVE", "DENY", 1],
  );

  // Audit history rows (marked as seed-sourced so they are never mistaken for live chain evidence)
  const seedAudit = [
    [id("audit-seed-1"), IDN.ADMIN, "IDENTITY_CREATED", "IDENTITY", IDN.MANAGER, "ALLOW", "Seed: manager identity registered", { source: "seed", note: "Fictional development data" }],
    [id("audit-seed-2"), IDN.ADMIN, "ROLE_ASSIGNED", "IDENTITY", IDN.MANAGER, "ALLOW", "Seed: MANAGER role assigned", { source: "seed", note: "Fictional development data" }],
    [id("audit-seed-3"), IDN.ADMIN, "ASSET_CREATED", "ASSET", "DEV-INSTRUMENT-002", "ALLOW", "Seed: instrument asset registered", { source: "seed", note: "Fictional development data" }],
    [id("audit-seed-4"), IDN.MANAGER, "ASSET_ASSIGNED", "ASSET", "DEV-SPEC-003", "ALLOW", "Seed: specification placed with the auditor", { source: "seed", note: "Fictional development data" }],
  ];
  for (const [eventId, actorId, action, resourceType, resourceId, decision, reason, metadata] of seedAudit) {
    await upsert(
      "INSERT INTO audit_events (id, actorIdentityId, action, resourceType, resourceId, decision, reason, metadata, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APPLICATION') ON DUPLICATE KEY UPDATE reason = VALUES(reason)",
      [eventId, actorId, action, resourceType, resourceId, decision, reason, JSON.stringify(metadata)],
    );
  }

  await connection.commit();
  console.log("Deterministic SAMPRAAN development seed applied (idempotent).");
  console.log("Local accounts (fictional, dev-only):");
  console.log("  admin@sampraan.dev   / SampraanAdmin#2026   (ADMIN)");
  console.log("  manager@sampraan.dev / SampraanManager#2026 (MANAGER)");
  console.log("  auditor@sampraan.dev / SampraanAuditor#2026 (AUDITOR)");
  console.log("  user@sampraan.dev    / SampraanUser#2026    (USER)");
} catch (error) {
  await connection.rollback();
  throw error;
} finally {
  await connection.end();
}
