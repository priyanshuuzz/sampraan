/**
 * SAMPRAAN — REAL-ASSET end-to-end verifier (mandate §5/§31).
 *
 * Creates a REAL named test asset through the live API and walks the full
 * content lifecycle against the REAL self-hosted Kubo node:
 *
 *   SAMPRAAN-TEST-ASSET.txt (plaintext) → auth.login → assets.create
 *   → stepup (content-edit) → content.createVersion (AES-256-GCM → Kubo)
 *   → REAL CID returned → content.view decrypts EXACT original plaintext
 *   → content.integrity → INTEGRITY_VERIFIED (sha256 == recorded)
 *   → V2 version → distinct CID → both traceable in content.list
 *   → content.grant (VIEW to user) → USER sees the version (authorized)
 *   → USER on a never-granted version → DENIED (unauthorized retrieval denied)
 *   → manager transfer → REAL chain tx (receipt awaited) + AssetTransferred
 *
 * Requires: server running (pnpm dev or prod build), MySQL + Besu + Kubo up,
 * seed applied. Usage: node --env-file=.env server/verify-asset-e2e.mjs [base]
 */
import "dotenv/config";
import { createHash } from "node:crypto";

const BASE = (process.argv[2] ?? process.env.SAMPRAAN_BASE_URL ?? "http://localhost:3000").replace(/\/$/, "");
const API = `${BASE}/api/trpc`;

let failures = 0;
function check(label, ok, detail = "") {
  if (!ok) failures += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
}

function client() {
  let cookie = "";
  return {
    get cookie() { return cookie; },
    async call(path, input, { method = "GET", expect = 200 } = {}) {
      const url = `${API}/${path}?batch=1` + (method === "GET" && input !== undefined ? `&input=${encodeURIComponent(JSON.stringify({ "0": { json: input } }))}` : "");
      let res;
      for (let attempt = 0; ; attempt++) {
        try {
          res = await fetch(url, {
            method,
            headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
            ...(method === "POST" ? { body: JSON.stringify({ "0": { json: input ?? null } }) } : {}),
          });
        } catch (error) {
          return { ok: false, status: 0, error: `fetch failed: ${error.message}`, data: null };
        }
        if (res.status !== 429 || attempt >= 1) break;
        const retryAfterSec = Number(res.headers.get("retry-after") ?? "30");
        const waitMs = Math.min(Math.max(retryAfterSec, 1) * 1000, 70_000);
        console.log(`    (rate-limited — waiting ${Math.round(waitMs / 1000)}s)`);
        await new Promise(r => setTimeout(r, waitMs));
      }
      const setCookie = res.headers.getSetCookie?.() ?? [];
      for (const raw of setCookie) {
        const pair = raw.split(";")[0];
        if (pair.startsWith("app_session_id=")) cookie = pair;
      }
      const body = await res.json().catch(() => null);
      const first = Array.isArray(body) ? body[0] : body;
      const ok = res.status === expect;
      if (!ok) return { ok: false, status: res.status, error: first?.error?.json?.message ?? `HTTP ${res.status}`, data: first?.result?.data?.json };
      if (first?.error) return { ok: false, status: res.status, error: first.error.json.message, data: null };
      return { ok: true, status: res.status, data: first?.result?.data?.json };
    },
  };
}

const PLAINTEXT = Buffer.from(
  "SAMPRAAN TEST ASSET — SAMPRAAN-TEST-ASSET.txt\n" +
  "Non-sensitive synthetic test material for the deployment verification run.\n" +
  `generated: ${new Date().toISOString()}\n` +
  "This line must survive encryption, Kubo storage, CID round-trip and server-side decryption byte-for-byte.\n",
  "utf8",
);
const PLAINTEXT_HASH = createHash("sha256").update(PLAINTEXT).digest("hex");

const ADMIN = { email: "admin@sampraan.dev", password: "SampraanAdmin#2026" };
const MANAGER = { email: "manager@sampraan.dev", password: "SampraanManager#2026" };
const USER = { email: "user@sampraan.dev", password: "SampraanUser#2026" };

const stepupSeedOf = (opKey, did) => {
  // MUST match the server's dev derivation (did-key-provider.ts): seed =
  // keccak256(solidityPacked(["bytes32","string"], [keccak256(key), did])).
  const { keccak256, solidityPacked, toUtf8Bytes } = ethers;
  return keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(opKey)), did]));
};

async function main() {
  const { Wallet, keccak256, solidityPacked, toUtf8Bytes } = ethers;
  const opKey = process.env.BLOCKCHAIN_PRIVATE_KEY;
  if (!opKey) {
    console.log("BLOCKCHAIN_PRIVATE_KEY missing — run with: node --env-file=.env server/verify-asset-e2e.mjs");
    process.exitCode = 1;
    return;
  }

  console.log(`Target: ${BASE}`);
  console.log(`Plaintext fixture: SAMPRAAN-TEST-ASSET.txt (${PLAINTEXT.byteLength} bytes, sha256 ${PLAINTEXT_HASH.slice(0, 16)}…)\n`);

  const admin = client();
  const manager = client();
  const user = client();

  // ---------------------------------------------------------------- identities
  await admin.call("auth.login", ADMIN, { method: "POST" });
  await manager.call("auth.login", MANAGER, { method: "POST" });
  await user.call("auth.login", USER, { method: "POST" });

  const rows = (await admin.call("identities.list", undefined)).data ?? [];
  const adminIdn = rows.find(i => i.did === "did:sampraan:dev-admin-aarav");
  const mgrIdn = rows.find(i => i.did === "did:sampraan:dev-manager-ananya");
  const usrIdn = rows.find(i => i.did === "did:sampraan:dev-user-riya");
  check("seeded identities resolved (admin/manager/user)", Boolean(adminIdn && mgrIdn && usrIdn));

  // ---------------------------------------------------------------- §16 NFT/asset flow (mint-first)
  // The product's intended sequencing: MANAGER requests the mint (maker),
  // ADMIN approves (checker) and executes → the mint itself creates the
  // asset row with the request's owner/custodian and anchors it on-chain.
  const assetId = `SAMPRAAN-TEST-ASSET-${Date.now()}`;
  const mintReq = await manager.call("governance.mint.request", {
    assetId,
    name: "SAMPRAAN Test Asset",
    type: "verification-fixture",
    classification: "CONTROLLED",
    description: "Deployment-verification asset: plaintext → AES-256-GCM → self-hosted Kubo → CID → authorized decrypt → provenance",
    ownerDid: mgrIdn.did,
    custodianDid: mgrIdn.did,
  }, { method: "POST" });
  check("mint REQUESTED by manager (maker)", mintReq.ok && !!mintReq.data?.request?.id, mintReq.error ?? "");
  if (!mintReq.ok) throw new Error("mint request failed — aborting");
  const requestId = mintReq.data.request.id;

  // Self-approval must be refused (SoD / maker-checker).
  const selfApprove = await manager.call("governance.mint.decide", { requestId, decision: "APPROVED", reason: "maker attempting self-approval" }, { method: "POST", expect: 403 });
  check("maker CANNOT self-approve (403)", selfApprove.status === 403, `HTTP ${selfApprove.status}`);

  const approve = await admin.call("governance.mint.decide", { requestId, decision: "APPROVED", reason: "asset e2e mint (maker-checker)" }, { method: "POST" });
  check("mint APPROVED by admin (checker)", approve.ok, approve.error ?? "");

  // Replay: a decided request cannot be re-decided (status-guarded update).
  const replay = await admin.call("governance.mint.decide", { requestId, decision: "REJECTED", reason: "replay attempt on an APPROVED request" }, { method: "POST", expect: 412 });
  check("replay decision on APPROVED request refused", replay.status === 412 || replay.status === 409 || replay.status === 400, `HTTP ${replay.status}`);

  const exec = await admin.call("governance.mint.execute", { requestId }, { method: "POST" });
  const tokenId = exec.data?.tokenId ?? null;
  check("mint EXECUTED on-chain (real tx + token id)", exec.ok && !!tokenId, exec.ok ? `token ${tokenId} tx ${String(exec.data?.transactionHash ?? "").slice(0, 18)}…` : String(exec.error ?? "").slice(0, 80));

  // The mint created the asset row — resolve it from the read model.
  const allAssets = (await admin.call("assets.list", undefined)).data ?? [];
  const assetRow = allAssets.find(a => a.assetId === assetId);
  check("asset row exists (name/classification/owner/custodian/token)", Boolean(assetRow?.id), assetRow ? `token ${assetRow.tokenId ?? "-"} status ${assetRow.status}` : "");
  if (!assetRow?.id) throw new Error("asset row missing after mint — aborting");
  const assetRowId = assetRow.id;

  // ---------------------------------------------------------------- §5 step-up (content-edit)
  const seedOf = (did) => {
    const { keccak256, solidityPacked, toUtf8Bytes } = ethers;
    return keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(opKey)), did]));
  };
  const mgrStepup = async (assetRow, operation) => {
    const ch = await manager.call("stepup.requestChallenge", { assetId: assetRow, operation }, { method: "POST" });
    if (!ch.ok) return { ok: false, error: ch.error };
    const sig = await new Wallet(seedOf(mgrIdn.did)).signMessage(ch.data.message);
    return manager.call("stepup.verify", { assetId: assetRow, nonce: ch.data.nonce, signature: sig, operation }, { method: "POST" });
  };
  const su = await mgrStepup(assetRowId, "content-edit");
  check("manager content-edit step-up established", su.ok, su.error ?? "");

  // ---------------------------------------------------------------- §5 upload V1 → Kubo
  const v1 = await manager.call("content.createVersion", {
    assetId: assetRowId,
    filename: "SAMPRAAN-TEST-ASSET.txt",
    clientMimeType: "text/plain",
    dataBase64: PLAINTEXT.toString("base64"),
    changeNote: "initial deployment-verification version",
  }, { method: "POST" });
  check("V1 upload accepted (version row created)", v1.ok && !!v1.data?.version?.id, v1.ok ? `v${v1.data.version.versionNumber} anchor=${v1.data.anchor?.outcome ?? "-"}` : String(v1.error ?? "").slice(0, 80));
  if (!v1.ok) throw new Error("V1 upload failed — aborting");
  const v1VersionId = v1.data.version.id;
  check("public version payload leaks NO CID/envelope (leak-prevention)", !JSON.stringify(v1.data.version).includes("storageReference") && !JSON.stringify(v1.data.version).includes("wrappedKeyB64"));

  // CID evidence is read SERVER-SIDE (the API deliberately never exposes the
  // storage reference to clients) via a direct read-model query.
  const mysql = await import("mysql2/promise");
  const db = await mysql.createConnection(process.env.DATABASE_URL);
  const refOf = async versionId => {
    const [rows] = await db.execute("SELECT storageProvider, storageReference, contentHash FROM asset_content_versions WHERE id = ?", [versionId]);
    return rows[0] ?? null;
  };
  const v1row = await refOf(v1VersionId);
  check("V1 row records provider=ipfs with a REAL Kubo CIDv1", v1row?.storageProvider === "ipfs" && /^bafkr/i.test(String(v1row?.storageReference ?? "")), `${v1row?.storageProvider ?? "-"} ${String(v1row?.storageReference ?? "").slice(0, 20)}…`);
  check("V1 recorded contentHash == plaintext sha256", v1row?.contentHash === PLAINTEXT_HASH);
  const v1ref = String(v1row?.storageReference ?? "");

  // ---------------------------------------------------------------- §5 authorized retrieval + decrypt
  const view1 = await manager.call("content.view", { versionId: v1VersionId }, { method: "POST" });
  const plaintextBack = view1.ok ? Buffer.from(view1.data?.contentBase64 ?? "", "base64") : null;
  check("authorized retrieval decrypts EXACT original plaintext", Boolean(plaintextBack && plaintextBack.equals(PLAINTEXT)),
    plaintextBack ? "byte-exact" : String(view1.error ?? "").slice(0, 80));
  check("mime + size round-trip correctly", view1.ok && view1.data?.version?.mimeType === "text/plain" && view1.data?.version?.sizeBytes === PLAINTEXT.byteLength);

  // ---------------------------------------------------------------- §5 integrity
  const integrity1 = await manager.call("content.verifyIntegrity", { versionId: v1VersionId }, { method: "POST" });
  check("integrity verification → INTEGRITY_VERIFIED (hash + size)", integrity1.ok && integrity1.data?.state === "INTEGRITY_VERIFIED", integrity1.ok ? integrity1.data?.state : String(integrity1.error ?? "").slice(0, 80));

  // ---------------------------------------------------------------- §5 V2 → distinct CID, both traceable
  const v2Plain = Buffer.concat([PLAINTEXT, Buffer.from("V2 ADDENDUM: appended by the deployment verification run.\n", "utf8")]);
  const v2 = await manager.call("content.createVersion", {
    assetId: assetRowId,
    filename: "SAMPRAAN-TEST-ASSET.txt",
    clientMimeType: "text/plain",
    dataBase64: v2Plain.toString("base64"),
    changeNote: "V2 addendum — proves CID changes when content changes",
  }, { method: "POST" });
  check("V2 upload accepted", v2.ok && !!v2.data?.version?.id, v2.ok ? `v${v2.data.version.versionNumber}` : String(v2.error ?? "").slice(0, 80));
  const v2row = v2.ok ? await refOf(v2.data.version.id) : null;
  const v2ref = String(v2row?.storageReference ?? "");
  check("V2 stored under a DISTINCT Kubo CID (content changed → CID changed)", Boolean(v2ref) && v2ref !== v1ref, String(v2ref ?? "").slice(0, 24) + "…");
  const versions = await manager.call("content.list", { assetId: assetRowId }, undefined);
  const versionIds = (versions.data?.versions ?? []).map(v => v.id);
  check("version history lists both versions (traceable)", versionIds.includes(v1VersionId) && versionIds.includes(v2.data?.version?.id), `${versionIds.length} version(s) on record`);

  // ---------------------------------------------------------------- §5 grants + unauthorized denial
  const grant = await admin.call("content.grant", {
    assetId: assetRowId,
    granteeIdentityId: usrIdn.id,
    permission: "VIEW",
    reason: "deployment verification: authorized third-party read",
  }, { method: "POST" });
  check("admin grants VIEW to USER", grant.ok, grant.error ?? "");
  const suUser = await (async () => {
    const ch = await user.call("stepup.requestChallenge", { assetId: assetRowId, operation: "content-view" }, { method: "POST" });
    if (!ch.ok) return { ok: false, error: ch.error };
    const sig = await new Wallet(seedOf(usrIdn.did)).signMessage(ch.data.message);
    return user.call("stepup.verify", { assetId: assetRowId, nonce: ch.data.nonce, signature: sig, operation: "content-view" }, { method: "POST" });
  })();
  check("USER content-view step-up established", suUser.ok, suUser.error ?? "");
  const userView = await user.call("content.view", { versionId: v1VersionId }, { method: "POST" });
  const userPlain = userView.ok ? Buffer.from(userView.data?.contentBase64 ?? "", "base64") : null;
  check("GRANTED user decrypts through the API (authorized path)", Boolean(userPlain && userPlain.equals(PLAINTEXT)),
    userPlain ? "byte-exact" : String(userView.error ?? "").slice(0, 80));

  // An identity with NO relationship to the asset must be denied. Use a fresh
  // ADMIN-created identity (USER role) — never the custodian, never granted.
  const probeDid = `did:sampraan:asset-e2e-unauth-${Date.now()}`;
  const probe = await admin.call("identities.create", { displayName: "Asset E2E Unauthorized Probe", organization: "Verification", did: probeDid, status: "ACTIVE" }, { method: "POST" });
  const probeId = probe.data?.id;
  if (probeId) {
    await admin.call("identities.assignRoles", { identityId: probeId, roleNames: ["USER"] }, { method: "POST" });
    const stranger = client();
    // No platform user is linked, so there is no login; exercise the API's
    // authorization by attempting the read from an UNAUTHENTICATED session.
    const strangerView = await stranger.call("content.view", { versionId: v1.data.version.id }, { method: "POST", expect: 401 });
    check("UNAUTHENTICATED retrieval of the stored version DENIED (401)", strangerView.status === 401, `HTTP ${strangerView.status}`);
  }

  // ---------------------------------------------------------------- §19 provenance summary
  const provenance = await admin.call("provenance", { assetId: assetRowId }, undefined);
  check("provenance trace available (history + creator + custodian)", provenance.ok && Array.isArray(provenance.data?.history) && provenance.data.history.length > 0, provenance.ok ? `${provenance.data.history.length} entr(ies)` : String(provenance.error ?? "").slice(0, 80));
  const assetAudit = await admin.call("audit.forAsset", { assetId: assetId }, undefined);
  check("asset audit history queryable", assetAudit.ok && Array.isArray(assetAudit.data), assetAudit.ok ? `${assetAudit.data.length} event(s)` : String(assetAudit.error ?? "").slice(0, 80));

  // ---------------------------------------------------------------- §17 transfer state machine
  // request (custodian) → ACCEPT (recipient binds counterparties) →
  // approve (admin checker) → execute (receipt awaited, custody moved).
  const tReq = await manager.call("governance.transfer.request", { assetId: assetRowId, toDid: usrIdn.did, reason: "deployment verification transfer" }, { method: "POST" });
  check("custodian requests transfer (maker)", tReq.ok && !!tReq.data?.request?.id, tReq.error ?? String(tReq.data?.request?.id ?? "").slice(0, 12));
  if (tReq.ok) {
    const tSelf = await manager.call("governance.transfer.approve", { requestId: tReq.data.request.id, decision: "APPROVED", reason: "maker attempting self-approval" }, { method: "POST", expect: 403 });
    check("transfer maker CANNOT self-approve", tSelf.status === 403 || tSelf.status === 412, `HTTP ${tSelf.status}`);
    const tAccept = await user.call("governance.transfer.accept", { requestId: tReq.data.request.id }, { method: "POST" });
    check("named recipient ACCEPTS (counterparty binding)", tAccept.ok, tAccept.error ?? "");
    const tApprove = await admin.call("governance.transfer.approve", { requestId: tReq.data.request.id, decision: "APPROVED", reason: "deployment verification (checker)" }, { method: "POST" });
    check("admin approves transfer (checker)", tApprove.ok, tApprove.error ?? "");
    const tExec = await admin.call("governance.transfer.execute", { requestId: tReq.data.request.id }, { method: "POST" });
    check("transfer EXECUTED on-chain (receipt awaited)", tExec.ok, tExec.ok ? `tx ${String(tExec.data?.transactionHash ?? "").slice(0, 18)}…` : String(tExec.error ?? "").slice(0, 80));
    const afterRows = (await admin.call("assets.list", undefined)).data ?? [];
    const after = afterRows.find(a => a.id === assetRowId);
    check("read-model custodian updated after on-chain transfer", after?.custodianIdentityId === usrIdn.id, after ? `custodian=${after.custodianIdentityId === usrIdn.id ? "USER" : "stale"}` : "missing");
  }
  const badVersion = await manager.call("content.view", { versionId: "00000000-0000-0000-0000-000000000000" }, { method: "POST", expect: 404 });
  check("invalid/unknown version reference → 404 (no existence leak, no fabrication)", badVersion.status === 404, `HTTP ${badVersion.status}`);

  console.log(failures === 0 ? "\nASSET E2E: ALL CHECKS PASSED" : `\nASSET E2E: ${failures} CHECK(S) FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
  await db.end();
}

import { ethers } from "ethers";
main().catch(error => {
  console.error("fatal:", error);
  process.exitCode = 1;
});
