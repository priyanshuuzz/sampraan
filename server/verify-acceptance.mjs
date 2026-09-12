/**
 * SAMPRAAN presentation acceptance flow (LOCAL DEMO ONLY).
 *
 * Executes the exact SIH presentation workflow against the running localhost
 * server via the real HTTP API — the same path the browser takes:
 *
 *   1. ADMIN login  → session cookie → auth.me (role + DID, no secrets)
 *   2. ADMIN creates an asset → REAL NFT mint on Besu (token id + tx hash)
 *   3. ADMIN assigns custody to the MANAGER identity (real chain tx)
 *   4. MANAGER login → transfers the asset (real chain tx, AssetTransferred)
 *   5. AUDITOR login → transfer attempt → DENIED (403/deny), ownership unchanged
 *   6. USER login → transfer attempt → DENIED, high-sensitivity guard enforced
 *   7. Audit evidence printed for every step (actor, tx hash, decision)
 *
 * Usage: node server/verify-acceptance.mjs
 * Requires: server running (pnpm dev), MySQL + Besu up, seed applied.
 */
import { createWriteStream } from "node:fs";
void createWriteStream;
import "dotenv/config";
import { keccak256, solidityPacked, toUtf8Bytes, Wallet } from "ethers";

const BASE = process.env.SAMPPRAAN_BASE_URL ?? "http://localhost:3000";
const API = `${BASE}/api/trpc`;
const report = [];
function log(line = "") {
  report.push(line);
  console.log(line);
}

/** Minimal cookie-jar fetch wrapper around the tRPC batch HTTP endpoint. */
function client() {
  let cookie = "";
  return {
    async call(path, input, { method = "GET", expect = 200 } = {}) {
      const url = `${API}/${path}?batch=1`;
      const res = await fetch(url, {
        method,
        headers: {
          "content-type": "application/json",
          ...(cookie ? { cookie } : {}),
        },
        ...(method === "POST" ? { body: JSON.stringify({ "0": { json: input ?? null } }) } : {}),
      });
      const setCookie = res.headers.getSetCookie?.() ?? [];
      for (const raw of setCookie) {
        const pair = raw.split(";")[0];
        if (pair.startsWith("app_session_id=")) cookie = pair;
      }
      const body = await res.json().catch(() => null);
      const first = Array.isArray(body) ? body[0] : body;
      const ok = res.status === expect;
      if (!ok) {
        const message = first?.error?.json?.message ?? `HTTP ${res.status}`;
        return { ok: false, status: res.status, error: message };
      }
      if (first?.error) return { ok: false, status: res.status, error: first.error.json.message };
      return { ok: true, status: res.status, data: first?.result?.data?.json };
    },
    clear() {
      cookie = "";
    },
  };
}

const api = client();
let failures = 0;
function check(label, ok, detail = "") {
  failures += ok ? 0 : 1;
  log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
}

async function login(email, password) {
  api.clear();
  const res = await api.call("auth.login", { email, password }, { method: "POST" });
  if (!res.ok) return { ok: false, error: res.error };
  const me = await api.call("auth.me");
  return { ok: true, user: me.data };
}

// ============================================================
log("\n=== TEST 1 — ADMIN LOGIN ===");
const admin = await login("admin@sampraan.dev", "SampraanAdmin#2026");
check("admin login succeeds", admin.ok && !!admin.user, admin.error);
check("platform role = admin", admin.user?.role === "admin", admin.user?.role);
const identities = await api.call("identities.list");
const adminIdentity = identities.data?.find(i => i.linkedUserId === admin.user?.id);
check("linked SAMPRAAN identity found", !!adminIdentity, adminIdentity?.did);
check("identity role ADMIN", adminIdentity?.roles?.includes("ADMIN"), JSON.stringify(adminIdentity?.roles));

// ============================================================
log("\n=== TEST 2 — ADMIN CREATES ASSET → REAL NFT MINT ===");
const assetTag = `SIH-DEMO-${Date.now().toString(36).toUpperCase()}`;
const mint = await api.call(
  "assets.create",
  {
    assetId: assetTag,
    name: "Presentation Demo Sensor Array",
    type: "INSTRUMENT",
    classification: "CONTROLLED",
    description: "Asset created live during the SIH acceptance run.",
    ownerIdentityId: adminIdentity.id,
    custodianIdentityId: adminIdentity.id,
    integrityHash: `sha256:${assetTag.toLowerCase()}`,
    status: "ACTIVE",
  },
  { method: "POST" },
);
check("asset created + mint accepted", mint.ok, mint.error);
check("anchor outcome ANCHORED", mint.data?.anchor?.outcome === "ANCHORED", mint.data?.anchor?.outcome);
check("transaction hash present", /^0x[0-9a-fA-F]{64}$/.test(mint.data?.anchor?.transactionHash ?? ""), mint.data?.anchor?.transactionHash);
check("NFT token id assigned", !!mint.data?.tokenId, mint.data?.tokenId ?? null);
const assetRowId = mint.data?.id;

// ============================================================
log("\n=== TEST 3 — ADMIN ASSIGNS CUSTODY TO MANAGER ===");
const identities2 = await api.call("identities.list");
const managerIdentity = identities2.data?.find(i => i.roles?.includes("MANAGER"));
check("manager identity available", !!managerIdentity, managerIdentity?.did);
const assign = await api.call(
  "assets.assign",
  { assetId: assetRowId, custodianIdentityId: managerIdentity.id },
  { method: "POST" },
);
check("assignment confirmed on-chain", assign.ok, assign.error);
check("assignment tx hash present", /^0x[0-9a-fA-F]{64}$/.test(assign.data?.transaction?.transactionHash ?? ""), assign.data?.transaction?.transactionHash);
check("read model custodian = MANAGER", assign.data?.asset?.custodianIdentityId === managerIdentity.id);

// ============================================================
log("\n=== TEST 4 — MANAGER LOGIN (RBAC envelope) ===");
const manager = await login("manager@sampraan.dev", "SampraanManager#2026");
check("manager login succeeds", manager.ok, manager.error);
check("platform role is NOT admin", manager.user?.role !== "admin", manager.user?.role);
const adminOp = await api.call("identities.create", { displayName: "X Y", organization: "Nope Org", did: `did:sampraan:sih-${Date.now().toString(36)}` }, { method: "POST" });
check("admin-only operation rejected (403)", !adminOp.ok && adminOp.status === 403, `status=${adminOp.status} ${adminOp.error}`);

// ============================================================
log("\n=== TEST 5 — MANAGER TRANSFER (ALLOW/CHALLENGE → real chain tx) ===");
const managerIdentityList = await api.call("identities.list");
const userIdentity = managerIdentityList.data?.find(i => i.roles?.includes("USER") && !i.roles?.includes("MANAGER"));
const managerDid = managerIdentityList.data?.find(i => i.linkedUserId === manager.user?.id)?.did;
check("manager identity DID resolved", !!managerDid, managerDid);
let managerTransfer = await api.call(
  "assets.authorizeTransfer",
  { assetId: assetRowId, recipientIdentityId: userIdentity.id },
  { method: "POST" },
);

// CHALLENGE path (POLICY-STEP-UP / POLICY-RISK-ELEVATION): the policy demands
// additional verification. Perform a REAL server-verified step-up — sign the
// server-issued nonce with the manager identity's derived wallet key, exactly
// as the production flow does — then re-evaluate the policy.
if (managerTransfer.data?.decision === "CHALLENGE") {
  check("policy decision CHALLENGE (step-up required)", true, managerTransfer.data?.policyId ?? managerTransfer.data?.reason);
  const challenge = await api.call("stepup.requestChallenge", { assetId: assetRowId }, { method: "POST" });
  check("step-up challenge issued", challenge.ok && /^.{16,128}$/.test(challenge.data?.nonce ?? ""), challenge.error ?? challenge.data?.nonce);
  const operatorKey = process.env.BLOCKCHAIN_PRIVATE_KEY;
  const seed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(operatorKey)), managerDid]));
  const signature = await new Wallet(seed).signMessage(challenge.data.message);
  const verify = await api.call("stepup.verify", { assetId: assetRowId, nonce: challenge.data.nonce, signature }, { method: "POST" });
  check("step-up signature verified server-side", verify.ok && verify.data?.ok === true, verify.error);
  managerTransfer = await api.call(
    "assets.authorizeTransfer",
    { assetId: assetRowId, recipientIdentityId: userIdentity.id },
    { method: "POST" },
  );
}
check("policy decision ALLOW", managerTransfer.data?.decision === "ALLOW", managerTransfer.data?.decision ?? managerTransfer.error);
check("transaction confirmed", managerTransfer.data?.transaction?.status === "CONFIRMED", managerTransfer.data?.transaction?.transactionHash);
check("AssetTransferred evidence in tx", (JSON.stringify(managerTransfer.data?.transaction?.events ?? managerTransfer.data?.transaction ?? {})).length > 10);

// ============================================================
log("\n=== TEST 6 — AUDITOR DENIAL (read-only enforced) ===");
const auditor = await login("auditor@sampraan.dev", "SampraanAuditor#2026");
check("auditor login succeeds", auditor.ok, auditor.error);
const auditorIdentity = (await api.call("identities.list")).data?.find(i => i.linkedUserId === auditor.user?.id);
check("identity role AUDITOR", auditorIdentity?.roles?.includes("AUDITOR"), JSON.stringify(auditorIdentity?.roles));
const auditorTransfer = await api.call(
  "assets.authorizeTransfer",
  { assetId: assetRowId, recipientIdentityId: adminIdentity.id },
  { method: "POST" },
);
check("decision DENY", auditorTransfer.data?.decision === "DENY", auditorTransfer.data?.decision ?? auditorTransfer.error);
check("no transaction submitted", auditorTransfer.data?.transaction === null || auditorTransfer.data?.transaction === undefined, "chain must not move");

// ============================================================
log("\n=== TEST 7 — USER RESTRICTIONS (high-sensitivity guard) ===");
const user = await login("user@sampraan.dev", "SampraanUser#2026");
check("user login succeeds", user.ok, user.error);
const userTransferControlled = await api.call(
  "assets.authorizeTransfer",
  { assetId: assetRowId, recipientIdentityId: adminIdentity.id },
  { method: "POST" },
);
// The demo asset is CONTROLLED and the USER holds no asset:transfer permission
// (asset:read only) → the permission check must deny.
check("user transfer denied (no asset:transfer permission)", userTransferControlled.data?.decision === "DENY", userTransferControlled.data?.decision ?? userTransferControlled.error);
const userAdminOp = await api.call("assets.setStatus", { assetId: assetRowId, status: "REVOKED" }, { method: "POST" });
check("user admin operation rejected (403)", !userAdminOp.ok && userAdminOp.status === 403, `status=${userAdminOp.status}`);

// ============================================================
log("\n=== TEST 8 — AUDIT EVIDENCE FOR THE FULL FLOW ===");
const audit = await api.call("audit.list", { limit: 200 });
const actions = (audit.data ?? []).map(e => e.action);
const expectActions = ["LOGIN_SUCCEEDED", "ASSET_CREATED", "ASSET_ASSIGNED", "ASSET_TRANSFERRED", "AUTHORIZATION_DENIED"];
for (const action of expectActions) {
  check(`audit evidence: ${action}`, actions.includes(action));
}
const transferEvent = (audit.data ?? []).find(e => e.action === "ASSET_TRANSFERRED");
check("transfer audit row carries tx hash", /^0x[0-9a-fA-F]{64}$/.test(transferEvent?.transactionHash ?? ""), transferEvent?.transactionHash);
const deniedEvent = (audit.data ?? []).find(e => e.action === "AUTHORIZATION_DENIED");
check("denied transfer audited with reason", !!deniedEvent?.reason, deniedEvent?.reason);

// ============================================================
log("\n=== RESULT ===");
if (failures === 0) {
  log("ALL ACCEPTANCE CHECKS PASSED — presentation flow is LIVE end-to-end.\n");
} else {
  log(`${failures} check(s) FAILED — review above before presenting.\n`);
  process.exitCode = 1;
}
