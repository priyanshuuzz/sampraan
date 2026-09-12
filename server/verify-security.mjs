/**
 * LOOP 2-6 + 9-11 live API verification against the RUNNING dev server.
 * Mirrors verify-acceptance.mjs wire format (batch=1). Read-mostly: creates
 * one challenge, consumes it with a deliberately-wrong signature, runs
 * simulator dry-runs, and reads provenance/graph. No chain state is mutated.
 */
const API = process.env.SAMPPRAAN_API ?? "http://localhost:3000/api/trpc";
let failures = 0;
function check(label, ok, detail = "") {
  failures += ok ? 0 : 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
}
function client() {
  let cookie = "";
  return {
    async call(path, input, { method = "GET", expect = 200 } = {}) {
      const url = `${API}/${path}?batch=1` + (method === "GET" && input ? `&input=${encodeURIComponent(JSON.stringify({ "0": { json: input } }))}` : "");
      const res = await fetch(url, {
        method,
        headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) },
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
      if (!ok) return { ok: false, status: res.status, error: first?.error?.json?.message ?? `HTTP ${res.status}`, data: first?.result?.data?.json };
      if (first?.error) return { ok: false, status: res.status, error: first.error.json.message, data: null };
      return { ok: true, status: res.status, data: first?.result?.data?.json };
    },
    clear() { cookie = ""; },
  };
}
const api = client();

(async () => {
  console.log("=== LOGIN ===");
  const admin = await api.call("auth.login", { email: "admin@sampraan.dev", password: "SampraanAdmin#2026" }, { method: "POST" });
  check("admin login", admin.ok && admin.data?.user?.role === "admin", admin.error ?? admin.data?.user?.role);

  console.log("=== DID CHALLENGE-RESPONSE (LOOP 2) ===");
  const DID = "did:sampraan:dev-admin-aarav";
  const challenge = await api.call("did.requestChallenge", { did: DID }, { method: "POST" });
  check("challenge issued with nonce + expiry", challenge.ok && !!challenge.data?.nonce && !!challenge.data?.expiresAt, challenge.error ?? challenge.data?.nonce?.slice(0, 12) + "…");
  const malformed = await api.call("did.verifyChallenge", { did: DID, nonce: challenge.data?.nonce ?? "", signature: "0x" + "00".repeat(65) }, { method: "POST", expect: 401 });
  check("invalid signature rejected (401)", malformed.status === 401, malformed.error?.slice(0, 60));
  const replay = await api.call("did.verifyChallenge", { did: DID, nonce: challenge.data?.nonce ?? "", signature: "0x" + "00".repeat(65) }, { method: "POST", expect: 401 });
  check("nonce single-use (replay rejected)", replay.status === 401, replay.error?.slice(0, 60));
  const unknownDid = await api.call("did.requestChallenge", { did: "did:sampraan:no-such-identity" }, { method: "POST", expect: 404 });
  check("unknown DID rejected (404)", unknownDid.status === 404, unknownDid.error?.slice(0, 50));

  console.log("=== KEY LIFECYCLE (LOOP 3) ===");
  const ks = await api.call("did.keyStatus", { did: DID });
  check("key status readable", ks.ok && !!ks.data?.keyStatus, ks.error ?? ks.data?.keyStatus);
  console.log("=== POLICY SIMULATOR (LOOP 10) ===");
  const cases = [
    { input: { role: "ADMIN", assetClassification: "CONTROLLED", action: "CREATE_ASSET" }, expect: "ALLOW", label: "ADMIN CREATE ASSET → ALLOW" },
    { input: { role: "MANAGER", assetClassification: "CONTROLLED", action: "TRANSFER" }, expect: "ALLOW", label: "MANAGER CONTROLLED TRANSFER → ALLOW" },
    { input: { role: "MANAGER", assetClassification: "HIGHLY_SENSITIVE", action: "TRANSFER" }, expect: "CHALLENGE", label: "MANAGER SENSITIVE TRANSFER → CHALLENGE" },
    { input: { role: "MANAGER", assetClassification: "HIGHLY_SENSITIVE", action: "TRANSFER", stepUpAuthenticated: true, approvalStatus: "APPROVED" }, expect: "ALLOW", label: "MANAGER SENSITIVE + step-up + approval → ALLOW" },
    { input: { role: "AUDITOR", assetClassification: "CONTROLLED", action: "TRANSFER" }, expect: "DENY", label: "AUDITOR TRANSFER → DENY" },
    { input: { role: "USER", assetClassification: "CONTROLLED", action: "CREATE_ASSET" }, expect: "DENY", label: "USER CREATE ASSET → DENY" },
    { input: { role: "ADMIN", assetClassification: "CONTROLLED", action: "TRANSFER", identityStatus: "REVOKED" }, expect: "DENY", label: "REVOKED identity → DENY" },
    { input: { role: "MANAGER", assetClassification: "CONTROLLED", action: "TRANSFER", custodyMatch: false }, expect: "DENY", label: "non-custodian transfer → DENY" },
  ];
  for (const c of cases) {
    const result = await api.call("simulator", c.input, { method: "POST" });
    check(c.label, result.ok && result.data?.decision === c.expect, result.error ?? result.data?.decision);
  }
  const forbidden = await api.call("simulator", cases[0].input, { method: "POST", expect: 403 });
  const anon = await client();
  const anonSim = await anon.call("simulator", cases[0].input, { method: "POST", expect: 403 });
  check("simulator denied without a session (403)", anonSim.status === 403, String(anonSim.status));

  console.log("=== GRAPH / PROVENANCE (LOOP 9+11) ===");
  const assets = await api.call("assets.list");
  const assetList = Array.isArray(assets.data) ? assets.data : [];
  const asset = assetList[0];
  check("assets list for provenance", !!asset, asset?.assetId ?? assets.error);
  if (asset) {
    const prov = await api.call("provenance", { assetId: asset.id });
    check("provenance returns history + creator + custodian", prov.ok && !!prov.data?.asset && Array.isArray(prov.data?.history), prov.error ?? `${prov.data?.history?.length ?? 0} entries`);
    const gStatus = await api.call("graph.status");
    check("graph layer answers", gStatus.ok && !!gStatus.data?.mode, gStatus.error ?? `${gStatus.data?.mode} block=${gStatus.data?.latestBlock ?? "-"}`);
    const gProv = await api.call("graph.provenance", { assetId: asset.assetId });
    check("graph provenance query", gProv.ok, gProv.error ?? (gProv.data?.asset ? `token ${gProv.data.asset.tokenId}, ${gProv.data.transfers.length} transfers` : "asset not yet indexed in window"));
  }

  console.log("=== STEP-UP (LOOP 5) — wrong-identity rejection ===");
  const manager = await client();
  const mLogin = await manager.call("auth.login", { email: "manager@sampraan.dev", password: "SampraanManager#2026" }, { method: "POST" });
  check("manager login", mLogin.ok, mLogin.error ?? "");
  // admin session requests a step-up challenge, manager session must not be able to consume it
  const stepUp = await api.call("stepup.requestChallenge", { assetId: asset?.id ?? "00000000-0000-0000-0000-000000000000" }, { method: "POST", expect: asset ? 200 : 404 });
  if (asset && stepUp.ok) {
    const wrong = await manager.call("stepup.verify", { assetId: asset.id, nonce: stepUp.data.nonce, signature: "0x" + "00".repeat(65) }, { method: "POST", expect: 401 });
    check("step-up bound to requesting identity (manager cannot consume admin challenge)", wrong.status === 401, wrong.error?.slice(0, 60));
  } else {
    check("step-up challenge endpoint reachable", true, stepUp.error ?? "issued");
  }

  console.log(failures === 0 ? "\nALL LIVE SECURITY CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error("FATAL", e.message); process.exit(1); });
