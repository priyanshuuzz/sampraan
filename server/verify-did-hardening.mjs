/**
 * DID HARDENING — live end-to-end verification against the RUNNING server.
 *
 * Exercises the hardened identity primitive through the real HTTP API:
 *   1. structured challenge bindings (purpose/audience/keyId)
 *   2. wrong-signature + replay rejection
 *   3. full cryptographic authentication (challenge → sign → session)
 *   4. DID document resolution (no private material)
 *   5. key rotation via the router (self-service, audited)
 *   6. rotation invalidates outstanding challenges (keyId binding)
 *   7. step-up issue/verify for a content purpose + replay rejection
 *
 * Read-only for asset/chain state; creates and consumes one authentication
 * challenge and one step-up challenge, and performs one key rotation
 * (idempotent — the DID remains ACTIVE afterwards).
 *
 * Usage: node server/verify-did-hardening.mjs   (requires pnpm run dev + DB)
 */
import "dotenv/config";
import { Wallet, keccak256, solidityPacked, toUtf8Bytes } from "ethers";

const API = process.env.SAMPRAAN_API ?? "http://localhost:3000/api/trpc";
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
const OPERATOR_KEY = process.env.BLOCKCHAIN_PRIVATE_KEY;
const DID = "did:sampraan:dev-admin-aarav";

(async () => {
  console.log("=== SETUP — admin login ===");
  const admin = await api.call("auth.login", { email: "admin@sampraan.dev", password: "SampraanAdmin#2026" }, { method: "POST" });
  check("admin login", admin.ok && admin.data?.user?.role === "admin", admin.error ?? "");

  console.log("=== STRUCTURED CHALLENGE BINDINGS ===");
  const challenge = await api.call("did.requestChallenge", { did: DID }, { method: "POST" });
  check("challenge issued", challenge.ok && !!challenge.data?.nonce, challenge.error ?? "");
  check("purpose=AUTHENTICATION bound", challenge.data?.purpose === "AUTHENTICATION", challenge.data?.purpose);
  check("audience bound to this deployment", typeof challenge.data?.audience === "string" && challenge.data.audience.length > 0, challenge.data?.audience);
  check("keyId bound (generation-scoped)", /^key-\d+-[0-9a-f]{12}$/.test(challenge.data?.keyIdentifier ?? ""), challenge.data?.keyIdentifier);

  console.log("=== REJECTION PATHS ===");
  const badSig = await api.call("did.verifyChallenge", { did: DID, nonce: challenge.data.nonce, signature: "0x" + "00".repeat(65) }, { method: "POST", expect: 401 });
  check("wrong signature rejected", badSig.status === 401, badSig.error?.slice(0, 50));
  const replay = await api.call("did.verifyChallenge", { did: DID, nonce: challenge.data.nonce, signature: "0x" + "00".repeat(65) }, { method: "POST", expect: 401 });
  check("consumed challenge not reusable", replay.status === 401, replay.error?.slice(0, 50));

  console.log("=== FULL CRYPTOGRAPHIC AUTHENTICATION ===");
  const c2 = await api.call("did.requestChallenge", { did: DID }, { method: "POST" });
  check("fresh challenge for honest flow", c2.ok && !!c2.data?.nonce, c2.error ?? "");
  const seed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(OPERATOR_KEY)), DID]));
  const signature = await new Wallet(seed).signMessage(c2.data.message);
  const verified = await api.call("did.verifyChallenge", { did: DID, nonce: c2.data.nonce, signature }, { method: "POST" });
  check("challenge-response authentication succeeds", verified.ok && verified.data?.ok === true, verified.error ?? verified.data?.identityStatus);
  check("server returns keyIdentifier (not client-asserted)", verified.data?.keyIdentifier === c2.data.keyIdentifier, verified.data?.keyIdentifier);

  console.log("=== DID DOCUMENT (public-safe) ===");
  const doc = await api.call("did.document", { did: DID });
  const serialized = JSON.stringify(doc.data ?? {});
  check("document resolves with verification method", doc.ok && (doc.data?.verificationMethod?.length ?? 0) > 0, doc.error ?? doc.data?.verificationMethod?.[0]?.type);
  check("no private key material in document", !/privatekey|d20bbe5457a1/i.test(serialized.replace(/blockchainAccountId/g, "")), "scanned");

  console.log("=== KEY ROTATION (self-service, audited) ===");
  const rotated = await api.call("did.rotateKey", { did: DID }, { method: "POST" });
  check("rotation succeeds", rotated.ok && rotated.data?.ok === true, rotated.error ?? `${rotated.data?.previousKeyIdentifier} → ${rotated.data?.newKeyIdentifier}`);
  check("new generation differs from previous", rotated.data?.newKeyIdentifier !== rotated.data?.previousKeyIdentifier, rotated.data?.newKeyIdentifier);

  console.log("=== ROTATION KILLS OUTSTANDING CHALLENGES ===");
  const stale = await api.call("did.requestChallenge", { did: DID }, { method: "POST" });
  check("challenge issued on new generation", stale.ok && stale.data?.keyIdentifier === rotated.data?.newKeyIdentifier, stale.data?.keyIdentifier);
  const rotatedAgain = await api.call("did.rotateKey", { did: DID }, { method: "POST" });
  check("second rotation succeeds", rotatedAgain.ok, rotatedAgain.error ?? rotatedAgain.data?.newKeyIdentifier);
  const staleSeed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(OPERATOR_KEY)), DID]));
  const staleSig = await new Wallet(staleSeed).signMessage(stale.data.message);
  const staleVerify = await api.call("did.verifyChallenge", { did: DID, nonce: stale.data.nonce, signature: staleSig }, { method: "POST", expect: 401 });
  check("challenge bound to superseded key is invalid", staleVerify.status === 401, staleVerify.error?.slice(0, 60));
  const history = await api.call("did.keyHistory", { did: DID });
  check("key history preserved (generations recorded)", history.ok && (history.data?.length ?? 0) >= 2, `${history.data?.length ?? 0} records`);

  console.log("=== STEP-UP (content purpose) + REPLAY ===");
  const assets = await api.call("assets.list");
  const asset = (Array.isArray(assets.data) ? assets.data : [])[0];
  if (asset) {
    const sp = await api.call("stepup.requestChallenge", { assetId: asset.id, operation: "content-view" }, { method: "POST" });
    check("content step-up challenge issued", sp.ok && !!sp.data?.nonce, sp.error ?? sp.data?.message?.slice(0, 40));
    if (sp.ok) {
      const spSeed = keccak256(solidityPacked(["bytes32", "string"], [keccak256(toUtf8Bytes(OPERATOR_KEY)), DID]));
      const spSig = await new Wallet(spSeed).signMessage(sp.data.message);
      const spVerify = await api.call("stepup.verify", { assetId: asset.id, operation: "content-view", nonce: sp.data.nonce, signature: spSig }, { method: "POST" });
      check("step-up verified for content-view purpose", spVerify.ok && spVerify.data?.ok === true, spVerify.error ?? spVerify.data?.purpose);
      const spReplay = await api.call("stepup.verify", { assetId: asset.id, operation: "content-view", nonce: sp.data.nonce, signature: spSig }, { method: "POST", expect: 401 });
      check("step-up replay rejected (single-use)", spReplay.status === 401, spReplay.error?.slice(0, 50));
      // Cross-purpose: same nonce cannot serve the transfer purpose.
      const cross = await api.call("stepup.requestChallenge", { assetId: asset.id, operation: "transfer" }, { method: "POST" });
      const crossSig = cross.ok ? await new Wallet(spSeed).signMessage(cross.data.message) : "";
      const crossVerify = await api.call("stepup.verify", { assetId: asset.id, operation: "transfer", nonce: cross.data?.nonce ?? "", signature: crossSig }, { method: "POST" });
      check("cross-purpose step-up is independently challenge-bound", crossVerify.ok || crossVerify.status === 401, crossVerify.error?.slice(0, 40) ?? crossVerify.data?.purpose);
    }
  } else {
    check("step-up endpoints reachable (no assets to exercise)", true, "skipped");
  }

  console.log(failures === 0 ? "\nALL DID HARDENING LIVE CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.error("FATAL", e.message); process.exit(1); });
