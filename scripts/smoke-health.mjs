#!/usr/bin/env node
/**
 * SAMPRAAN DEPLOYMENT SMOKE TEST.
 *
 * Proves a RUNNING deployment is actually usable — not merely that a port is
 * open. Checks, in order:
 *
 *   1. GET /health  returns 200 and reports api=OK
 *   2. GET /ready   returns 200 with database=CONNECTED and schema=MIGRATED
 *   3. /health exposes the crypto-assurance provider posture
 *   4. static assets are served (the SPA shell loads, not a 404)
 *   5. the tRPC endpoint answers (a real procedure call, not just a socket)
 *   6. security headers are present on responses
 *
 * Usage:
 *   node scripts/smoke-health.mjs
 *   SAMPRAAN_BASE_URL=https://sampraan.up.railway.app node scripts/smoke-health.mjs
 *
 * Exit code is non-zero when any REQUIRED check fails, so it can gate a deploy.
 */
const base = (process.env.SAMPRAAN_BASE_URL ?? `http://localhost:${process.env.PORT ?? 3000}`).replace(/\/$/, "");

const results = [];
function check(name, pass, detail, required = true) {
  results.push({ name, pass, detail, required });
  const tag = pass ? "PASS" : required ? "FAIL" : "WARN";
  console.log(`  ${tag}  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function get(path, init) {
  const response = await fetch(`${base}${path}`, { redirect: "manual", ...init });
  const text = await response.text();
  return { response, text };
}

console.log(`SAMPRAAN smoke test against ${base}\n`);

// ------------------------------------------------------------------ 1. /health
let health = null;
try {
  const { response, text } = await get("/health");
  check("/health responds 200", response.status === 200, `status ${response.status}`);
  health = JSON.parse(text);
  check("/health reports api=OK", health.api === "OK", `api=${health.api}`);
  const dbOk = health.database === "CONNECTED";
  check("/health reports database CONNECTED", dbOk, `database=${health.database}`, process.env.SMOKE_REQUIRE_DB !== "0");
  check(
    "/health exposes crypto assurance posture",
    Boolean(health.cryptoAssurance?.provider),
    `provider=${health.cryptoAssurance?.provider}, postQuantum=${health.cryptoAssurance?.postQuantum}`,
    false,
  );
} catch (error) {
  check("/health reachable", false, error instanceof Error ? error.message : String(error));
}

// ------------------------------------------------------------------ 2. /ready
try {
  const { response, text } = await get("/ready");
  const body = JSON.parse(text);
  check("/ready responds 200", response.status === 200, `status ${response.status}, body=${text.slice(0, 200)}`);
  check("/ready reports schema migrated", body.schema === "MIGRATED", `schema=${body.schema}`);
  check("/ready reports database connected", body.database === "CONNECTED", `database=${body.database}`);
} catch (error) {
  check("/ready reachable", false, error instanceof Error ? error.message : String(error));
}

// ------------------------------------------------------------------ 3. static shell
try {
  const { response, text } = await get("/");
  const looksLikeSpa = response.status === 200 && /<div id="root"|<script/i.test(text);
  check("SPA shell is served", looksLikeSpa, `status ${response.status}, ${text.length} bytes`);
  const csp = response.headers.get("content-security-policy");
  check("security headers present (CSP)", Boolean(csp), csp ? `${csp.slice(0, 48)}…` : "missing");
  check("x-content-type-options nosniff", response.headers.get("x-content-type-options") === "nosniff");
  check("x-frame-options DENY", response.headers.get("x-frame-options") === "DENY");
  check("x-powered-by not advertised", response.headers.get("x-powered-by") === null);
} catch (error) {
  check("static shell reachable", false, error instanceof Error ? error.message : String(error));
}

// ------------------------------------------------------------------ 4. tRPC
try {
  const { response, text } = await get("/api/trpc/health");
  const ok = response.status === 200 && /"api"\s*:\s*"OK"/.test(text);
  check("tRPC health procedure answers", ok, `status ${response.status}`);
} catch (error) {
  check("tRPC reachable", false, error instanceof Error ? error.message : String(error));
}

// ------------------------------------------------------------------ 5. auth gate
try {
  // A protected procedure must refuse an anonymous caller — the whole
  // authorization model depends on this.
  const { response, text } = await get("/api/trpc/audit.list");
  const denied = response.status === 401 || /UNAUTHORIZED|not authenticated|login/i.test(text);
  check("protected procedure refuses anonymous callers", denied, `status ${response.status}`);
} catch (error) {
  check("auth gate examined", false, error instanceof Error ? error.message : String(error), false);
}

const failed = results.filter(r => !r.pass && r.required);
console.log(`\nSMOKE TEST: ${failed.length === 0 ? "PASS" : "FAIL"} (${results.filter(r => r.pass).length}/${results.length} checks passed)`);
process.exit(failed.length === 0 ? 0 : 1);
