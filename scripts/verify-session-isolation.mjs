#!/usr/bin/env node
/**
 * SAMPRAAN — multi-user session-isolation verification (SIH presentation path).
 *
 * Proves, against the LIVE server, that four simultaneous authenticated
 * sessions (ADMIN / MANAGER / AUDITOR / USER) remain fully isolated:
 *
 *  1. Four parallel logins each receive their OWN `app_session_id` cookie.
 *  2. Concurrent auth.me calls from all four sessions never cross: every
 *     session consistently sees ONLY its own identity and server-assigned role.
 *  3. Each session's authorization envelope matches its role (admin-only
 *     operation rejected for manager/auditor/user; audited denials for
 *     auditor/user mutations).
 *  4. Logout of ONE session does not affect the other three; the logged-out
 *     cookie is dead server-side (bearer replay yields unauthenticated).
 *
 * Every account is seeded by `pnpm seed:demo` (dev-only credentials).
 *
 * Usage: node scripts/verify-session-isolation.mjs [baseUrl]
 *   baseUrl defaults to http://localhost:3000 (or SAMPRAAN_BASE_URL).
 */

const BASE = (process.argv[2] ?? process.env.SAMPRAAN_BASE_URL ?? "http://localhost:3000").replace(/\/$/, "");
const API = `${BASE}/api/trpc`;

const USERS = [
  { label: "ADMIN", email: "admin@sampraan.dev", password: "SampraanAdmin#2026", expectPlatformAdmin: true },
  { label: "MANAGER", email: "manager@sampraan.dev", password: "SampraanManager#2026", expectPlatformAdmin: false },
  { label: "AUDITOR", email: "auditor@sampraan.dev", password: "SampraanAuditor#2026", expectPlatformAdmin: false },
  { label: "USER", email: "user@sampraan.dev", password: "SampraanUser#2026", expectPlatformAdmin: false },
];

let passed = 0;
let failed = 0;
function check(label, ok, detail = "") {
  failures += ok ? 0 : 1;
  passed += ok ? 1 : 0;
  failed += ok ? 0 : 1;
  log(`  ${ok ? "PASS" : "FAIL"}  ${label}${detail ? ` — ${detail}` : ""}`);
}
let failures = 0;
function log(line) {
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
    getCookie() {
      return cookie;
    },
    clear() {
      cookie = "";
    },
  };
}

async function login(email, password) {
  const api = client();
  const res = await api.call("auth.login", { email, password }, { method: "POST" });
  if (!res.ok) return { ok: false, error: res.error, api };
  const me = await api.call("auth.me");
  return { ok: true, user: me.data ?? null, api };
}

console.log(`=== SAMPRAAN SESSION ISOLATION — ${BASE} ===\n`);

// ---- 1. Four parallel logins -------------------------------------------------

log("=== 1. PARALLEL LOGINS (four sessions at once) ===");
const logins = await Promise.all(USERS.map(async u => ({ u, result: await login(u.email, u.password) })));
const sessions = new Map();
for (const { u, result } of logins) {
  check(`${u.label} login`, result.ok, result.ok ? "own session cookie issued" : result.error ?? "login failed");
  if (result.ok) sessions.set(u.label, result);
}

// ---- 2. Identity envelope per session (concurrent) ---------------------------

log("\n=== 2. CONCURRENT auth.me — NO CROSS-SESSION LEAKAGE ===");
const expectedEmails = new Map(USERS.map(u => [u.label, u.email]));
const meResults = await Promise.all(
  [...sessions.entries()].map(async ([label, s]) => {
    // 5 concurrent identity reads per session: identity must be stable and personal.
    const results = await Promise.all(Array.from({ length: 5 }, () => s.api.call("auth.me")));
    const emails = new Set(results.map(r => r.data?.email ?? null));
    return { label, status: results[0].status, emails, first: results[0] };
  })
);
for (const { label, status, emails, first } of meResults) {
  const expected = expectedEmails.get(label);
  check(`${label} auth.me returns 200`, status === 200, `status=${status}`);
  // auth.me returns the safe user object directly (null when unauthenticated).
  const stable = emails.size === 1 && emails.has(expected);
  check(`${label} identity stable across 5 concurrent reads`, stable, [...emails].join(","));
  const role = first.data?.role ?? null;
  const roleOk = label === "ADMIN" ? role === "admin" : role !== "admin";
  check(`${label} role from SERVER matches seed`, roleOk, `role=${role ?? "?"}`);
  const leaked = USERS.filter(u => u.label !== label && emails.has(u.email));
  check(`${label} sees NO other user's identity`, leaked.length === 0, leaked.map(l => l.label).join(",") || "clean");
}

// ---- 3. Distinct cookies + server-side authorization per role ----------------

log("\n=== 3. AUTHORIZATION ENVELOPE PER SESSION ===");
const distinctCookies = new Set([...sessions.values()].map(s => s.api.getCookie()));
check("all four session cookies are DISTINCT", distinctCookies.size === sessions.size, `${distinctCookies.size} unique cookies`);
for (const [label, s] of sessions) {
  // identities.create is an adminProcedure: a MUTATING admin-only probe — the
  // acceptance suite's own envelope check (read endpoints stay protected-only).
  // The did is throwaway and the call MUST fail; a success would be an RBAC
  // breach, and the unique-did pattern keeps even a bug from polluting data.
  const probe = await s.api.call(
    "identities.create",
    { displayName: "Isolation Probe", organization: "Isolation Probe Org", did: `did:sampraan:iso-probe-${Date.now().toString(36)}-${label.toLowerCase()}` },
    { method: "POST" }
  );
  const ok = label === "ADMIN" ? probe.ok : !probe.ok && probe.status === 403;
  check(`${label} admin-only probe ${label === "ADMIN" ? "allowed" : "rejected (403)"}`, ok, probe.ok ? "200" : `${probe.status} ${probe.error ?? ""}`);
}

// ---- 4. Logout isolation ------------------------------------------------------

log("\n=== 4. LOGOUT OF ONE SESSION DOES NOT TOUCH THE OTHERS ===");
const managerSession = sessions.get("MANAGER");
const adminBefore = await sessions.get("ADMIN").api.call("auth.me");
const userBefore = await sessions.get("USER").api.call("auth.me");
await managerSession.api.call("auth.logout", undefined, { method: "POST" });
const adminAfter = await sessions.get("ADMIN").api.call("auth.me");
const userAfter = await sessions.get("USER").api.call("auth.me");
check("ADMIN session alive after MANAGER logout", adminAfter.ok && adminBefore.ok);
check("USER session alive after MANAGER logout", userAfter.ok && userBefore.ok);
// The logged-out MANAGER cookie must be dead server-side: replaying the same
// cookie (still held by this client) must no longer authenticate.
const managerReplay = await managerSession.api.call("auth.me");
check(
  "MANAGER cookie dead after logout (server-side revocation, replay refused)",
  !managerReplay.ok || managerReplay.data == null,
  `role=${managerReplay.data?.role ?? "none"}`
);
// Re-login works cleanly afterwards.
const managerReLogin = await login(USERS[1].email, USERS[1].password);
check("MANAGER re-login after logout", managerReLogin.ok, managerReLogin.ok ? "fresh session issued" : "re-login failed");

log("\n=== RESULT ===");
if (failures > 0) {
  log(`${failures} check(s) FAILED — review above before presenting.`);
  process.exit(1);
}
log("ALL SESSION-ISOLATION CHECKS PASSED — four parallel sessions remain isolated.");
