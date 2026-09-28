#!/usr/bin/env node
/**
 * SAMPRAAN MIGRATION ACCEPTANCE VERIFIER
 *
 * Proves the database story on a REAL database, not by inspection:
 *
 *   1. FRESH APPLY      — every journal entry applies to an empty database
 *                         through the production runner (no drizzle-kit).
 *   2. RECORDED ONCE    — __drizzle_migrations has exactly one row per entry,
 *                         with matching timestamps (no duplicate/skipped runs).
 *   3. SCHEMA SHAPE     — every table the application depends on exists, plus
 *                         the critical enum/column definitions the security
 *                         model relies on (classification, lifecycleState,
 *                         assurance levels, key statuses).
 *   4. IDEMPOTENT RE-RUN— a second apply is a no-op and still succeeds.
 *   5. INDEX/UNIQUE     — the uniqueness constraints that make races safe
 *                         (asset version numbering, grants, key ids, nonces).
 *
 * Point it at ANY empty MySQL database you control:
 *
 *   FRESH_DATABASE_URL=mysql://user:pass@host:3306/sampraan_migrate_fresh \
 *     node scripts/verify-migrations.mjs
 *
 * The script DROPS nothing. If the target is not empty it reports that and
 * still verifies idempotency (use a dedicated database for a clean 1-4 run).
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";
import mysql from "mysql2/promise";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const target = process.env.FRESH_DATABASE_URL;
if (!target) {
  console.error("FRESH_DATABASE_URL is required (an EMPTY database you control).");
  process.exit(2);
}

const results = [];
function check(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`  ${pass ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
}

function connConfig(url) {
  const parsed = new URL(url);
  return {
    host: parsed.hostname,
    port: Number(parsed.port || 3306),
    user: decodeURIComponent(parsed.username),
    password: decodeURIComponent(parsed.password),
    database: parsed.pathname.slice(1),
    multipleStatements: false,
  };
}

/**
 * Run the PRODUCTION migration entry point as a child process.
 *
 * Invoked as `node <tsx cli> server/migrate.ts` rather than through `npx`:
 * npx is a .cmd shim on Windows, so execFileSync('npx', ...) fails with ENOENT
 * there and silently produced an empty error — exactly the kind of
 * platform-specific breakage a deployment verifier must not have.
 */
function runMigrations(url, label) {
  console.log(`\n=== ${label} ===`);
  const tsxCli = path.join(root, "node_modules", "tsx", "dist", "cli.mjs");
  if (!existsSync(tsxCli)) {
    console.log(`  FAIL  tsx CLI not found at ${tsxCli} — run pnpm install first`);
    return { ok: false };
  }
  try {
    const output = execFileSync(process.execPath, [tsxCli, "server/migrate.ts"], {
      cwd: root,
      env: { ...process.env, DATABASE_URL: url, DOTENV_CONFIG_QUIET: "true" },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    console.log(output.trim().split("\n").map(l => `  ${l}`).join("\n"));
    return { ok: true };
  } catch (error) {
    const out = `${error.stdout ?? ""}${error.stderr ?? ""}`.trim();
    console.log(out.split("\n").map(l => `  ${l}`).join("\n"));
    return { ok: false };
  }
}

/** Migration rows, or null when the table does not exist yet. */
async function readAppliedMigrations(conn) {
  try {
    const [rows] = await conn.query("SELECT hash, created_at FROM __drizzle_migrations ORDER BY created_at");
    return rows;
  } catch {
    return null;
  }
}

const REQUIRED_TABLES = [
  "users", "identities", "did_records", "did_key_records", "did_challenges", "step_up_sessions",
  "asset_content_versions", "asset_access_grants", "asset_approvals", "asset_ownership", "asset_custody",
  "mint_requests", "asset_transfer_requests", "asset_disputes", "identity_anomalies", "audit_report_hashes",
  "did_document_versions", "consent_grants", "key_recovery_requests", "ownership_presentations",
  "pqc_key_records", "assurance_challenges",
  "roles", "permissions", "role_permissions", "identity_roles", "policies",
  "assets", "authorization_decisions", "audit_events", "security_alerts", "sessions",
];

const REQUIRED_ENUMS = [
  ["assets", "classification", ["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]],
  ["identities", "lifecycleState", ["PENDING", "VERIFIED", "SUSPENDED", "DEACTIVATED"]],
  ["assurance_challenges", "assuranceLevel", ["BASELINE", "ELEVATED", "QUANTUM_HARDENED"]],
  ["pqc_key_records", "status", ["ACTIVE", "ROTATED", "REVOKED"]],
  ["pqc_key_records", "keySource", ["REGISTERED", "SERVER_DERIVED"]],
  ["mint_requests", "status", ["PENDING", "APPROVED", "REJECTED", "EXECUTED"]],
  ["asset_transfer_requests", "status", ["PENDING", "ACCEPTED", "APPROVED", "REJECTED", "EXECUTED", "CANCELLED"]],
];

const REQUIRED_UNIQUE = [
  ["asset_version_unique", "SELECT COUNT(*) AS c FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'asset_content_versions' AND non_unique = 0 AND index_name = 'asset_versions_asset_version_idx'"],
  ["grant_unique", "SELECT COUNT(*) AS c FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'asset_access_grants' AND non_unique = 0 AND index_name = 'asset_access_grants_asset_grantee_perm_idx'"],
  ["pqc_key_unique", "SELECT COUNT(*) AS c FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'pqc_key_records' AND non_unique = 0 AND index_name = 'pqc_key_records_did_key_idx'"],
  ["assurance_nonce_unique", "SELECT COUNT(*) AS c FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'assurance_challenges' AND non_unique = 0 AND index_name = 'assurance_challenges_nonce_unique'"],
];

// ---------------------------------------------------------------- 1. fresh apply
const before = await mysql.createConnection(connConfig(target));
const [existingTables] = await before.query("SHOW TABLES");
const startedEmpty = existingTables.length === 0;
console.log(`Target database tables before migration: ${existingTables.length}`);
if (existingTables.length > 0) {
  console.log("NOTE: target was not empty — fresh-apply proof requires an empty database.");
}
await before.end();

const first = runMigrations(target, "FRESH APPLY (production runner)");
check("migration runner exits 0", first.ok);

// ---------------------------------------------------------------- 2. recorded once
const conn = await mysql.createConnection(connConfig(target));
const journal = JSON.parse(readFileSync(path.join(root, "drizzle", "meta", "_journal.json"), "utf8"));
const applied = (await readAppliedMigrations(conn)) ?? [];
check("migration journal table exists", applied.length > 0, "__drizzle_migrations");
check("one migration row per journal entry", applied.length === journal.entries.length, `${applied.length} rows / ${journal.entries.length} entries`);
const recordedTimes = new Set(applied.map(r => Number(r.created_at)));
const missing = journal.entries.filter(e => !recordedTimes.has(Number(e.when))).map(e => e.tag);
check("every journal entry is recorded", missing.length === 0, missing.join(", ") || "all present");

// Hashes are informational (the migrator orders by timestamp) but a mismatch
// means the .sql file changed after being applied — worth surfacing.
const hashMismatches = [];
for (const entry of journal.entries) {
  const file = path.join(root, "drizzle", `${entry.tag}.sql`);
  if (!existsSync(file)) continue;
  const hash = createHash("sha256").update(readFileSync(file).toString()).digest("hex");
  const row = applied.find(r => Number(r.created_at) === Number(entry.when));
  if (row && row.hash !== hash) hashMismatches.push(entry.tag);
}
console.log(`  INFO  migration file hash drift after apply: ${hashMismatches.join(", ") || "none"}`);

// ---------------------------------------------------------------- 3. schema shape
const [tables] = await conn.query("SHOW TABLES");
const tableNames = new Set(tables.map(t => Object.values(t)[0]));
const missingTables = REQUIRED_TABLES.filter(t => !tableNames.has(t));
check("all required tables exist", missingTables.length === 0, missingTables.join(", ") || `${REQUIRED_TABLES.length} tables`);

for (const [table, column, values] of REQUIRED_ENUMS) {
  const [cols] = await conn.query("SELECT COLUMN_TYPE AS t FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?", [table, column]);
  const type = cols[0]?.t ?? "";
  const ok = values.every(v => type.includes(`'${v}'`));
  check(`enum ${table}.${column}`, ok, type || "column missing");
}

for (const [name, sql] of REQUIRED_UNIQUE) {
  const [rows] = await conn.query(sql);
  check(`unique constraint ${name}`, Number(rows[0]?.c ?? 0) > 0);
}

// ---------------------------------------------------------------- 4. idempotent re-run
const second = runMigrations(target, "IDEMPOTENT RE-RUN");
check("re-running migrations succeeds (no-op)", second.ok);
const after = (await readAppliedMigrations(conn)) ?? [];
check("no duplicate migration rows after re-run", after.length === applied.length, `${after.length} rows`);

await conn.end();

const failed = results.filter(r => !r.pass);
console.log(`\n${failed.length === 0 ? "MIGRATION ACCEPTANCE: PASS" : "MIGRATION ACCEPTANCE: FAIL"} (${results.length - failed.length}/${results.length} checks)`);
if (startedEmpty) {
  console.log("Fresh-apply proof: the target started EMPTY, so checks 1-4 are a true cold-start install.");
} else {
  console.log("Fresh-apply proof: INCOMPLETE (target was not empty). Re-run against an empty database for the full proof.");
}
process.exit(failed.length === 0 ? 0 : 1);
