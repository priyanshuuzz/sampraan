#!/usr/bin/env node
/**
 * SAMPRAAN CONFIGURATION DOCTOR
 *
 * Prints what this deployment will actually see, with every secret REDACTED,
 * and reports what is missing for the target environment. Run it before a
 * deploy (or as a first step when a deploy misbehaves) instead of grepping
 * `.env` by hand — and it never prints a password, key or token.
 *
 *   node scripts/check-env.mjs
 *   NODE_ENV=production node scripts/check-env.mjs
 */
import "dotenv/config";

const isProduction = process.env.NODE_ENV === "production";

/** Variables that are secret: presence and length only, never the value. */
const SECRETS = new Set([
  "DATABASE_URL",
  "JWT_SECRET",
  "BLOCKCHAIN_PRIVATE_KEY",
  "BLOCKCHAIN_AUDITOR_PRIVATE_KEY",
  "ASSET_CONTENT_MASTER_KEY",
  "PQC_PRIVATE_KEY",
  "BUILT_IN_FORGE_API_KEY",
  "MYSQL_ROOT_PASSWORD",
  "MYSQL_PASSWORD",
]);

const REQUIRED_IN_PRODUCTION = ["DATABASE_URL", "JWT_SECRET", "VITE_APP_ID", "ASSET_CONTENT_MASTER_KEY"];
const RECOMMENDED_IN_PRODUCTION = [
  "APP_URL",
  "BLOCKCHAIN_RPC_URL",
  "BLOCKCHAIN_PRIVATE_KEY",
  "CORS_ORIGIN",
  "TRUST_PROXY",
];

function redact(name, value) {
  if (value === undefined || value === "") return "(unset)";
  if (!SECRETS.has(name)) return value;
  // Show only enough to confirm the intended value is present.
  if (name === "DATABASE_URL") {
    try {
      const url = new URL(value);
      return `${url.protocol}//${url.username ? "<user>" : ""}${url.username ? ":" : ""}${url.password ? "<password>" : ""}@${url.host}${url.pathname}`;
    } catch {
      return `(unparseable, ${value.length} chars)`;
    }
  }
  return `(set, ${value.length} chars)`;
}

const WATCHED = [
  "NODE_ENV",
  "PORT",
  "APP_URL",
  "APP_VERSION",
  "DATABASE_URL",
  "JWT_SECRET",
  "VITE_APP_ID",
  "TRUST_PROXY",
  "CORS_ORIGIN",
  "OAUTH_SERVER_URL",
  "BLOCKCHAIN_RPC_URL",
  "BLOCKCHAIN_CHAIN_ID",
  "BLOCKCHAIN_PRIVATE_KEY",
  "ASSET_CONTENT_MASTER_KEY",
  "ASSET_CONTENT_STORAGE_DIR",
  "IPFS_API_URL",
  "PQC_KEY_PROVIDER",
  "GRAPH_SUBGRAPH_URL",
];

console.log(`SAMPRAAN configuration — NODE_ENV=${process.env.NODE_ENV ?? "development"}\n`);
for (const name of WATCHED) {
  console.log(`  ${name.padEnd(30)} ${redact(name, process.env[name])}`);
}

const problems = [];
const warnings = [];

if (!process.env.DATABASE_URL) {
  (isProduction ? problems : warnings).push("DATABASE_URL is not set — no read model, no audit trail, no authorization data.");
} else if (!/^mysql(s)?:\/\//i.test(process.env.DATABASE_URL)) {
  problems.push("DATABASE_URL must be a mysql:// URL (this build uses the MySQL driver, not Postgres).");
}

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  (isProduction ? problems : warnings).push("JWT_SECRET is missing or shorter than 32 characters — sessions would be forgeable.");
}

if (!process.env.VITE_APP_ID) {
  (isProduction ? problems : warnings).push("VITE_APP_ID is not set — session tokens are not bound to this deployment.");
}

if (isProduction && !process.env.ASSET_CONTENT_MASTER_KEY) {
  problems.push("ASSET_CONTENT_MASTER_KEY is not set — encrypted asset content cannot be served in production.");
}

if (process.env.TRUST_PROXY === "1" && !isProduction) {
  // Fine, but the operator should know the rate limiter now trusts headers.
  warnings.push("TRUST_PROXY=1 outside production — only safe if a real proxy fronts this process locally.");
}

if (isProduction) {
  for (const name of RECOMMENDED_IN_PRODUCTION) {
    if (!process.env[name]) warnings.push(`${name} is not set — the related capability degrades (see .env.example).`);
  }
  if (process.env.PQC_KEY_PROVIDER === "local-dev") {
    warnings.push("PQC_KEY_PROVIDER=local-dev is ignored in production; register holder-held ML-DSA-65 keys instead.");
  }
}

if (warnings.length > 0) {
  console.log(`\nWARNINGS (${warnings.length}):`);
  for (const warning of warnings) console.log(`  - ${warning}`);
}
if (problems.length > 0) {
  console.log(`\nBLOCKING PROBLEMS (${problems.length}):`);
  for (const problem of problems) console.log(`  - ${problem}`);
  console.log("\nThe application will REFUSE to start in this state.");
  process.exit(1);
}

console.log(`\nCONFIGURATION OK${warnings.length > 0 ? ` (${warnings.length} warning(s))` : ""}.`);
