#!/usr/bin/env node
/**
 * BASELINE A MIGRATION AGAINST AN EXISTING DATABASE
 *
 * Why this exists
 * ---------------
 * Drizzle's migrator decides what to run purely by comparing the FOLDER
 * timestamp (`when`) of each journal entry against the newest row in
 * `__drizzle_migrations`. It never re-checks whether the schema already
 * exists. So if a database was created with `drizzle-kit push` (a direct
 * schema sync) instead of `drizzle-kit migrate`, the migration table has no
 * record of the objects that push created, and a later `migrate` will try to
 * re-apply DDL that is already there — failing on the first `CREATE TABLE`
 * or `ALTER TABLE`.
 *
 * `mark-migration-applied` records that a migration's DDL is ALREADY present
 * in this database, exactly as the migrator would have recorded it, so
 * `drizzle-kit migrate` resumes from the next unapplied migration.
 *
 * USE ONLY WHEN THE SCHEMA GENUINELY EXISTS. This tool does not create or
 * verify schema — it records an assertion. It therefore:
 *   - prints the migration's statements so the operator can see what is
 *     being asserted,
 *   - requires --confirm with the migration tag echoed back,
 *   - refuses to overwrite an existing record for that migration,
 *   - writes to the same table/columns the migrator uses.
 *
 * Usage (from the repository root):
 *   node scripts/ops/mark-migration-applied.mjs --list
 *   node scripts/ops/mark-migration-applied.mjs 0007_governance_lifecycle --confirm 0007_governance_lifecycle
 */
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";
import mysql from "mysql2/promise";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const migrationsFolder = path.join(root, "drizzle");

function readJournal() {
  const journalPath = path.join(migrationsFolder, "meta", "_journal.json");
  if (!existsSync(journalPath)) throw new Error(`Cannot find ${journalPath}`);
  return JSON.parse(readFileSync(journalPath, "utf8"));
}

function loadMigration(tag) {
  const file = path.join(migrationsFolder, `${tag}.sql`);
  if (!existsSync(file)) throw new Error(`Migration file not found: ${file}`);
  const content = readFileSync(file).toString();
  return { content, hash: createHash("sha256").update(content).digest("hex") };
}

function connectionConfig() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is required");
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

const args = process.argv.slice(2);
const journal = readJournal();

if (args.includes("--list") || args.length === 0) {
  const conn = await mysql.createConnection(connectionConfig());
  const [rows] = await conn.query("SELECT created_at FROM __drizzle_migrations ORDER BY created_at");
  const applied = new Set(rows.map(r => Number(r.created_at)));
  console.log(`Migrations folder: ${migrationsFolder}`);
  console.log(`Recorded in __drizzle_migrations: ${applied.size}\n`);
  for (const entry of journal.entries) {
    const state = applied.has(Number(entry.when)) ? "APPLIED " : "PENDING ";
    console.log(`  ${state} idx=${entry.idx}  when=${entry.when}  ${entry.tag}`);
  }
  await conn.end();
  process.exit(0);
}

const tag = args[0];
const entry = journal.entries.find(e => e.tag === tag);
if (!entry) throw new Error(`Unknown migration tag "${tag}". Run with --list to see the journal.`);
const confirmIndex = args.indexOf("--confirm");
if (confirmIndex === -1 || args[confirmIndex + 1] !== tag) {
  throw new Error(`Refusing to record ${tag} without confirmation. Re-run with: --confirm ${tag}`);
}

const { content, hash } = loadMigration(tag);
const conn = await mysql.createConnection(connectionConfig());

await conn.query(`
  create table if not exists \`__drizzle_migrations\` (
    id serial primary key,
    hash text not null,
    created_at bigint
  )
`);

const [existing] = await conn.query("SELECT id FROM __drizzle_migrations WHERE created_at = ?", [Number(entry.when)]);
if (existing.length > 0) {
  console.log(`Migration ${tag} is ALREADY recorded (created_at=${entry.when}) — nothing to do.`);
  await conn.end();
  process.exit(0);
}

console.log(`About to record migration "${tag}" as applied.`);
console.log(`  file      : drizzle/${tag}.sql`);
console.log(`  statements: ${content.split("--> statement-breakpoint").length}`);
console.log("  hash      :", hash);
console.log("\nThese statements are being ASSERTED as already present:\n");
console.log(
  content
    .split("--> statement-breakpoint")
    .map(s => "    " + s.trim().split("\n")[0].slice(0, 110))
    .join("\n"),
);

await conn.query("INSERT INTO `__drizzle_migrations` (`hash`, `created_at`) VALUES (?, ?)", [hash, Number(entry.when)]);
console.log(`\nRecorded ${tag} as applied. Run "pnpm exec drizzle-kit migrate" to apply the remaining migrations.`);
await conn.end();
