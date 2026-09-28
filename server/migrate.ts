/**
 * SAMPRAAN DATABASE MIGRATION RUNNER (production entry point).
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The production container installs runtime dependencies only (`pnpm install
 * --prod`), so `drizzle-kit` — a devDependency — is NOT present. Documenting
 * `pnpm drizzle-kit migrate` as the deploy step therefore produced a command
 * that could not run in the very image it was documented for. This runner uses
 * `drizzle-orm`'s migrator, which ships in `dependencies`, so migrations can be
 * applied inside the production image (and from a Railway/Render release
 * command) with no build toolchain.
 *
 * Behaviour:
 *  - refuses to run without DATABASE_URL (fail closed, clear message);
 *  - applies every journal entry newer than the newest recorded row, in order;
 *  - exits non-zero on failure so a deployment/release command actually fails;
 *  - is safe to re-run: already-applied migrations are skipped by the migrator.
 *
 * Usage:
 *   node dist/migrate.js                 # production image
 *   pnpm run db:migrate                  # local/dev (tsx)
 *   MIGRATIONS_FOLDER=/some/path node dist/migrate.js
 */
import "dotenv/config";
import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/mysql2";
import { migrate } from "drizzle-orm/mysql2/migrator";

async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error(
      "[Migrate] DATABASE_URL is not set. Refusing to run: a migration against an unknown database is never safe.",
    );
    process.exit(1);
  }

  // Resolve the migrations folder relative to THIS file so the runner works
  // both from source (server/migrate.ts → ../drizzle) and from the bundle
  // (dist/migrate.js → ../drizzle).
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.MIGRATIONS_FOLDER,
    path.resolve(here, "..", "drizzle"),
    path.resolve(here, "..", "..", "drizzle"),
    path.resolve(process.cwd(), "drizzle"),
  ].filter((value): value is string => typeof value === "string" && value.length > 0);
  const migrationsFolder = candidates.find(folder => existsSync(path.join(folder, "meta", "_journal.json")));
  if (!migrationsFolder) {
    console.error(
      `[Migrate] Could not locate the drizzle migrations folder (looked in: ${candidates.join(", ")}). Set MIGRATIONS_FOLDER explicitly.`,
    );
    process.exit(1);
  }

  console.log(`[Migrate] Applying migrations from ${migrationsFolder}`);
  console.log(`[Migrate] Target database: ${describeDatabase(databaseUrl)}`);

  const db = drizzle(databaseUrl);
  try {
    await migrate(db, { migrationsFolder });
    console.log("[Migrate] All pending migrations applied successfully.");
  } catch (error) {
    console.error(
      "[Migrate] Migration FAILED:",
      error instanceof Error ? error.message : String(error),
    );
    process.exit(1);
  }
  // Exit explicitly: the mysql2 pool keeps a handle open and would otherwise
  // hang a release command that has already finished its work.
  process.exit(0);
}

/** Host/database only — credentials are NEVER logged. */
function describeDatabase(databaseUrl: string): string {
  try {
    const parsed = new URL(databaseUrl);
    return `${parsed.hostname}:${parsed.port || "3306"}/${parsed.pathname.replace(/^\//, "")}`;
  } catch {
    return "<unparseable DATABASE_URL>";
  }
}

main().catch(error => {
  console.error("[Migrate] Unexpected failure:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
