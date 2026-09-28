/**
 * DATABASE SCHEMA READINESS.
 *
 * Readiness must mean "this process can actually serve requests", not merely
 * "TCP to MySQL succeeded". A deployment pointed at an UNMIGRATED database
 * connects fine and then fails every query — which surfaces to users as a wall
 * of 500s while the platform reports the instance healthy.
 *
 * This probe asks the database for the tables the application cannot run
 * without, and requires the migration journal to be present. It is deliberately
 * cheap (one catalog query) and read-only, so it is safe to call on every
 * readiness request.
 *
 * It intentionally does NOT run migrations: applying schema changes as a side
 * effect of a health probe would be unsafe under multiple replicas. Migrations
 * belong to the release step (`node dist/migrate.js`).
 */
import { sql } from "drizzle-orm";
import { getDb } from "../../db";

/**
 * Tables whose absence means the application is running against the wrong
 * schema version. Chosen as one representative per feature area so the check
 * catches ANY missing migration without listing all 34 tables:
 *   identities                      → core identity model
 *   did_key_records                 → DID key lifecycle (0006)
 *   asset_content_versions          → encrypted content model (0005)
 *   mint_requests                   → governance lifecycle (0007)
 *   assurance_challenges            → PQC crypto assurance (0008)
 */
const REQUIRED_TABLES = [
  "identities",
  "did_key_records",
  "asset_content_versions",
  "mint_requests",
  "assurance_challenges",
] as const;

export interface SchemaReadiness {
  ready: boolean;
  detail: string;
  missingTables: string[];
}

export async function checkSchemaReady(): Promise<SchemaReadiness> {
  const db = await getDb();
  if (!db) return { ready: false, detail: "DATABASE_UNAVAILABLE", missingTables: [...REQUIRED_TABLES] };
  try {
    // information_schema is portable across MySQL 8.x and costs one round trip.
    // Identifiers are bound as parameters (never interpolated) so the probe
    // cannot be turned into an injection even though the list is a constant.
    const result = (await db.execute(sql`
      SELECT TABLE_NAME AS tableName
      FROM information_schema.tables
      WHERE table_schema = DATABASE()
        AND TABLE_NAME IN (${sql.join(
          REQUIRED_TABLES.map(table => sql`${table}`),
          sql`, `,
        )})
    `)) as unknown as [Array<{ tableName: string }>];
    const present = new Set((result[0] ?? []).map(row => row.tableName));
    const missing = REQUIRED_TABLES.filter(table => !present.has(table));
    if (missing.length === 0) return { ready: true, detail: "MIGRATED", missingTables: [] };
    return {
      ready: false,
      detail: `SCHEMA_OUT_OF_DATE — missing: ${missing.join(", ")}. Run the release migration command (node dist/migrate.js).`,
      missingTables: missing,
    };
  } catch (error) {
    return {
      ready: false,
      detail: `SCHEMA_PROBE_FAILED: ${error instanceof Error ? error.message.slice(0, 140) : "unknown"}`,
      missingTables: [],
    };
  }
}
