/**
 * F5 REGRESSION — access-grant re-issue after soft revocation.
 *
 * BUG THIS PINS: grants are soft-revoked (revokedAt) for auditability, but
 * the UNIQUE (assetId, granteeIdentityId, permission) index spans live AND
 * revoked rows. Re-issuing a previously revoked grant hit the raw duplicate
 * key and surfaced as a masked 500 — Manage Access was effectively
 * single-use per (asset, identity, permission). The fix revives the revoked
 * row atomically instead of inserting a second row (the constraint stays,
 * which is what keeps racing grants safe).
 *
 * DB-backed: skipped automatically when no MySQL is reachable.
 */
import "dotenv/config";
import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createAssetAccessGrant,
  createAuditEvent,
  getDb,
  listActiveAssetAccessGrants,
  revokeAssetAccessGrant,
} from "../../db";
import { assetAccessGrants, assets, identities } from "../../../drizzle/schema";
import { eq } from "drizzle-orm";

async function dbAvailable(): Promise<boolean> {
  try {
    const db = await getDb();
    if (!db) return false;
    await db.select({ id: assets.id }).from(assets).limit(1);
    return true;
  } catch {
    return false;
  }
}

const testShouldRun = await dbAvailable();
const d = testShouldRun ? describe : describe.skip;

/** Test fixtures are created AND cleaned up by the suite itself. */
async function setupFixture(): Promise<{ assetRowId: string; granteeIdentityId: string; grantorIdentityId: string } | null> {
  const db = await getDb();
  if (!db) return null;
  // Use the demo admin identity as grantor and create a THROWAWAY grantee
  // identity so re-runs never collide with demo rows.
  const adminRows = await db.select({ id: identities.id }).from(identities).where(eq(identities.did, "did:sampraan:dev-admin-aarav")).limit(1);
  const grantorIdentityId = adminRows[0]?.id;
  if (!grantorIdentityId) return null;
  const granteeIdentityId = randomUUID();
  await db.insert(identities).values({
    id: granteeIdentityId,
    displayName: "F5 Regression Grantee",
    organization: "SAMPRAAN TEST",
    status: "ACTIVE",
    did: `did:sampraan:f5-regression-${randomUUID().slice(0, 8)}`,
  });
  // A throwaway asset row keeps the probe self-contained.
  const assetRowId = randomUUID();
  await db.insert(assets).values({
    id: assetRowId,
    assetId: `F5-REGRESSION-${randomUUID().slice(0, 8)}`,
    name: "F5 Regression Probe Asset",
    type: "TEST",
    classification: "CONTROLLED",
    ownerIdentityId: grantorIdentityId,
    custodianIdentityId: grantorIdentityId,
    status: "ACTIVE",
  });
  return { assetRowId, granteeIdentityId, grantorIdentityId };
}

async function cleanupFixture(ids: { assetRowId: string; granteeIdentityId: string } | null): Promise<void> {
  if (!ids) return;
  const db = await getDb();
  if (!db) return;
  await db.delete(assetAccessGrants).where(eq(assetAccessGrants.assetId, ids.assetRowId));
  await db.delete(assets).where(eq(assets.id, ids.assetRowId));
  await db.delete(identities).where(eq(identities.id, ids.granteeIdentityId));
}

d("asset access grants: re-issue after revocation (F5)", () => {
  it("re-granting a previously revoked permission succeeds (no duplicate-key 500)", async () => {
    const ids = await setupFixture();
    expect(ids).not.toBeNull();
    if (!ids) return;
    try {
      const created = await createAuditEvent({ actorIdentityId: null, action: "F5_TEST_PROBE", resourceType: "TEST", resourceId: "f5" });
      expect(created).toBeDefined();

      const first = await createAssetAccessGrant({
        assetId: ids.assetRowId,
        granteeIdentityId: ids.granteeIdentityId,
        permission: "VIEW",
        grantedByIdentityId: ids.grantorIdentityId,
        reason: "first issue",
      });
      expect(first).toBeDefined();
      expect(first?.revokedAt ?? null).toBeNull();

      const revoked = await revokeAssetAccessGrant(first!.id);
      expect(revoked).toBe(true);

      // THE FIX UNDER TEST: re-issue the SAME (asset, grantee, permission).
      // Previously: raw duplicate-key failure (masked 500).
      const second = await createAssetAccessGrant({
        assetId: ids.assetRowId,
        granteeIdentityId: ids.granteeIdentityId,
        permission: "VIEW",
        grantedByIdentityId: ids.grantorIdentityId,
        reason: "re-issue after revocation",
      });
      expect(second).toBeDefined();
      expect(second?.revokedAt ?? null).toBeNull();
      expect(second?.id).toBe(first!.id); // the soft-revoked row was revived
      expect(second?.reason).toBe("re-issue after revocation");

      // The active-grant probe (used by the content gate) now sees VIEW again.
      const active = await listActiveAssetAccessGrants(ids.assetRowId, ids.granteeIdentityId);
      expect(active.map(row => row.permission)).toContain("VIEW");

      // Exactly ONE row exists for the triple (constraint preserved, no dupes).
      const db = await getDb();
      const allRows = await db!.select().from(assetAccessGrants).where(eq(assetAccessGrants.assetId, ids.assetRowId));
      expect(allRows.length).toBe(1);
    } finally {
      await cleanupFixture(ids);
    }
  }, 30_000);

  it("re-granting over a LIVE grant still conflicts (does not silently overwrite)", async () => {
    const ids = await setupFixture();
    expect(ids).not.toBeNull();
    if (!ids) return;
    try {
      const first = await createAssetAccessGrant({
        assetId: ids.assetRowId,
        granteeIdentityId: ids.granteeIdentityId,
        permission: "EDIT",
        grantedByIdentityId: ids.grantorIdentityId,
      });
      expect(first).toBeDefined();
      await expect(
        createAssetAccessGrant({
          assetId: ids.assetRowId,
          granteeIdentityId: ids.granteeIdentityId,
          permission: "EDIT",
          grantedByIdentityId: ids.grantorIdentityId,
        }),
      ).rejects.toThrow(/DUPLICATE_ACTIVE_GRANT/);
      // The live row is untouched.
      const active = await listActiveAssetAccessGrants(ids.assetRowId, ids.granteeIdentityId);
      expect(active.length).toBe(1);
    } finally {
      await cleanupFixture(ids);
    }
  }, 30_000);
});
