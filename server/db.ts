import { and, desc, eq, inArray, isNotNull, isNull } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  assetCustody,
  assets,
  auditEvents,
  authorizationDecisions,
  identities,
  didRecords,
  identityRoles,
  permissions,
  rolePermissions,
  roles,
  securityAlerts,
  sessions,
  users,
  type Asset,
  type Identity,
  type InsertAsset,
  type InsertIdentity,
  type InsertUser,
} from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

// TODO: add feature queries here as your schema grows.


export async function listIdentities() {
  const db = await getDb();
  return db ? db.select().from(identities).orderBy(desc(identities.createdAt)) : [];
}

export async function createIdentity(input: Omit<InsertIdentity, "id" | "createdAt" | "updatedAt">) {
  const db = await getDb();
  if (!db) throw new Error("Database is not configured");
  const id = crypto.randomUUID();
  await db.insert(identities).values({ ...input, id });
  const rows = await db.select().from(identities).where(eq(identities.id, id)).limit(1);
  return rows[0];
}

export async function getIdentityById(id: string) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(identities).where(eq(identities.id, id)).limit(1);
  return rows[0];
}

export async function listAssets() {
  const db = await getDb();
  return db ? db.select().from(assets).orderBy(desc(assets.createdAt)) : [];
}

export async function createAsset(input: Omit<InsertAsset, "id" | "createdAt" | "updatedAt">) {
  const db = await getDb();
  if (!db) throw new Error("Database is not configured");
  const id = crypto.randomUUID();
  await db.insert(assets).values({ ...input, id });
  const rows = await db.select().from(assets).where(eq(assets.id, id)).limit(1);
  return rows[0];
}

export async function getAssetById(id: string) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(assets).where(eq(assets.id, id)).limit(1);
  return rows[0];
}

/**
 * Resolves the SAMPRAAN identity linked to a platform user (Manus auth user id).
 * Returns undefined when no identity is linked or the database is unavailable.
 */
export async function getIdentityByLinkedUserId(linkedUserId: number) {
  const db = await getDb();
  if (!db) return undefined;
  const rows = await db.select().from(identities).where(eq(identities.linkedUserId, linkedUserId)).limit(1);
  return rows[0];
}

/**
 * Resolves the effective SAMPRAAN role names and permission keys granted to an
 * identity through identity_roles -> role_permissions -> permissions.
 */
export async function getIdentityRolesAndPermissions(identityId: string): Promise<{ roles: string[]; permissions: string[] }> {
  const db = await getDb();
  if (!db) return { roles: [], permissions: [] };

  const roleRows = await db
    .select({ roleId: roles.id, roleName: roles.name })
    .from(identityRoles)
    .innerJoin(roles, eq(identityRoles.roleId, roles.id))
    .where(eq(identityRoles.identityId, identityId));

  if (roleRows.length === 0) return { roles: [], permissions: [] };

  const permissionRows = await db
    .selectDistinct({ key: permissions.key })
    .from(rolePermissions)
    .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
    .where(inArray(rolePermissions.roleId, roleRows.map(row => row.roleId)));

  return {
    roles: roleRows.map(row => row.roleName),
    permissions: permissionRows.map(row => row.key),
  };
}

export async function createAuthorizationDecision(input: typeof authorizationDecisions.$inferInsert) {
  const db = await getDb();
  if (!db) return undefined;
  const id = input.id ?? crypto.randomUUID();
  await db.insert(authorizationDecisions).values({ ...input, id });
  const rows = await db.select().from(authorizationDecisions).where(eq(authorizationDecisions.id, id)).limit(1);
  return rows[0];
}

export async function createAuditEvent(input: typeof auditEvents.$inferInsert) {
  const db = await getDb();
  if (!db) return undefined;
  const id = input.id ?? crypto.randomUUID();
  await db.insert(auditEvents).values({ ...input, id });
  const rows = await db.select().from(auditEvents).where(eq(auditEvents.id, id)).limit(1);
  return rows[0];
}

export async function listAuditEvents(limit = 50) {
  const db = await getDb();
  return db ? db.select().from(auditEvents).orderBy(desc(auditEvents.timestamp)).limit(limit) : [];
}

export async function listSecurityAlerts() {
  const db = await getDb();
  return db ? db.select().from(securityAlerts).orderBy(desc(securityAlerts.createdAt)) : [];
}

export async function countOpenAlerts() {
  const db = await getDb();
  if (!db) return 0;
  const rows = await db.select().from(securityAlerts).where(and(eq(securityAlerts.status, "OPEN")));
  return rows.length;
}


export async function createDidRecord(input: Omit<typeof didRecords.$inferInsert, "id" | "createdAt">) {
  const db = await getDb();
  if (!db) throw new Error("Database is not configured");
  const id = crypto.randomUUID();
  await db.insert(didRecords).values({ ...input, id });
  const rows = await db.select().from(didRecords).where(eq(didRecords.id, id)).limit(1);
  return rows[0];
}

/**
 * BUG-006: after a successful on-chain custody transfer the read model must
 * reflect the new custodian, otherwise the DB and the chain disagree and the
 * UI keeps showing the pre-transfer custodian. Also closes the previous
 * custody row and opens a new one so the custody history stays accurate.
 *
 * Returns the updated asset, or null when the DB is unavailable (evidence is
 * already on-chain; the caller records the mismatch as a FAILED audit event).
 */
export async function applyCustodyTransfer(input: {
  assetRowId: string;
  newCustodianIdentityId: string | null;
  reason: string;
  transactionHash?: string | null;
  blockNumber?: number | null;
}): Promise<Asset | null> {
  const db = await getDb();
  if (!db) return null;

  await db.transaction(async tx => {
    if (input.newCustodianIdentityId) {
      await tx
        .update(assets)
        .set({ custodianIdentityId: input.newCustodianIdentityId })
        .where(eq(assets.id, input.assetRowId));
    }
    // Close the currently open custody row (if the table has one) and open a
    // new row for the incoming custodian.
    await tx
      .update(assetCustody)
      .set({ endedAt: new Date() })
      .where(and(eq(assetCustody.assetId, input.assetRowId), isNull(assetCustody.endedAt)));
    if (input.newCustodianIdentityId) {
      await tx.insert(assetCustody).values({
        id: crypto.randomUUID(),
        assetId: input.assetRowId,
        custodianIdentityId: input.newCustodianIdentityId,
        reason: input.reason,
      });
    }
  });

  const rows = await db.select().from(assets).where(eq(assets.id, input.assetRowId)).limit(1);
  return rows[0] ?? null;
}

/**
 * BUG-007 support: mark an identity SUSPENDED/REVOKED in the read model and
 * keep derived records consistent (DID record status, revokedAt timestamps).
 * Returns the updated identity or null when the DB is unavailable.
 */
export async function applyIdentityStatusChange(input: {
  identityId: string;
  status: "ACTIVE" | "SUSPENDED" | "REVOKED";
}): Promise<Identity | null> {
  const db = await getDb();
  if (!db) return null;

  const revokedAt = input.status === "REVOKED" ? new Date() : null;
  await db
    .update(identities)
    .set({
      status: input.status,
      ...(revokedAt ? { revokedAt } : {}),
    })
    .where(eq(identities.id, input.identityId));

  // Keep the DID record lifecycle in sync (a revoked identity must not keep
  // an ACTIVE DID document).
  const identityRows = await db.select().from(identities).where(eq(identities.id, input.identityId)).limit(1);
  const identity = identityRows[0];
  if (identity?.did) {
    await db
      .update(didRecords)
      .set({
        status: input.status === "ACTIVE" ? "ACTIVE" : "REVOKED",
        ...(input.status !== "ACTIVE" ? { revokedAt: new Date() } : {}),
      })
      .where(eq(didRecords.did, identity.did));
  }

  return identity ?? null;
}

/**
 * BUG-028: assets created through the API default to PENDING and previously
 * had NO transition path to ACTIVE — every API-created asset was permanently
 * untransferable. Admin-driven lifecycle change for the read model.
 */
export async function applyAssetStatusChange(input: {
  assetRowId: string;
  status: "ACTIVE" | "REVOKED" | "PENDING";
}): Promise<Asset | null> {
  const db = await getDb();
  if (!db) return null;
  await db
    .update(assets)
    .set({ status: input.status })
    .where(eq(assets.id, input.assetRowId));
  const rows = await db.select().from(assets).where(eq(assets.id, input.assetRowId)).limit(1);
  return rows[0] ?? null;
}

/**
 * BUG-030: the chain-event indexer deduplicated only against an in-memory
 * Set, so every process restart re-projected the same chain events and
 * duplicated audit rows (observed live: one tx anchored 4 times). This
 * returns the set of transaction hashes already recorded from the chain so
 * the indexer can skip them durably, across restarts.
 */
export async function listIndexedChainTxHashes(): Promise<Set<string>> {
  const db = await getDb();
  if (!db) return new Set();
  const rows = await db
    .select({ transactionHash: auditEvents.transactionHash })
    .from(auditEvents)
    .where(and(eq(auditEvents.source, "CHAIN_READ_MODEL"), isNotNull(auditEvents.transactionHash)));
  return new Set(rows.map(r => r.transactionHash).filter((h): h is string => Boolean(h)));
}

/**
 * QA #5 (server-side session revocation): given a session token, classify
 * its server-side tracking state. DISTINCT outcomes matter:
 *  - "UNTRACKED"  — no row exists for this token (e.g. cron sessions,
 *    tokens minted before tracking began): JWT verification governs alone.
 *  - "ACTIVE"     — tracked, not revoked, not expired: the session stands.
 *  - "REVOKED"   — an administrator revoked it server-side: reject NOW,
 *    regardless of the JWT's own expiry.
 *  - "EXPIRED"   — the tracked row's expiry has passed: reject NOW.
 */
export type PlatformSessionState =
  | { state: "UNTRACKED" }
  | { state: "ACTIVE"; id: string; identityId: string; expiresAt: Date }
  | { state: "REVOKED" }
  | { state: "EXPIRED" };

export async function classifyPlatformSession(sessionToken: string): Promise<PlatformSessionState> {
  const db = await getDb();
  if (!db) return { state: "UNTRACKED" };
  const rows = await db
    .select({
      id: sessions.id,
      identityId: sessions.identityId,
      expiresAt: sessions.expiresAt,
      revokedAt: sessions.revokedAt,
    })
    .from(sessions)
    .where(eq(sessions.sessionId, sessionToken))
    .limit(1);
  const row = rows[0];
  if (!row) return { state: "UNTRACKED" };
  if (row.revokedAt) return { state: "REVOKED" };
  if (row.expiresAt.getTime() <= Date.now()) return { state: "EXPIRED" };
  return { state: "ACTIVE", id: row.id, identityId: row.identityId, expiresAt: row.expiresAt };
}

/**
 * Revoke a tracked platform session server-side (admin action). Returns
 * true when a row was revoked, false when the token is not tracked.
 */
export async function revokePlatformSession(sessionToken: string): Promise<boolean> {
  const db = await getDb();
  if (!db) return false;
  const result = await db
    .update(sessions)
    .set({ revokedAt: new Date() })
    .where(and(eq(sessions.sessionId, sessionToken), isNull(sessions.revokedAt)));
  return (result as unknown as { affectedRows?: number }).affectedRows !== 0;
}

/**
 * Track a newly issued platform session token so server-side revocation
 * (classifyPlatformSession / revokePlatformSession) has a row to act on.
 *
 * SECURITY: without this insert, every session minted by a real OAuth login
 * is UNTRACKED — classifyPlatformSession returns { state: "UNTRACKED" } and
 * an administrator revocation can never take effect. Tracking is therefore
 * part of the login path itself, not an optional extra.
 *
 * Best-effort by design: a tracking failure must NOT lock the user out of a
 * cryptographically valid session (availability), but it is logged loudly
 * because it weakens the revocation guarantee until the next login.
 *
 * The identity linkage uses the SAMPRAAN identity bound to the platform
 * user when one exists; sessions for platform users without a linked
 * SAMPRAAN identity are tracked against a sentinel identity reference so
 * the NOT NULL FK still holds. The sentinel row is created on demand.
 */
const UNLINKED_SESSIONS_IDENTITY_ID = "00000000-0000-4000-8000-000000000000";
const UNLINKED_SESSIONS_DID = "did:sampraan:platform-user-sessions";

async function ensureUnlinkedSessionsIdentity(db: NonNullable<Awaited<ReturnType<typeof getDb>>>): Promise<void> {
  await db
    .insert(identities)
    .values({
      id: UNLINKED_SESSIONS_IDENTITY_ID,
      displayName: "Platform User Sessions",
      organization: "SAMPRAAN",
      status: "ACTIVE",
      did: UNLINKED_SESSIONS_DID,
    })
    .onDuplicateKeyUpdate({ set: { updatedAt: new Date() } });
}

export async function trackPlatformSession(input: {
  sessionToken: string;
  linkedUserId: number;
  expiresAt: Date;
}): Promise<void> {
  const db = await getDb();
  if (!db) {
    // No database: revocation tracking is impossible. Log it — the JWT
    // itself is still the (only) validity boundary in this mode.
    console.warn("[Auth] Cannot track platform session: database not available");
    return;
  }

  try {
    const userRows = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.id, input.linkedUserId))
      .limit(1);
    if (userRows.length === 0) {
      console.warn("[Auth] Cannot track platform session: user row disappeared mid-login");
      return;
    }

    const identityRows = await db
      .select({ id: identities.id })
      .from(identities)
      .where(eq(identities.linkedUserId, input.linkedUserId))
      .limit(1);

    let identityId = identityRows[0]?.id;
    if (!identityId) {
      await ensureUnlinkedSessionsIdentity(db);
      identityId = UNLINKED_SESSIONS_IDENTITY_ID;
    }

    await db
      .insert(sessions)
      .values({
        id: crypto.randomUUID(),
        identityId,
        sessionId: input.sessionToken,
        expiresAt: input.expiresAt,
      })
      .onDuplicateKeyUpdate({
        set: { expiresAt: input.expiresAt, revokedAt: null },
      });
  } catch (error) {
    console.error("[Auth] Failed to track platform session:", error);
  }
}
