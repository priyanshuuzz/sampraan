import { and, desc, eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import {
  assets,
  auditEvents,
  authorizationDecisions,
  identities,
  didRecords,
  securityAlerts,
  users,
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
