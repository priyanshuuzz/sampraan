import { randomUUID } from "node:crypto";
import { bigint, boolean, index, int, json, mysqlEnum, mysqlTable, primaryKey, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

/**
 * Managed template auth user. This table is retained for Manus OAuth and is
 * deliberately separate from SAMPRAAN's cryptographic identity model.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

const uuid = (name: string) => varchar(name, { length: 36 }).$defaultFn(() => randomUUID());
const createdAt = () => timestamp("createdAt").defaultNow().notNull();

export const identities = mysqlTable("identities", {
  id: uuid("id").primaryKey(),
  linkedUserId: int("linkedUserId").references(() => users.id),
  displayName: varchar("displayName", { length: 160 }).notNull(),
  organization: varchar("organization", { length: 180 }).notNull(),
  status: mysqlEnum("status", ["ACTIVE", "REVOKED", "SUSPENDED"]).default("ACTIVE").notNull(),
  did: varchar("did", { length: 255 }).notNull().unique(),
  createdAt: createdAt(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  revokedAt: timestamp("revokedAt"),
}, table => ({ organizationIdx: index("identities_organization_idx").on(table.organization) }));

export const publicKeys = mysqlTable("public_keys", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  keyIdentifier: varchar("keyIdentifier", { length: 160 }).notNull(),
  algorithm: varchar("algorithm", { length: 64 }).notNull(),
  publicKey: text("publicKey").notNull(),
  status: mysqlEnum("status", ["ACTIVE", "REVOKED"]).default("ACTIVE").notNull(),
  createdAt: createdAt(),
  revokedAt: timestamp("revokedAt"),
}, table => ({ identityIdx: index("public_keys_identity_idx").on(table.identityId), uniqueKey: uniqueIndex("public_keys_identity_key_idx").on(table.identityId, table.keyIdentifier) }));

export const roles = mysqlTable("roles", {
  id: uuid("id").primaryKey(),
  name: varchar("name", { length: 40 }).notNull().unique(),
  description: text("description"),
  createdAt: createdAt(),
});

export const permissions = mysqlTable("permissions", {
  id: uuid("id").primaryKey(),
  key: varchar("key", { length: 100 }).notNull().unique(),
  description: text("description"),
  createdAt: createdAt(),
});

export const rolePermissions = mysqlTable("role_permissions", {
  roleId: varchar("roleId", { length: 36 }).notNull().references(() => roles.id),
  permissionId: varchar("permissionId", { length: 36 }).notNull().references(() => permissions.id),
  createdAt: createdAt(),
}, table => ({ pk: primaryKey({ columns: [table.roleId, table.permissionId] }) }));

export const identityRoles = mysqlTable("identity_roles", {
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  roleId: varchar("roleId", { length: 36 }).notNull().references(() => roles.id),
  assignedByIdentityId: varchar("assignedByIdentityId", { length: 36 }).references(() => identities.id),
  createdAt: createdAt(),
}, table => ({ pk: primaryKey({ columns: [table.identityId, table.roleId] }) }));

export const policies = mysqlTable("policies", {
  id: uuid("id").primaryKey(),
  name: varchar("name", { length: 160 }).notNull(),
  description: text("description"),
  subjectRole: varchar("subjectRole", { length: 40 }),
  resourceType: varchar("resourceType", { length: 100 }).notNull(),
  action: varchar("action", { length: 100 }).notNull(),
  assetClassification: varchar("assetClassification", { length: 80 }),
  organization: varchar("organization", { length: 180 }),
  effect: mysqlEnum("effect", ["ALLOW", "DENY", "CHALLENGE"]).default("DENY").notNull(),
  active: boolean("active").default(true).notNull(),
  createdAt: createdAt(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => ({ policyMatchIdx: index("policies_match_idx").on(table.resourceType, table.action, table.active) }));

export const assets = mysqlTable("assets", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 120 }).notNull().unique(),
  name: varchar("name", { length: 200 }).notNull(),
  type: varchar("type", { length: 80 }).notNull(),
  classification: varchar("classification", { length: 80 }).notNull(),
  description: text("description"),
  ownerIdentityId: varchar("ownerIdentityId", { length: 36 }).notNull().references(() => identities.id),
  custodianIdentityId: varchar("custodianIdentityId", { length: 36 }).notNull().references(() => identities.id),
  integrityHash: varchar("integrityHash", { length: 255 }),
  tokenId: varchar("tokenId", { length: 160 }),
  status: mysqlEnum("status", ["ACTIVE", "REVOKED", "PENDING"]).default("PENDING").notNull(),
  createdAt: createdAt(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
}, table => ({ ownerIdx: index("assets_owner_idx").on(table.ownerIdentityId), custodyIdx: index("assets_custodian_idx").on(table.custodianIdentityId) }));

export const assetOwnership = mysqlTable("asset_ownership", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  ownerIdentityId: varchar("ownerIdentityId", { length: 36 }).notNull().references(() => identities.id),
  startedAt: createdAt(),
  endedAt: timestamp("endedAt"),
});

export const assetCustody = mysqlTable("asset_custody", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  custodianIdentityId: varchar("custodianIdentityId", { length: 36 }).notNull().references(() => identities.id),
  reason: varchar("reason", { length: 200 }),
  startedAt: createdAt(),
  endedAt: timestamp("endedAt"),
});

export const authorizationDecisions = mysqlTable("authorization_decisions", {
  id: uuid("id").primaryKey(),
  actorIdentityId: varchar("actorIdentityId", { length: 36 }).notNull().references(() => identities.id),
  resourceType: varchar("resourceType", { length: 100 }).notNull(),
  resourceId: varchar("resourceId", { length: 160 }).notNull(),
  action: varchar("action", { length: 100 }).notNull(),
  decision: mysqlEnum("decision", ["ALLOW", "DENY", "CHALLENGE"]).notNull(),
  reason: text("reason").notNull(),
  policyId: varchar("policyId", { length: 36 }).references(() => policies.id),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
}, table => ({ actorTimeIdx: index("authorization_actor_time_idx").on(table.actorIdentityId, table.timestamp) }));

export const auditEvents = mysqlTable("audit_events", {
  id: uuid("id").primaryKey(),
  actorIdentityId: varchar("actorIdentityId", { length: 36 }).references(() => identities.id),
  action: varchar("action", { length: 100 }).notNull(),
  resourceType: varchar("resourceType", { length: 100 }).notNull(),
  resourceId: varchar("resourceId", { length: 160 }),
  decision: mysqlEnum("decision", ["ALLOW", "DENY", "CHALLENGE"]),
  reason: text("reason"),
  timestamp: timestamp("timestamp").defaultNow().notNull(),
  transactionHash: varchar("transactionHash", { length: 255 }),
  blockNumber: bigint("blockNumber", { mode: "number" }),
  metadata: json("metadata"),
  source: mysqlEnum("source", ["APPLICATION", "CHAIN_READ_MODEL"]).default("APPLICATION").notNull(),
}, table => ({ eventTimeIdx: index("audit_events_time_idx").on(table.timestamp), resourceIdx: index("audit_events_resource_idx").on(table.resourceType, table.resourceId) }));

export const securityAlerts = mysqlTable("security_alerts", {
  id: uuid("id").primaryKey(),
  title: varchar("title", { length: 200 }).notNull(),
  severity: mysqlEnum("severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM").notNull(),
  status: mysqlEnum("status", ["OPEN", "INVESTIGATING", "RESOLVED"]).default("OPEN").notNull(),
  identityId: varchar("identityId", { length: 36 }).references(() => identities.id),
  assetId: varchar("assetId", { length: 36 }).references(() => assets.id),
  description: text("description").notNull(),
  riskScore: int("riskScore"),
  createdAt: createdAt(),
  resolvedAt: timestamp("resolvedAt"),
});

export const sessions = mysqlTable("sessions", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  // BUG-027: JWT session tokens (jose HS256, appId-bound claims) serialize to
  // 250+ characters — a 160-char column silently made server-side session
  // tracking impossible to ever store a real token. 512 gives ample margin.
  sessionId: varchar("sessionId", { length: 512 }).notNull().unique(),
  expiresAt: timestamp("expiresAt").notNull(),
  revokedAt: timestamp("revokedAt"),
  createdAt: createdAt(),
});

export type Identity = typeof identities.$inferSelect;
export type InsertIdentity = typeof identities.$inferInsert;
export type Asset = typeof assets.$inferSelect;
export type InsertAsset = typeof assets.$inferInsert;
export type Policy = typeof policies.$inferSelect;
export type AuditEvent = typeof auditEvents.$inferSelect;
export type AuthorizationDecision = typeof authorizationDecisions.$inferSelect;


/** DID material is separated from the identity profile so it can later be resolved and revoked independently. */
export const didRecords = mysqlTable("did_records", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  did: varchar("did", { length: 255 }).notNull().unique(),
  method: varchar("method", { length: 80 }).notNull(),
  subject: varchar("subject", { length: 255 }).notNull(),
  document: json("document"),
  status: mysqlEnum("status", ["ACTIVE", "REVOKED"]).default("ACTIVE").notNull(),
  createdAt: createdAt(),
  revokedAt: timestamp("revokedAt"),
}, table => ({ identityIdx: index("did_records_identity_idx").on(table.identityId) }));

export type DidRecord = typeof didRecords.$inferSelect;
export type InsertDidRecord = typeof didRecords.$inferInsert;
