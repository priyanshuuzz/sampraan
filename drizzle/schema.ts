import { randomUUID } from "node:crypto";
import { bigint, boolean, index, int, json, mysqlEnum, mysqlTable, primaryKey, text, timestamp, uniqueIndex, varchar } from "drizzle-orm/mysql-core";

/**
 * Managed template auth user. This table is retained for the OAuth sync flow and is
 * deliberately separate from SAMPRAAN's cryptographic identity model.
 */
export const users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  /**
   * LOCAL AUTH (development/team demonstration):
   * scrypt password hash ("scrypt$N$r$p$salt$hash", base64url components) for
   * accounts provisioned by the dev seed. OAuth remains the production auth
   * path; local accounts are created ONLY through the seed/admin tooling,
   * never self-service, and always with server-side hashing.
   */
  passwordHash: varchar("passwordHash", { length: 255 }),
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
  // GOVERNANCE LIFECYCLE (document "Role Definitions and Access Rights"):
  // PENDING/VERIFIED/SUSPENDED/DEACTIVATED — tracked SEPARATELY from DID key
  // state. VERIFIED is the only state permitted protected operations.
  lifecycleState: mysqlEnum("lifecycleState", ["PENDING", "VERIFIED", "SUSPENDED", "DEACTIVATED"]).default("VERIFIED").notNull(),
  /** Mandatory reason for the last privileged lifecycle mutation (verify/suspend/reactivate/deactivate). */
  statusReason: varchar("statusReason", { length: 300 }),
  /** Manager data scope (organization boundary); managers act ONLY inside it. */
  scope: varchar("scope", { length: 180 }),
  deactivatedAt: timestamp("deactivatedAt"),
  createdAt: createdAt(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  revokedAt: timestamp("revokedAt"),
}, table => ({ organizationIdx: index("identities_organization_idx").on(table.organization) }));

/** Maker-checker minting: Manager requests, Admin approves, execution mints+assigns atomically. */
export const mintRequests = mysqlTable("mint_requests", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 120 }).notNull().unique(),
  name: varchar("name", { length: 200 }).notNull(),
  type: varchar("type", { length: 80 }).notNull(),
  classification: mysqlEnum("classification", ["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]).notNull(),
  description: text("description"),
  integrityHash: varchar("integrityHash", { length: 255 }),
  ownerIdentityId: varchar("ownerIdentityId", { length: 36 }).notNull().references(() => identities.id),
  custodianIdentityId: varchar("custodianIdentityId", { length: 36 }).notNull().references(() => identities.id),
  requestedByIdentityId: varchar("requestedByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  requesterScope: varchar("requesterScope", { length: 180 }),
  status: mysqlEnum("status", ["PENDING", "APPROVED", "REJECTED", "EXECUTED"]).default("PENDING").notNull(),
  decidedByIdentityId: varchar("decidedByIdentityId", { length: 36 }).references(() => identities.id),
  decisionReason: varchar("decisionReason", { length: 300 }),
  decidedAt: timestamp("decidedAt"),
  executedAt: timestamp("executedAt"),
  tokenId: varchar("tokenId", { length: 160 }),
  transactionHash: varchar("transactionHash", { length: 255 }),
  createdAt: createdAt(),
});

/** Controlled NFT transfer: request → recipient accept → scoped approval → on-chain execution. */
export const assetTransferRequests = mysqlTable("asset_transfer_requests", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  tokenId: varchar("tokenId", { length: 160 }),
  fromIdentityId: varchar("fromIdentityId", { length: 36 }).notNull().references(() => identities.id),
  toIdentityId: varchar("toIdentityId", { length: 36 }).notNull().references(() => identities.id),
  requestedByIdentityId: varchar("requestedByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  acceptedAt: timestamp("acceptedAt"),
  status: mysqlEnum("status", ["PENDING", "ACCEPTED", "APPROVED", "REJECTED", "EXECUTED", "CANCELLED"]).default("PENDING").notNull(),
  approverIdentityId: varchar("approverIdentityId", { length: 36 }).references(() => identities.id),
  decisionReason: varchar("decisionReason", { length: 300 }),
  decidedAt: timestamp("decidedAt"),
  executedAt: timestamp("executedAt"),
  transactionHash: varchar("transactionHash", { length: 255 }),
  createdAt: createdAt(),
});

/** Auditor-raised disputes; an OPEN/UPHELD dispute freezes the asset transfer. */
export const assetDisputes = mysqlTable("asset_disputes", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  raisedByIdentityId: varchar("raisedByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  evidenceHash: varchar("evidenceHash", { length: 64 }).notNull(),
  reason: varchar("reason", { length: 300 }).notNull(),
  onChainDisputeId: int("onChainDisputeId"),
  status: mysqlEnum("status", ["OPEN", "UPHELD", "REJECTED"]).default("OPEN").notNull(),
  resolvedByIdentityId: varchar("resolvedByIdentityId", { length: 36 }).references(() => identities.id),
  resolutionReason: varchar("resolutionReason", { length: 300 }),
  resolvedAt: timestamp("resolvedAt"),
  transactionHash: varchar("transactionHash", { length: 255 }),
  createdAt: createdAt(),
});

/** Auditor anomaly flags — evidence only, never a mutation vector. */
export const identityAnomalies = mysqlTable("identity_anomalies", {
  id: uuid("id").primaryKey(),
  targetIdentityId: varchar("targetIdentityId", { length: 36 }).references(() => identities.id),
  assetId: varchar("assetId", { length: 36 }).references(() => assets.id),
  flaggedByIdentityId: varchar("flaggedByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  reason: varchar("reason", { length: 300 }).notNull(),
  onChainAnomalyId: int("onChainAnomalyId"),
  transactionHash: varchar("transactionHash", { length: 255 }),
  createdAt: createdAt(),
});

/** Off-chain audit report HASHES committed on-chain (contents never on-chain). */
export const auditReportHashes = mysqlTable("audit_report_hashes", {
  id: uuid("id").primaryKey(),
  auditorIdentityId: varchar("auditorIdentityId", { length: 36 }).notNull().references(() => identities.id),
  reportHash: varchar("reportHash", { length: 64 }).notNull().unique(),
  onChainReportId: int("onChainReportId"),
  transactionHash: varchar("transactionHash", { length: 255 }),
  createdAt: createdAt(),
});

/** Versioned DID document hashes (contents stay off-chain; history preserved). */
export const didDocumentVersions = mysqlTable("did_document_versions", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  versionNumber: int("versionNumber").notNull(),
  documentHash: varchar("documentHash", { length: 64 }).notNull(),
  reason: varchar("reason", { length: 300 }),
  createdByIdentityId: varchar("createdByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  onChainVersion: int("onChainVersion"),
  transactionHash: varchar("transactionHash", { length: 255 }),
  createdAt: createdAt(),
}, table => ({ identityVersionIdx: uniqueIndex("did_document_versions_identity_version_idx").on(table.identityId, table.versionNumber) }));

/** Selective-disclosure consent: binds subject + verifier + scope, expires, revocable. Grants NO authority. */
export const consentGrants = mysqlTable("consent_grants", {
  id: uuid("id").primaryKey(),
  subjectIdentityId: varchar("subjectIdentityId", { length: 36 }).notNull().references(() => identities.id),
  verifierDid: varchar("verifierDid", { length: 255 }).notNull(),
  scope: varchar("scope", { length: 180 }).notNull(),
  grantedAt: createdAt(),
  expiresAt: timestamp("expiresAt").notNull(),
  revokedAt: timestamp("revokedAt"),
}, table => ({ subjectVerifierIdx: index("consent_grants_subject_idx").on(table.subjectIdentityId, table.verifierDid) }));

/** Key recovery: manager-assisted + admin approval; guardian approval ledger in JSON. */
export const keyRecoveryRequests = mysqlTable("key_recovery_requests", {
  id: uuid("id").primaryKey(),
  subjectIdentityId: varchar("subjectIdentityId", { length: 36 }).notNull().references(() => identities.id),
  requestedByIdentityId: varchar("requestedByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  newKeyDigest: varchar("newKeyDigest", { length: 64 }).notNull(),
  status: mysqlEnum("status", ["PENDING", "AWAITING_ADMIN", "APPROVED", "REJECTED", "EXECUTED"]).default("PENDING").notNull(),
  guardianApprovals: json("guardianApprovals"),
  decidedByIdentityId: varchar("decidedByIdentityId", { length: 36 }).references(() => identities.id),
  decisionReason: varchar("decisionReason", { length: 300 }),
  executedAt: timestamp("executedAt"),
  createdAt: createdAt(),
});

/** Single-use nonce-bound ownership presentations (verifiable proof). */
export const ownershipPresentations = mysqlTable("ownership_presentations", {
  id: uuid("id").primaryKey(),
  subjectIdentityId: varchar("subjectIdentityId", { length: 36 }).notNull().references(() => identities.id),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  verifierDid: varchar("verifierDid", { length: 255 }).notNull(),
  purpose: varchar("purpose", { length: 120 }).notNull(),
  nonce: varchar("nonce", { length: 128 }).notNull().unique(),
  signature: text("signature").notNull(),
  keyIdentifier: varchar("keyIdentifier", { length: 80 }).notNull(),
  message: text("message").notNull(),
  expiresAt: timestamp("expiresAt").notNull(),
  consumedAt: timestamp("consumedAt"),
  createdAt: createdAt(),
});

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

/**
 * POST-QUANTUM VERIFICATION KEYS (ML-DSA-65) — the PQC half of the crypto
 * assurance layer.
 *
 * Holds PUBLIC key material ONLY; secret/private key material must never be
 * written here. keySource records provenance:
 *   REGISTERED      — supplied by the holder. This is the PRODUCTION path: the
 *                     secret key stays inside the holder's KMS/HSM/wallet and
 *                     the server only ever holds the public key.
 *   SERVER_DERIVED  — derived deterministically from the server operator key by
 *                     the LOCAL DEV provider (demo only; refused in production
 *                     unless explicitly enabled).
 * Lifecycle mirrors did_key_records: ACTIVE / ROTATED / REVOKED, so key
 * rotation and revocation are attributable without destroying history.
 */
export const pqcKeyRecords = mysqlTable("pqc_key_records", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  /** DID this verification key is bound to (rotation follows the identity's DID). */
  did: varchar("did", { length: 255 }).notNull(),
  keyIdentifier: varchar("keyIdentifier", { length: 80 }).notNull(),
  /** Explicit algorithm metadata, e.g. "ML-DSA-65" — never implied. */
  algorithm: varchar("algorithm", { length: 64 }).notNull().default("ML-DSA-65"),
  /** Base64url-encoded PUBLIC key (1952 bytes for ML-DSA-65). Never secret. */
  publicKey: text("publicKey").notNull(),
  /** sha256 hex of the raw public key — stable, non-reversible key fingerprint. */
  publicKeyFingerprint: varchar("publicKeyFingerprint", { length: 64 }).notNull(),
  keySource: mysqlEnum("keySource", ["REGISTERED", "SERVER_DERIVED"]).default("REGISTERED").notNull(),
  status: mysqlEnum("status", ["ACTIVE", "ROTATED", "REVOKED"]).default("ACTIVE").notNull(),
  registeredByIdentityId: varchar("registeredByIdentityId", { length: 36 }).references(() => identities.id),
  supersededByKeyIdentifier: varchar("supersededByKeyIdentifier", { length: 80 }),
  note: varchar("note", { length: 200 }),
  createdAt: createdAt(),
  deactivatedAt: timestamp("deactivatedAt"),
}, table => ({
  identityIdx: index("pqc_key_records_identity_idx").on(table.identityId),
  didIdx: index("pqc_key_records_did_idx").on(table.did),
  uniqueKey: uniqueIndex("pqc_key_records_did_key_idx").on(table.did, table.keyIdentifier),
}));

export type PqcKeyRecord = typeof pqcKeyRecords.$inferSelect;
export type InsertPqcKeyRecord = typeof pqcKeyRecords.$inferInsert;

/**
 * CRYPTO ASSURANCE CHALLENGES (policy-driven PQC step-up).
 *
 * A high-risk operation whose policy-derived assurance level requires more
 * than the ECDSA baseline gets ONE challenge that must be satisfied by BOTH
 * a secp256k1 (EIP-191) signature AND an ML-DSA-65 signature over the SAME
 * canonical payload. The payload binds identity, DID, key ids, both
 * algorithms, operation, resource, audience, nonce, issued-at and expiry, so
 * a signature is valid for exactly one operation on exactly one resource in
 * exactly one deployment — cross-operation, cross-resource, cross-audience,
 * cross-key and replayed signatures all fail closed.
 *
 * Consumption is atomic (single guarded UPDATE on consumedAt IS NULL), so a
 * concurrent replay loses the race at the database layer.
 *
 * NO SECRET MATERIAL IS STORED: the row holds public key ids and digests of
 * the signatures' audit metadata only.
 */
export const assuranceChallenges = mysqlTable("assurance_challenges", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  did: varchar("did", { length: 255 }).notNull(),
  /** AS-BAC operation label, e.g. GOVERNANCE_PROPOSAL / ASSET_TRANSFER. */
  operation: varchar("operation", { length: 120 }).notNull(),
  resourceType: varchar("resourceType", { length: 100 }).notNull(),
  resourceId: varchar("resourceId", { length: 160 }).notNull(),
  /** Policy-derived assurance level this challenge must satisfy. */
  assuranceLevel: mysqlEnum("assuranceLevel", ["BASELINE", "ELEVATED", "QUANTUM_HARDENED"]).notNull(),
  /** Ordered algorithm list the verifier will accept, e.g. ["ECDSA_SECP256K1","ML_DSA_65"]. */
  requiredAlgorithms: json("requiredAlgorithms").notNull(),
  /** Machine-readable policy reason codes (explainability / audit). */
  reasonCodes: json("reasonCodes").notNull(),
  audience: varchar("audience", { length: 120 }).notNull(),
  ecdsaKeyIdentifier: varchar("ecdsaKeyIdentifier", { length: 80 }).notNull(),
  pqcKeyIdentifier: varchar("pqcKeyIdentifier", { length: 80 }),
  nonce: varchar("nonce", { length: 128 }).notNull().unique(),
  /** Canonical payload both signatures must cover (client cannot alter it). */
  message: text("message").notNull(),
  ecdsaVerified: boolean("ecdsaVerified").default(false).notNull(),
  pqcVerified: boolean("pqcVerified").default(false).notNull(),
  expiresAt: timestamp("expiresAt").notNull(),
  /** Set when the dual signature was accepted — the grant's validity anchor. */
  consumedAt: timestamp("consumedAt"),
  /**
   * Set when the grant was CLAIMED by exactly one protected operation. The
   * claim is a status-guarded UPDATE, so a verified grant is single-use: it
   * cannot authorize the same critical operation twice (no replay).
   */
  executedAt: timestamp("executedAt"),
  createdAt: createdAt(),
}, table => ({
  identityIdx: index("assurance_challenges_identity_idx").on(table.identityId),
  resourceIdx: index("assurance_challenges_resource_idx").on(table.resourceType, table.resourceId),
}));

export type AssuranceChallenge = typeof assuranceChallenges.$inferSelect;
export type InsertAssuranceChallenge = typeof assuranceChallenges.$inferInsert;

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
  // DEFENSE IN DEPTH (adversarial review): the classification drives
  // POLICY-HIGH-SENS-TRANSFER / POLICY-STEP-UP. The tRPC input schema is
  // already an enum, but the DATABASE column must also refuse values outside
  // the 5 blessed classifications so no write path (future admin tooling, a
  // forgotten validator, direct SQL) can smuggle an unknown classification
  // past the policy engine.
  classification: mysqlEnum("classification", ["PUBLIC", "CONTROLLED", "SENSITIVE", "HIGHLY_SENSITIVE", "CRITICAL"]).notNull(),
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
  // Key lifecycle (LOOP 3): ACTIVE = current signing key; ROTATED = superseded
  // key that must not authenticate where policy requires the current key;
  // REVOKED = permanently unusable. Additive column — existing rows default ACTIVE.
  keyStatus: mysqlEnum("keyStatus", ["ACTIVE", "ROTATED", "REVOKED"]).default("ACTIVE").notNull(),
  // DID HARDENING: identifier of the CURRENT verification key. Included in
  // every signed challenge payload so a signature bound to key generation N
  // can never authenticate as key generation N+1 (rotation kills in-flight
  // challenges). Legacy rows (pre-hardening) resolve to "key-1" in code.
  keyIdentifier: varchar("keyIdentifier", { length: 80 }),
  // The key id this key superseded (rotation chain head), null for the first key.
  rotatedFrom: varchar("rotatedFrom", { length: 80 }),
  rotatedAt: timestamp("rotatedAt"),
  createdAt: createdAt(),
  revokedAt: timestamp("revokedAt"),
}, table => ({ identityIdx: index("did_records_identity_idx").on(table.identityId) }));

export type DidRecord = typeof didRecords.$inferSelect;
export type InsertDidRecord = typeof didRecords.$inferInsert;

/**
 * Per-key lifecycle history (DID hardening). One row per verification-key
 * generation so rotation/revocation is attributable and auditable without
 * destroying historical verification metadata. The CURRENT authority gate
 * remains did_records.keyStatus (fail-closed summary); this table is the
 * evidence-grade history: which key id existed, when, in which state.
 * No private key material is ever stored here — key ids are digests.
 */
export const didKeyRecords = mysqlTable("did_key_records", {
  id: uuid("id").primaryKey(),
  did: varchar("did", { length: 255 }).notNull(),
  /** Stable identifier of this key generation (digest — never secret material). */
  keyIdentifier: varchar("keyIdentifier", { length: 80 }).notNull(),
  algorithm: varchar("algorithm", { length: 64 }).notNull().default("EcdsaSecp256k1Recovery"),
  status: mysqlEnum("status", ["ACTIVE", "ROTATED", "REVOKED"]).default("ACTIVE").notNull(),
  createdByIdentityId: varchar("createdByIdentityId", { length: 36 }).references(() => identities.id),
  supersededByKeyIdentifier: varchar("supersededByKeyIdentifier", { length: 80 }),
  note: varchar("note", { length: 200 }),
  createdAt: createdAt(),
  deactivatedAt: timestamp("deactivatedAt"),
}, table => ({
  didKeyIdx: index("did_key_records_did_idx").on(table.did),
  didKeyUnique: uniqueIndex("did_key_records_did_key_idx").on(table.did, table.keyIdentifier),
}));

export type DidKeyRecord = typeof didKeyRecords.$inferSelect;
export type InsertDidKeyRecord = typeof didKeyRecords.$inferInsert;

/**
 * Single-use DID authentication challenges (LOOP 2, hardened). The stored
 * message is the CANONICAL structured payload the caller must have signed
 * verbatim — DID, purpose, audience, nonce, iat, exp, keyId — so a signature
 * is only valid for exactly the challenge the server issued, for exactly
 * this DID, purpose, audience, and key generation. The row is consumed
 * atomically (single UPDATE guarded on consumedAt IS NULL + expiry).
 */
export const didChallenges = mysqlTable("did_challenges", {
  id: uuid("id").primaryKey(),
  did: varchar("did", { length: 255 }).notNull(),
  purpose: varchar("purpose", { length: 60 }).notNull().default("AUTHENTICATION"),
  audience: varchar("audience", { length: 120 }).notNull().default("sampraan"),
  keyIdentifier: varchar("keyIdentifier", { length: 80 }),
  nonce: varchar("nonce", { length: 128 }).notNull().unique(),
  message: text("message").notNull(),
  expiresAt: timestamp("expiresAt").notNull(),
  consumedAt: timestamp("consumedAt"),
  createdAt: createdAt(),
}, table => ({ didIdx: index("did_challenges_did_idx").on(table.did) }));

export type DidChallenge = typeof didChallenges.$inferSelect;
export type InsertDidChallenge = typeof didChallenges.$inferInsert;

/** Server-verified step-up sessions (LOOP 5). A CHALLENGE policy decision is only satisfied by a consumed, unexpired step-up row. */
export const stepUpSessions = mysqlTable("step_up_sessions", {
  id: uuid("id").primaryKey(),
  identityId: varchar("identityId", { length: 36 }).notNull().references(() => identities.id),
  purpose: varchar("purpose", { length: 120 }).notNull(),
  nonce: varchar("nonce", { length: 128 }).notNull().unique(),
  expiresAt: timestamp("expiresAt").notNull(),
  consumedAt: timestamp("consumedAt"),
  createdAt: createdAt(),
}, table => ({ identityIdx: index("step_up_identity_idx").on(table.identityId) }));

export type StepUpSession = typeof stepUpSessions.$inferSelect;
export type InsertStepUpSession = typeof stepUpSessions.$inferInsert;

/**
 * SAMPRAAN controlled digital-asset content model.
 *
 * An asset (assets table) remains the registered, NFT-backed registry record;
 * its ACTUAL digital content lives in versioned, encrypted content objects
 * (asset_content_versions). Plaintext content is never stored: every version
 * row references ciphertext held by a StorageProvider (local encrypted store
 * for development, IPFS-compatible content-addressed store otherwise) and
 * carries only ENCRYPTED (wrapped) key material plus verifiable metadata
 * (content hash, MIME, size) required for integrity verification.
 */
export const assetContentVersions = mysqlTable("asset_content_versions", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  /** 1-based, gapless per asset; allocated inside the version transaction. */
  versionNumber: int("versionNumber").notNull(),
  /** Sanitized storage-safe filename (traversal-neutralized, bounded). */
  filename: varchar("filename", { length: 255 }).notNull(),
  /** Client-provided original name, kept for attribution display only. */
  originalFilename: varchar("originalFilename", { length: 255 }).notNull(),
  /** Server-SNiffED MIME type from magic bytes — never the client header. */
  mimeType: varchar("mimeType", { length: 127 }).notNull(),
  /** Plaintext byte length (the ciphertext size is a provider detail). */
  sizeBytes: bigint("sizeBytes", { mode: "number" }).notNull(),
  /** sha256 hex digest of the PLAINTEXT — the integrity anchor. */
  contentHash: varchar("contentHash", { length: 64 }).notNull(),
  /** "local-encrypted" | "ipfs" — resolved through the storage abstraction. */
  storageProvider: varchar("storageProvider", { length: 40 }).notNull(),
  /** Content-addressed reference (CIDv1) of the ENCRYPTED object. */
  storageReference: varchar("storageReference", { length: 512 }).notNull(),
  /**
   * Encrypted-at-rest key material and AES-GCM parameters:
   * { alg, keyId, wrappedKeyB64, ivB64, tagB64 }. The DEK is stored ONLY in
   * wrapped form (encrypted with the server-side master key); no plaintext
   * key ever touches the database, logs, or the wire.
   */
  encryption: json("encryption").notNull(),
  /** Actor attribution resolved server-side from the session. */
  createdByIdentityId: varchar("createdByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  changeNote: varchar("changeNote", { length: 300 }),
  /** Blockchain provenance for the version event (best-effort anchor). */
  createdTxHash: varchar("createdTxHash", { length: 255 }),
  createdBlockNumber: bigint("createdBlockNumber", { mode: "number" }),
  createdAt: createdAt(),
}, table => ({
  currentVersionIdx: uniqueIndex("asset_versions_asset_version_idx").on(table.assetId, table.versionNumber),
  assetIdx: index("asset_versions_asset_idx").on(table.assetId),
  hashIdx: index("asset_versions_hash_idx").on(table.contentHash),
}));

export type AssetContentVersion = typeof assetContentVersions.$inferSelect;
export type InsertAssetContentVersion = typeof assetContentVersions.$inferInsert;

/**
 * Explicit per-identity content access grants (Manage Access). Ownership and
 * custody always confer their policy-defined baseline; grants EXTEND access
 * (VIEW/EDIT) to other authorized identities. Revocation is soft (revokedAt)
 * so the grant history remains auditable.
 */
export const assetAccessGrants = mysqlTable("asset_access_grants", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  granteeIdentityId: varchar("granteeIdentityId", { length: 36 }).notNull().references(() => identities.id),
  permission: mysqlEnum("permission", ["VIEW", "EDIT"]).notNull(),
  grantedByIdentityId: varchar("grantedByIdentityId", { length: 36 }).notNull().references(() => identities.id),
  reason: varchar("reason", { length: 300 }),
  createdAt: createdAt(),
  revokedAt: timestamp("revokedAt"),
}, table => ({
  granteeIdx: index("asset_access_grants_grantee_idx").on(table.granteeIdentityId),
  assetGranteeIdx: uniqueIndex("asset_access_grants_asset_grantee_perm_idx").on(table.assetId, table.granteeIdentityId, table.permission),
}));

export type AssetAccessGrant = typeof assetAccessGrants.$inferSelect;
export type InsertAssetAccessGrant = typeof assetAccessGrants.$inferInsert;

/** Application-level approval for sensitive operations (LOOP 6). A REJECTED or missing approval MUST gate the blockchain operation; execution revalidates everything. */
export const assetApprovals = mysqlTable("asset_approvals", {
  id: uuid("id").primaryKey(),
  assetId: varchar("assetId", { length: 36 }).notNull().references(() => assets.id),
  requesterIdentityId: varchar("requesterIdentityId", { length: 36 }).notNull().references(() => identities.id),
  approverIdentityId: varchar("approverIdentityId", { length: 36 }).references(() => identities.id),
  action: varchar("action", { length: 100 }).notNull(),
  targetIdentityId: varchar("targetIdentityId", { length: 36 }).references(() => identities.id),
  status: mysqlEnum("status", ["PENDING", "APPROVED", "REJECTED", "EXECUTED"]).default("PENDING").notNull(),
  reason: varchar("reason", { length: 300 }),
  createdAt: createdAt(),
  decidedAt: timestamp("decidedAt"),
  executedAt: timestamp("executedAt"),
}, table => ({ assetIdx: index("asset_approvals_asset_idx").on(table.assetId), statusIdx: index("asset_approvals_status_idx").on(table.status) }));

export type AssetApproval = typeof assetApprovals.$inferSelect;
export type InsertAssetApproval = typeof assetApprovals.$inferInsert;
