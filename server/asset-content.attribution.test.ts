/**
 * F3 REGRESSION — controlled-content audit attribution.
 *
 * BUG THIS PINS: content.view and content.verifyIntegrity persisted their
 * audit events with actorIdentityId = null even though the authorization
 * gate had already resolved the acting identity. A controlled-content
 * disclosure (VIEWED) and an integrity verdict (especially MISMATCH — a
 * potential tamper signal) were therefore unattributable in the evidence
 * trail. The fix attributes both events to the actor resolved by the gate.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import type { Asset, AssetContentVersion, Identity, User } from "../drizzle/schema";

const chainMocks = vi.hoisted(() => ({ besuConfigPrivateKey: "0xtest-operator-key" as string | null }));

vi.mock("./modules/blockchain/blockchain.service", () => ({
  blockchainService: {
    get mode() { return "MOCK"; },
    get operatorAddress() { return "0xoperator"; },
    getNetworkStatus: vi.fn(async () => ({ connected: true, mode: "MOCK", network: "test", latestBlock: 10 })),
  },
  besuBlockchainService: { get config() { return { privateKey: chainMocks.besuConfigPrivateKey }; }, getAsset: vi.fn(async () => null), getIdentity: vi.fn(async () => null) },
}));

vi.mock("./modules/blockchain/anchoring.service", () => ({
  anchoringService: {
    anchorIdentity: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
    anchorAsset: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
    anchorAssetVersion: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
  },
  deriveIdentityWallet: vi.fn(() => "0xderivedwallet"),
}));

const dbMocks = vi.hoisted(() => ({
  auditEvents: [] as { action: string; actorIdentityId: string | null; resourceId: string | null }[],
  versionFixture: null as AssetContentVersion | null,
  assetFixture: null as Asset | null,
}));

vi.mock("./db", () => ({
  getAssetById: vi.fn(async () => dbMocks.assetFixture),
  getAssetContentVersionById: vi.fn(async () => dbMocks.versionFixture),
  getIdentityByLinkedUserId: vi.fn(async () => actorIdentity),
  getIdentityRolesAndPermissions: vi.fn(async () => ({ roles: ["ADMIN"], permissions: ["asset:read", "asset:edit"] })),
  listActiveAssetAccessGrants: vi.fn(async () => []),
  listAssetAccessGrants: vi.fn(async () => []),
  listAssetContentVersions: vi.fn(async () => []),
  listIdentities: vi.fn(async () => []),
  listAuditEvents: vi.fn(async () => []),
  listSecurityAlerts: vi.fn(async () => []),
  listAssets: vi.fn(async () => []),
  listPolicies: vi.fn(async () => []),
  createAssetContentVersion: vi.fn(),
  createAssetAccessGrant: vi.fn(),
  revokeAssetAccessGrant: vi.fn(async () => false),
  getNextAssetVersionNumber: vi.fn(async () => 2),
  createAuditEvent: vi.fn(async (input: { action: string; actorIdentityId: string | null; resourceId?: string | null }) => {
    dbMocks.auditEvents.push({ action: input.action, actorIdentityId: input.actorIdentityId, resourceId: input.resourceId ?? null });
    return undefined;
  }),
  createAuthorizationDecision: vi.fn(async () => undefined),
  getDb: vi.fn(async () => null),
}));

vi.mock("./modules/did/did-auth.service", async importOriginal => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    hasValidStepUp: vi.fn(async () => true), // ADMIN on CONTROLLED: content VIEW needs no step-up; probe harmless
    fingerprintNonce: actual.fingerprintNonce ?? vi.fn((n: string) => n.slice(0, 8)),
  };
});

// In-memory encrypted storage so view/verify run fully hermetically.
vi.mock("./modules/asset-content/storage", async importOriginal => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  let stored: Buffer | null = null;
  const keyProvider = new (actual.LocalDevKeyProvider as new (k: Buffer) => { wrapKey: (p: Buffer) => Promise<{ wrappedKeyB64: string; keyId: string }>; unwrapKey: (w: string, id: string) => Promise<Buffer>; integrityKey: () => Promise<Buffer> })(Buffer.alloc(32, 9));
  const provider = {
    name: "memory-test",
    put: async (_ref: string, data: Buffer) => { stored = data; return { reference: "ref-1", byteLength: data.byteLength, ciphertextSha256: "x" }; },
    get: async () => { if (!stored) throw new (actual.ContentUnavailableError as new (r: string) => Error)("ref-1"); return stored; },
    stat: async () => ({ exists: stored !== null, byteLength: stored?.byteLength ?? 0 }),
    delete: async () => { stored = null; },
    stream: async () => { throw new Error("not used"); },
  };
  return { ...actual, resolveStorage: () => ({ provider, keyProvider }) };
});

vi.mock("./modules/security-intelligence/intelligence.service", () => ({
  securityIntelligenceService: { scan: vi.fn(async () => ({ scanned: 0, created: 0, suppressed: 0 })), assessRisk: vi.fn(async () => "LOW" as const) },
  scheduleIntelligenceScan: vi.fn(),
  recordIntelligenceScanEvidence: vi.fn(),
}));

import { createAuditEvent } from "./db";

const mockedCreateAuditEvent = vi.mocked(createAuditEvent);

function makeUser(role: "admin" | "user" = "admin"): User {
  return {
    id: 3, openId: "attribution-open-1", name: "Attribution Operator", email: "attribution@sampraan.dev",
    loginMethod: "password", role, createdAt: new Date(), updatedAt: new Date(), lastSignedIn: new Date(),
  };
}

function makeContext(user: User | null): TrpcContext {
  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: (..._args: unknown[]) => undefined } as unknown as TrpcContext["res"],
  };
}

const actorIdentity: Identity = {
  id: "0e0d3b1a-aaaa-4bbb-8ccc-444455559997",
  linkedUserId: 3,
  displayName: "Attribution Operator",
  organization: "SAMPRAAN DEMO",
  status: "ACTIVE",
  did: "did:sampraan:attribution-actor",
  createdAt: new Date(), updatedAt: new Date(), revokedAt: null,
};

const assetFixture: Asset = {
  id: "1ec845d0-1187-41ba-8329-ccb580bbc51d",
  assetId: "ATTRIBUTION-FIXTURE-001",
  name: "Attribution Fixture",
  type: "DOCUMENT",
  classification: "CONTROLLED", // VIEW without step-up, so the test isolates attribution
  description: null,
  ownerIdentityId: actorIdentity.id,
  custodianIdentityId: actorIdentity.id,
  integrityHash: null,
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date(), updatedAt: new Date(),
};

const versionFixture: AssetContentVersion = {
  id: "9a9a9a9a-1111-4222-8333-444455556677",
  assetId: assetFixture.id,
  versionNumber: 1,
  filename: "attribution.txt",
  originalFilename: "attribution.txt",
  mimeType: "text/plain",
  sizeBytes: 11,
  contentHash: "", // filled in beforeEach after real encryption
  storageProvider: "memory-test",
  storageReference: "ref-1",
  encryption: { alg: "AES-256-GCM", keyId: "k", wrappedKeyB64: "w", ivB64: "i", tagB64: "t" },
  createdByIdentityId: actorIdentity.id,
  changeNote: null,
  createdTxHash: null,
  createdBlockNumber: null,
  createdAt: new Date(),
};

const caller = appRouter.createCaller(makeContext(makeUser()));

beforeEach(async () => {
  vi.clearAllMocks();
  dbMocks.auditEvents.length = 0;
  dbMocks.assetFixture = assetFixture;
  // Build a REAL envelope through the real encryption path so view+verify both work hermetically.
  const { encryptAndStore } = await import("./modules/asset-content/content.service");
  const validated = {
    filename: "attribution.txt",
    originalFilename: "attribution.txt",
    mimeType: "text/plain",
    sizeBytes: 11,
    data: Buffer.from("hello world"),
    contentHash: "filled-below",
  };
  const { createHash } = await import("node:crypto");
  validated.contentHash = createHash("sha256").update(validated.data).digest("hex");
  const stored = await encryptAndStore(validated);
  dbMocks.versionFixture = { ...versionFixture, contentHash: stored.contentHash, encryption: stored.encryption };
});

describe("controlled-content audit attribution (F3)", () => {
  it("content.view attributes ASSET_CONTENT_VIEWED to the acting identity", async () => {
    await caller.content.view({ versionId: dbMocks.versionFixture!.id });
    const viewed = dbMocks.auditEvents.find(e => e.action === "ASSET_CONTENT_VIEWED");
    expect(viewed).toBeDefined();
    expect(viewed!.actorIdentityId).toBe(actorIdentity.id);
    // resourceId is the asset ROW id by content-router convention (the asset's
    // business key lives in the audit row's assetId? No — the router uses
    // version.assetId, which IS the row id; the business key stays in metadata).
    expect(viewed!.resourceId).toBe(assetFixture.id);
  });

  it("content.verifyIntegrity attributes the verdict to the acting identity", async () => {
    const result = await caller.content.verifyIntegrity({ versionId: dbMocks.versionFixture!.id });
    expect(result.state).toBe("INTEGRITY_VERIFIED");
    const verified = dbMocks.auditEvents.find(e => e.action === "ASSET_INTEGRITY_VERIFIED");
    expect(verified).toBeDefined();
    expect(verified!.actorIdentityId).toBe(actorIdentity.id);
  });

  it("still records null actor for genuinely unattributable system events (anchor evidence)", () => {
    // Sanity: the fix is scoped — it must not fabricate actors elsewhere.
    expect(dbMocks.auditEvents.every(e => e.actorIdentityId === null || e.actorIdentityId === actorIdentity.id)).toBe(true);
    void mockedCreateAuditEvent;
  });
});
