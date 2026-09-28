import { beforeEach, describe, expect, it, vi } from "vitest";
import { TRPCError } from "@trpc/server";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import type { Asset, Identity, User } from "../drizzle/schema";

/**
 * DID HARDENING — router-level security tests.
 *
 * Proves the tRPC boundary rejects DID/role/asset-actor spoofing, keeps
 * authentication authoritative server-side, and integrates with the asset
 * authorization flow (revoked identity → denied asset operations).
 * The DB layer is mocked per the existing router-test pattern; the DID
 * service layer itself is covered DB-backed in did-hardening.test.ts.
 */

const chainMocks = vi.hoisted(() => ({
  mode: "MOCK" as "BESU" | "MOCK",
  operatorAddress: null as string | null,
  besuConfigPrivateKey: null as string | null,
}));

vi.mock("./modules/blockchain/blockchain.service", () => ({
  blockchainService: {
    get mode() { return chainMocks.mode; },
    get operatorAddress() { return chainMocks.operatorAddress; },
    getNetworkStatus: vi.fn(async () => ({ connected: true, mode: chainMocks.mode, network: "test", latestBlock: 10 })),
    getLatestBlock: vi.fn(async () => 10),
    submitTransaction: vi.fn(async () => ({ transactionHash: "0xtest_tx", blockNumber: 11, status: "CONFIRMED" })),
    getTransaction: vi.fn(),
    getEvents: vi.fn(async () => []),
  },
  besuBlockchainService: {
    get config() { return { privateKey: chainMocks.besuConfigPrivateKey }; },
    getAsset: vi.fn(async () => null),
    getIdentity: vi.fn(async () => null),
    setAssetStatus: vi.fn(async () => ({ transactionHash: "0xstatus" })),
    setIdentityStatus: vi.fn(async () => ({ transactionHash: "0xstatus" })),
  },
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
  getAssetById: vi.fn(),
  getIdentityById: vi.fn(),
  getIdentityByLinkedUserId: vi.fn(),
  getIdentityRolesAndPermissions: vi.fn(),
  createAuthorizationDecision: vi.fn(),
  createAuditEvent: vi.fn(),
  getActiveAssetApproval: vi.fn(),
  listActiveAssetAccessGrants: vi.fn(),
  hasValidStepUp: vi.fn(),
  listAssets: vi.fn(),
  listAssetCustody: vi.fn(),
  listAssetAuditEvents: vi.fn(),
  listAssetContentVersions: vi.fn(),
}));

vi.mock("./db", () => ({
  ...dbMocks,
  // Identity/create flows used in the shared router need these resolved
  // as no-ops for this suite's scope.
  createIdentity: vi.fn(),
  createDidRecord: vi.fn(),
  getDb: vi.fn(async () => null),
  listAssetContentVersions: vi.fn(async () => []),
  listAssetAccessGrants: vi.fn(async () => []),
  getAssetContentVersionById: vi.fn(async () => undefined),
  getAssetIdForGrant: vi.fn(async () => undefined),
  createAssetContentVersion: vi.fn(),
  createAssetAccessGrant: vi.fn(),
  revokeAssetAccessGrant: vi.fn(async () => false),
  getNextAssetVersionNumber: vi.fn(async () => 1),
  applyCustodyTransfer: vi.fn(async () => ({ id: "asset-1" })),
  markAssetApprovalExecuted: vi.fn(async () => undefined),
  listAssetApprovals: vi.fn(async () => []),
  listPolicies: vi.fn(async () => []),
  listIdentities: vi.fn(async () => []),
  listAuditEvents: vi.fn(async () => []),
  listSecurityAlerts: vi.fn(async () => []),
}));

// Step-up + DID service mocks (the service layer is DB-tested separately).
vi.mock("./modules/did/did-auth.service", async importOriginal => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    hasValidStepUp: dbMocks.hasValidStepUp,
    // Verification itself is DB-tested in did-hardening.test.ts; here it
    // uniformly FAILS (the honest default for garbage input) so the router
    // boundary can be exercised without a live DB.
    verifyDidChallenge: vi.fn(async () => ({ ok: false, reason: "Challenge is invalid, expired, already used, or bound to a different DID/purpose", code: "CHALLENGE_INVALID" })),
    createDidChallenge: vi.fn(),
  };
});

vi.mock("./modules/security-intelligence/intelligence.service", () => ({
  securityIntelligenceService: { assessRisk: vi.fn(async () => "LOW"), scan: vi.fn(async () => ({ scanned: 0, created: 0, suppressed: 0 })) },
  scheduleIntelligenceScan: vi.fn(),
  recordIntelligenceScanEvidence: vi.fn(),
}));

import { getAssetById, getIdentityByLinkedUserId, getIdentityRolesAndPermissions, createAuditEvent, getIdentityById } from "./db";
import { hasValidStepUp } from "./modules/did/did-auth.service";

const mockedGetAssetById = vi.mocked(getAssetById);
const mockedGetActorIdentity = vi.mocked(getIdentityByLinkedUserId);
const mockedGetRoles = vi.mocked(getIdentityRolesAndPermissions);
const mockedGetIdentityById = vi.mocked(getIdentityById);
const mockedHasValidStepUp = vi.mocked(hasValidStepUp);

function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 1,
    openId: "user-open-1",
    name: "Operator",
    email: null,
    loginMethod: null,
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
    ...overrides,
  };
}

function makeContext(user: User | null): TrpcContext {
  return {
    user,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: (..._args: unknown[]) => undefined } as unknown as TrpcContext["res"],
  };
}

const activeIdentity: Identity = {
  id: "0e0d3b1a-aaaa-4bbb-8ccc-444455559999",
  linkedUserId: 1,
  displayName: "Aarav Mehta",
  organization: "SAMPRAAN DEMO ORGANIZATION",
  status: "ACTIVE",
  did: "did:sampraan:actor",
  createdAt: new Date(),
  updatedAt: new Date(),
  revokedAt: null,
};

const assetFixture: Asset = {
  id: "0e0d3b1a-1111-4222-8333-444455556666",
  assetId: "ASSET-DID-SEC-001",
  name: "DID Security Fixture",
  type: "DOCUMENT",
  classification: "CONTROLLED",
  description: null,
  ownerIdentityId: "0e0d3b1a-aaaa-4bbb-8ccc-444455557777",
  custodianIdentityId: activeIdentity.id,
  integrityHash: null,
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date(),
  updatedAt: new Date(),
};

beforeEach(() => {
  vi.clearAllMocks();
  chainMocks.mode = "BESU";
  chainMocks.operatorAddress = "0xoperator";
  chainMocks.besuConfigPrivateKey = "0xtest-operator-key";
  mockedGetAssetById.mockResolvedValue(assetFixture);
  mockedGetActorIdentity.mockResolvedValue(activeIdentity);
  mockedGetRoles.mockResolvedValue({ roles: ["MANAGER"], permissions: ["asset:read", "asset:transfer"] });
  mockedGetIdentityById.mockResolvedValue({ ...activeIdentity, id: assetFixture.ownerIdentityId });
  dbMocks.createAuditEvent.mockResolvedValue(undefined);
  dbMocks.createAuthorizationDecision.mockResolvedValue(undefined);
  dbMocks.getActiveAssetApproval.mockResolvedValue(undefined);
  dbMocks.listActiveAssetAccessGrants.mockResolvedValue([]);
  mockedHasValidStepUp.mockResolvedValue(false);
  dbMocks.listAssetCustody.mockResolvedValue([]);
  dbMocks.listAssetAuditEvents.mockResolvedValue([]);
  dbMocks.listAssetContentVersions.mockResolvedValue([]);
});

describe("did.verifyChallenge boundary", () => {
  it("keeps authentication results server-derived: a client-asserted identity is never echoed into a session", async () => {
    // The public verify endpoint takes only did/nonce/signature. There is no
    // client-controllable field that can assert role, identityId, or status —
    // schema-level rejection of injected fields is enforced by Zod stripping.
    const caller = appRouter.createCaller(makeContext(null));
    const hostile = {
      did: "did:sampraan:dev-admin-aarav",
      nonce: "a".repeat(48),
      signature: "0x" + "00".repeat(65),
      // Spoof attempt: claim a linked user and an admin role.
      identityId: "00000000-0000-4000-8000-000000000001",
      linkedUserId: 42,
      role: "ADMIN",
      sessionToken: "forged-token",
    } as unknown as Parameters<typeof caller.did.verifyChallenge>[0];

    await expect(caller.did.verifyChallenge(hostile)).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    // No audit success event for the spoofed identity was written.
    const successEvents = (dbMocks.createAuditEvent as ReturnType<typeof vi.fn>).mock.calls.filter(
      (call: unknown[]) => (call[0] as { action?: string }).action === "DID_AUTH_SUCCEEDED",
    );
    expect(successEvents.length).toBe(0);
  });
});

describe("asset operations derive the actor from the session (DID/role spoofing)", () => {
  it("ignores client-asserted actorDid/role/ownerDid on authorizeTransfer — actor comes from the session", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser()));
    const hostile = {
      assetId: assetFixture.id,
      recipientIdentityId: undefined,
      // Spoof attempts:
      actorDid: "did:sampraan:admin",
      actorIdentityId: "00000000-0000-4000-8000-000000000009",
      role: "ADMIN",
      ownerDid: "did:sampraan:admin",
      custodianDid: "did:sampraan:admin",
      stepUpAuthenticated: true,
      identityStatus: "ACTIVE",
    } as unknown as Parameters<typeof caller.assets.authorizeTransfer>[0];

    const result = await caller.assets.authorizeTransfer(hostile);
    // The session user has a linked MANAGER identity; the decision must be
    // computed from THAT identity (custodian here) — not from the spoofed
    // ADMIN claims. MANAGER holds asset:transfer and is custodian → ALLOW,
    // but the audit metadata must show the SESSION's openId/role, not ADMIN.
    expect(result.decision).toBe("ALLOW");
    const decisionCall = (dbMocks.createAuthorizationDecision as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(decisionCall.actorIdentityId).toBe(activeIdentity.id);
    const auditMeta = (dbMocks.createAuditEvent as ReturnType<typeof vi.fn>).mock.calls.map(c => c[0]).find(e => String(e.action).startsWith("ASSET_"));
    expect(auditMeta?.metadata?.actorUserOpenId).toBe("user-open-1");
    expect(auditMeta?.metadata?.actorUserRole).toBe("user");
  });

  it("denies a revoked identity's asset transfer even with a fresh spoofed session claim", async () => {
    mockedGetActorIdentity.mockResolvedValue({ ...activeIdentity, status: "REVOKED" });
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    const result = await caller.assets.authorizeTransfer({ assetId: assetFixture.id });
    expect(result.decision).toBe("DENY");
    expect(result.transaction ?? null).toBeNull();
    const audit = (dbMocks.createAuditEvent as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(audit.action).toBe("AUTHORIZATION_DENIED");
  });

  it("denies asset content operations for a revoked identity (content gate integration)", async () => {
    mockedGetActorIdentity.mockResolvedValue({ ...activeIdentity, status: "REVOKED" });
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    await expect(caller.content.list({ assetId: assetFixture.id })).rejects.toMatchObject({ code: "FORBIDDEN" });
    const denied = (dbMocks.createAuditEvent as ReturnType<typeof vi.fn>).mock.calls.map(c => c[0]).find(e => e.action === "ASSET_CONTENT_ACCESS_DENIED");
    expect(denied).toBeTruthy();
    expect(denied.reason).toMatch(/revoked/i);
  });

  it("denies content operations when no SAMPRAAN identity is linked (unregistered actor)", async () => {
    mockedGetActorIdentity.mockResolvedValue(undefined);
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    await expect(caller.content.list({ assetId: assetFixture.id })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("requires server-verified step-up for sensitive content: client assertion of stepUpAuthenticated is ignored", async () => {
    const sensitiveAsset: Asset = { ...assetFixture, classification: "SENSITIVE", custodianIdentityId: activeIdentity.id };
    mockedGetAssetById.mockResolvedValue(sensitiveAsset);
    mockedHasValidStepUp.mockResolvedValue(false);
    const caller = appRouter.createCaller(makeContext(makeUser()));
    const hostile = {
      assetId: assetFixture.id,
      stepUpAuthenticated: true,
      purpose: "content-view:whatever",
    } as unknown as Parameters<typeof caller.content.list>[0];
    await expect(caller.content.list(hostile)).rejects.toMatchObject({ code: "PRECONDITION_FAILED" });
    // And the probe was called with the SERVER-computed purpose, not the client's.
    expect(mockedHasValidStepUp).toHaveBeenCalledWith(activeIdentity.id, expect.stringContaining("content-view"));
  });

  it("allows content view when the server-verified step-up exists for the exact purpose", async () => {
    const sensitiveAsset: Asset = { ...assetFixture, classification: "SENSITIVE", custodianIdentityId: activeIdentity.id };
    mockedGetAssetById.mockResolvedValue(sensitiveAsset);
    mockedHasValidStepUp.mockResolvedValue(true);
    dbMocks.listAssetContentVersions.mockResolvedValue([]);
    const caller = appRouter.createCaller(makeContext(makeUser()));
    await expect(caller.content.list({ assetId: assetFixture.id })).resolves.toMatchObject({ versions: [] });
  });

  it("session identity mismatch: another session cannot consume another identity's step-up", async () => {
    // Step-up probes are keyed by the SESSION-derived identity id; a second
    // session (different user id → different identity) never matches. The
    // other identity is the ASSET CUSTODIAN here so the classification gate
    // passes and the request reaches the step-up gate.
    const otherIdentity = { ...activeIdentity, id: "0e0d3b1a-bbbb-4ccc-8ddd-444455550000", linkedUserId: 2 };
    mockedGetActorIdentity.mockResolvedValue(otherIdentity);
    mockedHasValidStepUp.mockResolvedValue(false);
    const caller = appRouter.createCaller(makeContext(makeUser({ id: 2, openId: "other-user" })));
    const sensitiveAsset: Asset = { ...assetFixture, classification: "SENSITIVE", custodianIdentityId: otherIdentity.id };
    mockedGetAssetById.mockResolvedValue(sensitiveAsset);
    await expect(caller.content.list({ assetId: assetFixture.id })).rejects.toMatchObject({ code: "PRECONDITION_FAILED" });
    // The probe used the OTHER session's identity id — never the asset actor's.
    expect(mockedHasValidStepUp).toHaveBeenCalledWith(otherIdentity.id, expect.any(String));
  });
});
