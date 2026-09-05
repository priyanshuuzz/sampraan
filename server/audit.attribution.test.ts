import { beforeEach, describe, expect, it, vi } from "vitest";
import type { TrpcContext } from "./_core/context";
import type { Asset, Identity, User } from "../drizzle/schema";

/**
 * SECURITY REGRESSION: audit-evidence actor attribution.
 *
 * identities.setStatus recorded actorIdentityId = the TARGET identity's id,
 * so a revocation looked like a self-revocation in the evidence trail.
 * assets.setStatus recorded actorIdentityId = null, losing attribution
 * entirely. Both must attribute the ACTING administrator, resolved
 * server-side from the authenticated session.
 */

const dbMocks = vi.hoisted(() => ({
  getIdentityById: vi.fn(),
  getIdentityByLinkedUserId: vi.fn(),
  applyIdentityStatusChange: vi.fn(),
  getAssetById: vi.fn(),
  applyAssetStatusChange: vi.fn(),
  createAuditEvent: vi.fn(async (input: unknown) => input),
  listIdentities: vi.fn(async () => []),
  listAssets: vi.fn(async () => []),
  listAuditEvents: vi.fn(async () => []),
  listSecurityAlerts: vi.fn(async () => []),
}));

const blockchainMocks = vi.hoisted(() => ({
  getNetworkStatus: vi.fn(),
  getLatestBlock: vi.fn(),
  submitTransaction: vi.fn(),
  getTransaction: vi.fn(),
  getEvents: vi.fn(),
  operatorAddress: null as string | null,
  mode: "MOCK" as const,
  besu: null,
}));

vi.mock("./db", () => dbMocks);
vi.mock("./modules/blockchain/blockchain.service", () => ({
  blockchainService: {
    getNetworkStatus: blockchainMocks.getNetworkStatus,
    getLatestBlock: blockchainMocks.getLatestBlock,
    submitTransaction: blockchainMocks.submitTransaction,
    getTransaction: blockchainMocks.getTransaction,
    getEvents: blockchainMocks.getEvents,
    operatorAddress: blockchainMocks.operatorAddress,
    mode: blockchainMocks.mode,
  },
  besuBlockchainService: blockchainMocks.besu,
}));
vi.mock("./modules/blockchain/anchoring.service", () => ({
  anchoringService: {
    anchorIdentity: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
    anchorAsset: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
  },
  deriveIdentityWallet: vi.fn(() => "0x0000000000000000000000000000000000000000"),
}));

import { appRouter } from "./routers";
import { createAuditEvent, getIdentityByLinkedUserId } from "./db";

const adminUser: User = {
  id: 7,
  openId: "admin-open-id",
  name: "Root Admin",
  email: null,
  loginMethod: null,
  role: "admin",
  createdAt: new Date(),
  updatedAt: new Date(),
  lastSignedIn: new Date(),
};

const adminIdentity: Identity = {
  id: "11111111-1111-4111-8111-111111111111",
  linkedUserId: 7,
  displayName: "Root Admin Identity",
  organization: "SAMPRAAN",
  status: "ACTIVE",
  did: "did:demo:root-admin",
  createdAt: new Date(),
  updatedAt: new Date(),
  revokedAt: null,
};

const targetIdentity: Identity = {
  id: "22222222-2222-4222-8222-222222222222",
  linkedUserId: null,
  displayName: "Compromised Operator",
  organization: "Third Party",
  status: "ACTIVE",
  did: "did:demo:compromised",
  createdAt: new Date(),
  updatedAt: new Date(),
  revokedAt: null,
};

const targetAsset: Asset = {
  id: "33333333-3333-4333-8333-333333333333",
  assetId: "ASSET-ATTR-001",
  name: "Attribution Fixture",
  type: "FIRMWARE",
  classification: "CONTROLLED",
  description: null,
  ownerIdentityId: targetIdentity.id,
  custodianIdentityId: targetIdentity.id,
  integrityHash: null,
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date(),
  updatedAt: new Date(),
};

function ctx(): TrpcContext {
  return {
    user: adminUser,
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: { clearCookie: vi.fn() } as unknown as TrpcContext["res"],
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(getIdentityByLinkedUserId).mockResolvedValue(adminIdentity);
  dbMocks.getIdentityById.mockResolvedValue(targetIdentity);
  dbMocks.applyIdentityStatusChange.mockResolvedValue({ ...targetIdentity, status: "SUSPENDED" });
  dbMocks.getAssetById.mockResolvedValue(targetAsset);
  dbMocks.applyAssetStatusChange.mockResolvedValue({ ...targetAsset, status: "REVOKED" });
  blockchainMocks.getNetworkStatus.mockResolvedValue({
    connected: false,
    mode: "MOCK",
    network: "SAMPRAAN-DEMO-QBFT",
    latestBlock: 1,
  });
});

describe("audit actor attribution — identities.setStatus", () => {
  it("attributes the ACTING admin, never the target identity", async () => {
    const caller = appRouter.createCaller(ctx());
    await caller.identities.setStatus({
      identityId: targetIdentity.id,
      status: "SUSPENDED",
    });

    expect(createAuditEvent).toHaveBeenCalled();
    const event = vi.mocked(createAuditEvent).mock.calls[0][0] as Record<string, unknown>;
    // The actor is the administrator who performed the action...
    expect(event.actorIdentityId).toBe(adminIdentity.id);
    // ...explicitly NOT the identity whose status changed.
    expect(event.actorIdentityId).not.toBe(targetIdentity.id);
    // The target stays referenced in the event body for traceability.
    expect(event.resourceId).toBe(targetIdentity.id);
    expect((event.metadata as Record<string, unknown>).targetIdentityId).toBe(targetIdentity.id);
  });
});

describe("audit actor attribution — assets.setStatus", () => {
  it("attributes the ACTING admin instead of null", async () => {
    const caller = appRouter.createCaller(ctx());
    await caller.assets.setStatus({
      assetId: targetAsset.id,
      status: "REVOKED",
    });

    expect(createAuditEvent).toHaveBeenCalled();
    const event = vi.mocked(createAuditEvent).mock.calls[0][0] as Record<string, unknown>;
    expect(event.actorIdentityId).toBe(adminIdentity.id);
    expect(event.actorIdentityId).not.toBeNull();
    expect(event.resourceId).toBe(targetAsset.assetId);
  });
});
