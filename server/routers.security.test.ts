import { beforeEach, describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import type { Asset, Identity, User } from "../drizzle/schema";

/**
 * Procedure-level security tests for the SAMPRAAN backend boundary.
 *
 * The database layer (server/db.ts) is mocked so authorization behavior can be
 * verified without a live MySQL instance. This proves the tRPC procedures
 * enforce the boundary themselves — frontend checks are never assumed.
 */

vi.mock("./db", async (importOriginal: () => Promise<unknown>) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    getAssetById: vi.fn(),
    getIdentityByLinkedUserId: vi.fn(),
    getIdentityRolesAndPermissions: vi.fn(),
    createAuthorizationDecision: vi.fn(async (input: unknown) => input),
    createAuditEvent: vi.fn(async (input: unknown) => input),
  };
});

import {
  createAuditEvent,
  createAuthorizationDecision,
  getAssetById,
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
} from "./db";

const mockedGetAssetById = vi.mocked(getAssetById);
const mockedGetIdentityByLinkedUserId = vi.mocked(getIdentityByLinkedUserId);
const mockedGetRolesAndPermissions = vi.mocked(getIdentityRolesAndPermissions);
const mockedCreateAuditEvent = vi.mocked(createAuditEvent);
const mockedCreateDecision = vi.mocked(createAuthorizationDecision);

type CookieCall = { name: string; options: Record<string, unknown> };

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
    res: {
      clearCookie: (..._args: unknown[]) => undefined,
    } as unknown as TrpcContext["res"],
  };
}

const UNAUTHORIZED = /login/i;
const NOT_FOUND = /not found/i;
const INVALID_INPUT = /validation|invalid argument/i;

const activeAsset: Asset = {
  id: "0e0d3b1a-1111-4222-8333-444455556666",
  assetId: "ASSET-DEMO-FIRMWARE-001",
  name: "Restricted Firmware Package",
  type: "FIRMWARE",
  classification: "HIGHLY_SENSITIVE",
  description: null,
  ownerIdentityId: "0e0d3b1a-aaaa-4bbb-8ccc-444455557777",
  custodianIdentityId: "0e0d3b1a-aaaa-4bbb-8ccc-444455558888",
  integrityHash: null,
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date(),
  updatedAt: new Date(),
};

const activeIdentity: Identity = {
  id: "0e0d3b1a-aaaa-4bbb-8ccc-444455559999",
  linkedUserId: 1,
  displayName: "Aarav Mehta",
  organization: "SAMPRAAN DEMO ORGANIZATION",
  status: "ACTIVE",
  did: "did:demo:aarav-mehta",
  createdAt: new Date(),
  updatedAt: new Date(),
  revokedAt: null,
};

const transferInput = { assetId: activeAsset.id };

beforeEach(() => {
  vi.clearAllMocks();
  mockedGetAssetById.mockResolvedValue(activeAsset);
  mockedGetIdentityByLinkedUserId.mockResolvedValue(undefined);
  mockedGetRolesAndPermissions.mockResolvedValue({
    roles: [],
    permissions: [],
  });
});

describe("authentication boundary (protected procedures)", () => {
  it("rejects assets.authorizeTransfer without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(
      caller.assets.authorizeTransfer(transferInput)
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects identities.create without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(
      caller.identities.create({
        displayName: "Aarav Mehta",
        organization: "SAMPRAAN",
        did: "did:demo:aarav",
      })
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects assets.create without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(
      caller.assets.create({
        assetId: "A-1",
        name: "Asset",
        type: "FW",
        classification: "CONTROLLED",
        ownerIdentityId: activeIdentity.id,
        custodianIdentityId: activeIdentity.id,
      })
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects audit.list without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(caller.audit.list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects alerts.list without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(caller.alerts.list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("rejects identities.list without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(caller.identities.list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("allows auth.me for anonymous users (public procedure)", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(caller.auth.me()).resolves.toBeNull();
  });
});

describe("assets.authorizeTransfer", () => {
  it("throws NOT_FOUND for a missing asset", async () => {
    mockedGetAssetById.mockResolvedValue(undefined);
    const caller = appRouter.createCaller(makeContext(makeUser()));
    await expect(
      caller.assets.authorizeTransfer(transferInput)
    ).rejects.toMatchObject({ code: "NOT_FOUND", message: NOT_FOUND });
  });

  it("throws PRECONDITION_FAILED for a revoked asset before any policy evaluation", async () => {
    mockedGetAssetById.mockResolvedValue({ ...activeAsset, status: "REVOKED" });
    const caller = appRouter.createCaller(makeContext(makeUser()));
    await expect(
      caller.assets.authorizeTransfer(transferInput)
    ).rejects.toMatchObject({ code: "PRECONDITION_FAILED" });
    expect(mockedCreateAuditEvent).not.toHaveBeenCalled();
  });

  it("DENIES an authenticated user with no linked SAMPRAAN identity (never evaluates as ACTIVE)", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(undefined);
    const caller = appRouter.createCaller(makeContext(makeUser()));
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
    // The denial is still audited, with a nullable actor identity.
    expect(mockedCreateAuditEvent).toHaveBeenCalledTimes(1);
    const auditCall = mockedCreateAuditEvent.mock.calls[0][0];
    expect(auditCall.actorIdentityId).toBeNull();
    expect(auditCall.action).toBe("AUTHORIZATION_DENIED");
    expect(auditCall.decision).toBe("DENY");
    expect(auditCall.metadata).toMatchObject({ actorOpenId: "user-open-1" });
    // No authorization_decision row is possible without a registered identity.
    expect(mockedCreateDecision).not.toHaveBeenCalled();
  });

  it("DENIES a suspended linked identity even for a platform admin, and audits the actor", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue({
      ...activeIdentity,
      status: "SUSPENDED",
    });
    const caller = appRouter.createCaller(
      makeContext(makeUser({ role: "admin" }))
    );
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
    expect(mockedCreateDecision).toHaveBeenCalledTimes(1);
    const decisionCall = mockedCreateDecision.mock.calls[0][0];
    expect(decisionCall.actorIdentityId).toBe(activeIdentity.id);
    expect(decisionCall.decision).toBe("DENY");
    expect(mockedCreateAuditEvent).toHaveBeenCalledTimes(1);
    const auditCall = mockedCreateAuditEvent.mock.calls[0][0];
    expect(auditCall.actorIdentityId).toBe(activeIdentity.id);
    expect(auditCall.action).toBe("AUTHORIZATION_DENIED");
  });

  it("CHALLENGEs an admin on a HIGHLY_SENSITIVE asset without step-up, and submits no transaction", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });
    const caller = appRouter.createCaller(
      makeContext(makeUser({ role: "admin" }))
    );
    const result = await caller.assets.authorizeTransfer({
      ...transferInput,
      stepUpAuthenticated: false,
    });

    expect(result.decision).toBe("CHALLENGE");
    expect(result.transaction).toBeNull();
    expect(mockedCreateAuditEvent).toHaveBeenCalledTimes(1);
    expect(mockedCreateAuditEvent.mock.calls[0][0].action).toBe(
      "AUTHORIZATION_CHALLENGED"
    );
  });

  it("ALLOWs an admin with step-up, records the decision and audit trail with the transaction", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage", "asset:transfer"],
    });
    const caller = appRouter.createCaller(
      makeContext(makeUser({ role: "admin" }))
    );
    const result = await caller.assets.authorizeTransfer({
      ...transferInput,
      stepUpAuthenticated: true,
    });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction).toMatchObject({ status: "CONFIRMED" });
    expect(result.transaction.transactionHash).toMatch(/^0xmock_/);
    expect(mockedCreateDecision).toHaveBeenCalledTimes(1);
    expect(mockedCreateDecision.mock.calls[0][0].decision).toBe("ALLOW");
    expect(mockedCreateAuditEvent).toHaveBeenCalledTimes(1);
    const auditCall = mockedCreateAuditEvent.mock.calls[0][0];
    expect(auditCall.action).toBe("AUTHORIZATION_ALLOWED");
    expect(auditCall.actorIdentityId).toBe(activeIdentity.id);
    expect(auditCall.transactionHash).toBe(result.transaction.transactionHash);
    expect(auditCall.blockNumber).toBe(result.transaction.blockNumber);
  });

  it("ALLOWs a non-admin identity holding asset:transfer through its granted permissions", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["MANAGER"],
      permissions: ["asset:transfer"],
    });
    // A CONTROLLED asset so the HIGHLY_SENSITIVE USER guard does not apply.
    mockedGetAssetById.mockResolvedValue({
      ...activeAsset,
      classification: "CONTROLLED",
    });
    const caller = appRouter.createCaller(makeContext(makeUser()));
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction).toMatchObject({ status: "CONFIRMED" });
  });

  it("DENIES a MANAGER without asset:transfer even on a controlled asset", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["MANAGER"],
      permissions: ["asset:read"],
    });
    mockedGetAssetById.mockResolvedValue({
      ...activeAsset,
      classification: "CONTROLLED",
    });
    const caller = appRouter.createCaller(makeContext(makeUser()));
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
  });

  it("rejects a non-UUID assetId (validation)", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser()));
    await expect(
      caller.assets.authorizeTransfer({ assetId: "not-a-uuid" })
    ).rejects.toMatchObject({ code: "BAD_REQUEST", message: INVALID_INPUT });
  });

  it("ignores client-supplied assetClassification (policy uses the database value)", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });
    const caller = appRouter.createCaller(
      makeContext(makeUser({ role: "admin" }))
    );
    // Client claims CONTROLLED; DB says HIGHLY_SENSITIVE. Without step-up the
    // engine must CHALLENGE — proving the client value is never trusted.
    const result = await caller.assets.authorizeTransfer({
      ...transferInput,
      assetClassification: "CONTROLLED",
      stepUpAuthenticated: false,
    });
    expect(result.decision).toBe("CHALLENGE");
  });
});

describe("audit.list validation", () => {
  it("rejects limit=0, negative, fractional, and >200 limits", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser()));
    for (const limit of [0, -1, 1.5, 201]) {
      await expect(caller.audit.list({ limit })).rejects.toMatchObject({
        code: "BAD_REQUEST",
      });
    }
  });

  it("accepts the documented limit range", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser()));
    await expect(caller.audit.list({ limit: 1 })).resolves.toBeDefined();
    await expect(caller.audit.list({ limit: 200 })).resolves.toBeDefined();
  });
});
