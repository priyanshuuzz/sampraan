import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TRPCError } from "@trpc/server";
import { COOKIE_NAME, UNAUTHED_ERR_MSG } from "../shared/const";
import type { TrpcContext } from "./_core/context";

// --- db + blockchain mocks (must be declared before importing the router) ----

const dbMocks = vi.hoisted(() => ({
  listIdentities: vi.fn(),
  getIdentitiesWithRoles: vi.fn(),
  createIdentity: vi.fn(),
  listAssets: vi.fn(),
  createAsset: vi.fn(),
  getAssetById: vi.fn(),
  getIdentityById: vi.fn(),
  getIdentityByLinkedUserId: vi.fn(),
  getIdentityRolesAndPermissions: vi.fn(),
  createAuthorizationDecision: vi.fn(),
  createAuditEvent: vi.fn(),
  listAuditEvents: vi.fn(),
  listSecurityAlerts: vi.fn(),
  createDidRecord: vi.fn(),
  applyCustodyTransfer: vi.fn(),
  applyIdentityStatusChange: vi.fn(),
}));

const blockchainMocks = vi.hoisted(() => ({
  getNetworkStatus: vi.fn(),
  getLatestBlock: vi.fn(),
  submitTransaction: vi.fn(),
  getTransaction: vi.fn(),
  getEvents: vi.fn(),
  operatorAddress: null as string | null,
  mode: "MOCK" as const,
  besu: null as null | {
    operatorAddress: string;
    registerIdentity: ReturnType<typeof vi.fn>;
    registerAsset: ReturnType<typeof vi.fn>;
    setIdentityStatus: ReturnType<typeof vi.fn>;
  },
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
}));

// NODE_ENV is frozen at module load for the demo router guard, so load the
// router once per environment inside a dynamic import after the env is set.
async function loadRouter() {
  const mod = await import("./routers");
  return mod;
}

beforeEach(() => {
  vi.clearAllMocks();
  blockchainMocks.getNetworkStatus.mockResolvedValue({
    connected: false,
    mode: "MOCK",
    network: "SAMPRAAN-DEMO-QBFT",
    latestBlock: 18402,
  });
  blockchainMocks.getLatestBlock.mockResolvedValue(18402);
  blockchainMocks.submitTransaction.mockResolvedValue({
    transactionHash: "0xmock_transfer",
    blockNumber: 18403,
    status: "CONFIRMED",
  });
  dbMocks.createAuthorizationDecision.mockResolvedValue(undefined);
  dbMocks.createAuditEvent.mockResolvedValue(undefined);
  dbMocks.createDidRecord.mockResolvedValue(undefined);
  dbMocks.createIdentity.mockResolvedValue(undefined);
  // BUG-006: the custody read-model sync after a confirmed on-chain transfer.
  // Default to a successful no-change update; individual tests override it.
  dbMocks.applyCustodyTransfer.mockResolvedValue({ id: "asset-1", updated: true });
  dbMocks.applyIdentityStatusChange.mockResolvedValue({ id: "identity-1", status: "ACTIVE" });
  // Merged authorizeTransfer resolves the actor identity and the asset owner
  // from the database. Default: no linked SAMPRAAN identity (strict DENY) and
  // an ACTIVE owner so the owner guard never masks the case under test.
  dbMocks.getIdentityByLinkedUserId.mockResolvedValue(undefined);
  dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
    roles: [],
    permissions: [],
  });
  dbMocks.getIdentityById.mockResolvedValue({
    id: "owner-identity",
    status: "ACTIVE",
  });
});

afterEach(() => {
  vi.resetModules();
});

// --- context factories -------------------------------------------------------

type TestUser = NonNullable<TrpcContext["user"]>;

function userFixture(overrides: Partial<TestUser> = {}): TestUser {
  return {
    id: 1,
    openId: "sample-user",
    email: "sample@example.com",
    name: "Sample User",
    loginMethod: "manus",
    role: "user",
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
    ...overrides,
  };
}

function context(user: TestUser | null): TrpcContext {
  return {
    user,
    req: {
      protocol: "https",
      headers: {},
    } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
    } as unknown as TrpcContext["res"],
  };
}

function anonContext(): TrpcContext {
  return context(null);
}

async function callerFor(ctx: TrpcContext) {
  const { appRouter } = await loadRouter();
  return appRouter.createCaller(ctx);
}

async function expectTrpcError(
  promise: Promise<unknown>,
  expected: { code: TRPCError["code"]; message?: string }
) {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(TRPCError);
    const trpcError = error as TRPCError;
    expect(trpcError.code).toBe(expected.code);
    if (expected.message) {
      expect(trpcError.message).toBe(expected.message);
    }
    return;
  }
  throw new Error("Expected the procedure call to reject");
}

// --- tests -------------------------------------------------------------------

describe("protected procedures require authentication", () => {
  it.each([
    ["identities.list", (c: TrpcContext) => c.identities.list()],
    ["assets.list", (c: TrpcContext) => c.assets.list()],
    ["audit.list", (c: TrpcContext) => c.audit.list()],
    ["alerts.list", (c: TrpcContext) => c.alerts.list()],
  ] as const)("rejects anonymous access to %s", async (name, invoke) => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(invoke(caller), {
      code: "UNAUTHORIZED",
      message: UNAUTHED_ERR_MSG,
    });
    expect(name).toBeTruthy();
  });

  it("allows authenticated users to list identities", async () => {
    // identities.list serves the enriched registry (identity + role names).
    const identities = [{ id: "identity-1", displayName: "Aarav Mehta", roles: ["USER"] }];
    dbMocks.getIdentitiesWithRoles.mockResolvedValue(identities);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.identities.list()).resolves.toEqual(identities);
    expect(dbMocks.getIdentitiesWithRoles).toHaveBeenCalledTimes(1);
  });

  it("allows authenticated users to list assets", async () => {
    const assets = [{ id: "asset-1", assetId: "ASSET-001" }];
    dbMocks.listAssets.mockResolvedValue(assets);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.assets.list()).resolves.toEqual(assets);
  });

  it("allows authenticated users to list audit events with the default limit", async () => {
    const events = [{ id: "event-1", action: "IDENTITY_CREATED" }];
    dbMocks.listAuditEvents.mockResolvedValue(events);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.audit.list()).resolves.toEqual(events);
    expect(dbMocks.listAuditEvents).toHaveBeenCalledWith(50);
  });

  it("forwards an explicit audit limit to listAuditEvents", async () => {
    dbMocks.listAuditEvents.mockResolvedValue([]);
    const caller = await callerFor(context(userFixture()));
    await caller.audit.list({ limit: 10 });
    expect(dbMocks.listAuditEvents).toHaveBeenCalledWith(10);
  });

  it("allows authenticated users to list security alerts", async () => {
    const alerts = [{ id: "alert-1", status: "OPEN" }];
    dbMocks.listSecurityAlerts.mockResolvedValue(alerts);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.alerts.list()).resolves.toEqual(alerts);
  });
});

describe("identities.create", () => {
  const validInput = {
    displayName: "Aarav Mehta",
    organization: "SAMPRAAN Demo Org",
    did: "did:web:demo.sampraan",
  };

  it("creates an identity and the matching DID record for an admin", async () => {
    const identity = { id: "new-identity", ...validInput, status: "ACTIVE" };
    dbMocks.createIdentity.mockResolvedValue(identity);
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );

    const result = await caller.identities.create(validInput);

    // The creation response now carries the on-chain anchor outcome
    // (BUG-003): the record itself must round-trip unchanged.
    expect(result).toMatchObject(identity);
    expect(result.anchor).toBeDefined();
    expect(["ANCHORED", "SKIPPED", "FAILED"]).toContain(result.anchor.outcome);
    expect(dbMocks.createIdentity).toHaveBeenCalledWith({
      ...validInput,
      status: "ACTIVE",
    });
    expect(dbMocks.createDidRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        identityId: identity.id,
        did: validInput.did,
        method: "web",
        status: "ACTIVE",
      })
    );
  });

  it("rejects a regular authenticated user (admin-only procedure)", async () => {
    // identities.create mints trust-registry records; only platform admins
    // may call it after the security hardening.
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(caller.identities.create(validInput), {
      code: "FORBIDDEN",
    });
    expect(dbMocks.createIdentity).not.toHaveBeenCalled();
  });

  it("rejects a non-authenticated caller", async () => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.identities.create(validInput), {
      code: "FORBIDDEN",
    });
  });

  it("throws INTERNAL_SERVER_ERROR when the identity cannot be created", async () => {
    dbMocks.createIdentity.mockResolvedValue(undefined);
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );
    await expectTrpcError(caller.identities.create(validInput), {
      code: "INTERNAL_SERVER_ERROR",
      message: "Identity could not be created",
    });
  });

  it.each([
    ["displayName too short", { displayName: "A" }],
    ["displayName too long", { displayName: "a".repeat(161) }],
    ["organization too short", { organization: "S" }],
    ["did too short", { did: "did:x" }],
    ["did too long", { did: `did:web:${"a".repeat(300)}` }],
    ["invalid status", { status: "DISABLED" }],
  ])("rejects input where %s", async (_label, override) => {
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );
    await expectTrpcError(
      caller.identities.create({ ...validInput, ...override }),
      {
        code: "BAD_REQUEST",
      }
    );
    expect(dbMocks.createIdentity).not.toHaveBeenCalled();
  });
});

describe("assets.authorizeTransfer", () => {
  const assetFixture = {
    id: "11111111-1111-4111-8111-111111111111",
    assetId: "ASSET-001",
    name: "Demo Asset",
    type: "DOCUMENT",
    classification: "HIGHLY_SENSITIVE",
    ownerIdentityId: "owner-uuid",
    custodianIdentityId: "custodian-uuid",
    status: "ACTIVE",
  } as const;

  function expectDeniedAuditEvent() {
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "AUTHORIZATION_DENIED",
        decision: "DENY",
        resourceType: "ASSET",
        resourceId: "ASSET-001",
      })
    );
  }

  it("requires authentication", async () => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(
      caller.assets.authorizeTransfer({
        assetId: "00000000-0000-4000-8000-000000000000",
      }),
      { code: "UNAUTHORIZED" }
    );
    expect(dbMocks.getAssetById).not.toHaveBeenCalled();
  });

  it("throws NOT_FOUND for an unknown asset", async () => {
    dbMocks.getAssetById.mockResolvedValue(undefined);
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(
      caller.assets.authorizeTransfer({
        assetId: "00000000-0000-4000-8000-000000000000",
      }),
      { code: "NOT_FOUND", message: "Asset not found" }
    );
    expect(dbMocks.createAuthorizationDecision).not.toHaveBeenCalled();
  });

  it("requires a uuid assetId", async () => {
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(
      caller.assets.authorizeTransfer({ assetId: "not-a-uuid" }),
      { code: "BAD_REQUEST" }
    );
  });

  it("denies a regular user without a linked SAMPRAAN identity (identity gate)", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    const caller = await callerFor(context(userFixture()));

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
    });

    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
    // The actor resolves to no SAMPRAAN identity, so the engine evaluates
    // UNREGISTERED — the identity-status gate denies before permissions.
    expect(dbMocks.createAuthorizationDecision).not.toHaveBeenCalled();
    expectDeniedAuditEvent();
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("denies a linked regular user lacking asset:transfer (permission gate)", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "actor-identity",
      linkedUserId: 1,
      status: "ACTIVE",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["USER"],
      permissions: ["asset:read"],
    });
    const caller = await callerFor(context(userFixture()));

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
    });

    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
    expect(result.reason).toBe("Role USER does not hold asset:transfer");
    expect(dbMocks.createAuthorizationDecision).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: "DENY",
        reason: "Role USER does not hold asset:transfer",
      })
    );
    expectDeniedAuditEvent();
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("challenges an admin transferring a highly sensitive asset without step-up", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "actor-identity",
      linkedUserId: 1,
      status: "ACTIVE",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
    });

    expect(result.decision).toBe("CHALLENGE");
    expect(result.transaction).toBeNull();
    expect(dbMocks.createAuthorizationDecision).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: "CHALLENGE",
        // The decision row's policyId is UUID-FK-bound; the engine's
        // POLICY-STEP-UP label is recorded in the audit metadata instead.
        policyId: null,
      })
    );
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "AUTHORIZATION_CHALLENGED",
        decision: "CHALLENGE",
        metadata: expect.objectContaining({ policyId: "POLICY-STEP-UP" }),
      })
    );
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("CHALLENGEs an admin asserting step-up from the client (no server-verified step-up exists)", async () => {
    // STALE EXPECTATION UPDATED: the merged schema strips client
    // stepUpAuthenticated — there is no server-side step-up mechanism, so a
    // HIGHLY_SENSITIVE transfer must CHALLENGE, never ALLOW, on assertion.
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "actor-identity",
      linkedUserId: 1,
      status: "ACTIVE",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
      stepUpAuthenticated: true,
    } as Parameters<typeof caller.assets.authorizeTransfer>[0]);

    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
    expect(result.transaction).toBeNull();
    expect(dbMocks.createAuthorizationDecision).toHaveBeenCalledWith(
      expect.objectContaining({ decision: "CHALLENGE" })
    );
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "AUTHORIZATION_CHALLENGED",
        decision: "CHALLENGE",
      })
    );
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("ignores caller-asserted classification; the stored classification governs", async () => {
    // STALE EXPECTATION UPDATED: the historical vulnerability accepted a
    // client-supplied classification to defeat POLICY-HIGH-SENS-TRANSFER.
    // The merged schema strips the field entirely; the DB classification
    // (HIGHLY_SENSITIVE) governs, so the admin is CHALLENGEd.
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "actor-identity",
      linkedUserId: 1,
      status: "ACTIVE",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
      assetClassification: "CONTROLLED",
    } as Parameters<typeof caller.assets.authorizeTransfer>[0]);

    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
    expect(result.transaction).toBeNull();
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("allows an admin transferring a controlled asset and submits the transaction", async () => {
    dbMocks.getAssetById.mockResolvedValue({
      ...assetFixture,
      classification: "CONTROLLED",
    });
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "actor-identity",
      linkedUserId: 1,
      status: "ACTIVE",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
    });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction).toEqual({
      transactionHash: "0xmock_transfer",
      blockNumber: 18403,
      status: "CONFIRMED",
    });
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "ASSET_TRANSFERRED",
        decision: "ALLOW",
        reason: "Custody transfer confirmed on-chain",
      })
    );
    expect(blockchainMocks.submitTransaction).toHaveBeenCalledWith({
      action: "ASSET_TRANSFER",
      payload: {
        assetId: "ASSET-001",
        toCustodianWallet: null,
        actor: "admin-user",
      },
    });
  });

  it("denies a regular user transferring a controlled asset without a linked identity", async () => {
    dbMocks.getAssetById.mockResolvedValue({
      ...assetFixture,
      classification: "CONTROLLED",
    });
    const caller = await callerFor(context(userFixture()));

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
    });

    // Unregistered actor: the identity-status gate denies before permissions.
    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });
});

describe("assets.create", () => {
  const validInput = {
    assetId: "ASSET-002",
    name: "Demo Asset",
    type: "DOCUMENT",
    classification: "CONTROLLED",
    ownerIdentityId: "00000000-0000-4000-8000-000000000001",
    custodianIdentityId: "00000000-0000-4000-8000-000000000002",
  };

  it("creates an asset for a platform admin", async () => {
    const created = { id: "new-asset", ...validInput, status: "PENDING" };
    dbMocks.createAsset.mockResolvedValue(created);
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );

    const createResult = await caller.assets.create(validInput);
    // BUG-003: the asset creation response carries the on-chain anchor
    // outcome; the asset record itself must round-trip unchanged.
    expect(createResult).toMatchObject(created);
    expect(createResult.anchor).toBeDefined();
    expect(["ANCHORED", "SKIPPED", "FAILED"]).toContain(createResult.anchor.outcome);
    expect(dbMocks.createAsset).toHaveBeenCalledWith({
      ...validInput,
      status: "PENDING",
    });
  });

  it("rejects a regular authenticated user (admin-only procedure)", async () => {
    // assets.create registers classification-bearing records; only platform
    // admins may call it after the security hardening.
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(caller.assets.create(validInput), {
      code: "FORBIDDEN",
    });
    expect(dbMocks.createAsset).not.toHaveBeenCalled();
  });

  it("requires authentication", async () => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.assets.create(validInput), {
      code: "FORBIDDEN",
    });
  });

  it.each([
    ["assetId too short", { assetId: "A" }],
    ["name too long", { name: "a".repeat(201) }],
    ["missing type", { type: "" }],
    ["missing classification", { classification: "" }],
    ["ownerIdentityId not a uuid", { ownerIdentityId: "nope" }],
    ["custodianIdentityId not a uuid", { custodianIdentityId: "nope" }],
    ["invalid status", { status: "ARCHIVED" }],
    ["description too long", { description: "a".repeat(5001) }],
  ])("rejects input where %s", async (_label, override) => {
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" }))
    );
    await expectTrpcError(
      caller.assets.create({ ...validInput, ...override }),
      { code: "BAD_REQUEST" }
    );
    expect(dbMocks.createAsset).not.toHaveBeenCalled();
  });
});

describe("public procedures", () => {
  it("health reports API status without authentication", async () => {
    const caller = await callerFor(anonContext());
    const result = await caller.health();
    expect(result.api).toBe("OK");
    expect(result.blockchain).toMatchObject({ mode: "MOCK" });
  });

  it("observatory aggregates counts without authentication", async () => {
    dbMocks.listIdentities.mockResolvedValue([{}, {}]);
    dbMocks.listAssets.mockResolvedValue([{}]);
    dbMocks.listAuditEvents.mockResolvedValue([{}]);
    dbMocks.listSecurityAlerts.mockResolvedValue([
      { status: "OPEN" },
      { status: "RESOLVED" },
      { status: "OPEN" },
    ]);
    const caller = await callerFor(anonContext());
    const result = await caller.observatory();
    expect(result).toEqual({
      identityCount: 2,
      assetCount: 1,
      auditEventCount: 1,
      openAlertCount: 2,
      blockchain: {
        connected: false,
        mode: "MOCK",
        network: "SAMPRAAN-DEMO-QBFT",
        latestBlock: 18402,
      },
    });
  });

  it("auth.me returns null for an anonymous caller", async () => {
    const caller = await callerFor(anonContext());
    await expect(caller.auth.me()).resolves.toBeNull();
  });

  it("auth.me returns the context user when authenticated", async () => {
    const user = userFixture();
    const caller = await callerFor(context(user));
    await expect(caller.auth.me()).resolves.toEqual(user);
  });

  it("blockchain.status is public", async () => {
    const caller = await callerFor(anonContext());
    await expect(caller.blockchain.status()).resolves.toEqual({
      connected: false,
      mode: "MOCK",
      network: "SAMPRAAN-DEMO-QBFT",
      latestBlock: 18402,
    });
  });
});

describe("demo procedures are development-only", () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it("serves demo identities in development", async () => {
    process.env.NODE_ENV = "development";
    dbMocks.listIdentities.mockResolvedValue([]);
    const caller = await callerFor(anonContext());
    await expect(caller.demo.identities()).resolves.toEqual([]);
  });

  it("serves demo audit events in development with limit 200", async () => {
    process.env.NODE_ENV = "development";
    dbMocks.listAuditEvents.mockResolvedValue([]);
    const caller = await callerFor(anonContext());
    await caller.demo.audit();
    expect(dbMocks.listAuditEvents).toHaveBeenCalledWith(200);
  });

  it("blocks demo data outside development", async () => {
    process.env.NODE_ENV = "production";
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.demo.identities(), {
      code: "FORBIDDEN",
      message: "Demo data is available only in development",
    });
    expect(dbMocks.listIdentities).not.toHaveBeenCalled();
  });

  it("blocks demo assets outside development", async () => {
    process.env.NODE_ENV = "production";
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.demo.assets(), { code: "FORBIDDEN" });
    expect(dbMocks.listAssets).not.toHaveBeenCalled();
  });

  it("blocks demo audit outside development", async () => {
    process.env.NODE_ENV = "production";
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.demo.audit(), { code: "FORBIDDEN" });
    expect(dbMocks.listAuditEvents).not.toHaveBeenCalled();
  });

  it("blocks demo alerts outside development", async () => {
    process.env.NODE_ENV = "production";
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.demo.alerts(), { code: "FORBIDDEN" });
    expect(dbMocks.listSecurityAlerts).not.toHaveBeenCalled();
  });
});

describe("system.health (public) after dead-template removal", () => {
  // The template notifyOwner mutation was removed together with the
  // unreferenced heartbeat/notification modules. The public health
  // procedure remains and must not require authentication.
  it("answers an anonymous caller without error", async () => {
    const caller = await callerFor(anonContext());
    const result = await caller.system.health({ timestamp: 1 });
    expect(result).toEqual({ ok: true });
  });

  it("validates a negative timestamp as BAD_REQUEST", async () => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.system.health({ timestamp: -1 }), {
      code: "BAD_REQUEST",
    });
  });
});

describe("auth.logout through the app router", () => {
  it("clears the session cookie with maxAge -1", async () => {
    const res = { clearCookie: vi.fn() } as unknown as TrpcContext["res"];
    const ctx: TrpcContext = {
      user: userFixture(),
      req: { protocol: "https", headers: {} } as TrpcContext["req"],
      res,
    };
    const caller = await callerFor(ctx);
    await expect(caller.auth.logout()).resolves.toEqual({ success: true });
    expect(res.clearCookie).toHaveBeenCalledWith(
      COOKIE_NAME,
      expect.objectContaining({ maxAge: -1, httpOnly: true })
    );
  });
});
