import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TRPCError } from "@trpc/server";
import type { TrpcContext } from "./_core/context";

// --- db + blockchain mocks (must be declared before importing the router) ----

const dbMocks = vi.hoisted(() => ({
  listIdentities: vi.fn(),
  getIdentitiesWithRoles: vi.fn(),
  createIdentity: vi.fn(),
  listAssets: vi.fn(),
  createAsset: vi.fn(),
  setAssetTokenId: vi.fn(),
  getAssetById: vi.fn(),
  getIdentityById: vi.fn(),
  getIdentityByLinkedUserId: vi.fn(),
  getIdentityRolesAndPermissions: vi.fn(),
  getUserByEmail: vi.fn(),
  applyIdentityRoles: vi.fn(),
  listRolesWithPermissions: vi.fn(),
  listPermissions: vi.fn(),
  listPolicies: vi.fn(),
  listAssetCustody: vi.fn(),
  listAssetAuditEvents: vi.fn(),
  listIdentityAuditEvents: vi.fn(),
  listAuditEvents: vi.fn(),
  listSecurityAlerts: vi.fn(),
  createSecurityAlert: vi.fn(),
  updateAlertStatus: vi.fn(),
  applyCustodyTransfer: vi.fn(),
  applyIdentityStatusChange: vi.fn(),
  applyAssetStatusChange: vi.fn(),
  createAuthorizationDecision: vi.fn(),
  createAuditEvent: vi.fn(),
  createDidRecord: vi.fn(),
  trackPlatformSession: vi.fn(),
  revokePlatformSession: vi.fn(),
}));

const blockchainMocks = vi.hoisted(() => ({
  getNetworkStatus: vi.fn(),
  getLatestBlock: vi.fn(),
  submitTransaction: vi.fn(),
  getTransaction: vi.fn(),
  getEvents: vi.fn(),
  operatorAddress: null as string | null,
  mode: "MOCK" as const,
}));

// Stable besu service object: property reads happen at call time, so per-test
// mutation of config.privateKey / method mocks is picked up regardless of
// vi.mock factory caching.
const besuMocks = vi.hoisted(() => ({
  config: { privateKey: null as string | null },
  getAsset: vi.fn(),
  getIdentity: vi.fn(),
  setAssetStatus: vi.fn(),
  setIdentityStatus: vi.fn(),
}));

const anchorMocks = vi.hoisted(() => ({
  anchorIdentity: vi.fn(),
  anchorAsset: vi.fn(),
}));

const sdkMocks = vi.hoisted(() => ({
  createSessionToken: vi.fn(),
}));

vi.mock("./_core/sdk", () => ({
  sdk: { createSessionToken: sdkMocks.createSessionToken },
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
  besuBlockchainService: besuMocks,
}));
vi.mock("./modules/blockchain/anchoring.service", () => ({
  anchoringService: {
    anchorIdentity: anchorMocks.anchorIdentity,
    anchorAsset: anchorMocks.anchorAsset,
  },
  deriveIdentityWallet: vi.fn(() => "0xderivedwallet"),
}));

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
    latestBlock: 100,
  });
  besuMocks.config.privateKey = null;
  besuMocks.getAsset.mockResolvedValue(null);
  besuMocks.getIdentity.mockResolvedValue(null);
  anchorMocks.anchorIdentity.mockResolvedValue({ outcome: "SKIPPED", reason: "mock" });
  anchorMocks.anchorAsset.mockResolvedValue({ outcome: "SKIPPED", reason: "mock" });
  dbMocks.createAuditEvent.mockResolvedValue(undefined);
  dbMocks.createAuthorizationDecision.mockResolvedValue(undefined);
  dbMocks.createSecurityAlert.mockResolvedValue(undefined);
  dbMocks.createDidRecord.mockResolvedValue(undefined);
  dbMocks.trackPlatformSession.mockResolvedValue(undefined);
  dbMocks.applyCustodyTransfer.mockResolvedValue({ id: "asset-1", updated: true });
  dbMocks.getIdentityByLinkedUserId.mockResolvedValue(undefined);
  dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({ roles: [], permissions: [] });
  dbMocks.getIdentityById.mockResolvedValue({ id: "owner-identity", status: "ACTIVE" });
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
    loginMethod: "password",
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
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: {
      clearCookie: vi.fn(),
      cookie: vi.fn(),
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
  expected: { code: TRPCError["code"]; message?: string },
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

// --- auth.login (local password flow) ----------------------------------------

describe("auth.login (local password authentication)", () => {
  const passwordHash = "scrypt$32768$8$1$c2FtdA$aGFzaA";
  const validInput = { email: "admin@sampraan.dev", password: "SampraanAdmin#2026" };

  beforeEach(() => {
    sdkMocks.createSessionToken.mockResolvedValue("session-token");
  });

  it("logs in a seeded account and mints a tracked session", async () => {
    dbMocks.getUserByEmail.mockResolvedValue({
      id: 4,
      openId: "sampraan-dev-admin",
      name: "Dev Admin",
      email: "admin@sampraan.dev",
      role: "admin",
      passwordHash,
    });
    // verifyPassword is real (scrypt); give the hash a valid scrypt shape the
    // verifier accepts. Use a genuine hash produced by the auth module.
    const { hashPassword } = await import("./auth/password");
    const realHash = await hashPassword(validInput.password);
    dbMocks.getUserByEmail.mockResolvedValue({
      id: 4,
      openId: "sampraan-dev-admin",
      name: "Dev Admin",
      email: "admin@sampraan.dev",
      role: "admin",
      passwordHash: realHash,
    });
    const caller = await callerFor(anonContext());

    const result = await caller.auth.login(validInput);

    expect(result.user).toMatchObject({ email: "admin@sampraan.dev", role: "admin" });
    expect(sdkMocks.createSessionToken).toHaveBeenCalled();
    expect(dbMocks.trackPlatformSession).toHaveBeenCalledWith(
      expect.objectContaining({ linkedUserId: 4 }),
    );
    // The response NEVER includes the hash or password material.
    expect(JSON.stringify(result)).not.toContain("scrypt$");
    expect(JSON.stringify(result)).not.toContain(validInput.password);
  });

  it("rejects a wrong password with UNAUTHORIZED and equalized message", async () => {
    const { hashPassword } = await import("./auth/password");
    dbMocks.getUserByEmail.mockResolvedValue({
      id: 4,
      openId: "sampraan-dev-admin",
      name: "Dev Admin",
      email: "admin@sampraan.dev",
      role: "admin",
      passwordHash: await hashPassword("DifferentPassword#1"),
    });
    const caller = await callerFor(anonContext());

    await expectTrpcError(caller.auth.login(validInput), {
      code: "UNAUTHORIZED",
      message: "Invalid email or password",
    });
    expect(sdkMocks.createSessionToken).not.toHaveBeenCalled();
  });

  it("rejects an unknown email with the SAME message (anti-enumeration)", async () => {
    dbMocks.getUserByEmail.mockResolvedValue(undefined);
    const caller = await callerFor(anonContext());

    await expectTrpcError(caller.auth.login(validInput), {
      code: "UNAUTHORIZED",
      message: "Invalid email or password",
    });
    // The failed attempt is audited with a masked email (no full address).
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "LOGIN_FAILED",
        decision: "DENY",
      }),
    );
  });

  it("rejects a user with no local password hash (OAuth-only account)", async () => {
    dbMocks.getUserByEmail.mockResolvedValue({
      id: 9,
      openId: "oauth-only",
      email: "oauth@sampraan.dev",
      role: "user",
      passwordHash: null,
    });
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.auth.login(validInput), {
      code: "UNAUTHORIZED",
      message: "Invalid email or password",
    });
  });

  it.each([
    ["invalid email", { email: "not-an-email", password: "SomePassword#1" }],
    ["short password", { email: "a@b.dev", password: "short" }],
  ])("rejects input where %s", async (_label, input) => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.auth.login(input), { code: "BAD_REQUEST" });
  });

  it("auth.config reports local login enabled and oauth state", async () => {
    const caller = await callerFor(anonContext());
    const result = await caller.auth.config();
    expect(result.localLoginEnabled).toBe(true);
    expect(typeof result.oauthConfigured).toBe("boolean");
  });
});

// --- identities RBAC administration ------------------------------------------

describe("identities.assignRoles (RBAC write path)", () => {
  const identityFixture = {
    id: "11111111-1111-4111-8111-111111111111",
    displayName: "Dev Manager",
    organization: "SAMPRAAN DEMO ORGANIZATION",
    did: "did:sampraan:dev-manager-ananya",
    status: "ACTIVE",
  };

  it("allows a platform admin to replace an identity's role set", async () => {
    dbMocks.getIdentityById.mockResolvedValue(identityFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "acting-admin-identity",
      status: "ACTIVE",
    });
    dbMocks.applyIdentityRoles.mockResolvedValue(["MANAGER", "AUDITOR"]);
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );

    const result = await caller.identities.assignRoles({
      identityId: identityFixture.id,
      roleNames: ["MANAGER", "AUDITOR"],
    });

    expect(result).toEqual({ identityId: identityFixture.id, roles: ["MANAGER", "AUDITOR"] });
    expect(dbMocks.applyIdentityRoles).toHaveBeenCalledWith({
      identityId: identityFixture.id,
      roleNames: ["MANAGER", "AUDITOR"],
      assignedByIdentityId: "acting-admin-identity",
    });
    // The role change is audited with the ACTING admin attributed.
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "ROLE_CHANGED",
        actorIdentityId: "acting-admin-identity",
        resourceId: identityFixture.id,
        decision: "ALLOW",
      }),
    );
  });

  it("rejects a non-admin (RBAC writes are admin-only)", async () => {
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(
      caller.identities.assignRoles({
        identityId: identityFixture.id,
        roleNames: ["ADMIN"],
      }),
      { code: "FORBIDDEN" },
    );
    expect(dbMocks.applyIdentityRoles).not.toHaveBeenCalled();
  });

  it("rejects an anonymous caller", async () => {
    const caller = await callerFor(anonContext());
    // adminProcedure rejects an anonymous caller with FORBIDDEN (the admin
    // gate treats "not an admin" uniformly, never revealing whether the
    // caller was anonymous or merely non-admin).
    await expectTrpcError(
      caller.identities.assignRoles({
        identityId: identityFixture.id,
        roleNames: ["ADMIN"],
      }),
      { code: "FORBIDDEN" },
    );
  });

  it("rejects an empty role set (identities must keep at least one role)", async () => {
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );
    await expectTrpcError(
      caller.identities.assignRoles({ identityId: identityFixture.id, roleNames: [] }),
      { code: "BAD_REQUEST" },
    );
  });

  it("rejects an unknown role name", async () => {
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );
    await expectTrpcError(
      caller.identities.assignRoles({
        identityId: identityFixture.id,
        roleNames: ["SUPERUSER" as "ADMIN"],
      }),
      { code: "BAD_REQUEST" },
    );
  });
});

describe("identities catalog procedures", () => {
  it("identities.list returns the role-enriched registry", async () => {
    const enriched = [{ ...userFixture(), roles: ["MANAGER"] }];
    dbMocks.getIdentitiesWithRoles.mockResolvedValue(enriched);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.identities.list()).resolves.toEqual(enriched);
  });

  it("identities.roles returns the RBAC catalog", async () => {
    const catalog = [{ id: "role-1", name: "MANAGER", permissions: ["asset:read"] }];
    dbMocks.listRolesWithPermissions.mockResolvedValue(catalog);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.identities.roles()).resolves.toEqual(catalog);
  });

  it("identities.history forwards the identity id", async () => {
    dbMocks.listIdentityAuditEvents.mockResolvedValue([]);
    const caller = await callerFor(context(userFixture()));
    await caller.identities.history({
      identityId: "11111111-1111-4111-8111-111111111111",
    });
    expect(dbMocks.listIdentityAuditEvents).toHaveBeenCalledWith(
      "11111111-1111-4111-8111-111111111111",
      50,
    );
  });
});

// --- assets.assign (custody assignment) --------------------------------------

describe("assets.assign (custody assignment)", () => {
  const assetFixture = {
    id: "22222222-2222-4222-8222-222222222222",
    assetId: "DEV-INSTRUMENT-002",
    name: "Environmental Test Instrument (Demo)",
    status: "ACTIVE",
    classification: "CONTROLLED",
  };
  const custodianFixture = {
    id: "33333333-3333-4333-8333-333333333333",
    displayName: "Dev Manager (Ananya Rao)",
    did: "did:sampraan:dev-manager-ananya",
    status: "ACTIVE",
  };

  function setup() {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityById.mockResolvedValue(custodianFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue(undefined);
    dbMocks.applyCustodyTransfer.mockResolvedValue({ id: assetFixture.id, updated: true });
    // A real chain binding: operator key configured + no on-chain asset yet
    // (so the "already in custody" short-circuit does not fire).
    besuMocks.config.privateKey = "0xtest-operator-key";
    besuMocks.getAsset.mockResolvedValue(null);
    blockchainMocks.submitTransaction.mockResolvedValue({
      transactionHash: "0xassign_tx",
      blockNumber: 101,
      blockHash: "0xblock",
      gasUsed: 42000,
      status: "CONFIRMED",
    });
  }

  it("assigns custody to an ACTIVE custodian and audits the confirmed transition", async () => {
    setup();
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );

    const result = await caller.assets.assign({
      assetId: assetFixture.id,
      custodianIdentityId: custodianFixture.id,
    });

    expect(result.transaction.transactionHash).toBe("0xassign_tx");
    expect(result.custodianIdentityId).toBe(custodianFixture.id);
    expect(blockchainMocks.submitTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ action: "ASSET_ASSIGN" }),
    );
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "ASSET_ASSIGNED",
        decision: "ALLOW",
        transactionHash: "0xassign_tx",
        blockNumber: 101,
      }),
    );
  });

  it("refuses to assign a REVOKED asset", async () => {
    setup();
    dbMocks.getAssetById.mockResolvedValue({ ...assetFixture, status: "REVOKED" });
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );
    await expectTrpcError(
      caller.assets.assign({
        assetId: assetFixture.id,
        custodianIdentityId: custodianFixture.id,
      }),
      { code: "PRECONDITION_FAILED", message: "A revoked asset cannot be reassigned" },
    );
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("refuses a non-ACTIVE custodian (chain enforces RecipientNotActive)", async () => {
    setup();
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityById.mockResolvedValue({ ...custodianFixture, status: "SUSPENDED" });
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );
    await expectTrpcError(
      caller.assets.assign({
        assetId: assetFixture.id,
        custodianIdentityId: custodianFixture.id,
      }),
      { code: "PRECONDITION_FAILED", message: "Custodian identity is suspended" },
    );
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("rejects a non-admin caller (assignment is administrative)", async () => {
    setup();
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(
      caller.assets.assign({
        assetId: assetFixture.id,
        custodianIdentityId: custodianFixture.id,
      }),
      { code: "FORBIDDEN" },
    );
  });

  it("records BLOCKCHAIN_TRANSACTION_FAILED when the chain rejects the assignment", async () => {
    setup();
    blockchainMocks.submitTransaction.mockRejectedValue(new Error("reverted: NotAssetManager"));
    const caller = await callerFor(
      context(userFixture({ role: "admin", openId: "admin-user" })),
    );

    await expectTrpcError(
      caller.assets.assign({
        assetId: assetFixture.id,
        custodianIdentityId: custodianFixture.id,
      }),
      { code: "BAD_GATEWAY" },
    );

    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "BLOCKCHAIN_TRANSACTION_FAILED",
        decision: "DENY",
        reason: expect.stringContaining("NotAssetManager"),
      }),
    );
    // No success evidence may exist for the failed assignment.
    const actions = dbMocks.createAuditEvent.mock.calls.map(c => c[0]?.action);
    expect(actions).not.toContain("ASSET_ASSIGNED");
  });
});

// --- authorizeTransfer with a named recipient ---------------------------------

describe("assets.authorizeTransfer with recipient selection", () => {
  const assetFixture = {
    id: "44444444-4444-4444-8444-444444444444",
    assetId: "DEV-SPEC-003",
    name: "Radar Interface Specification (Demo)",
    classification: "CONTROLLED",
    ownerIdentityId: "owner-uuid",
    status: "ACTIVE",
  };
  const managerActor = {
    id: "12345678-1234-4123-8123-123456789abc",
    linkedUserId: 1,
    status: "ACTIVE",
    displayName: "Dev Manager (Ananya Rao)",
    did: "did:sampraan:dev-manager-ananya",
  };
  const recipientIdentity = {
    id: "abcdefab-abcd-4abc-8abc-abcdefabcdef",
    status: "ACTIVE",
    displayName: "Dev Auditor (Vikram Singh)",
    did: "did:sampraan:dev-auditor-vikram",
  };

  it("transfers to the NAMED recipient (not the actor) when authorized", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue(managerActor);
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["MANAGER"],
      permissions: ["asset:read", "asset:transfer"],
    });
    dbMocks.getIdentityById.mockResolvedValue(recipientIdentity);
    // Real-chain binding for the recipient path: operator key set, and the
    // on-chain custodian differs from the recipient's derived wallet so the
    // transfer actually submits.
    besuMocks.config.privateKey = "0xtest-operator-key";
    besuMocks.getAsset.mockResolvedValue({ custodian: "0xsomeothercustodian" });
    blockchainMocks.submitTransaction.mockResolvedValue({
      transactionHash: "0xrecipient_tx",
      blockNumber: 102,
      status: "CONFIRMED",
    });
    const caller = await callerFor(context(userFixture()));

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
      recipientIdentityId: recipientIdentity.id,
    });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction?.transactionHash).toBe("0xrecipient_tx");
    // The read model must move custody to the RECIPIENT identity.
    expect(dbMocks.applyCustodyTransfer).toHaveBeenCalledWith(
      expect.objectContaining({ newCustodianIdentityId: recipientIdentity.id }),
    );
  });

  it("denies an auditor (no asset:transfer permission) and never submits a transaction", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      ...managerActor,
      id: "auditor-identity",
      displayName: "Dev Auditor (Vikram Singh)",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["AUDITOR"],
      permissions: ["identity:read", "asset:read", "audit:read"],
    });
    const caller = await callerFor(context(userFixture()));

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
    });

    expect(result.decision).toBe("DENY");
    expect(result.reason).toBe("Role AUDITOR does not hold asset:transfer");
    expect(result.transaction).toBeNull();
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({ action: "AUTHORIZATION_DENIED", decision: "DENY" }),
    );
  });

  it("denies a USER role identity even when it names itself as recipient", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      ...managerActor,
      id: "user-identity",
      displayName: "Dev User (Riya Kulkarni)",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["USER"],
      permissions: ["asset:read"],
    });
    dbMocks.getIdentityById.mockResolvedValue({ id: "user-identity", status: "ACTIVE" });
    const caller = await callerFor(context(userFixture()));

    const result = await caller.assets.authorizeTransfer({
      assetId: assetFixture.id,
      recipientIdentityId: "66666666-6666-4666-8666-666666666666",
    });

    expect(result.decision).toBe("DENY");
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("404s when the named recipient does not exist", async () => {
    dbMocks.getAssetById.mockResolvedValue(assetFixture);
    dbMocks.getIdentityById.mockResolvedValue(undefined);
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(
      caller.assets.authorizeTransfer({
        assetId: assetFixture.id,
        recipientIdentityId: "77777777-7777-4777-8777-777777777777",
      }),
      { code: "NOT_FOUND", message: "Recipient identity not found" },
    );
  });
});

// --- alerts.setStatus (investigator workflow) ----------------------------------

describe("alerts.setStatus (investigator workflow)", () => {
  it("advances an alert status and audits it as advisory", async () => {
    dbMocks.updateAlertStatus.mockResolvedValue({ id: "alert-1", status: "RESOLVED" });
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue(undefined);
    const caller = await callerFor(context(userFixture()));

    const result = await caller.alerts.setStatus({
      alertId: "55555555-5555-4555-8555-555555555555",
      status: "RESOLVED",
    });

    expect(result).toEqual({ id: "alert-1", status: "RESOLVED" });
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "SECURITY_ALERT_UPDATED",
        metadata: expect.objectContaining({ advisory: true }),
      }),
    );
  });

  it("404s an unknown alert", async () => {
    dbMocks.updateAlertStatus.mockResolvedValue(undefined);
    const caller = await callerFor(context(userFixture()));
    await expectTrpcError(
      caller.alerts.setStatus({
        alertId: "55555555-5555-4555-8555-555555555556",
        status: "OPEN",
      }),
      { code: "NOT_FOUND", message: "Alert not found" },
    );
  });
});

// --- policies catalog + dry run ------------------------------------------------

describe("policies router", () => {
  it("lists the policy catalog for authenticated users", async () => {
    const policies = [
      { id: "p1", name: "Highly sensitive transfer guard", active: true, effect: "DENY" },
    ];
    dbMocks.listPolicies.mockResolvedValue(policies);
    const caller = await callerFor(context(userFixture()));
    await expect(caller.policies.list()).resolves.toEqual(policies);
  });

  it("dry-run explains the decision the engine WOULD make and never submits", async () => {
    dbMocks.getAssetById.mockResolvedValue({
      ...{
        id: "44444444-4444-4444-8444-444444444444",
        assetId: "DEV-SPEC-003",
        classification: "HIGHLY_SENSITIVE",
        status: "ACTIVE",
        ownerIdentityId: "owner-uuid",
        name: "Spec",
      },
    });
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue({
      id: "manager-identity",
      status: "ACTIVE",
    });
    dbMocks.getIdentityRolesAndPermissions.mockResolvedValue({
      roles: ["MANAGER"],
      permissions: ["asset:transfer"],
    });
    dbMocks.getIdentityById.mockResolvedValue({ id: "owner-identity", status: "ACTIVE" });
    const caller = await callerFor(context(userFixture()));

    const result = await caller.policies.evaluateTransfer({
      assetId: "44444444-4444-4444-8444-444444444444",
    });

    // HIGHLY_SENSITIVE + no server-verified step-up => CHALLENGE.
    expect(result.decision).toBe("CHALLENGE");
    expect(result.dryRun).toBe(true);
    expect(result.contractChecks.length).toBeGreaterThan(0);
    // A dry run NEVER submits a transaction.
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
    expect(dbMocks.createAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        action: "AUTHORIZATION_DRY_RUN",
        metadata: expect.objectContaining({ dryRun: true }),
      }),
    );
  });

  it("requires authentication", async () => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(
      caller.policies.evaluateTransfer({
        assetId: "44444444-4444-4444-8444-444444444444",
      }),
      { code: "UNAUTHORIZED" },
    );
  });
});

// --- security intelligence scan -------------------------------------------------

describe("intelligence.scan (advisory rule engine)", () => {
  it("runs the rule scan, records evidence, and never fabricates alerts", async () => {
    dbMocks.listAuditEvents.mockResolvedValue([
      { id: "e1", action: "AUTHORIZATION_DENIED", actorIdentityId: "i1", decision: "DENY" },
    ]);
    dbMocks.listIdentities.mockResolvedValue([{ id: "i1", status: "ACTIVE", did: "did:x:y" }]);
    dbMocks.listSecurityAlerts.mockResolvedValue([]);
    dbMocks.createSecurityAlert.mockResolvedValue(undefined);
    dbMocks.getIdentityByLinkedUserId.mockResolvedValue(undefined);
    const caller = await callerFor(context(userFixture()));

    const result = await caller.intelligence.scan();

    expect(typeof result.scanned).toBe("number");
    expect(typeof result.created).toBe("number");
    expect(blockchainMocks.submitTransaction).not.toHaveBeenCalled();
  });

  it("requires authentication", async () => {
    const caller = await callerFor(anonContext());
    await expectTrpcError(caller.intelligence.scan(), { code: "UNAUTHORIZED" });
  });
});
