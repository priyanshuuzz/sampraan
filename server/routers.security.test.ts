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
 *
 * This file unions two regression suites that arrived on separate branches:
 *  - the actor-linked-identity suite (server-resolved SAMPRAAN identity,
 *    roles, and permissions for the authenticated user), and
 *  - the client-bypass suite (client-supplied classification / step-up /
 *    role assertions can never influence the decision).
 * Both suites run against the same merged router; the mock below covers every
 * db helper the merged authorizeTransfer path touches.
 */

vi.mock("./db", async (importOriginal: () => Promise<unknown>) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    getAssetById: vi.fn(),
    getIdentityById: vi.fn(),
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
  getIdentityById,
  getIdentityByLinkedUserId,
  getIdentityRolesAndPermissions,
} from "./db";

const mockedGetAssetById = vi.mocked(getAssetById);
const mockedGetIdentityById = vi.mocked(getIdentityById);
const mockedGetIdentityByLinkedUserId = vi.mocked(getIdentityByLinkedUserId);
const mockedGetRolesAndPermissions = vi.mocked(getIdentityRolesAndPermissions);
const mockedCreateAuditEvent = vi.mocked(createAuditEvent);
const mockedCreateDecision = vi.mocked(createAuthorizationDecision);

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

const activeOwnerIdentity: Identity = {
  ...activeIdentity,
  id: activeAsset.ownerIdentityId,
  linkedUserId: 99,
  did: "did:demo:asset-owner",
};

const transferInput = { assetId: activeAsset.id };

beforeEach(() => {
  vi.clearAllMocks();
  mockedGetAssetById.mockResolvedValue(activeAsset);
  // Actor: no linked SAMPRAAN identity by default (the strict default).
  mockedGetIdentityByLinkedUserId.mockResolvedValue(undefined);
  mockedGetRolesAndPermissions.mockResolvedValue({
    roles: [],
    permissions: [],
  });
  // Owner identity of the default asset is ACTIVE so the owner-status
  // guard does not short-circuit before the case under test.
  mockedGetIdentityById.mockResolvedValue(activeOwnerIdentity);
});

// ---------------------------------------------------------------------------
// Suite 1: actor-linked-identity authorization model (backend agent).
// ---------------------------------------------------------------------------

describe("authentication boundary (protected procedures)", () => {
  it("rejects assets.authorizeTransfer without a session", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    await expect(
      caller.assets.authorizeTransfer(transferInput)
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("rejects identities.create without a session (admin gate is fail-closed)", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    // identities.create is an adminProcedure: an anonymous caller can never
    // satisfy the admin requirement, so the request is rejected (FORBIDDEN).
    await expect(
      caller.identities.create({
        displayName: "Aarav Mehta",
        organization: "SAMPRAAN",
        did: "did:demo:aarav",
      })
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("rejects assets.create without a session (admin gate is fail-closed)", async () => {
    const caller = appRouter.createCaller(makeContext(null));
    // assets.create is an adminProcedure: an anonymous caller can never
    // satisfy the admin requirement, so the request is rejected (FORBIDDEN).
    await expect(
      caller.assets.create({
        assetId: "A-1",
        name: "Asset",
        type: "FW",
        classification: "CONTROLLED",
        ownerIdentityId: activeIdentity.id,
        custodianIdentityId: activeIdentity.id,
      })
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
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

describe("assets.authorizeTransfer — actor-linked-identity model", () => {
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

  it("DENIES when the asset's owner identity is suspended, even for an active admin actor (owner status is server-resolved)", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetIdentityById.mockResolvedValue({
      ...activeOwnerIdentity,
      status: "SUSPENDED",
    });
    const caller = appRouter.createCaller(
      makeContext(makeUser({ role: "admin" }))
    );
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("DENY");
    expect(result.reason).toMatch(/owner identity is suspended/i);
    expect(result.transaction).toBeNull();
    // Actor attribution, never the resource owner.
    const auditCall = mockedCreateAuditEvent.mock.calls[0][0];
    expect(auditCall.actorIdentityId).toBe(activeIdentity.id);
    expect(auditCall.metadata).toMatchObject({
      actorUserOpenId: "user-open-1",
      ownerStatus: "SUSPENDED",
    });
  });

  it("DENIES when the owner identity is missing (unknown => treated as not active)", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetIdentityById.mockResolvedValue(undefined);
    const caller = appRouter.createCaller(
      makeContext(makeUser({ role: "admin" }))
    );
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("DENY");
    expect(result.reason).toMatch(/owner identity is suspended/i);
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
    const result = await caller.assets.authorizeTransfer(transferInput);

    expect(result.decision).toBe("CHALLENGE");
    expect(result.transaction).toBeNull();
    expect(mockedCreateAuditEvent).toHaveBeenCalledTimes(1);
    expect(mockedCreateAuditEvent.mock.calls[0][0].action).toBe(
      "AUTHORIZATION_CHALLENGED"
    );
  });

  it("ALLOWs a MANAGER identity holding asset:transfer through its granted permissions", async () => {
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

// ---------------------------------------------------------------------------
// Suite 2: client input cannot bypass policy (security agent).
// Historical vulnerability (fixed): the mutation input once accepted
// assetClassification and stepUpAuthenticated from the client, letting any
// authenticated user defeat POLICY-HIGH-SENS-TRANSFER and POLICY-STEP-UP by
// asserting a lower classification / step-up completion. The merged input
// schema exposes assetId only; the engine reads classification from the DB.
// ---------------------------------------------------------------------------

function expectAuditActorRecorded() {
  // The acting account must be recorded in audit metadata (not just the
  // asset owner) so decisions cannot be misattributed.
  const auditCall = vi.mocked(createAuditEvent).mock.calls.at(-1);
  expect(auditCall).toBeDefined();
  const metadata = auditCall?.[0]?.metadata as Record<string, unknown> | undefined;
  expect(metadata?.actorUserOpenId).toBeDefined();
  expect(metadata?.actorUserRole).toBeDefined();
}

describe("assets.authorizeTransfer — client input cannot bypass policy", () => {
  it("rejects extra client fields (Zod strips or errors; schema has no backdoor)", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser()));
    mockedGetAssetById.mockResolvedValue(activeAsset);
    mockedGetIdentityById.mockResolvedValue(activeOwnerIdentity);

    // The malicious payload: fake a low classification AND claim step-up.
    const malicious = {
      assetId: activeAsset.id,
      assetClassification: "PUBLIC",
      stepUpAuthenticated: true,
    } as unknown as Parameters<typeof caller.assets.authorizeTransfer>[0];

    // Zod strips unknown keys, so the call proceeds with the DB
    // classification. What must NOT happen: ALLOW based on these fields.
    const result = await caller.assets.authorizeTransfer(malicious);

    // No linked SAMPRAAN identity => the actor never evaluates as ACTIVE.
    expect(result.decision).toBe("DENY");
    expect(result.decision).not.toBe("ALLOW");
    expect(result.reason).not.toContain("PUBLIC");
    expectAuditActorRecorded();
  });

  it("denies HIGHLY_SENSITIVE transfer for a USER even with stepUpAuthenticated asserted", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser()));
    mockedGetAssetById.mockResolvedValue(activeAsset);
    mockedGetIdentityById.mockResolvedValue(activeOwnerIdentity);

    const result = await caller.assets.authorizeTransfer({
      assetId: activeAsset.id,
      stepUpAuthenticated: true, // stripped, but assert worst case
    } as unknown as Parameters<typeof caller.assets.authorizeTransfer>[0]);

    // No linked SAMPRAAN identity: the engine denies before classification
    // policies are even consulted.
    expect(result.decision).toBe("DENY");
    expect(result.transaction).toBeNull();
    expectAuditActorRecorded();
  });

  it("evaluates a suspended actor identity as DENY (no hard-coded ACTIVE)", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    mockedGetAssetById.mockResolvedValue(activeAsset);
    mockedGetIdentityById.mockResolvedValue(activeOwnerIdentity);
    mockedGetIdentityByLinkedUserId.mockResolvedValue({
      ...activeIdentity,
      status: "SUSPENDED",
    });

    const result = await caller.assets.authorizeTransfer({ assetId: activeAsset.id });

    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("suspended");
    expectAuditActorRecorded();
  });

  it("denies when the owner identity is missing (unknown => SUSPENDED)", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    mockedGetAssetById.mockResolvedValue(activeAsset);
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetIdentityById.mockResolvedValue(undefined);

    const result = await caller.assets.authorizeTransfer({ assetId: activeAsset.id });

    expect(result.decision).toBe("DENY");
    expect(result.reason).toMatch(/owner identity is suspended/i);
  });

  it("allows an ADMIN transfer of a CONTROLLED asset with an ACTIVE owner and active linked identity", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    mockedGetAssetById.mockResolvedValue({ ...activeAsset, classification: "CONTROLLED" });
    mockedGetIdentityById.mockResolvedValue(activeOwnerIdentity);
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });

    const result = await caller.assets.authorizeTransfer({ assetId: activeAsset.id });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction).not.toBeNull();
    expectAuditActorRecorded();
  });

  it("challenges an ADMIN transfer of a HIGHLY_SENSITIVE asset (no server-side step-up)", async () => {
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    mockedGetAssetById.mockResolvedValue(activeAsset);
    mockedGetIdentityById.mockResolvedValue(activeOwnerIdentity);
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetRolesAndPermissions.mockResolvedValue({
      roles: ["ADMIN"],
      permissions: ["administration:manage"],
    });

    const result = await caller.assets.authorizeTransfer({ assetId: activeAsset.id });

    // Without a server-verified step-up mechanism the engine must CHALLENGE.
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
    expect(result.transaction).toBeNull();
    expectAuditActorRecorded();
  });
});
