import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";

/**
 * SECURITY REGRESSION TESTS: authorization bypass in assets.authorizeTransfer.
 *
 * Historical vulnerability (fixed): the mutation input accepted
 * `assetClassification` and `stepUpAuthenticated` from the client, letting
 * any authenticated user defeat POLICY-HIGH-SENS-TRANSFER and
 * POLICY-STEP-UP by asserting a lower classification / step-up completion.
 *
 * These tests pin the fixed behavior: server-side data only, with the
 * deterministic AuthorizationService remaining the sole decision authority.
 */

// ---- test fixtures ----------------------------------------------------------

const ASSET_ID = "123e4567-e89b-42d3-a456-426614174000";
const OWNER_ID = "123e4567-e89b-42d3-a456-426614174111";

type AssetRow = typeof import("../drizzle/schema").Asset;
type IdentityRow = typeof import("../drizzle/schema").Identity;

function makeIdentity(status: IdentityRow["status"]): IdentityRow {
  return {
    id: OWNER_ID,
    linkedUserId: null,
    displayName: "Test Owner",
    organization: "Test Org",
    status,
    did: "did:test:owner",
    createdAt: new Date(),
    updatedAt: new Date(),
    revokedAt: null,
  };
}

function makeAsset(classification: string): AssetRow {
  return {
    id: ASSET_ID,
    assetId: "ASSET-TEST-001",
    name: "Test Asset",
    type: "DOCUMENT",
    classification,
    description: null,
    ownerIdentityId: OWNER_ID,
    custodianIdentityId: OWNER_ID,
    integrityHash: null,
    tokenId: null,
    status: "ACTIVE",
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function makeCtx(role: "user" | "admin"): TrpcContext {
  return {
    user: {
      id: 1,
      openId: "attacker-openid",
      email: "attacker@example.com",
      name: "Attacker",
      loginMethod: "manus",
      role,
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    },
    req: { protocol: "https", headers: {} } as TrpcContext["req"],
    res: {} as TrpcContext["res"],
  };
}

// The router module reads the DB through "../db"; without DATABASE_URL the
// helpers return undefined/empty. To exercise the decision logic we mock the
// module so getAssetById/getIdentityById return controlled fixtures.
vi.mock("./db", async importOriginal => {
  const actual = await importOriginal<typeof import("./db")>();
  return {
    ...actual,
    getAssetById: vi.fn(),
    getIdentityById: vi.fn(),
    createAuthorizationDecision: vi.fn().mockResolvedValue(undefined),
    createAuditEvent: vi.fn().mockResolvedValue(undefined),
  };
});

import * as db from "./db";

const mockedGetAssetById = vi.mocked(db.getAssetById);
const mockedGetIdentityById = vi.mocked(db.getIdentityById);

function expectAuditActorRecorded() {
  // The acting account must be recorded in audit metadata (not just the
  // asset owner) so decisions cannot be misattributed.
  const auditCall = vi.mocked(db.createAuditEvent).mock.calls.at(-1);
  expect(auditCall).toBeDefined();
  const metadata = auditCall?.[0]?.metadata as Record<string, unknown> | undefined;
  expect(metadata?.actorUserOpenId).toBe("attacker-openid");
  expect(metadata?.actorUserRole).toBeDefined();
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("assets.authorizeTransfer — client input cannot bypass policy", () => {
  it("rejects extra client fields (Zod strips or errors; schema has no backdoor)", async () => {
    const caller = appRouter.createCaller(makeCtx("user"));
    mockedGetAssetById.mockResolvedValue(makeAsset("HIGHLY_SENSITIVE"));
    mockedGetIdentityById.mockResolvedValue(makeIdentity("ACTIVE"));

    // The malicious payload: fake a low classification AND claim step-up.
    const malicious = {
      assetId: ASSET_ID,
      assetClassification: "PUBLIC",
      stepUpAuthenticated: true,
    } as unknown as Parameters<typeof caller.assets.authorizeTransfer>[0];

    // Zod strips unknown keys, so the call proceeds with the DB
    // classification. What must NOT happen: ALLOW based on these fields.
    const result = await caller.assets.authorizeTransfer(malicious);

    // USER + HIGHLY_SENSITIVE (true classification from DB) => DENY or
    // CHALLENGE, never ALLOW.
    expect(["DENY", "CHALLENGE"]).toContain(result.decision);
    expect(result.decision).not.toBe("ALLOW");
    // And the evaluation used the stored classification, not "PUBLIC".
    expect(result.reason).not.toContain("PUBLIC");
    expectAuditActorRecorded();
  });

  it("denies HIGHLY_SENSITIVE transfer for USER even with stepUpAuthenticated asserted", async () => {
    const caller = appRouter.createCaller(makeCtx("user"));
    mockedGetAssetById.mockResolvedValue(makeAsset("HIGHLY_SENSITIVE"));
    mockedGetIdentityById.mockResolvedValue(makeIdentity("ACTIVE"));

    const result = await caller.assets.authorizeTransfer({
      assetId: ASSET_ID,
      stepUpAuthenticated: true, // stripped, but assert worst case
    } as unknown as Parameters<typeof caller.assets.authorizeTransfer>[0]);

    // USER holds no asset:transfer permission, so the deterministic engine
    // denies before classification policies are even consulted.
    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("Role USER");
    expect(result.transaction).toBeNull();
    expectAuditActorRecorded();
  });

  it("evaluates a suspended owner identity as DENY (no hard-coded ACTIVE)", async () => {
    const caller = appRouter.createCaller(makeCtx("admin"));
    mockedGetAssetById.mockResolvedValue(makeAsset("CONTROLLED"));
    mockedGetIdentityById.mockResolvedValue(makeIdentity("SUSPENDED"));

    const result = await caller.assets.authorizeTransfer({ assetId: ASSET_ID });

    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("suspended");
    expectAuditActorRecorded();
  });

  it("denies when the owner identity is missing (unknown => SUSPENDED)", async () => {
    const caller = appRouter.createCaller(makeCtx("admin"));
    mockedGetAssetById.mockResolvedValue(makeAsset("CONTROLLED"));
    mockedGetIdentityById.mockResolvedValue(undefined);

    const result = await caller.assets.authorizeTransfer({ assetId: ASSET_ID });

    expect(result.decision).toBe("DENY");
    expect(result.reason).toContain("suspended");
  });

  it("allows an ADMIN transfer of a CONTROLLED asset with an ACTIVE owner", async () => {
    const caller = appRouter.createCaller(makeCtx("admin"));
    mockedGetAssetById.mockResolvedValue(makeAsset("CONTROLLED"));
    mockedGetIdentityById.mockResolvedValue(makeIdentity("ACTIVE"));

    const result = await caller.assets.authorizeTransfer({ assetId: ASSET_ID });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction).not.toBeNull();
    expectAuditActorRecorded();
  });

  it("challenges an ADMIN transfer of a HIGHLY_SENSITIVE asset (no server-side step-up)", async () => {
    const caller = appRouter.createCaller(makeCtx("admin"));
    mockedGetAssetById.mockResolvedValue(makeAsset("HIGHLY_SENSITIVE"));
    mockedGetIdentityById.mockResolvedValue(makeIdentity("ACTIVE"));

    const result = await caller.assets.authorizeTransfer({ assetId: ASSET_ID });

    // Without a server-verified step-up mechanism the engine must CHALLENGE.
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
    expect(result.transaction).toBeNull();
    expectAuditActorRecorded();
  });
});
