import { beforeEach, describe, expect, it, vi } from "vitest";
import { TRPCError } from "@trpc/server";
import { governanceRouter } from "./modules/governance/governance.router";
import type { TrpcContext } from "./_core/context";
import type { Identity, User } from "../drizzle/schema";

/**
 * GOVERNANCE & LIFECYCLE — router-level security tests.
 *
 * Proves the tRPC boundary enforces the document's authorization rules
 * SERVER-SIDE: scope containment, role exclusivity, last-admin protection,
 * maker-checker self-approval blocks, lifecycle gates, and DID format
 * validation. The DB/chain layers are mocked per the established
 * router-test pattern (did.router.security.test.ts); each rule exercised
 * here is a regression test for its document section.
 */

const chainMocks = vi.hoisted(() => ({
  besuConfigPrivateKey: "0x" + "aa".repeat(64) as string | null,
  proposeGovernanceAction: vi.fn(),
  approveGovernanceAction: vi.fn(),
  cancelGovernanceProposal: vi.fn(),
  executeGovernanceProposal: vi.fn(),
  getGovernanceProposal: vi.fn(),
  listGovernanceProposals: vi.fn(),
  getGovernanceStatus: vi.fn(),
  proposeDeactivateIdentity: vi.fn(),
  registerAsset: vi.fn(),
  transferAsset: vi.fn(),
  getAsset: vi.fn(),
  setIdentityStatus: vi.fn(),
  auditorFlagAnomaly: vi.fn(),
  auditorRaiseDispute: vi.fn(),
  auditorStoreAuditReportHash: vi.fn(),
  resolveDispute: vi.fn(),
  updateDidDocument: vi.fn(),
}));

vi.mock("./modules/blockchain/blockchain.service", () => ({
  besuBlockchainService: {
    get config() { return { privateKey: chainMocks.besuConfigPrivateKey }; },
    proposeGovernanceAction: chainMocks.proposeGovernanceAction,
    approveGovernanceProposal: chainMocks.approveGovernanceAction,
    cancelGovernanceProposal: chainMocks.cancelGovernanceProposal,
    executeGovernanceProposal: chainMocks.executeGovernanceProposal,
    getGovernanceProposal: chainMocks.getGovernanceProposal,
    listGovernanceProposals: chainMocks.listGovernanceProposals,
    getGovernanceStatus: chainMocks.getGovernanceStatus,
    proposeDeactivateIdentity: chainMocks.proposeDeactivateIdentity,
    registerAsset: chainMocks.registerAsset,
    transferAsset: chainMocks.transferAsset,
    getAsset: chainMocks.getAsset,
    setIdentityStatus: chainMocks.setIdentityStatus,
    auditorFlagAnomaly: chainMocks.auditorFlagAnomaly,
    auditorRaiseDispute: chainMocks.auditorRaiseDispute,
    auditorStoreAuditReportHash: chainMocks.auditorStoreAuditReportHash,
    resolveDispute: chainMocks.resolveDispute,
    updateDidDocument: chainMocks.updateDidDocument,
  },
  blockchainService: { mode: "MOCK" },
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
  applyIdentityRoles: vi.fn(),
  countActiveAdminIdentities: vi.fn(),
  createAssetTransferRequest: vi.fn(),
  createAuditEvent: vi.fn(),
  createDidDocumentVersion: vi.fn(),
  createIdentityAnomaly: vi.fn(),
  createKeyRecoveryRequest: vi.fn(),
  createMintRequest: vi.fn(),
  createOwnershipPresentation: vi.fn(),
  createAsset: vi.fn(),
  getAssetById: vi.fn(),
  getAssetDispute: vi.fn(),
  getAssetTransferRequest: vi.fn(),
  getKeyRecoveryRequest: vi.fn(),
  getIdentityById: vi.fn(),
  getIdentityByLinkedUserId: vi.fn(),
  getIdentityRolesAndPermissions: vi.fn(),
  getMintRequest: vi.fn(),
  listAssetDisputes: vi.fn(),
  listAssetTransferRequests: vi.fn(),
  listAuditEvents: vi.fn(),
  listDidDocumentVersions: vi.fn(),
  listIdentityAuditEvents: vi.fn(),
  listKeyRecoveryRequests: vi.fn(),
  listMintRequests: vi.fn(),
  listOpenDisputesForAsset: vi.fn(),
  resolveAssetDispute: vi.fn(),
  revokeConsent: vi.fn(),
  grantConsent: vi.fn(),
  listConsents: vi.fn(),
  setIdentityScope: vi.fn(),
  updateIdentityLifecycle: vi.fn(),
  updateKeyRecoveryRequest: vi.fn(),
  decideMintRequest: vi.fn(),
  markMintRequestExecuted: vi.fn(),
  updateAssetTransferRequest: vi.fn(),
  consumeOwnershipPresentation: vi.fn(),
  /** Rows returned by the fake drizzle chain used for DID lookups. */
  didLookupRows: [] as Identity[],
}));

vi.mock("./db", () => ({
  ...dbMocks,
  getDb: vi.fn(async () => ({
    select: () => ({
      from: () => ({
        where: () => ({
          limit: async () => dbMocks.didLookupRows,
        }),
      }),
    }),
  })),
  listIdentitiesInScope: vi.fn(async () => []),
  listAssets: vi.fn(async () => []),
  createAssetDispute: vi.fn(async () => ({ id: "dispute-row" })),
  createAuditReportHash: vi.fn(async () => ({ id: "report-row" })),
  listIdentityAnomalies: vi.fn(async () => []),
  setAssetTokenId: vi.fn(async () => undefined),
  applyCustodyTransfer: vi.fn(async () => ({ id: "asset-1" })),
  listAssetAccessGrants: vi.fn(async () => []),
}));

import { getIdentityByLinkedUserId, getIdentityRolesAndPermissions, createAuditEvent } from "./db";

const mockedGetActorIdentity = vi.mocked(getIdentityByLinkedUserId);
const mockedGetRoles = vi.mocked(getIdentityRolesAndPermissions);
const mockedAudit = vi.mocked(createAuditEvent);

let identitySeq = 1;
function makeIdentity(overrides: Partial<Identity> = {}): Identity {
  identitySeq += 1;
  return {
    id: overrides.id ?? `identity-${identitySeq}`,
    linkedUserId: null,
    displayName: "Target",
    organization: "Alpha Corp",
    status: "ACTIVE",
    did: `did:sampraan:target-${identitySeq}`,
    lifecycleState: "VERIFIED",
    scope: "Alpha Corp",
    statusReason: null,
    deactivatedAt: null,
    revokedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as Identity;
}

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

function callerFor(user: User | null) {
  return governanceRouter.createCaller(makeContext(user));
}

/** Actor identity wired to a platform user with the given roles. */
function wireActor(overrides: Partial<Identity> & { roles: string[] }) {
  const actor = makeIdentity({ linkedUserId: 1, ...overrides });
  mockedGetActorIdentity.mockResolvedValue(actor);
  mockedGetRoles.mockImplementation(async (identityId: string) => ({
    roles: identityId === actor.id ? overrides.roles : [],
    permissions: [],
  }));
  return actor;
}

const REASON = "governance regression test";

beforeEach(() => {
  vi.clearAllMocks();
  identitySeq = 1;
  dbMocks.didLookupRows = [];
  mockedAudit.mockResolvedValue({ id: "audit-row" } as never);
  chainMocks.setIdentityStatus.mockResolvedValue({ transactionHash: "0xstatus", blockNumber: 2, status: "CONFIRMED" });
});

describe("governance: authentication + lifecycle gates (§19)", () => {
  it("rejects unauthenticated callers", async () => {
    await expect(callerFor(null).lifecycle.list()).rejects.toThrow(TRPCError);
  });

  it("rejects sessions without a linked SAMPRAAN identity", async () => {
    mockedGetActorIdentity.mockResolvedValue(undefined as never);
    await expect(callerFor(makeUser()).lifecycle.list()).rejects.toThrow(/No SAMPRAAN identity/);
  });

  it("blocks PENDING identities from protected operations", async () => {
    wireActor({ roles: ["USER"], lifecycleState: "PENDING" });
    await expect(callerFor(makeUser()).lifecycle.list()).rejects.toThrow(/lifecycle is PENDING/);
  });

  it("blocks SUSPENDED identities from protected operations", async () => {
    wireActor({ roles: ["USER"], lifecycleState: "SUSPENDED" });
    await expect(callerFor(makeUser()).transfer.list()).rejects.toThrow(/protected operations are blocked/);
  });
});

describe("governance: scoped manager onboarding (§7, §20)", () => {
  it("manager verifies a PENDING USER inside own scope and audits with attribution", async () => {
    const actor = wireActor({ roles: ["MANAGER"], scope: "Alpha Corp", organization: "Alpha Corp" });
    const target = makeIdentity({ did: "did:sampraan:pending-user", lifecycleState: "PENDING", scope: "Alpha Corp" });
    dbMocks.didLookupRows = [target];
    dbMocks.updateIdentityLifecycle.mockResolvedValue({ ...target, lifecycleState: "VERIFIED" });
    const result = await callerFor(makeUser()).lifecycle.verify({ did: target.did, reason: REASON });
    expect(result.identity.lifecycleState).toBe("VERIFIED");
    expect(dbMocks.updateIdentityLifecycle).toHaveBeenCalledWith(expect.objectContaining({ identityId: target.id, lifecycleState: "VERIFIED" }));
    expect(mockedAudit).toHaveBeenCalledWith(expect.objectContaining({ action: "USER_VERIFIED", actorIdentityId: actor.id }));
  });

  it("manager cannot verify identities OUTSIDE own scope (IDOR)", async () => {
    wireActor({ roles: ["MANAGER"], scope: "Alpha Corp", organization: "Alpha Corp" });
    const target = makeIdentity({ did: "did:sampraan:other-scope", lifecycleState: "PENDING", scope: "Beta Corp" });
    dbMocks.didLookupRows = [target];
    await expect(callerFor(makeUser()).lifecycle.verify({ did: target.did, reason: REASON })).rejects.toThrow(/outside your scope/);
  });

  it("manager cannot verify a non-USER (escalation attempt)", async () => {
    const actor = wireActor({ roles: ["MANAGER"], scope: "Alpha Corp" });
    const managerTarget = makeIdentity({ did: "did:sampraan:manager-target", lifecycleState: "PENDING", scope: "Alpha Corp", id: actor.id === "identity-2" ? "identity-9" : "identity-9" });
    dbMocks.didLookupRows = [managerTarget];
    mockedGetRoles.mockImplementation(async (identityId: string) => ({
      roles: identityId === actor.id ? ["MANAGER"] : ["MANAGER"],
      permissions: [],
    }));
    await expect(callerFor(makeUser()).lifecycle.verify({ did: managerTarget.did, reason: REASON })).rejects.toThrow(/managers may only manage USER identities/);
  });

  it("manager cannot act on their own identity (self-assignment)", async () => {
    const actor = wireActor({ roles: ["MANAGER"], scope: "Alpha Corp" });
    dbMocks.didLookupRows = [actor];
    await expect(callerFor(makeUser()).lifecycle.verify({ did: actor.did, reason: REASON })).rejects.toThrow(/self-assignment|managers may only manage USER identities/);
  });

  it("manager can only assign the USER role, in scope", async () => {
    const actor = wireActor({ roles: ["MANAGER"], scope: "Alpha Corp" });
    const target = makeIdentity({ did: "did:sampraan:new-user", scope: "Alpha Corp" });
    dbMocks.didLookupRows = [target];
    dbMocks.applyIdentityRoles.mockResolvedValue(["USER"]);
    const result = await callerFor(makeUser()).lifecycle.assignUserRole({ did: target.did, role: "USER", reason: REASON });
    expect(result.roles).toEqual(["USER"]);
    expect(dbMocks.setIdentityScope).toHaveBeenCalledWith(target.id, "Alpha Corp");
  });
});

describe("governance: exclusivity + last-admin (§4, §5)", () => {
  it("refuses AUDITOR combined with ADMIN or MANAGER", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.didLookupRows = [makeIdentity({ did: "did:sampraan:x" })];
    await expect(
      callerFor(makeUser({ role: "admin" })).lifecycle.assignRolesAdmin({ did: "did:sampraan:x", roles: ["AUDITOR", "ADMIN"], reason: REASON }),
    ).rejects.toThrow(/AUDITOR is exclusive/);
  });

  it("refuses privileged roles on a PENDING identity", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.didLookupRows = [makeIdentity({ did: "did:sampraan:pending", lifecycleState: "PENDING" })];
    await expect(
      callerFor(makeUser({ role: "admin" })).lifecycle.assignRolesAdmin({ did: "did:sampraan:pending", roles: ["MANAGER"], reason: REASON }),
    ).rejects.toThrow(/PENDING identity cannot receive privileged roles/);
  });

  it("enforces last-admin protection on suspension", async () => {
    wireActor({ roles: ["ADMIN"] });
    const otherAdmin = makeIdentity({ did: "did:sampraan:admin2", scope: null });
    dbMocks.didLookupRows = [otherAdmin];
    mockedGetRoles.mockImplementation(async () => ({ roles: ["ADMIN"], permissions: [] }));
    dbMocks.countActiveAdminIdentities.mockResolvedValue(1);
    await expect(
      callerFor(makeUser({ role: "admin" })).lifecycle.suspend({ did: otherAdmin.did, reason: REASON }),
    ).rejects.toThrow(/Last-admin protection/);
  });

  it("enforces last-admin protection on role removal", async () => {
    wireActor({ roles: ["ADMIN"] });
    const otherAdmin = makeIdentity({ did: "did:sampraan:admin3", scope: null });
    dbMocks.didLookupRows = [otherAdmin];
    mockedGetRoles.mockImplementation(async () => ({ roles: ["ADMIN"], permissions: [] }));
    dbMocks.countActiveAdminIdentities.mockResolvedValue(1);
    await expect(
      callerFor(makeUser({ role: "admin" })).lifecycle.assignRolesAdmin({ did: otherAdmin.did, roles: ["USER"], reason: REASON }),
    ).rejects.toThrow(/Last-admin protection/);
  });
});

describe("governance: maker-checker minting (§9)", () => {
  it("non-managers cannot request mints", async () => {
    wireActor({ roles: ["USER"] });
    await expect(
      callerFor(makeUser()).mint.request({
        assetId: "DEV-FIRMWARE-NEW", name: "FW", type: "firmware", classification: "CONTROLLED",
        ownerDid: "did:sampraan:o", custodianDid: "did:sampraan:c",
      }),
    ).rejects.toThrow(/MANAGER role/);
  });

  it("admin cannot approve their own request (self-approval)", async () => {
    const admin = wireActor({ roles: ["ADMIN"] });
    dbMocks.getMintRequest.mockResolvedValue({ id: "11111111-2222-7333-8444-555555555555", status: "PENDING", requestedByIdentityId: admin.id, assetId: "A-1" });
    await expect(
      callerFor(makeUser({ role: "admin" })).mint.decide({ requestId: "11111111-2222-7333-8444-555555555555", decision: "APPROVED", reason: REASON }),
    ).rejects.toThrow(/Self-approval is not permitted/);
  });

  it("only PENDING requests can be decided (duplicate/replayed decision)", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.getMintRequest.mockResolvedValue({ id: "11111111-2222-7333-8444-555555555555", status: "REJECTED", requestedByIdentityId: "someone-else" });
    await expect(
      callerFor(makeUser({ role: "admin" })).mint.decide({ requestId: "11111111-2222-7333-8444-555555555555", decision: "APPROVED", reason: REASON }),
    ).rejects.toThrow(/Only PENDING requests/);
  });
});

describe("governance: controlled transfer (§10)", () => {
  it("non-custodians cannot request a transfer", async () => {
    const actor = wireActor({ roles: ["USER"] });
    dbMocks.getAssetById.mockResolvedValue({ id: "asset-row-1", assetId: "A-1", status: "ACTIVE", custodianIdentityId: "not-actor", ownerIdentityId: "not-actor", tokenId: "7" });
    await expect(
      callerFor(makeUser()).transfer.request({ assetId: "22222222-3333-7444-8555-666666666666", toDid: "did:sampraan:r", reason: REASON }),
    ).rejects.toThrow(/Only the current custodian/);
  });

  it("recipient cannot approve (approver ≠ sender/recipient)", async () => {
    const actor = wireActor({ roles: ["MANAGER"], scope: "Alpha Corp" });
    dbMocks.getAssetTransferRequest.mockResolvedValue({
      id: "t-1", status: "ACCEPTED", fromIdentityId: "sender-1", toIdentityId: actor.id, assetId: "asset-row-1",
    });
    await expect(
      callerFor(makeUser()).transfer.approve({ requestId: "11111111-2222-7333-8444-555555555555", decision: "APPROVED", reason: REASON }),
    ).rejects.toThrow(/Approver cannot be the sender or the recipient/);
  });

  it("unprivileged roles cannot approve transfers", async () => {
    wireActor({ roles: ["USER"] });
    dbMocks.getAssetTransferRequest.mockResolvedValue({
      id: "t-2", status: "ACCEPTED", fromIdentityId: "sender-1", toIdentityId: "recipient-1", assetId: "asset-row-1",
    });
    await expect(
      callerFor(makeUser()).transfer.approve({ requestId: "11111111-2222-7333-8444-555555555555", decision: "APPROVED", reason: REASON }),
    ).rejects.toThrow(/Approval requires ADMIN or MANAGER/);
  });

  it("execution refuses STALE approval after custody changed (TOCTOU)", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.getAssetTransferRequest.mockResolvedValue({
      id: "t-3", status: "APPROVED", fromIdentityId: "sender-1", toIdentityId: "recipient-1", assetId: "asset-row-1",
    });
    dbMocks.getAssetById.mockResolvedValue({ id: "asset-row-1", assetId: "A-1", status: "ACTIVE", custodianIdentityId: "someone-new", tokenId: "7" });
    await expect(callerFor(makeUser({ role: "admin" })).transfer.execute({ requestId: "11111111-2222-7333-8444-555555555555" })).rejects.toThrow(/stale/);
  });

  it("execution refuses while a dispute HOLD is open", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.getAssetTransferRequest.mockResolvedValue({
      id: "t-4", status: "APPROVED", fromIdentityId: "sender-1", toIdentityId: "recipient-1", assetId: "asset-row-1",
    });
    dbMocks.getAssetById.mockResolvedValue({ id: "asset-row-1", assetId: "A-1", status: "ACTIVE", custodianIdentityId: "sender-1", tokenId: "7" });
    dbMocks.listOpenDisputesForAsset.mockResolvedValue([{ id: "dispute-1" }]);
    await expect(callerFor(makeUser({ role: "admin" })).transfer.execute({ requestId: "11111111-2222-7333-8444-555555555555" })).rejects.toThrow(/HOLD/);
  });
});

describe("governance: auditor surfaces (§11–§14)", () => {
  it("non-auditors cannot flag anomalies", async () => {
    wireActor({ roles: ["USER"] });
    await expect(
      callerFor(makeUser()).auditor.flagAnomaly({ targetDid: "did:sampraan:x", reason: REASON }),
    ).rejects.toThrow(/AUDITOR role/);
  });

  it("non-auditors cannot commit audit report hashes", async () => {
    wireActor({ roles: ["MANAGER"] });
    await expect(
      callerFor(makeUser()).auditor.storeAuditReportHash({ reportHash: `0x${"ab".repeat(32)}` }),
    ).rejects.toThrow(/AUDITOR role/);
  });
});

describe("governance: multisig proposals (§1, §2)", () => {
  it("non-admins cannot create governance proposals", async () => {
    wireActor({ roles: ["MANAGER"] });
    await expect(
      callerFor(makeUser()).proposals.propose({ kind: "PAUSE_REGISTRY", reason: REASON }),
    ).rejects.toThrow(/requires the ADMIN role/);
  });

  it("admin proposal flows through the chain service and is audited", async () => {
    const actor = wireActor({ roles: ["ADMIN"] });
    chainMocks.proposeGovernanceAction.mockResolvedValue({ proposalId: 3n, executableAt: 123n, requiredApprovals: 2n });
    const result = await callerFor(makeUser({ role: "admin" })).proposals.propose({ kind: "PAUSE_REGISTRY", reason: REASON });
    expect(result.proposalId).toBe("3");
    expect(chainMocks.proposeGovernanceAction).toHaveBeenCalledWith(expect.objectContaining({ kind: "PAUSE_REGISTRY", reason: REASON }));
    expect(mockedAudit).toHaveBeenCalledWith(expect.objectContaining({ action: "GOVERNANCE_PROPOSAL_CREATED", actorIdentityId: actor.id }));
  });

  it("execution below quorum is refused server-side", async () => {
    wireActor({ roles: ["ADMIN"] });
    chainMocks.getGovernanceProposal.mockResolvedValue({ proposalId: 5, kind: 5, approvals: 1, requiredApprovals: 2, executableAt: 1, executed: false, cancelled: false, target: "0xt" });
    await expect(
      callerFor(makeUser({ role: "admin" })).proposals.execute({ proposalId: "5" }),
    ).rejects.toThrow(/Quorum not reached/);
  });

  it("execution before the timelock elapses is refused server-side", async () => {
    wireActor({ roles: ["ADMIN"] });
    chainMocks.getGovernanceProposal.mockResolvedValue({
      proposalId: 6, kind: 5, approvals: 2, requiredApprovals: 2,
      executableAt: Math.floor(Date.now() / 1000) + 3600, executed: false, cancelled: false, target: "0xt",
    });
    await expect(
      callerFor(makeUser({ role: "admin" })).proposals.execute({ proposalId: "6" }),
    ).rejects.toThrow(/Timelock has not elapsed/);
  });

  it("double execution is refused (replay)", async () => {
    wireActor({ roles: ["ADMIN"] });
    chainMocks.getGovernanceProposal.mockResolvedValue({ proposalId: 7, kind: 5, approvals: 2, requiredApprovals: 2, executableAt: 1, executed: true, cancelled: false, target: "0xt" });
    await expect(
      callerFor(makeUser({ role: "admin" })).proposals.execute({ proposalId: "7" }),
    ).rejects.toThrow(/already executed/);
  });
});

describe("governance: consent + recovery (§16, §17)", () => {
  it("self-consent is rejected", async () => {
    const actor = wireActor({ roles: ["USER"] });
    await expect(
      callerFor(makeUser()).self.grantConsent({ verifierDid: actor.did, scope: "profile", expiresInDays: 7 }),
    ).rejects.toThrow(/Self-consent/);
  });

  it("recovery decision refuses self-approval and non-PENDING rows", async () => {
    const admin = wireActor({ roles: ["ADMIN"] });
    dbMocks.getKeyRecoveryRequest.mockResolvedValue({ id: "11111111-2222-7333-8444-555555555555", status: "PENDING", requestedByIdentityId: admin.id, subjectIdentityId: "subj-1" });
    await expect(
      callerFor(makeUser({ role: "admin" })).self.decideKeyRecovery({ requestId: "11111111-2222-7333-8444-555555555555", decision: "APPROVED", reason: REASON }),
    ).rejects.toThrow(/Self-approval is not permitted/);
  });

  it("recovery execution only runs for APPROVED requests (replay-proof)", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.getKeyRecoveryRequest.mockResolvedValue({ id: "11111111-2222-7333-8444-555555555555", status: "PENDING", requestedByIdentityId: "mgr-1", subjectIdentityId: "subj-1" });
    await expect(
      callerFor(makeUser({ role: "admin" })).self.executeKeyRecovery({ requestId: "11111111-2222-7333-8444-555555555555", newPublicKey: `0x${"ab".repeat(33)}` }),
    ).rejects.toThrow(/Only APPROVED recovery requests/);
  });
});

describe("governance: input validation", () => {
  it("rejects malformed DIDs", async () => {
    wireActor({ roles: ["ADMIN"] });
    dbMocks.didLookupRows = [makeIdentity({ did: "not-a-did" })];
    await expect(
      callerFor(makeUser({ role: "admin" })).lifecycle.requestDeactivation({ did: "not-a-did", reason: REASON }),
    ).rejects.toThrow();
  });

  it("rejects missing/short reasons on privileged mutations", async () => {
    wireActor({ roles: ["MANAGER"], scope: "Alpha Corp" });
    const target = makeIdentity({ did: "did:sampraan:pending-user-2", lifecycleState: "PENDING", scope: "Alpha Corp" });
    dbMocks.didLookupRows = [target];
    await expect(
      callerFor(makeUser()).lifecycle.verify({ did: target.did, reason: "no" }),
    ).rejects.toThrow();
  });
});
