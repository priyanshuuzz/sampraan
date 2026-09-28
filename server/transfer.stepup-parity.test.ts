/**
 * TRANSFER STEP-UP PURPOSE PARITY — regression tests (final audit, F1).
 *
 * BUG THIS PINS: assets.authorizeTransfer probed hasValidStepUp with a
 * hand-composed `transfer:<asset BUSINESS key>`, while the step-up challenge
 * for transfers was issued — and signed — for the SINGLE-COMPOSER token
 * `content-transfer:<asset ROW id>` (stepUpPurposeFor("TRANSFER", asset.id)).
 * Every correctly-verified transfer step-up was therefore invisible to the
 * policy gate: the operator completed step-up perfectly and the engine still
 * returned CHALLENGE (POLICY-STEP-UP) forever. A dead-end for the honest
 * operator, and proof that the challenge/gate contract had drifted apart.
 *
 * The tests prove, at the router boundary, that a verified TRANSFER step-up
 * satisfies the transfer gate (and nothing else).
 * Single source of truth: server/modules/asset-content/asset-content.router.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import type { Asset, Identity, User } from "../drizzle/schema";

const chainMocks = vi.hoisted(() => ({
  besuConfigPrivateKey: "0xtest-operator-key" as string | null,
}));

vi.mock("./modules/blockchain/blockchain.service", () => ({
  blockchainService: {
    get mode() { return "MOCK"; },
    get operatorAddress() { return "0xoperator"; },
    getNetworkStatus: vi.fn(async () => ({ connected: true, mode: "MOCK", network: "test", latestBlock: 10 })),
  },
  besuBlockchainService: {
    get config() { return { privateKey: chainMocks.besuConfigPrivateKey }; },
    getAsset: vi.fn(async () => null),
    getIdentity: vi.fn(async () => null),
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
  probedPurposes: [] as string[],
  challengePurposes: [] as string[],
  storedChallenges: [] as { identityId: string; purpose: string; nonce: string; verified: boolean }[],
  assetFixture: null as Asset | null,
}));

vi.mock("./db", () => ({
  getAssetById: vi.fn(async () => dbMocks.assetFixture),
  getIdentityById: vi.fn(async (id: string) =>
    id === actorIdentity.id ? actorIdentity : { ...actorIdentity, id, status: "ACTIVE" as const }),
  getIdentityByLinkedUserId: vi.fn(async () => actorIdentity),
  getIdentityRolesAndPermissions: vi.fn(async () => ({ roles: ["MANAGER"], permissions: ["asset:read", "asset:edit", "asset:transfer"] })),
  createAuditEvent: vi.fn(async () => undefined),
  createAuthorizationDecision: vi.fn(async () => undefined),
  getActiveAssetApproval: vi.fn(async () => undefined),
  listIdentities: vi.fn(async () => []),
  listAuditEvents: vi.fn(async () => []),
  listSecurityAlerts: vi.fn(async () => []),
  listAssets: vi.fn(async () => []),
  listPolicies: vi.fn(async () => []),
  getDb: vi.fn(async () => null),
}));

vi.mock("./modules/did/did-auth.service", async importOriginal => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    createStepUpChallenge: vi.fn(async (_identityId: string, purpose: string) => {
      dbMocks.challengePurposes.push(purpose);
      const nonce = `nonce-${dbMocks.challengePurposes.length}`.padEnd(48, "0");
      dbMocks.storedChallenges.push({ identityId: _identityId, purpose, nonce, verified: false });
      return { nonce, message: `challenge for ${purpose}`, keyIdentifier: "key-1", expiresAt: new Date(Date.now() + 300_000).toISOString() };
    }),
    verifyStepUpChallenge: vi.fn(async (input: { identityId: string; purpose: string; nonce: string }) => {
      const row = dbMocks.storedChallenges.find(c => c.nonce === input.nonce && c.identityId === input.identityId && c.purpose === input.purpose);
      if (!row) return { ok: false as const, reason: "invalid", code: "STEP_UP_INVALID" };
      row.verified = true; // consume — like the real service stamps consumedAt
      return { ok: true as const };
    }),
    hasValidStepUp: vi.fn(async (_identityId: string, purpose: string) => {
      dbMocks.probedPurposes.push(purpose);
      // Only VERIFIED (consumed) challenges count — mirrors the real probe,
      // which looks for a row consumed within the validity window.
      return dbMocks.storedChallenges.some(c => c.purpose === purpose && c.verified);
    }),
    fingerprintNonce: actual.fingerprintNonce ?? vi.fn((n: string) => n.slice(0, 8)),
  };
});

vi.mock("./modules/security-intelligence/intelligence.service", () => ({
  securityIntelligenceService: {
    scan: vi.fn(async () => ({ scanned: 0, created: 0, suppressed: 0 })),
    assessRisk: vi.fn(async () => "LOW" as const),
  },
  scheduleIntelligenceScan: vi.fn(),
  recordIntelligenceScanEvidence: vi.fn(),
}));

import { getAssetById } from "./db";

const mockedGetAssetById = vi.mocked(getAssetById);

function makeUser(role: "admin" | "user" = "user"): User {
  return {
    id: 2,
    openId: "transfer-parity-open-1",
    name: "Transfer Parity Operator",
    email: "transfer-parity@sampraan.dev",
    loginMethod: "password",
    role,
    createdAt: new Date(),
    updatedAt: new Date(),
    lastSignedIn: new Date(),
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
  id: "0e0d3b1a-aaaa-4bbb-8ccc-444455559998",
  linkedUserId: 2,
  displayName: "Transfer Parity Operator",
  organization: "SAMPRAAN DEMO",
  status: "ACTIVE",
  did: "did:sampraan:transfer-parity-actor",
  createdAt: new Date(),
  updatedAt: new Date(),
  revokedAt: null,
};

// ROW id (uuid) and BUSINESS key are deliberately different strings — the
// exact pair that exposed the original mismatch (business key vs row id).
const rowId = "1ec845d0-1187-41ba-8329-ccb580bbc51c";
const BUSINESS_KEY = "DEV-FIRMWARE-001";

const HIGHLY_SENSITIVE: Asset = {
  id: rowId,
  assetId: BUSINESS_KEY,
  name: "Transfer Parity Fixture",
  type: "DOCUMENT",
  classification: "HIGHLY_SENSITIVE",
  description: null,
  ownerIdentityId: actorIdentity.id,
  custodianIdentityId: actorIdentity.id, // acting identity IS the custodian → custody check passes
  integrityHash: null,
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date(),
  updatedAt: new Date(),
};

const caller = appRouter.createCaller(makeContext(makeUser()));

beforeEach(() => {
  vi.clearAllMocks();
  dbMocks.probedPurposes.length = 0;
  dbMocks.challengePurposes.length = 0;
  dbMocks.storedChallenges.length = 0;
  dbMocks.assetFixture = HIGHLY_SENSITIVE;
  mockedGetAssetById.mockResolvedValue(HIGHLY_SENSITIVE);
});

/** Sign the challenge the way the operator console would (shape only). */
const goodSignature = "0x" + "22".repeat(65);

describe("transfer step-up purpose parity (challenge composer == transfer gate probe)", () => {
  it("a verified TRANSFER step-up satisfies POLICY-STEP-UP on authorizeTransfer", async () => {
    const challenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "transfer" });
    expect(dbMocks.challengePurposes[0]).toBe(`content-transfer:${rowId}`);
    await caller.stepup.verify({ assetId: rowId, operation: "transfer", nonce: challenge.nonce, signature: goodSignature });

    // The gate previously re-asked for step-up forever (dead-end). After the
    // fix the POLICY-STEP-UP check must PASS; the decision may still be
    // CHALLENGE for an independent reason (approval), but never for step-up.
    const result = await caller.assets.authorizeTransfer({ assetId: rowId, recipientIdentityId: actorIdentity.id });
    expect(result.decision).not.toBe("DENY");
    if (result.decision === "CHALLENGE") {
      expect(result.policyId).not.toBe("POLICY-STEP-UP");
    }
    // The probe used the composer's token — never the business-key variant.
    expect(dbMocks.probedPurposes).toContain(`content-transfer:${rowId}`);
    expect(dbMocks.probedPurposes).not.toContain(`transfer:${rowId}`);
    expect(dbMocks.probedPurposes).not.toContain(`transfer:${BUSINESS_KEY}`);
  });

  it("an UNVERIFIED transfer step-up still challenges (the gate is not opened by the fix)", async () => {
    const challenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "transfer" });
    // Deliberately DO NOT verify — the challenge exists but was never consumed.
    const result = await caller.assets.authorizeTransfer({ assetId: rowId });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
    expect(challenge.nonce).toBeTruthy();
  });

  it("a content-edit step-up does NOT satisfy the transfer gate (cross-purpose stays bound)", async () => {
    const challenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "content-edit" });
    await caller.stepup.verify({ assetId: rowId, operation: "content-edit", nonce: challenge.nonce, signature: goodSignature });
    const result = await caller.assets.authorizeTransfer({ assetId: rowId });
    expect(result.decision).toBe("CHALLENGE");
    expect(result.policyId).toBe("POLICY-STEP-UP");
  });

  it("challenge and probe compose from the SAME source of truth (stepUpPurposeFor)", async () => {
    await caller.stepup.requestChallenge({ assetId: rowId, operation: "transfer" });
    await caller.assets.authorizeTransfer({ assetId: rowId });
    // Exactly one challenge composition and at least one probe, both using
    // the single-composer token.
    expect(dbMocks.challengePurposes).toEqual([`content-transfer:${rowId}`]);
    expect(dbMocks.probedPurposes.every(p => p === `content-transfer:${rowId}`)).toBe(true);
  });
});
