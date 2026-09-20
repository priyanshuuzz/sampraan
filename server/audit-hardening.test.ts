import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuditEvent, Asset, Identity, User } from "../drizzle/schema";

/**
 * Consolidated regression suite for the 2026-09 security/reliability audit.
 *
 * Each block pins ONE audit fix so a future refactor cannot silently
 * reintroduce the defect:
 *
 *  1. parseListenPort            — invalid PORT values must never bind an
 *                                  ephemeral/random port in production.
 *  2. login throttle             — local password login is brute-force
 *                                  throttled per account.
 *  3. zero-key refusal           — an all-zero operator key degrades to MOCK
 *                                  instead of pretending the chain is ready.
 *  4. scrypt memory guard        — a hostile stored hash cannot make the login
 *                                  path allocate gigabytes.
 *  5. MOCK-mode fail-closed      — transfers NEVER produce fabricated
 *                                  "CONFIRMED" evidence without a real chain.
 *  6. approval→target binding    — an approval authorizes only the request it
 *                                  was granted FOR.
 *  7. DID key IDOR               — key status/rotation is scoped to the DID's
 *                                  own identity (or an admin).
 *  8. indexer checkpoint         — scans resume from the max indexed block, not
 *                                  a fixed lookback window.
 *  9. R7 login-failure rule      — repeated LOGIN_FAILED events raise an
 *                                  advisory security alert.
 */

// ---------------------------------------------------------------------------
// Hoisted mock state + module mocks (applied before importing ./routers)
// ---------------------------------------------------------------------------

const chainMocks = vi.hoisted(() => ({
  mode: "BESU" as "BESU" | "MOCK",
  operatorAddress: "0xoperatorwallet" as string | null,
}));

const besuState = vi.hoisted(() => ({
  // null = "unconfigured Besu adapter" (the routers default); indexer tests
  // install a fake adapter here because ChainEventIndexer requires one.
  service: null as {
    config: { privateKey: string; address: string };
    getNetworkStatus: (input?: unknown) => Promise<{ connected: boolean; latestBlock: number; mode: string; network: string }>;
    getEvents: (input: { fromBlock: number; toBlock: number }) => Promise<unknown[]>;
  } | null,
}));

vi.mock("./modules/blockchain/blockchain.service", () => ({
  blockchainService: {
    get mode() {
      return chainMocks.mode;
    },
    get operatorAddress() {
      return chainMocks.operatorAddress;
    },
    getNetworkStatus: vi.fn(async () => ({ connected: true, mode: chainMocks.mode, network: "test", latestBlock: 10 })),
    getLatestBlock: vi.fn(async () => 10),
    submitTransaction: vi.fn(async () => ({ transactionHash: "0xregression_tx", blockNumber: 12, status: "CONFIRMED" })),
    getTransaction: vi.fn(),
    getEvents: vi.fn(async () => []),
  },
  get besuBlockchainService() {
    return besuState.service;
  },
}));

vi.mock("./modules/blockchain/anchoring.service", () => ({
  anchoringService: {
    anchorIdentity: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
    anchorAsset: vi.fn(async () => ({ outcome: "SKIPPED", reason: "mock" })),
  },
  deriveIdentityWallet: vi.fn(() => "0xderivedwallet"),
}));

vi.mock("./modules/did/did-auth.service", () => ({
  createDidChallenge: vi.fn(async () => ({ nonce: "n".repeat(32), expiresAt: new Date() })),
  verifyDidChallenge: vi.fn(async () => ({ ok: false })),
  rotateDidKey: vi.fn(async () => ({ ok: true as const, did: "did:demo:aarav-mehta", keyStatus: "ROTATED" })),
  setDidKeyStatus: vi.fn(async () => ({ ok: true as const })),
  createStepUpChallenge: vi.fn(async () => ({ nonce: "n".repeat(32), expiresAt: new Date() })),
  verifyStepUpChallenge: vi.fn(async () => ({ ok: false })),
  hasValidStepUp: vi.fn(async () => false),
  fingerprintNonce: vi.fn(() => "fp"),
}));

vi.mock("./modules/security-intelligence/intelligence.service", () => ({
  securityIntelligenceService: { assessRisk: vi.fn(async () => "LOW" as const) },
  scheduleIntelligenceScan: vi.fn(),
  recordIntelligenceScanEvidence: vi.fn(),
}));

vi.mock("./db", async (importOriginal: () => Promise<Record<string, unknown>>) => {
  const actual = await importOriginal();
  return {
    ...actual,
    // Router-facing helpers.
    getAssetById: vi.fn(),
    getIdentityById: vi.fn(),
    getIdentityByLinkedUserId: vi.fn(),
    getIdentityRolesAndPermissions: vi.fn(),
    getActiveAssetApproval: vi.fn(async () => undefined),
    createAuthorizationDecision: vi.fn(async (input: unknown) => input),
    createAuditEvent: vi.fn(async (input: unknown) => input),
    // Intelligence-scan helpers (real service under test via importActual).
    listAuditEvents: vi.fn(async () => [] as AuditEvent[]),
    listIdentities: vi.fn(async () => [] as Identity[]),
    listSecurityAlerts: vi.fn(async () => []),
    createSecurityAlert: vi.fn(async (input: unknown) => input),
    // Indexer helpers.
    getMaxIndexedChainBlock: vi.fn(async () => null),
    listIndexedChainEventKeys: vi.fn(async () => new Set<string>()),
    listIndexedChainTxHashes: vi.fn(async () => new Set<string>()),
    // keyStatus reaches the DB only AFTER the ownership gate; keep it null so
    // a passed gate surfaces as a controlled "Database unavailable" error.
    getDb: vi.fn(async () => null),
  };
});

import { appRouter } from "./routers";
import type { TrpcContext } from "./_core/context";
import {
  createAuditEvent,
  createAuthorizationDecision,
  getActiveAssetApproval,
  getAssetById,
  getIdentityByLinkedUserId,
  getIdentityById,
  getIdentityRolesAndPermissions,
  getMaxIndexedChainBlock,
  listAuditEvents,
  listIdentities,
  listIndexedChainEventKeys,
  listIndexedChainTxHashes,
  createSecurityAlert,
  listSecurityAlerts,
} from "./db";
import { rotateDidKey, hasValidStepUp } from "./modules/did/did-auth.service";
import { ChainEventIndexer } from "./modules/blockchain/chain-event-indexer";
import { blockchainService } from "./modules/blockchain/blockchain.service";
import { anchoringService } from "./modules/blockchain/anchoring.service";
import { resolveBlockchainConfig } from "./modules/blockchain/blockchain.config";
import { verifyPassword } from "./auth/password";
import { clearLoginFailures, isLoginThrottled, recordLoginFailure, resetLoginThrottle } from "./common/login-throttle";
import { parseListenPort } from "./common/port";

const mockedGetAssetById = vi.mocked(getAssetById);
const mockedGetIdentityByLinkedUserId = vi.mocked(getIdentityByLinkedUserId);
const mockedGetIdentityById = vi.mocked(getIdentityById);
const mockedGetRolesAndPermissions = vi.mocked(getIdentityRolesAndPermissions);
const mockedGetActiveApproval = vi.mocked(getActiveAssetApproval);
const mockedCreateAuditEvent = vi.mocked(createAuditEvent);
const mockedCreateDecision = vi.mocked(createAuthorizationDecision);
const mockedRotateDidKey = vi.mocked(rotateDidKey);

// ---------------------------------------------------------------------------
// Fixtures (mirrors server/routers.security.test.ts)
// ---------------------------------------------------------------------------

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

const activeAsset: Asset = {
  id: "0e0d3b1a-1111-4222-8333-444455556666",
  assetId: "ASSET-REGRESSION-001",
  name: "Regression Fixture Asset",
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

const recipientIdentity: Identity = {
  ...activeIdentity,
  id: "0e0d3b1a-aaaa-4bbb-8ccc-44445555b1b1",
  linkedUserId: 77,
  did: "did:demo:recipient-b",
  displayName: "Recipient B",
};

beforeEach(() => {
  vi.clearAllMocks();
  chainMocks.mode = "BESU";
  chainMocks.operatorAddress = "0xoperatorwallet";
  besuState.service = null;
  mockedGetAssetById.mockResolvedValue(activeAsset);
  mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
  mockedGetIdentityById.mockResolvedValue(activeIdentity);
  mockedGetRolesAndPermissions.mockResolvedValue({ roles: ["ADMIN"], permissions: ["administration:manage"] });
});

// ---------------------------------------------------------------------------
// 1. parseListenPort
// ---------------------------------------------------------------------------

describe("parseListenPort (PORT=0 misconfiguration guard)", () => {
  it("accepts valid ports", () => {
    expect(parseListenPort("3000")).toBe(3000);
    expect(parseListenPort("1")).toBe(1);
    expect(parseListenPort("65535")).toBe(65535);
    expect(parseListenPort(" 8080 ")).toBe(8080);
  });

  it("returns null for unset/empty so the caller applies its default", () => {
    expect(parseListenPort(undefined)).toBeNull();
    expect(parseListenPort(null)).toBeNull();
    expect(parseListenPort("")).toBeNull();
    expect(parseListenPort("   ")).toBeNull();
  });

  it("refuses present-but-invalid values instead of silently coercing them", () => {
    // The reproduced live defect: PORT=0 binds an ephemeral port while the
    // healthcheck targets the configured one.
    expect(parseListenPort("0")).toBeNull();
    expect(parseListenPort("-1")).toBeNull();
    expect(parseListenPort("70000")).toBeNull();
    expect(parseListenPort("abc")).toBeNull();
    expect(parseListenPort("3.5")).toBeNull();
    expect(parseListenPort("0x50")).toBeNull();
    expect(parseListenPort("3000;rm -rf")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. login throttle
// ---------------------------------------------------------------------------

describe("local login brute-force throttle", () => {
  beforeEach(() => resetLoginThrottle());

  it("allows up to 4 failures and throttles the 5th within the window", () => {
    const t0 = 1_000_000;
    for (let i = 0; i < 4; i++) recordLoginFailure("Admin@Sampraan.dev", t0);
    expect(isLoginThrottled("admin@sampraan.dev", t0)).toBeNull();

    recordLoginFailure("admin@sampraan.dev", t0 + 1);
    const throttled = isLoginThrottled("admin@sampraan.dev", t0 + 2);
    expect(throttled).not.toBeNull();
    expect(throttled?.failures).toBe(5);
    expect(throttled!.retryAfterMs).toBeGreaterThan(0);
  });

  it("normalizes the email (trim + lowercase) so case variants share the counter", () => {
    const t0 = 2_000_000;
    for (let i = 0; i < 5; i++) recordLoginFailure("  User@X.com ", t0);
    expect(isLoginThrottled("user@x.com", t0)).not.toBeNull();
  });

  it("clears the counter after a successful authentication", () => {
    const t0 = 3_000_000;
    for (let i = 0; i < 5; i++) recordLoginFailure("victim@s.dev", t0);
    expect(isLoginThrottled("victim@s.dev", t0)).not.toBeNull();
    clearLoginFailures("victim@s.dev");
    expect(isLoginThrottled("victim@s.dev", t0)).toBeNull();
  });

  it("unblocks after the lockout window elapses", () => {
    const t0 = 4_000_000;
    for (let i = 0; i < 5; i++) recordLoginFailure("burst@s.dev", t0);
    const WINDOW_MS = 15 * 60 * 1000;
    expect(isLoginThrottled("burst@s.dev", t0 + WINDOW_MS - 1)).not.toBeNull();
    expect(isLoginThrottled("burst@s.dev", t0 + WINDOW_MS + 1)).toBeNull();
  });

  it("keeps accounts isolated", () => {
    const t0 = 5_000_000;
    for (let i = 0; i < 5; i++) recordLoginFailure("a@s.dev", t0);
    expect(isLoginThrottled("b@s.dev", t0)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. zero-key refusal (blockchain config)
// ---------------------------------------------------------------------------

describe("resolveBlockchainConfig — zero-key refusal", () => {
  const ENV_KEYS = ["BLOCKCHAIN_RPC_URL", "BLOCKCHAIN_CHAIN_ID", "BLOCKCHAIN_PRIVATE_KEY", "BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS", "BLOCKCHAIN_ASSET_CONTRACT_ADDRESS", "BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS"] as const;
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map(k => [k, process.env[k]]));
    process.env.BLOCKCHAIN_RPC_URL = "http://localhost:8545";
    process.env.BLOCKCHAIN_CHAIN_ID = "4224";
    process.env.BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS = "0x" + "11".repeat(20);
    process.env.BLOCKCHAIN_ASSET_CONTRACT_ADDRESS = "0x" + "22".repeat(20);
    process.env.BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS = "0x" + "33".repeat(20);
  });

  const restoreEnv = () => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };

  it("enables BESU mode with a real operator key", () => {
    process.env.BLOCKCHAIN_PRIVATE_KEY = "0x" + "ab".repeat(32);
    try {
      expect(resolveBlockchainConfig().mode).toBe("BESU");
    } finally {
      restoreEnv();
    }
  });

  it("degrades an all-zero key to MOCK instead of reporting a healthy chain", () => {
    process.env.BLOCKCHAIN_PRIVATE_KEY = "0x" + "00".repeat(32);
    try {
      const config = resolveBlockchainConfig();
      expect(config.mode).toBe("MOCK");
      expect(config.privateKey).toBeNull();
    } finally {
      restoreEnv();
    }
  });

  it("still refuses malformed keys", () => {
    process.env.BLOCKCHAIN_PRIVATE_KEY = "not-a-key";
    try {
      expect(resolveBlockchainConfig().mode).toBe("MOCK");
    } finally {
      restoreEnv();
    }
  });
});

// ---------------------------------------------------------------------------
// 4. scrypt memory guard
// ---------------------------------------------------------------------------

describe("verifyPassword — scrypt memory guard", () => {
  it("rejects a hostile stored hash without allocating GB-scale memory", async () => {
    // Shape-valid but 128*n*r ≈ 8 GB: the guard must refuse BEFORE scrypt runs.
    const hostile = ["scrypt", 1_048_576, 64, 1, Buffer.alloc(16).toString("base64url"), Buffer.alloc(64).toString("base64url")].join("$");
    const started = Date.now();
    await expect(verifyPassword("anything", hostile)).resolves.toBe(false);
    // Even on a slow machine, a real 8 GB scrypt derivation could not finish this fast.
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("still verifies a legitimately upgraded hash (n=2^17, r=8)", async () => {
    const { scrypt } = await import("node:crypto");
    const { promisify } = await import("node:util");
    const scryptAsync = promisify(scrypt) as (p: string, s: Buffer, k: number, o: object) => Promise<Buffer>;
    const salt = Buffer.alloc(16, 7);
    const derived = (await scryptAsync("correct horse", salt, 64, { N: 131_072, r: 8, p: 1, maxmem: 128 * 131_072 * 8 * 2 })) as Buffer;
    const stored = ["scrypt", 131_072, 8, 1, salt.toString("base64url"), derived.toString("base64url")].join("$");
    await expect(verifyPassword("correct horse", stored)).resolves.toBe(true);
    await expect(verifyPassword("wrong horse", stored)).resolves.toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 5. MOCK-mode fail-closed transfer
// ---------------------------------------------------------------------------

describe("assets.authorizeTransfer — no fabricated evidence without a real chain", () => {
  it("fails closed with PRECONDITION_FAILED when the chain is in MOCK mode", async () => {
    chainMocks.mode = "MOCK";
    // CONTROLLED classification: the policy engine ALLOWs this transfer, so
    // the test reaches the chain-mode gate (the subject of this regression).
    mockedGetAssetById.mockResolvedValue({ ...activeAsset, classification: "CONTROLLED" });
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));

    await expect(
      caller.assets.authorizeTransfer({ assetId: activeAsset.id })
    ).rejects.toMatchObject({ code: "PRECONDITION_FAILED", message: /MOCK/i });

    // The failure is audited as a chain failure, not shown as a transfer.
    const auditActions = mockedCreateAuditEvent.mock.calls.map(call => call[0].action);
    expect(auditActions).toContain("BLOCKCHAIN_TRANSACTION_FAILED");
  });

  it("completes with REAL-adapter evidence when the chain is configured", async () => {
    mockedGetAssetById.mockResolvedValue({ ...activeAsset, classification: "CONTROLLED" });
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));
    const result = await caller.assets.authorizeTransfer({ assetId: activeAsset.id });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction?.transactionHash).toBe("0xregression_tx");
    // The ALLOW decision is persisted as evidence either way.
    expect(mockedCreateDecision).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// 6. approval → target binding
// ---------------------------------------------------------------------------

describe("assets.authorizeTransfer — approval binds to its intended recipient", () => {
  beforeEach(() => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    mockedGetIdentityById.mockImplementation(async (id: string) => {
      if (id === recipientIdentity.id) return recipientIdentity;
      return activeIdentity; // owner/custodian lookup
    });
  });

  it("CHALLENGES a transfer naming a DIFFERENT recipient than the approval target", async () => {
    // Step-up is satisfied so the challenge provably comes from the APPROVAL
    // gate (POLICY-APPROVAL), not the step-up gate.
    vi.mocked(hasValidStepUp).mockResolvedValue(true);
    mockedGetActiveApproval.mockResolvedValue({ status: "APPROVED", targetIdentityId: recipientIdentity.id } as never);
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));

    const result = await caller.assets.authorizeTransfer({
      assetId: activeAsset.id,
      recipientIdentityId: activeIdentity.id, // NOT the approved target
    });

    // A stale/mismatched approval must not authorize a changed request: the
    // engine falls through the approval gate to CHALLENGE.
    expect(result.decision).toBe("CHALLENGE");
    expect(result.transaction).toBeNull();
    expect(result.policyId).toBe("POLICY-APPROVAL");
  });

  it("ALLOWS the transfer when the named recipient matches the approval target", async () => {
    vi.mocked(hasValidStepUp).mockResolvedValue(true);
    mockedGetActiveApproval.mockResolvedValue({ status: "APPROVED", targetIdentityId: recipientIdentity.id } as never);
    // Install a configured Besu adapter so the recipient-anchoring step runs
    // exactly as it would against the real chain.
    besuState.service = {
      config: { privateKey: "0x" + "ab".repeat(32), address: "0xoperator" },
      getNetworkStatus: async () => ({ connected: true, latestBlock: 10, mode: "BESU", network: "test" }),
      getEvents: vi.fn(async () => []),
      getAsset: vi.fn(async () => null),
    } as never;
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));

    const result = await caller.assets.authorizeTransfer({
      assetId: activeAsset.id,
      recipientIdentityId: recipientIdentity.id, // the approved target
    });

    expect(result.decision).toBe("ALLOW");
    expect(result.transaction?.transactionHash).toBe("0xregression_tx");
    // The recipient's identity reference was anchored before submission.
    expect(anchoringService.anchorIdentity).toHaveBeenCalled();
  });

  it("keeps legacy target-less approvals working (no recipient named)", async () => {
    vi.mocked(hasValidStepUp).mockResolvedValue(true);
    mockedGetActiveApproval.mockResolvedValue({ status: "APPROVED", targetIdentityId: null } as never);
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));

    const result = await caller.assets.authorizeTransfer({ assetId: activeAsset.id });
    expect(result.decision).toBe("ALLOW");
  });
});

// ---------------------------------------------------------------------------
// 7. DID key lifecycle IDOR
// ---------------------------------------------------------------------------

describe("did.keyStatus / did.rotateKey — ownership scoping", () => {
  const OTHER_DID = "did:demo:mallory";

  it("refuses a non-owner reading another DID's key status", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity); // did:demo:aarav-mehta
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "user" })));

    await expect(caller.did.keyStatus({ did: OTHER_DID })).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("refuses a non-owner rotating another DID's key and audits the denial", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "user" })));

    await expect(caller.did.rotateKey({ did: OTHER_DID })).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(mockedRotateDidKey).not.toHaveBeenCalled();
    const auditActions = mockedCreateAuditEvent.mock.calls.map(call => call[0].action);
    expect(auditActions).toContain("DID_KEY_ROTATION_DENIED");
  });

  it("allows the owner to rotate their own DID's key", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "user" })));

    const result = await caller.did.rotateKey({ did: activeIdentity.did });
    expect(result).toMatchObject({ ok: true });
    expect(mockedRotateDidKey).toHaveBeenCalledWith(activeIdentity.did);
  });

  it("lets a platform administrator rotate any DID (audited)", async () => {
    mockedGetIdentityByLinkedUserId.mockResolvedValue(activeIdentity);
    const caller = appRouter.createCaller(makeContext(makeUser({ role: "admin" })));

    const result = await caller.did.rotateKey({ did: OTHER_DID });
    expect(result).toMatchObject({ ok: true });
    const auditActions = mockedCreateAuditEvent.mock.calls.map(call => call[0].action);
    expect(auditActions).toContain("DID_KEY_ROTATED");
  });
});

// ---------------------------------------------------------------------------
// 8. Indexer checkpoint resume
// ---------------------------------------------------------------------------

describe("ChainEventIndexer — checkpoint resume", () => {
  function installBesuAdapter(latestBlock: number) {
    besuState.service = {
      config: { privateKey: "0x" + "ab".repeat(32), address: "0xoperator" },
      getNetworkStatus: async () => ({ connected: true, latestBlock, mode: "BESU", network: "test" }),
      getEvents: vi.fn(async () => []),
    };
  }

  it("resumes from the durable checkpoint instead of re-scanning the whole window", async () => {
    installBesuAdapter(10_000);
    vi.mocked(getMaxIndexedChainBlock).mockResolvedValue(9_500);
    const indexer = new ChainEventIndexer();

    await indexer.indexRecentEvents(500);

    const call = (besuState.service!.getEvents as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call).toEqual({ fromBlock: 9_500, toBlock: 10_000 });
  });

  it("starts a fresh scan at latest-500 when no checkpoint exists", async () => {
    installBesuAdapter(10_000);
    vi.mocked(getMaxIndexedChainBlock).mockResolvedValue(null);
    const indexer = new ChainEventIndexer();

    await indexer.indexRecentEvents(500);

    const call = (besuState.service!.getEvents as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call).toEqual({ fromBlock: 9_500, toBlock: 10_000 });
  });

  it("resumes from a checkpoint BEYOND the lookback window (restart after downtime)", async () => {
    installBesuAdapter(10_000);
    // Indexer was down long enough that latest-500 (9500) < checkpoint (9950):
    // without the checkpoint, blocks 9951..10000 would never be scanned.
    vi.mocked(getMaxIndexedChainBlock).mockResolvedValue(9_950);
    const indexer = new ChainEventIndexer();

    await indexer.indexRecentEvents(500);

    const call = (besuState.service!.getEvents as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call).toEqual({ fromBlock: 9_950, toBlock: 10_000 });
  });

  it("clamps a stale-ahead checkpoint to the chain head", async () => {
    installBesuAdapter(10_000);
    vi.mocked(getMaxIndexedChainBlock).mockResolvedValue(12_000);
    const indexer = new ChainEventIndexer();

    await indexer.indexRecentEvents(500);

    const call = (besuState.service!.getEvents as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(call).toEqual({ fromBlock: 10_000, toBlock: 10_000 });
  });

  it("reports a disconnected chain instead of fabricating a scan", async () => {
    besuState.service = {
      config: { privateKey: "0x" + "ab".repeat(32), address: "0xoperator" },
      getNetworkStatus: async () => ({ connected: false, latestBlock: 0, mode: "BESU", network: "test" }),
      getEvents: vi.fn(async () => []),
    };
    const indexer = new ChainEventIndexer();
    const result = await indexer.indexRecentEvents(500);
    expect(result.indexed).toBe(0);
    expect(besuState.service.getEvents).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// 9. R7 — repeated login failures raise an advisory alert
// ---------------------------------------------------------------------------

describe("SecurityIntelligenceService — R7 login-failure rule", () => {
  it("creates an R7 alert after 5 LOGIN_FAILED audit events", async () => {
    const events = Array.from({ length: 5 }, (_, i) => ({
      id: `login-fail-${i}`,
      actorIdentityId: null,
      action: "LOGIN_FAILED",
      resourceType: "SESSION",
      resourceId: "admin@sampraan.dev",
      decision: null,
      reason: "Invalid email or password",
      metadata: {},
      createdAt: new Date(),
    })) as unknown as AuditEvent[];
    vi.mocked(listAuditEvents).mockResolvedValue(events);
    vi.mocked(listIdentities).mockResolvedValue([]);
    vi.mocked(listSecurityAlerts).mockResolvedValue([]);

    // The module under test is mocked for the router graph; run the REAL
    // service implementation against the mocked db helpers.
    const actual = await vi.importActual<typeof import("./modules/security-intelligence/intelligence.service")>(
      "./modules/security-intelligence/intelligence.service"
    );
    const result = await new actual.SecurityIntelligenceService().scan({ windowEvents: 200 });

    expect(result.rules).toContainEqual(expect.objectContaining({ rule: "R7-LOGIN-FAILURES", count: 5 }));
    expect(createSecurityAlert).toHaveBeenCalledTimes(1);
    const alert = vi.mocked(createSecurityAlert).mock.calls[0][0] as { severity: string; description: string };
    expect(alert.severity).toBe("MEDIUM");
    expect(alert.description).toContain("rule-fingerprint:R7-LOGIN-FAILURES");
  });

  it("does not fire R7 below the 5-failure threshold", async () => {
    const events = Array.from({ length: 4 }, (_, i) => ({
      id: `login-fail-${i}`,
      actorIdentityId: null,
      action: "LOGIN_FAILED",
      resourceType: "SESSION",
      resourceId: "admin@sampraan.dev",
      decision: null,
      reason: "Invalid email or password",
      metadata: {},
      createdAt: new Date(),
    })) as unknown as AuditEvent[];
    vi.mocked(listAuditEvents).mockResolvedValue(events);

    const actual = await vi.importActual<typeof import("./modules/security-intelligence/intelligence.service")>(
      "./modules/security-intelligence/intelligence.service"
    );
    const result = await new actual.SecurityIntelligenceService().scan({ windowEvents: 200 });

    expect(result.rules).toEqual([]);
    expect(createSecurityAlert).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Static invariants
// ---------------------------------------------------------------------------

describe("audit invariants", () => {
  it("MOCK-mode evidence hash must never be accepted as a confirmed transfer", async () => {
    // The fabricated-evidence regression: MOCK hashes are 0xmock_*; the router
    // must refuse to submit them. Assert the guard wiring exists at the source.
    const routers = await import("fs").then(fs => fs.promises.readFile("server/routers.ts", "utf8"));
    expect(routers).toContain('blockchainService.mode !== "BESU"');
    expect(routers).toContain("BLOCKCHAIN_TRANSACTION_FAILED");
  });
});
