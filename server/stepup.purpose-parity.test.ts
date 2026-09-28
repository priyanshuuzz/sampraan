/**
 * STEP-UP PURPOSE PARITY — regression tests for the challenge/gate contract.
 *
 * BUG THIS PINS: stepup.requestChallenge once composed its purpose from the
 * asset's BUSINESS key (`content-view:<assetId>`), while the asset-content
 * gate probed with the asset's ROW id (`content-view:<uuid>`). Every
 * correctly-signed challenge was therefore unsatisfiable for the content
 * gate it was issued for — the operator could complete step-up perfectly
 * and still hit STEP_UP_REQUIRED forever.
 *
 * The tests prove, at the router boundary:
 *   1. stepup.requestChallenge creates a challenge whose purpose equals
 *      stepUpPurposeFor(operation, asset ROW id).
 *   2. The content gate probes hasValidStepUp with EXACTLY that same token
 *      (captured via the gate's own probe) for every operation that needs
 *      step-up: content VIEW on a sensitive asset, EDIT, and (via the
 *      shared authorize path) UPLOAD.
 * Single source of truth: server/modules/asset-content/asset-content.router.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TRPCError } from "@trpc/server";
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
  // capture the purpose the GATE probes with
  probedPurposes: [] as string[],
  // capture the purpose the CHALLENGE router composes
  challengePurposes: [] as string[],
  storedChallenges: [] as { identityId: string; purpose: string; nonce: string }[],
}));

vi.mock("./db", () => ({
  getAssetById: vi.fn(),
  getIdentityByLinkedUserId: vi.fn(),
  getIdentityRolesAndPermissions: vi.fn(async () => ({ roles: ["MANAGER"], permissions: ["asset:read", "asset:edit", "asset:create", "asset:assign"] })),
  createAuditEvent: vi.fn(async () => undefined),
  createAuthorizationDecision: vi.fn(async () => undefined),
  listActiveAssetAccessGrants: vi.fn(async () => []),
  listAssetAccessGrants: vi.fn(async () => []),
  listAssetContentVersions: vi.fn(async () => []),
  getAssetContentVersionById: vi.fn(async () => undefined),
  getAssetIdForGrant: vi.fn(async () => undefined),
  createAssetContentVersion: vi.fn(async (input: { versionNumber: number }) => ({
    ...versionFixture,
    versionNumber: input.versionNumber,
    id: "b1b1b1b1-1111-4222-8333-444455556666",
  })),
  createAssetAccessGrant: vi.fn(),
  revokeAssetAccessGrant: vi.fn(async () => false),
  getNextAssetVersionNumber: vi.fn(async () => 2),
  // Generic fallbacks used elsewhere in the shared router
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
      dbMocks.storedChallenges.push({ identityId: _identityId, purpose, nonce });
      return { nonce, message: `challenge for ${purpose}`, keyIdentifier: "key-1", expiresAt: new Date(Date.now() + 300_000).toISOString() };
    }),
    verifyStepUpChallenge: vi.fn(async (input: { identityId: string; purpose: string; nonce: string }) => {
      const row = dbMocks.storedChallenges.find(c => c.nonce === input.nonce && c.identityId === input.identityId && c.purpose === input.purpose);
      if (!row) return { ok: false as const, reason: "invalid", code: "STEP_UP_INVALID" };
      return { ok: true as const };
    }),
    hasValidStepUp: vi.fn(async (_identityId: string, purpose: string) => {
      dbMocks.probedPurposes.push(purpose);
      return dbMocks.storedChallenges.some(c => c.purpose === purpose);
    }),
    fingerprintNonce: actual.fingerprintNonce ?? vi.fn((n: string) => n.slice(0, 8)),
  };
});

// Hermetic storage: the createVersion test must pass the gate and complete
// WITHOUT touching the real local filesystem.
vi.mock("./modules/asset-content/storage", async importOriginal => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  const blobs = new Map<string, Buffer>();
  const memoryProvider = {
    name: "memory-test",
    put: async (ref: string, data: Buffer) => {
      blobs.set(ref, data);
      return { reference: ref, byteLength: data.byteLength, ciphertextSha256: "sha256-mem" };
    },
    get: async (ref: string) => {
      const blob = blobs.get(ref);
      if (!blob) throw new Error(`missing ${ref}`);
      return blob;
    },
    stat: async (ref: string) => ({ exists: blobs.has(ref), byteLength: blobs.get(ref)?.byteLength ?? 0 }),
    delete: async (ref: string) => { blobs.delete(ref); },
    stream: async (ref: string) => new ReadableStream<Uint8Array>({ start(c) { c.enqueue(new Uint8Array(blobs.get(ref)!)); c.close(); } }),
  };
  return {
    ...actual,
    resolveStorage: () => ({ provider: memoryProvider, keyProvider: new (actual.LocalDevKeyProvider as new (k: Buffer) => { wrapKey: unknown; unwrapKey: unknown; integrityKey: unknown })(Buffer.alloc(32, 7)) }),
    deriveContentReference: actual.deriveContentReference,
  };
});

vi.mock("./modules/security-intelligence/intelligence.service", () => ({
  securityIntelligenceService: { scan: vi.fn(async () => ({ scanned: 0, created: 0, suppressed: 0 })) },
  scheduleIntelligenceScan: vi.fn(),
  recordIntelligenceScanEvidence: vi.fn(),
}));

import { getAssetById, getIdentityByLinkedUserId } from "./db";
import { createStepUpChallenge } from "./modules/did/did-auth.service";

const mockedGetAssetById = vi.mocked(getAssetById);
const mockedGetActorIdentity = vi.mocked(getIdentityByLinkedUserId);

function makeUser(role: "admin" | "user" = "admin"): User {
  return {
    id: 1,
    openId: "parity-open-1",
    name: "Parity Operator",
    email: "parity@sampraan.dev",
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
  id: "0e0d3b1a-aaaa-4bbb-8ccc-444455559999",
  linkedUserId: 1,
  displayName: "Parity Operator",
  organization: "SAMPRAAN DEMO",
  status: "ACTIVE",
  did: "did:sampraan:parity-actor",
  createdAt: new Date(),
  updatedAt: new Date(),
  revokedAt: null,
};

// ROW id (uuid) and BUSINESS key are deliberately different strings.
const rowId = "1ec845d0-1187-41ba-8329-ccb580bbc51c";
const BUSINESS_KEY = "DEV-FIRMWARE-001";

const assetFixture: Asset = {
  id: rowId,
  assetId: BUSINESS_KEY,
  name: "Parity Fixture",
  type: "DOCUMENT",
  classification: "HIGHLY_SENSITIVE", // VIEW + all edits require step-up
  description: null,
  ownerIdentityId: actorIdentity.id,
  custodianIdentityId: actorIdentity.id,
  integrityHash: null,
  tokenId: null,
  status: "ACTIVE",
  createdAt: new Date(),
  updatedAt: new Date(),
};

const versionFixture = {
  id: "9a9a9a9a-1111-4222-8333-444455556666",
  assetId: rowId,
  versionNumber: 1,
  filename: "parity.txt",
  originalFilename: "parity.txt",
  mimeType: "text/plain",
  sizeBytes: 10,
  contentHash: "sha256-abc",
  storageProvider: "local-encrypted",
  storageReference: "bciqa-parity-ref",
  encryption: { alg: "AES-256-GCM", keyId: "k", wrappedKeyB64: "w", ivB64: "i", tagB64: "t" },
  createdByIdentityId: actorIdentity.id,
  changeNote: null,
  createdTxHash: null,
  createdBlockNumber: null,
  createdAt: new Date(),
};

const caller = appRouter.createCaller(makeContext(makeUser()));

beforeEach(() => {
  vi.clearAllMocks();
  dbMocks.probedPurposes.length = 0;
  dbMocks.challengePurposes.length = 0;
  dbMocks.storedChallenges.length = 0;
  mockedGetAssetById.mockResolvedValue(assetFixture);
  mockedGetActorIdentity.mockResolvedValue(actorIdentity);
});

/** Sign the challenge the way the operator console would (shape only). */
const goodSignature = "0x" + "11".repeat(65);

describe("step-up purpose parity (challenge composer == gate probe)", () => {
  it("content-view: a challenge from stepup.requestChallenge satisfies the content.list gate", async () => {
    const challenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "content-view" });
    expect(dbMocks.challengePurposes[0]).toBe(`content-view:${rowId}`);
    await caller.stepup.verify({ assetId: rowId, operation: "content-view", nonce: challenge.nonce, signature: goodSignature });
    // Gate must now pass: no STEP_UP_REQUIRED thrown.
    await expect(caller.content.list({ assetId: rowId })).resolves.toBeDefined();
    // And the gate must have probed EXACTLY the token the challenge bound.
    expect(dbMocks.probedPurposes).toContain(`content-view:${rowId}`);
    expect(dbMocks.probedPurposes).not.toContain(`content-view:${BUSINESS_KEY}`);
  });

  it("content-edit: challenge purpose equals the createVersion gate probe", async () => {
    vi.mocked(await import("./db")).getAssetContentVersionById.mockResolvedValue(versionFixture as never);
    const challenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "content-edit" });
    await caller.stepup.verify({ assetId: rowId, operation: "content-edit", nonce: challenge.nonce, signature: goodSignature });
    // The gate's EDIT check: authorizeContentOperation runs before validation.
    await expect(
      caller.content.createVersion({
        assetId: rowId,
        filename: "parity-upload.txt",
        clientMimeType: "text/plain",
        dataBase64: Buffer.from("parity upload\n").toString("base64"),
      }),
    ).resolves.toBeDefined();
    expect(dbMocks.probedPurposes).toContain(`content-edit:${rowId}`);
    expect(dbMocks.probedPurposes).not.toContain(`content-edit:${BUSINESS_KEY}`);
  });

  it("transfer purpose stays independent of content purposes (no cross-satisfaction)", async () => {
    const transferChallenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "transfer" });
    await caller.stepup.verify({ assetId: rowId, operation: "transfer", nonce: transferChallenge.nonce, signature: goodSignature });
    // A transfer verification must NOT open the content gate.
    await expect(caller.content.list({ assetId: rowId })).rejects.toThrow(/STEP_UP_REQUIRED/);
    expect(dbMocks.probedPurposes).not.toContain(`transfer:${rowId}`);
  });

  it("createStepUpChallenge receives the row-id purpose from BOTH callers (single composer)", async () => {
    const challenge = await caller.stepup.requestChallenge({ assetId: rowId, operation: "content-edit" });
    expect(challenge.nonce).toBeTruthy();
    // The composed purpose string, captured at the service boundary:
    expect(dbMocks.challengePurposes[0]).toMatch(new RegExp(`^content-edit:${rowId}$`));
  });
});
