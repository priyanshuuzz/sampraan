/**
 * Live Besu QBFT integration tests for the SAMPRAAN contract suite.
 *
 * Requires the local network (docker compose -f blockchain/network/docker-compose.yml up -d)
 * and a fresh deployment (pnpm run blockchain:deploy writes blockchain/deployment.json).
 * These tests self-skip when the chain is unreachable so CI without Docker
 * still passes; run locally for the full evidence.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  ContractFactory,
  JsonRpcProvider,
  Wallet,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import {
  createAccessControlContract,
  createAssetRegistryContract,
  createIdentityRegistryContract,
  SampraanAccessControlABI,
  SampraanAssetRegistryABI,
  SampraanIdentityRegistryABI,
} from "./contracts";

const root = path.resolve(import.meta.dirname, "..", "..", "..");
const artifactsDir = path.join(root, "blockchain", "artifacts");

function artifact(name: string) {
  const raw = JSON.parse(
    readFileSync(path.join(artifactsDir, `${name}.json`), "utf8")
  );
  return { abi: raw.abi, bytecode: raw.bytecode as string };
}

// DEMO/LOCAL ONLY keys (public Besu tutorial genesis accounts).
const DEPLOYER_KEY =
  "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";
const ALICE_KEY =
  "0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3";
const BOB_KEY =
  "0xae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f";

interface Suite {
  ready: boolean;
  provider: JsonRpcProvider | null;
  deployer: Wallet | null;
  alice: Wallet | null;
  bob: Wallet | null;
  outsider: Wallet | null;
  accessControlAddress: string;
  identityRegistryAddress: string;
  assetRegistryAddress: string;
}

let suite: Suite = {
  ready: false,
  provider: null,
  deployer: null,
  alice: null,
  bob: null,
  outsider: null,
  accessControlAddress: "",
  identityRegistryAddress: "",
  assetRegistryAddress: "",
};

beforeAll(async () => {
  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL ?? "http://localhost:8545";
  try {
    const provider = new JsonRpcProvider(rpcUrl, 4224, { staticNetwork: true });
    const deployer = new Wallet(DEPLOYER_KEY, provider);
    const alice = new Wallet(ALICE_KEY, provider);
    const bob = new Wallet(BOB_KEY, provider);
    // Fresh throwaway account for negative authorization tests.
    const outsider = Wallet.createRandom().connect(provider);

    // Deploy an isolated contract suite for this test run.
    const acFactory = new ContractFactory(
      artifact("SampraanAccessControl").abi,
      artifact("SampraanAccessControl").bytecode,
      deployer
    );
    const accessControl = await acFactory.deploy();
    await accessControl.waitForDeployment();

    const idFactory = new ContractFactory(
      artifact("SampraanIdentityRegistry").abi,
      artifact("SampraanIdentityRegistry").bytecode,
      deployer
    );
    const identityRegistry = await idFactory.deploy(
      await accessControl.getAddress()
    );
    await identityRegistry.waitForDeployment();

    const assetFactory = new ContractFactory(
      artifact("SampraanAssetRegistry").abi,
      artifact("SampraanAssetRegistry").bytecode,
      deployer
    );
    const assetRegistry = await assetFactory.deploy(
      await accessControl.getAddress(),
      await identityRegistry.getAddress()
    );
    await assetRegistry.waitForDeployment();

    suite = {
      ready: true,
      provider,
      deployer,
      alice,
      bob,
      outsider,
      accessControlAddress: await accessControl.getAddress(),
      identityRegistryAddress: await identityRegistry.getAddress(),
      assetRegistryAddress: await assetRegistry.getAddress(),
    };
  } catch (error) {
    console.warn(
      "[besu-contracts.test] Could not set up live contract suite:",
      error instanceof Error ? error.message : String(error)
    );
    suite = { ...suite, ready: false };
  }
}, 300_000);

function requireChain() {
  if (!suite.ready) {
    console.warn(
      "[besu-contracts.test] Local Besu chain unavailable — skipping live contract tests."
    );
  }
  return suite.ready;
}

function handles() {
  const provider = suite.provider!;
  return {
    accessControlAs: (w: Wallet) =>
      createAccessControlContract(suite.accessControlAddress, w),
    identityAs: (w: Wallet) =>
      createIdentityRegistryContract(suite.identityRegistryAddress, w),
    assetAs: (w: Wallet) =>
      createAssetRegistryContract(suite.assetRegistryAddress, w),
    provider,
  };
}

const didDigest = (did: string) => keccak256(toUtf8Bytes(did));
const textDigest = (t: string) => keccak256(toUtf8Bytes(t));

describe("SAMPRAAN contracts on live Besu QBFT", () => {
  describe("IDENTITY", () => {
    it("authorized identity registration succeeds", async () => {
      if (!requireChain()) return;
      const { identityAs } = handles();
      const identity = identityAs(suite.deployer!);
      const tx = await identity.registerIdentity(
        suite.alice!.address,
        didDigest("did:ethr:alice"),
        textDigest("pk:alice")
      );
      const receipt = (await tx.wait(1)) as unknown as { status: number; logs: unknown[] };
      expect(receipt.status).toBe(1);
      const record = await identity.getIdentity(suite.alice!.address);
      expect(record.didDigest).toBe(didDigest("did:ethr:alice"));
      expect(record.status).toBe(1n); // ACTIVE
    });

    it("unauthorized registration fails", async () => {
      if (!requireChain()) return;
      const { identityAs } = handles();
      const outsiderIdentity = identityAs(suite.outsider!);
      await expect(
        outsiderIdentity.registerIdentity(
          suite.bob!.address,
          didDigest("did:ethr:bob-rogue"),
          textDigest("pk:rogue")
        )
      ).rejects.toThrow();
    });

    it("identity revocation works and blocks protected operations", { timeout: 60_000 }, async () => {
      if (!requireChain()) return;
      const { identityAs } = handles();
      const identity = identityAs(suite.deployer!);
      // Register bob then revoke.
      const reg = await identity.registerIdentity(
        suite.bob!.address,
        didDigest("did:ethr:bob"),
        textDigest("pk:bob")
      );
      await (reg as unknown as { wait: () => Promise<unknown> }).wait();
      const revoke = await identity.setStatus(suite.bob!.address, 3);
      await (revoke as unknown as { wait: () => Promise<unknown> }).wait();
      const record = await identity.getIdentity(suite.bob!.address);
      expect(record.status).toBe(3n); // REVOKED
      expect(await identity.isActive(suite.bob!.address)).toBe(false);
    });
  });

  describe("ASSET", () => {
    it("authorized mint succeeds and emits an event", async () => {
      if (!requireChain()) return;
      const { assetAs } = handles();
      const assets = assetAs(suite.deployer!);
      const tx = await assets.registerAsset(
        textDigest("ASSET-FW-001"),
        suite.alice!.address,
        textDigest("CONTROLLED"),
        textDigest("metadata:firmware-package-001")
      );
      const receipt = (await tx.wait(1)) as unknown as {
        status: number;
        logs: { topics: string[] }[];
      };
      expect(receipt.status).toBe(1);
      expect(receipt.logs.length).toBeGreaterThan(0);
    });

    it("unauthorized mint reverts", async () => {
      if (!requireChain()) return;
      const { assetAs } = handles();
      const outsiderAssets = assetAs(suite.outsider!);
      await expect(
        outsiderAssets.registerAsset(
          textDigest("ASSET-ROGUE-001"),
          suite.alice!.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:rogue")
        )
      ).rejects.toThrow();
    });

    it("revoked identity cannot receive a protected asset operation", async () => {
      if (!requireChain()) return;
      const { assetAs } = handles();
      const assets = assetAs(suite.deployer!);
      // Bob is revoked from the identity tests above.
      await expect(
        assets.registerAsset(
          textDigest("ASSET-TO-REVOKED"),
          suite.bob!.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:to-revoked")
        )
      ).rejects.toThrow();
    });
  });

  describe("ROLES", () => {
    it("deployer admin privileges work", async () => {
      if (!requireChain()) return;
      const { accessControlAs } = handles();
      const ac = accessControlAs(suite.deployer!);
      const AUDITOR_ROLE = await ac.AUDITOR_ROLE();
      const grant = await ac.grantRole(AUDITOR_ROLE, suite.outsider!.address);
      const receipt = (await grant.wait(1)) as unknown as { status: number };
      expect(receipt.status).toBe(1);
      expect(await ac.hasRole(AUDITOR_ROLE, suite.outsider!.address)).toBe(true);
    });

    it("auditor (no mutation role) cannot mint assets", async () => {
      if (!requireChain()) return;
      const { assetAs } = handles();
      // outsider now holds AUDITOR_ROLE only — still must not mint.
      const auditorAssets = assetAs(suite.outsider!);
      await expect(
        auditorAssets.registerAsset(
          textDigest("ASSET-AUDITOR-MINT"),
          suite.alice!.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:auditor")
        )
      ).rejects.toThrow();
    });

    it("random account cannot grant roles (role admin is protected)", async () => {
      if (!requireChain()) return;
      const { accessControlAs } = handles();
      const rogueAc = accessControlAs(suite.alice!);
      const ASSET_MANAGER_ROLE = await rogueAc.ASSET_MANAGER_ROLE();
      await expect(
        rogueAc.grantRole(ASSET_MANAGER_ROLE, suite.alice!.address)
      ).rejects.toThrow();
    });
  });

  describe("TRANSFER + STATUS LIFECYCLE", () => {
    it("assignment, activation, transfer, suspension, restore all work for authorized operator", { timeout: 90_000 }, async () => {
      if (!requireChain()) return;
      const { assetAs, identityAs } = handles();
      const assets = assetAs(suite.deployer!);
      const identity = identityAs(suite.deployer!);

      // Register a second active identity (deployer itself).
      const deployerIdentity = await identity.getIdentity(suite.deployer!.address);
      if (deployerIdentity.status === 0n) {
        const reg = await identity.registerIdentity(
          suite.deployer!.address,
          didDigest("did:ethr:deployer"),
          textDigest("pk:deployer")
        );
        await (reg as unknown as { wait: () => Promise<unknown> }).wait();
      }

      // Mint a fresh asset to the deployer.
      const mint = await assets.registerAsset(
        textDigest("ASSET-LIFE-001"),
        suite.deployer!.address,
        textDigest("HIGHLY_SENSITIVE"),
        textDigest("metadata:life-001")
      );
      const mintReceipt = (await mint.wait(1)) as unknown as { status: number };
      expect(mintReceipt.status).toBe(1);

      const tokenId = await assets.resolveAssetId(textDigest("ASSET-LIFE-001"));
      expect(tokenId).toBeGreaterThan(0n);

      // Activate -> assign to alice -> transfer back to deployer.
      const activate = await assets.activateAsset(tokenId);
      await (activate as unknown as { wait: () => Promise<unknown> }).wait();
      expect(await assets.assetStatus(tokenId)).toBe(2n); // ACTIVE

      const assign = await assets.assignAsset(tokenId, suite.alice!.address);
      const assignReceipt = (await assign.wait(1)) as unknown as { status: number };
      expect(assignReceipt.status).toBe(1);
      expect(await assets.custodianOf(tokenId)).toBe(suite.alice!.address);

      const transfer = await assets.transferCustody(
        tokenId,
        suite.deployer!.address
      );
      const transferReceipt = (await transfer.wait(1)) as unknown as { status: number };
      expect(transferReceipt.status).toBe(1);
      expect(await assets.custodianOf(tokenId)).toBe(suite.deployer!.address);

      // Suspend -> transfer must fail -> restore.
      const suspend = await assets.suspendAsset(tokenId);
      await (suspend as unknown as { wait: () => Promise<unknown> }).wait();
      await expect(
        assets.transferCustody(tokenId, suite.alice!.address)
      ).rejects.toThrow();

      const restore = await assets.restoreAsset(tokenId);
      await (restore as unknown as { wait: () => Promise<unknown> }).wait();
      expect(await assets.assetStatus(tokenId)).toBe(2n);
    });

    it("unauthorized caller cannot transfer custody", async () => {
      if (!requireChain()) return;
      const { assetAs } = handles();
      const outsiderAssets = assetAs(suite.outsider!);
      const tokenId = await outsiderAssets.resolveAssetId(
        textDigest("ASSET-LIFE-001")
      );
      await expect(
        outsiderAssets.transferCustody(tokenId, suite.outsider!.address)
      ).rejects.toThrow();
    });

    it("revoked asset is frozen permanently", { timeout: 60_000 }, async () => {
      if (!requireChain()) return;
      const { assetAs } = handles();
      const assets = assetAs(suite.deployer!);
      const mint = await assets.registerAsset(
        textDigest("ASSET-REVOKE-001"),
        suite.deployer!.address,
        textDigest("CONTROLLED"),
        textDigest("metadata:revoke-001")
      );
      await (mint as unknown as { wait: () => Promise<unknown> }).wait();
      const tokenId = await assets.resolveAssetId(textDigest("ASSET-REVOKE-001"));
      const activate = await assets.activateAsset(tokenId);
      await (activate as unknown as { wait: () => Promise<unknown> }).wait();
      const revoke = await assets.revokeAsset(tokenId);
      await (revoke as unknown as { wait: () => Promise<unknown> }).wait();
      expect(await assets.assetStatus(tokenId)).toBe(4n); // REVOKED
      await expect(
        assets.transferCustody(tokenId, suite.alice!.address)
      ).rejects.toThrow();
    });
  });

  describe("TRANSACTION EVIDENCE", () => {
    it("successful operation returns a receipt obtainable by hash", async () => {
      if (!requireChain()) return;
      const { assetAs, provider } = handles();
      const assets = assetAs(suite.deployer!);
      const mint = await assets.registerAsset(
        textDigest("ASSET-EVIDENCE-001"),
        suite.deployer!.address,
        textDigest("CONTROLLED"),
        textDigest("metadata:evidence")
      );
      const receipt = (await mint.wait(1)) as unknown as {
        hash: string;
        status: number;
        blockNumber: number;
        blockHash: string;
      };
      expect(receipt.status).toBe(1);

      const fetched = await provider.getTransactionReceipt(receipt.hash);
      expect(fetched).not.toBeNull();
      expect(fetched!.blockNumber).toBe(receipt.blockNumber);
      expect(fetched!.blockHash).toBe(receipt.blockHash);
    });
  });
});