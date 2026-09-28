/**
 * Live Besu QBFT integration tests for the SAMPRAAN contract suite.
 *
 * Requires the local network (docker compose -f blockchain/network/docker-compose.yml up -d)
 * and compiled artifacts (`pnpm run contracts:compile`).
 *
 * HONESTY CONTRACT: when the chain cannot be reached, or setup fails for any
 * reason, this suite FAILS. It no longer converts an unreachable chain into
 * vacuous green passes. A host without Docker must opt out EXPLICITLY:
 *
 *     SAMPRAAN_SKIP_LIVE_CHAIN=1 pnpm test
 *
 * That flag is the only way these tests skip, and the skip is reported by the
 * runner as a skip instead of masquerading as a pass.
 *
 * The suite deploys its own isolated contract stack, so it never touches
 * blockchain/deployment.json nor the running application's contracts.
 */
import { beforeAll, describe, expect, it } from "vitest";
import {
  Contract,
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
  createGovernanceContract,
  createIdentityRegistryContract,
} from "./contracts";

const SKIP_LIVE_CHAIN = process.env.SAMPRAAN_SKIP_LIVE_CHAIN === "1";
// describe.skip marks the whole suite (children included) as SKIPPED, not passed.
const describeLive = SKIP_LIVE_CHAIN ? describe.skip : describe;

const root = path.resolve(import.meta.dirname, "..", "..", "..");
const artifactsDir = path.join(root, "blockchain", "artifacts");

// On-chain status enums — contracts/SampraanIdentityRegistry.sol + SampraanAssetRegistry.sol
const IDENTITY_NONE = 0n;
const IDENTITY_PENDING = 1n;
const IDENTITY_VERIFIED = 2n;
const IDENTITY_SUSPENDED = 3n;
const ASSET_PENDING = 1n;
const ASSET_ACTIVE = 2n;
const ASSET_SUSPENDED = 3n;
const ASSET_REVOKED = 4n;

function artifact(name: string) {
  const file = path.join(artifactsDir, `${name}.json`);
  if (!existsSync(file)) {
    throw new Error(
      `Missing artifact ${name}.json — run "pnpm run contracts:compile" first.`
    );
  }
  const raw = JSON.parse(readFileSync(file, "utf8"));
  return { abi: raw.abi, bytecode: raw.bytecode as string };
}

// DEMO/LOCAL ONLY keys (public Besu tutorial genesis accounts).
//
// KEY ISOLATION: the operator below is deliberately NOT the account used by
// besu-adapter.test.ts (0x8f2a55…) or the running application, both of which
// share one genesis key. Two suites submitting from one account race on the
// account nonce and produce "Nonce too low" flakes. BOB_KEY is that shared
// account and is only ever a *recipient* here, never a sender.
const DEPLOYER_KEY =
  "0xae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f";
const ALICE_KEY =
  "0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3";
const BOB_KEY =
  "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

interface Suite {
  provider: JsonRpcProvider;
  deployer: Wallet;
  alice: Wallet;
  bob: Wallet;
  outsider: Wallet;
  accessControlAddress: string;
  identityRegistryAddress: string;
  assetRegistryAddress: string;
  governanceAddress: string;
}

let suite: Suite | null = null;

beforeAll(async () => {
  if (SKIP_LIVE_CHAIN) {
    console.warn(
      "[besu-contracts.test] SAMPRAAN_SKIP_LIVE_CHAIN=1 — live chain suite skipped by explicit opt-out."
    );
    return;
  }

  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL ?? "http://localhost:8545";
  const chainId = Number(process.env.BLOCKCHAIN_CHAIN_ID ?? 4224);

  try {
    const provider = new JsonRpcProvider(rpcUrl, chainId, {
      staticNetwork: true,
      // ethers caches eth_getTransactionCount for 250ms by default. Under
      // QBFT a transaction can be mined inside that window, so the cached
      // nonce is then stale and the next submission is rejected with
      // "Nonce too low". Sequential test submissions need fresh reads.
      cacheTimeout: 0,
    });
    const deployer = new Wallet(DEPLOYER_KEY, provider);
    const alice = new Wallet(ALICE_KEY, provider);
    const bob = new Wallet(BOB_KEY, provider);
    // Fresh throwaway account for negative authorization tests.
    const outsider = Wallet.createRandom().connect(provider);

    // Fail fast (and legibly) when the chain is not reachable at all.
    const network = await provider.getNetwork();
    if (Number(network.chainId) !== chainId) {
      throw new Error(
        `chainId mismatch: RPC reports ${Number(network.chainId)}, expected ${chainId}`
      );
    }

    // --- 1. Access control -------------------------------------------------
    const accessControl = await new ContractFactory(
      artifact("SampraanAccessControl").abi,
      artifact("SampraanAccessControl").bytecode,
      deployer
    ).deploy();
    await accessControl.waitForDeployment();
    const accessControlAddress = await accessControl.getAddress();

    // --- 2. Governance: deployed BEFORE the registries, both of which take
    //        its address as an immutable constructor argument.
    const thirdSigner = Wallet.createRandom();
    const governance = await new ContractFactory(
      artifact("SampraanGovernance").abi,
      artifact("SampraanGovernance").bytecode,
      deployer
    ).deploy(
      accessControlAddress,
      [deployer.address, alice.address, thirdSigner.address],
      67n, // quorum percent
      60n, // timelock delay seconds (demo value)
      deployer.address // governance admin
    );
    await governance.waitForDeployment();
    const governanceAddress = await governance.getAddress();

    // --- 3. Identity registry ---------------------------------------------
    const identityRegistry = await new ContractFactory(
      artifact("SampraanIdentityRegistry").abi,
      artifact("SampraanIdentityRegistry").bytecode,
      deployer
    ).deploy(accessControlAddress, governanceAddress);
    await identityRegistry.waitForDeployment();
    const identityRegistryAddress = await identityRegistry.getAddress();

    // --- 4. Asset registry ------------------------------------------------
    const assetRegistry = await new ContractFactory(
      artifact("SampraanAssetRegistry").abi,
      artifact("SampraanAssetRegistry").bytecode,
      deployer
    ).deploy(accessControlAddress, identityRegistryAddress, governanceAddress);
    await assetRegistry.waitForDeployment();
    const assetRegistryAddress = await assetRegistry.getAddress();

    // --- 5. Bootstrap: register + VERIFY the operator identities. Protected
    //        on-chain operations require VERIFIED, never merely PENDING.
    for (const who of [deployer, alice]) {
      const did = `did:ethr:${who.address.toLowerCase()}`;
      const reg = await identityRegistry.registerIdentity(
        who.address,
        keccak256(toUtf8Bytes(did)),
        keccak256(toUtf8Bytes(`pk:${who.address.toLowerCase()}`))
      );
      await reg.wait(1);
      const ver = await identityRegistry.verifyIdentity(
        who.address,
        "test bootstrap"
      );
      await ver.wait(1);
      expect(await identityRegistry.isActive(who.address)).toBe(true);
    }

    suite = {
      provider,
      deployer,
      alice,
      bob,
      outsider,
      accessControlAddress,
      identityRegistryAddress,
      assetRegistryAddress,
      governanceAddress,
    };
  } catch (error) {
    // NEVER swallow this: a broken or unreachable chain must be a hard
    // failure, not a batch of empty green ticks.
    throw new Error(
      `[besu-contracts.test] live chain setup FAILED against ${rpcUrl}: ${
        error instanceof Error ? error.message : String(error)
      }\n` +
        `Start the local QBFT network (pnpm run blockchain:start) and compile artifacts ` +
        `(pnpm run contracts:compile), or opt out explicitly with SAMPRAAN_SKIP_LIVE_CHAIN=1.`
    );
  }
}, 300_000);

function s(): Suite {
  if (!suite) {
    throw new Error(
      "[besu-contracts.test] suite not initialised — live chain setup did not run."
    );
  }
  return suite;
}

function handles() {
  const { provider } = s();
  return {
    accessControlAs: (w: Wallet) =>
      createAccessControlContract(s().accessControlAddress, w),
    identityAs: (w: Wallet) =>
      createIdentityRegistryContract(s().identityRegistryAddress, w),
    assetAs: (w: Wallet) =>
      createAssetRegistryContract(s().assetRegistryAddress, w),
    provider,
  };
}

const textDigest = (t: string) => keccak256(toUtf8Bytes(t));
const didDigestOf = (did: string) => keccak256(toUtf8Bytes(did));

describeLive("SAMPRAAN contracts on live Besu QBFT", () => {
  describe("IDENTITY", () => {
    it("authorized registration succeeds and stays PENDING until explicitly verified", async () => {
      const { identityAs } = handles();
      const identity = identityAs(s().deployer);
      // A brand-new wallet so registration is a genuine first-time transition.
      const fresh = Wallet.createRandom();
      const did = `did:ethr:${fresh.address.toLowerCase()}`;

      const tx = await identity.registerIdentity(
        fresh.address,
        didDigestOf(did),
        textDigest(`pk:${fresh.address.toLowerCase()}`)
      );
      const receipt = (await tx.wait(1)) as unknown as {
        status: number;
        logs: unknown[];
      };
      expect(receipt.status).toBe(1);
      expect(receipt.logs.length).toBeGreaterThan(0);

      const record = await identity.getIdentity(fresh.address);
      expect(record.didDigest).toBe(didDigestOf(did));
      // Registration alone NEVER grants protected-operation rights.
      expect(record.status).toBe(IDENTITY_PENDING);
      expect(await identity.isActive(fresh.address)).toBe(false);

      // Explicit, attributed verification promotes PENDING -> VERIFIED.
      const verify = await identity.verifyIdentity(
        fresh.address,
        "kyc complete"
      );
      await (verify as unknown as { wait: () => Promise<unknown> }).wait();
      expect((await identity.getIdentity(fresh.address)).status).toBe(
        IDENTITY_VERIFIED
      );
      expect(await identity.isActive(fresh.address)).toBe(true);
    });

    it("unauthorized registration fails", async () => {
      const { identityAs } = handles();
      const outsiderIdentity = identityAs(s().outsider);
      await expect(
        outsiderIdentity.registerIdentity(
          s().bob.address,
          didDigestOf("did:ethr:bob-rogue"),
          textDigest("pk:rogue")
        )
      ).rejects.toThrow();
    });

    it(
      "suspended identity is inactive and cannot receive a protected asset operation",
      { timeout: 60_000 },
      async () => {
        const { identityAs, assetAs } = handles();
        const identity = identityAs(s().deployer);
        const bob = s().bob;

        const reg = await identity.registerIdentity(
          bob.address,
          didDigestOf("did:ethr:bob"),
          textDigest("pk:bob")
        );
        await (reg as unknown as { wait: () => Promise<unknown> }).wait();
        const verify = await identity.verifyIdentity(
          bob.address,
          "initial review"
        );
        await (verify as unknown as { wait: () => Promise<unknown> }).wait();
        expect(await identity.isActive(bob.address)).toBe(true);

        const suspend = await identity.suspendIdentity(
          bob.address,
          "policy breach"
        );
        await (suspend as unknown as { wait: () => Promise<unknown> }).wait();

        expect((await identity.getIdentity(bob.address)).status).toBe(
          IDENTITY_SUSPENDED
        );
        expect(await identity.isActive(bob.address)).toBe(false);

        // Enforcement is on-chain: a suspended identity cannot be a custodian.
        const assets = assetAs(s().deployer);
        await expect(
          assets.registerAsset(
            textDigest("ASSET-TO-SUSPENDED"),
            bob.address,
            textDigest("CONTROLLED"),
            textDigest("metadata:to-suspended")
          )
        ).rejects.toThrow();
      }
    );

    it("identity deactivation is governance-only (no direct admin path)", async () => {
      // The deployer IS an identity admin, yet must not be able to force the
      // terminal DEACTIVATED state directly — only the governance multisig can.
      const raw = new Contract(
        s().identityRegistryAddress,
        artifact("SampraanIdentityRegistry").abi,
        s().deployer
      );

      // 1. No direct admin entry point may exist in the ABI at all.
      expect(raw.interface.getFunction("deactivateIdentity")).toBeNull();
      expect(raw.interface.getFunction("setStatus")).toBeNull();

      // 2. The real entry point exists but is guarded to the governance contract.
      await expect(
        raw.governanceDeactivateIdentity(s().alice.address, "rogue")
      ).rejects.toThrow();
      expect((await raw.getIdentity(s().alice.address)).status).toBe(
        IDENTITY_VERIFIED
      );
    });

    it("an unknown wallet is implicitly NONE (never registered)", async () => {
      const { identityAs } = handles();
      const identity = identityAs(s().deployer);
      const stranger = Wallet.createRandom();
      expect((await identity.getIdentity(stranger.address)).status).toBe(
        IDENTITY_NONE
      );
      expect(await identity.isActive(stranger.address)).toBe(false);
    });
  });

  describe("ASSET", () => {
    it("authorized mint succeeds, is PENDING, and emits an event", async () => {
      const { assetAs } = handles();
      const assets = assetAs(s().deployer);
      const tx = await assets.registerAsset(
        textDigest("ASSET-FW-001"),
        s().alice.address,
        textDigest("CONTROLLED"),
        textDigest("metadata:firmware-package-001")
      );
      const receipt = (await tx.wait(1)) as unknown as {
        status: number;
        logs: { topics: string[] }[];
      };
      expect(receipt.status).toBe(1);
      expect(receipt.logs.length).toBeGreaterThan(0);

      const tokenId = await assets.resolveAssetId(textDigest("ASSET-FW-001"));
      expect(tokenId).toBeGreaterThan(0n);
      expect(await assets.assetStatus(tokenId)).toBe(ASSET_PENDING);
      expect(await assets.custodianOf(tokenId)).toBe(s().alice.address);
    });

    it("unauthorized mint reverts", async () => {
      const { assetAs } = handles();
      const outsiderAssets = assetAs(s().outsider);
      await expect(
        outsiderAssets.registerAsset(
          textDigest("ASSET-ROGUE-001"),
          s().alice.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:rogue")
        )
      ).rejects.toThrow();
    });

    it("inactive identity cannot receive a protected asset operation", async () => {
      const { assetAs, identityAs } = handles();
      const assets = assetAs(s().deployer);
      // Bob is suspended by the identity tests above.
      expect(await identityAs(s().deployer).isActive(s().bob.address)).toBe(
        false
      );
      await expect(
        assets.registerAsset(
          textDigest("ASSET-TO-INACTIVE"),
          s().bob.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:to-inactive")
        )
      ).rejects.toThrow();
    });

    it("duplicate asset id is rejected and an unknown id resolves to 0", async () => {
      const { assetAs } = handles();
      const assets = assetAs(s().deployer);
      await expect(
        assets.registerAsset(
          textDigest("ASSET-FW-001"),
          s().deployer.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:dup")
        )
      ).rejects.toThrow();
      expect(
        await assets.resolveAssetId(textDigest("ASSET-DOES-NOT-EXIST"))
      ).toBe(0n);
    });
  });

  describe("ROLES", () => {
    it("deployer admin privileges work", async () => {
      const { accessControlAs } = handles();
      const ac = accessControlAs(s().deployer);
      const AUDITOR_ROLE = await ac.AUDITOR_ROLE();
      const grant = await ac.grantRole(AUDITOR_ROLE, s().outsider.address);
      const receipt = (await grant.wait(1)) as unknown as { status: number };
      expect(receipt.status).toBe(1);
      expect(await ac.hasRole(AUDITOR_ROLE, s().outsider.address)).toBe(true);
    });

    it("auditor (read-only) cannot mint assets and holds no manager role", async () => {
      const { assetAs, accessControlAs } = handles();
      const ac = accessControlAs(s().deployer);
      const ASSET_MANAGER_ROLE = await ac.ASSET_MANAGER_ROLE();
      expect(await ac.hasRole(ASSET_MANAGER_ROLE, s().outsider.address)).toBe(
        false
      );

      // outsider now holds AUDITOR_ROLE only — still must not mint.
      const auditorAssets = assetAs(s().outsider);
      await expect(
        auditorAssets.registerAsset(
          textDigest("ASSET-AUDITOR-MINT"),
          s().alice.address,
          textDigest("CONTROLLED"),
          textDigest("metadata:auditor")
        )
      ).rejects.toThrow();
    });

    it("random account cannot grant roles (role admin is protected)", async () => {
      const { accessControlAs } = handles();
      const rogueAc = accessControlAs(s().alice);
      const ASSET_MANAGER_ROLE = await rogueAc.ASSET_MANAGER_ROLE();
      await expect(
        rogueAc.grantRole(ASSET_MANAGER_ROLE, s().alice.address)
      ).rejects.toThrow();
    });
  });

  describe("GOVERNANCE", () => {
    it("multisig is configured on-chain with the expected signer set and timelock", async () => {
      const gov = createGovernanceContract(s().governanceAddress, s().deployer);
      expect(await gov.signerCount()).toBe(3n);
      expect(await gov.timelockDelaySeconds()).toBe(60n);
      expect(await gov.isSigner(s().deployer.address)).toBe(true);
      expect(await gov.isSigner(s().alice.address)).toBe(true);
      expect(await gov.isSigner(s().outsider.address)).toBe(false);
      expect(await gov.proposalCount()).toBe(0n);
    });

    it("quorum requirement is the documented ceiling of the signer set", async () => {
      const gov = createGovernanceContract(s().governanceAddress, s().deployer);
      const signerCount = await gov.signerCount();
      const quorumRequired = await gov.quorumRequired();
      // On-chain formula: ceil(signerCount * quorumPercent / 100).
      // NOTE (finding, see report): 3 signers at 67% => ceil(2.01) = 3, i.e.
      // 3-of-3, NOT the "any 2 of 3" the deploy script comment claims. This
      // test records the ACTUAL contract behaviour rather than the claim.
      expect(quorumRequired).toBe((signerCount * 67n + 99n) / 100n);
      expect(quorumRequired).toBe(3n);
    });

    it("a non-signer cannot propose or approve a governance action", async () => {
      const gov = createGovernanceContract(s().governanceAddress, s().outsider);
      const assetTarget = await createAssetRegistryContract(
        s().assetRegistryAddress,
        s().outsider
      );
      expect(await assetTarget.totalAssets()).toBeGreaterThanOrEqual(0n);
      await expect(
        gov.propose(
          5, // OpKind.BURN_NFT
          s().assetRegistryAddress,
          `0x${"00".repeat(32)}`,
          s().outsider.address,
          1n,
          "rogue proposal"
        )
      ).rejects.toThrow();
      // Approving/cancelling/executing a non-existent proposal is likewise gated.
      await expect(gov.approve(999n, "rogue")).rejects.toThrow();
      await expect(gov.execute(999n)).rejects.toThrow();
      expect(await gov.proposalCount()).toBe(0n);
    });

    it("governance-only dispatches revert for a direct operator call", async () => {
      const outsiderAssets = createAssetRegistryContract(
        s().assetRegistryAddress,
        s().outsider
      );
      await expect(outsiderAssets.governancePause()).rejects.toThrow();
      const deployerAssets = createAssetRegistryContract(
        s().assetRegistryAddress,
        s().deployer
      );
      // Even the ASSET_MANAGER operator cannot pause or burn directly.
      await expect(deployerAssets.governancePause()).rejects.toThrow();
      expect(await deployerAssets.paused()).toBe(false);
    });
  });

  describe("TRANSFER + STATUS LIFECYCLE", () => {
    it(
      "assignment, activation, transfer, suspension, restore all work for an authorized operator",
      { timeout: 90_000 },
      async () => {
        const { assetAs } = handles();
        const assets = assetAs(s().deployer);

        // Mint a fresh asset to the verified deployer identity.
        const mint = await assets.registerAsset(
          textDigest("ASSET-LIFE-001"),
          s().deployer.address,
          textDigest("HIGHLY_SENSITIVE"),
          textDigest("metadata:life-001")
        );
        const mintReceipt = (await mint.wait(1)) as unknown as {
          status: number;
        };
        expect(mintReceipt.status).toBe(1);

        const tokenId = await assets.resolveAssetId(
          textDigest("ASSET-LIFE-001")
        );
        expect(tokenId).toBeGreaterThan(0n);

        // Activate -> assign to alice -> transfer back to deployer.
        const activate = await assets.activateAsset(tokenId);
        await (activate as unknown as { wait: () => Promise<unknown> }).wait();
        expect(await assets.assetStatus(tokenId)).toBe(ASSET_ACTIVE);

        const assign = await assets.assignAsset(tokenId, s().alice.address);
        const assignReceipt = (await assign.wait(1)) as unknown as {
          status: number;
        };
        expect(assignReceipt.status).toBe(1);
        expect(await assets.custodianOf(tokenId)).toBe(s().alice.address);

        const transfer = await assets.transferCustody(
          tokenId,
          s().deployer.address
        );
        const transferReceipt = (await transfer.wait(1)) as unknown as {
          status: number;
        };
        expect(transferReceipt.status).toBe(1);
        expect(await assets.custodianOf(tokenId)).toBe(s().deployer.address);

        // Suspend -> transfer must fail -> restore.
        const suspend = await assets.suspendAsset(tokenId);
        await (suspend as unknown as { wait: () => Promise<unknown> }).wait();
        expect(await assets.assetStatus(tokenId)).toBe(ASSET_SUSPENDED);
        await expect(
          assets.transferCustody(tokenId, s().alice.address)
        ).rejects.toThrow();

        const restore = await assets.restoreAsset(tokenId);
        await (restore as unknown as { wait: () => Promise<unknown> }).wait();
        expect(await assets.assetStatus(tokenId)).toBe(ASSET_ACTIVE);
      }
    );

    it("unauthorized caller cannot transfer custody", async () => {
      const { assetAs } = handles();
      const outsiderAssets = assetAs(s().outsider);
      const tokenId = await outsiderAssets.resolveAssetId(
        textDigest("ASSET-LIFE-001")
      );
      await expect(
        outsiderAssets.transferCustody(tokenId, s().outsider.address)
      ).rejects.toThrow();
    });

    it("revoked asset is frozen permanently", { timeout: 60_000 }, async () => {
      const { assetAs } = handles();
      const assets = assetAs(s().deployer);
      const mint = await assets.registerAsset(
        textDigest("ASSET-REVOKE-001"),
        s().deployer.address,
        textDigest("CONTROLLED"),
        textDigest("metadata:revoke-001")
      );
      await (mint as unknown as { wait: () => Promise<unknown> }).wait();
      const tokenId = await assets.resolveAssetId(
        textDigest("ASSET-REVOKE-001")
      );
      const activate = await assets.activateAsset(tokenId);
      await (activate as unknown as { wait: () => Promise<unknown> }).wait();
      const revoke = await assets.revokeAsset(tokenId);
      await (revoke as unknown as { wait: () => Promise<unknown> }).wait();
      expect(await assets.assetStatus(tokenId)).toBe(ASSET_REVOKED);
      await expect(
        assets.transferCustody(tokenId, s().alice.address)
      ).rejects.toThrow();
      // Revocation is terminal: no further status change is possible.
      await expect(assets.activateAsset(tokenId)).rejects.toThrow();
      await expect(assets.suspendAsset(tokenId)).rejects.toThrow();
    });
  });

  describe("TRANSACTION EVIDENCE", () => {
    it("successful operation returns a receipt obtainable by hash", async () => {
      const { assetAs, provider } = handles();
      const assets = assetAs(s().deployer);
      const mint = await assets.registerAsset(
        textDigest("ASSET-EVIDENCE-001"),
        s().deployer.address,
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
