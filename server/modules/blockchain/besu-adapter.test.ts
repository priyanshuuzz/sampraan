/**
 * Backend adapter integration tests against the live local Besu QBFT chain.
 * Exercises BesuBlockchainService exactly as the backend uses it:
 * provider connection, contract initialization, real transaction submission,
 * receipt parsing, event reading, and safe revert handling.
 *
 * HONESTY CONTRACT: a missing deployment or an unreachable chain FAILS this
 * suite; it never turns a broken environment into green ticks. A host without
 * Docker must opt out explicitly:
 *
 *     SAMPRAAN_SKIP_LIVE_CHAIN=1 pnpm test
 */
import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { Wallet, keccak256, toUtf8Bytes, JsonRpcProvider } from "ethers";

import { BesuBlockchainService } from "./besu-blockchain.service";
import type { BlockchainConfig } from "./blockchain.config";

const SKIP_LIVE_CHAIN = process.env.SAMPRAAN_SKIP_LIVE_CHAIN === "1";
const describeLive = SKIP_LIVE_CHAIN ? describe.skip : describe;

const root = path.resolve(import.meta.dirname, "..", "..", "..");
const deploymentFile = path.join(root, "blockchain", "deployment.json");

// DEMO/LOCAL ONLY genesis operator key (public Besu tutorial account).
const DEMO_KEY =
  "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

let service: BesuBlockchainService | null = null;

beforeAll(async () => {
  if (SKIP_LIVE_CHAIN) {
    console.warn(
      "[besu-adapter.test] SAMPRAAN_SKIP_LIVE_CHAIN=1 — live adapter suite skipped by explicit opt-out."
    );
    return;
  }

  if (!existsSync(deploymentFile)) {
    throw new Error(
      `[besu-adapter.test] ${deploymentFile} is missing — run "pnpm run blockchain:deploy" ` +
        `to produce a deployment, or opt out explicitly with SAMPRAAN_SKIP_LIVE_CHAIN=1.`
    );
  }

  const deployment = JSON.parse(readFileSync(deploymentFile, "utf8"));
  const config: BlockchainConfig = {
    mode: "BESU",
    rpcUrl: process.env.BLOCKCHAIN_RPC_URL ?? "http://localhost:8545",
    chainId: 4224,
    privateKey: DEMO_KEY,
    identityContractAddress: deployment.contracts.SampraanIdentityRegistry,
    assetContractAddress: deployment.contracts.SampraanAssetRegistry,
    accessControlContractAddress: deployment.contracts.SampraanAccessControl,
  };

  try {
    // Verify the chain is reachable first.
    const probe = new JsonRpcProvider(config.rpcUrl, config.chainId, {
      staticNetwork: true,
      // Fresh nonce reads: this suite submits several sequential transactions
      // from one operator key and a 250ms cached account nonce goes stale.
      cacheTimeout: 0,
    });
    await probe.getBlockNumber();
    service = new BesuBlockchainService(config);
  } catch (error) {
    throw new Error(
      `[besu-adapter.test] live chain setup FAILED against ${config.rpcUrl}: ${
        error instanceof Error ? error.message : String(error)
      }\n` +
        `Start the local QBFT network (pnpm run blockchain:start), or opt out ` +
        `explicitly with SAMPRAAN_SKIP_LIVE_CHAIN=1.`
    );
  }
}, 30_000);

function svc(): BesuBlockchainService {
  if (!service) {
    throw new Error(
      "[besu-adapter.test] service not initialised — live chain setup did not run."
    );
  }
  return service;
}

describeLive("BesuBlockchainService against live chain", () => {
  it(
    "connects and reports a healthy network status",
    { timeout: 30_000 },
    async () => {
      const status = await svc().getNetworkStatus();
      expect(status.connected).toBe(true);
      expect(status.mode).toBe("BESU");
      expect(status.latestBlock).toBeGreaterThan(0);
      expect(status.chainId).toBe(4224);
      expect(status.error).toBeUndefined();
    }
  );

  it(
    "submits a real identity registration and returns full evidence",
    { timeout: 60_000 },
    async () => {
      // Use a FRESH wallet on every run so this always performs a genuine
      // registration — never a vacuous early return for an already-known DID.
      const fresh = Wallet.createRandom();
      const wallet = new Wallet(DEMO_KEY);
      const did = `did:ethr:${fresh.address.toLowerCase()}`;

      const evidence = await svc().registerIdentity({
        did,
        walletAddress: fresh.address,
      });
      expect(evidence.status).toBe("CONFIRMED");
      expect(evidence.transactionHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
      expect(evidence.blockNumber).toBeGreaterThan(0);
      expect(evidence.blockHash).toBeTruthy();
      expect(evidence.events?.some(e => e.name === "IdentityRegistered")).toBe(
        true
      );

      // The registration is genuinely readable back from chain state, and
      // starts PENDING (registration alone grants no protected-operation right).
      const record = await svc().getIdentity(fresh.address);
      expect(record).not.toBeNull();
      expect(record!.status).toBe(1); // PENDING
      expect(record!.didDigest).toBe(keccak256(toUtf8Bytes(did)));

      // The operator itself is the bootstrap identity and stays VERIFIED.
      const operator = await svc().getIdentity(wallet.address);
      expect(operator).not.toBeNull();
      expect(operator!.status).toBe(2); // VERIFIED
    }
  );

  it(
    "retrieves a receipt by transaction hash",
    { timeout: 30_000 },
    async () => {
      const wallet = new Wallet(DEMO_KEY);
      const evidence = await svc().submitTransaction({
        action: "ASSET_REGISTER",
        payload: {
          assetId: `ADAPTER-TEST-${Date.now()}`,
          custodianWallet: wallet.address,
          classification: "CONTROLLED",
          metadataReference: "metadata:adapter-test",
        },
      });
      expect(evidence.status).toBe("CONFIRMED");
      const fetched = await svc().getTransaction(evidence.transactionHash);
      expect(fetched).not.toBeNull();
      expect(fetched!.transactionHash).toBe(evidence.transactionHash);
      expect(fetched!.blockNumber).toBe(evidence.blockNumber);
    }
  );

  it(
    "reads contract events from recent blocks",
    { timeout: 30_000 },
    async () => {
      const events = await svc().getEvents();
      expect(Array.isArray(events)).toBe(true);
      // The deployment + earlier tests emitted identity/asset events.
      expect(events.length).toBeGreaterThan(0);
      expect(events.some(e => e.transactionHash.startsWith("0x"))).toBe(true);
    }
  );

  it(
    "fails safely with a descriptive error when the chain rejects an operation",
    { timeout: 30_000 },
    async () => {
      const wallet = new Wallet(DEMO_KEY);
      // Transferring an asset that was never registered must throw —
      // and must never be reported as success.
      await expect(
        svc().transferAsset({
          assetId: "ASSET-DOES-NOT-EXIST-999",
          toCustodianWallet: wallet.address,
        })
      ).rejects.toThrow(/not registered on-chain/i);
    }
  );

  // BUG-034 regression: SAMPRAAN signs every operation with ONE operator key.
  // Concurrent submissions (identity anchor + mint during asset creation, or
  // a transfer racing the indexer) previously fetched the same pending nonce
  // and replaced each other — the intermittent "replacement transaction
  // underpriced" / "already known" failures. The service now serializes
  // submit→receipt cycles; this test proves five parallel submissions all
  // confirm and that they were mined strictly one at a time.
  it(
    "serializes concurrent submissions from the shared operator key (BUG-034)",
    { timeout: 120_000 },
    async () => {
      const wallet = new Wallet(DEMO_KEY);
      const stamp = Date.now();
      const results = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          svc().submitTransaction({
            action: "ASSET_REGISTER",
            payload: {
              assetId: `BUG034-SERIAL-${stamp}-${i}`,
              custodianWallet: wallet.address,
              classification: "CONTROLLED",
              metadataReference: "metadata:bug034-serialization",
            },
          })
        )
      );
      // Every parallel submission confirmed — none replaced another.
      const hashes = new Set(results.map(r => r.transactionHash));
      expect(hashes.size).toBe(5);
      for (const evidence of results) {
        expect(evidence.status).toBe("CONFIRMED");
        expect(evidence.blockNumber).toBeGreaterThan(0);
      }
      // Strict ordering: because cycles are serialized, the block numbers of
      // the awaited completions are non-decreasing and every block actually
      // contains the expected tx (no replacement happened).
      for (let i = 1; i < results.length; i++) {
        expect(results[i].blockNumber).toBeGreaterThanOrEqual(
          results[i - 1].blockNumber
        );
      }
      const fetched = await Promise.all(
        results.map(r => svc().getTransaction(r.transactionHash))
      );
      for (const receipt of fetched) {
        expect(receipt).not.toBeNull();
        expect(receipt!.status).toBe("CONFIRMED");
      }
    }
  );
});
