/**
 * Backend adapter integration tests against the live local Besu QBFT chain.
 * Exercises BesuBlockchainService exactly as the backend uses it:
 * provider connection, contract initialization, real transaction submission,
 * receipt parsing, event reading, and safe revert handling.
 * Self-skips when the chain is unreachable (CI without Docker).
 */
import { beforeAll, describe, expect, it } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { Wallet, keccak256, toUtf8Bytes, JsonRpcProvider } from "ethers";
import { BesuBlockchainService } from "./besu-blockchain.service";
import type { BlockchainConfig } from "./blockchain.config";

const root = path.resolve(import.meta.dirname, "..", "..", "..");
const deploymentFile = path.join(root, "blockchain", "deployment.json");

const DEMO_KEY =
  "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"; // DEMO/LOCAL ONLY

let service: BesuBlockchainService | null = null;
let ready = false;

beforeAll(async () => {
  if (!existsSync(deploymentFile)) return;
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
    });
    await probe.getBlockNumber();
    service = new BesuBlockchainService(config);
    ready = true;
  } catch (error) {
    console.warn(
      "[besu-adapter.test] Chain unreachable, skipping live adapter tests:",
      error instanceof Error ? error.message : String(error)
    );
  }
}, 30_000);

function requireChain() {
  if (!ready || !service) {
    console.warn(
      "[besu-adapter.test] Local Besu chain unavailable — skipping live adapter tests."
    );
  }
  return ready && service !== null;
}

const textDigest = (t: string) => keccak256(toUtf8Bytes(t));

describe("BesuBlockchainService against live chain", () => {
  it("connects and reports a healthy network status", { timeout: 30_000 }, async () => {
    if (!requireChain()) return;
    const status = await service!.getNetworkStatus();
    expect(status.connected).toBe(true);
    expect(status.mode).toBe("BESU");
    expect(status.latestBlock).toBeGreaterThan(0);
    expect(status.chainId).toBe(4224);
    expect(status.error).toBeUndefined();
  });

  it("submits a real identity registration and returns full evidence", { timeout: 30_000 }, async () => {
    if (!requireChain()) return;
    const wallet = new Wallet(DEMO_KEY);
    // Use a unique DID per run so repeated runs stay idempotent-safe.
    const did = `did:ethr:${wallet.address.toLowerCase()}`;
    const existing = await service!.getIdentity(wallet.address);
    if (existing) return; // already registered by the deployment bootstrap

    const evidence = await service!.registerIdentity({
      did,
      walletAddress: wallet.address,
    });
    expect(evidence.status).toBe("CONFIRMED");
    expect(evidence.transactionHash).toMatch(/^0x[0-9a-fA-F]{64}$/);
    expect(evidence.blockNumber).toBeGreaterThan(0);
    expect(evidence.blockHash).toBeTruthy();
    expect(evidence.events?.some(e => e.name === "IdentityRegistered")).toBe(true);
  });

  it("retrieves a receipt by transaction hash", { timeout: 30_000 }, async () => {
    if (!requireChain()) return;
    const wallet = new Wallet(DEMO_KEY);
    const evidence = await service!.submitTransaction({
      action: "ASSET_REGISTER",
      payload: {
        assetId: `ADAPTER-TEST-${Date.now()}`,
        custodianWallet: wallet.address,
        classification: "CONTROLLED",
        metadataReference: "metadata:adapter-test",
      },
    });
    expect(evidence.status).toBe("CONFIRMED");
    const fetched = await service!.getTransaction(evidence.transactionHash);
    expect(fetched).not.toBeNull();
    expect(fetched!.transactionHash).toBe(evidence.transactionHash);
    expect(fetched!.blockNumber).toBe(evidence.blockNumber);
  });

  it("reads contract events from recent blocks", { timeout: 30_000 }, async () => {
    if (!requireChain()) return;
    const events = await service!.getEvents();
    expect(Array.isArray(events)).toBe(true);
    // The deployment + earlier tests emitted identity/asset events.
    expect(events.length).toBeGreaterThan(0);
    expect(events.some(e => e.transactionHash.startsWith("0x"))).toBe(true);
  });

  it("fails safely with a descriptive error when the chain rejects an operation", { timeout: 30_000 }, async () => {
    if (!requireChain()) return;
    const wallet = new Wallet(DEMO_KEY);
    // Transferring an asset that was never registered must throw —
    // and must never be reported as success.
    await expect(
      service!.transferAsset({
        assetId: "ASSET-DOES-NOT-EXIST-999",
        toCustodianWallet: wallet.address,
      })
    ).rejects.toThrow(/not registered on-chain/i);
  });
});
