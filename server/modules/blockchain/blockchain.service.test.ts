import { describe, expect, it } from "vitest";
import { MockBlockchainService } from "./blockchain.service";

describe("MockBlockchainService", () => {
  it("does not claim a real Besu connection", async () => {
    const service = new MockBlockchainService();
    await expect(service.getNetworkStatus()).resolves.toMatchObject({
      connected: false,
      mode: "MOCK",
    });
  });

  it("simulates a confirmed transaction and retrieves it by hash", async () => {
    const service = new MockBlockchainService();
    const transaction = await service.submitTransaction({
      action: "ASSET_TRANSFER",
      payload: { assetId: "asset-demo" },
    });
    expect(transaction.status).toBe("CONFIRMED");
    await expect(
      service.getTransaction(transaction.transactionHash)
    ).resolves.toEqual(transaction);
  });

  it("returns null for an unknown transaction hash", async () => {
    const service = new MockBlockchainService();
    await expect(service.getTransaction("0xunknown")).resolves.toBeNull();
  });

  it("increments the block height for each submitted transaction", async () => {
    const service = new MockBlockchainService();
    const before = await service.getLatestBlock();
    await service.submitTransaction({ action: "ASSET_TRANSFER", payload: {} });
    await service.submitTransaction({
      action: "IDENTITY_CREATED",
      payload: {},
    });
    const after = await service.getLatestBlock();
    expect(after).toBe(before + 2);
    const status = await service.getNetworkStatus();
    expect(status.latestBlock).toBe(after);
  });

  it("issues unique transaction hashes", async () => {
    const service = new MockBlockchainService();
    const first = await service.submitTransaction({ action: "A", payload: {} });
    const second = await service.submitTransaction({
      action: "B",
      payload: {},
    });
    expect(first.transactionHash).not.toBe(second.transactionHash);
    expect(first.transactionHash).toMatch(/^0xmock_/);
    expect(second.transactionHash).toMatch(/^0xmock_/);
  });

  it("exposes an empty event stream in mock mode", async () => {
    const service = new MockBlockchainService();
    await expect(service.getEvents()).resolves.toEqual([]);
  });

  it("reports the demo QBFT network name", async () => {
    const service = new MockBlockchainService();
    const status = await service.getNetworkStatus();
    expect(status.network).toBe("SAMPRAAN-DEMO-QBFT");
  });
});
