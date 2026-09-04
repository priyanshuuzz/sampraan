import { describe, expect, it } from "vitest";
import { MockBlockchainService } from "./blockchain.service";

describe("MockBlockchainService", () => {
  it("does not claim a real Besu connection", async () => {
    const service = new MockBlockchainService();
    await expect(service.getNetworkStatus()).resolves.toMatchObject({ connected: false, mode: "MOCK" });
  });

  it("simulates a confirmed transaction and retrieves it by hash", async () => {
    const service = new MockBlockchainService();
    const transaction = await service.submitTransaction({ action: "ASSET_TRANSFER", payload: { assetId: "asset-demo" } });
    expect(transaction.status).toBe("CONFIRMED");
    await expect(service.getTransaction(transaction.transactionHash)).resolves.toEqual(transaction);
  });
});
