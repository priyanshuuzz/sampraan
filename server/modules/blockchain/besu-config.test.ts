import { describe, expect, it } from "vitest";
import { resolveBlockchainConfig } from "./blockchain.config";
import { MockBlockchainService } from "./mock-blockchain.service";
import type { BlockchainConfig } from "./blockchain.config";
import { BesuBlockchainService } from "./besu-blockchain.service";

describe("resolveBlockchainConfig", () => {
  it("falls back to MOCK mode when the private key is missing", () => {
    const previousKey = process.env.BLOCKCHAIN_PRIVATE_KEY;
    delete process.env.BLOCKCHAIN_PRIVATE_KEY;
    const config = resolveBlockchainConfig();
    expect(config.mode).toBe("MOCK");
    process.env.BLOCKCHAIN_PRIVATE_KEY = previousKey;
  });

  it("enables BESU mode when all required configuration is present", () => {
    const env = {
      BLOCKCHAIN_PRIVATE_KEY: "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63",
      BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS: "0xa50a51c09a5c451C52BB714527E1974b686D8e77",
      BLOCKCHAIN_ASSET_CONTRACT_ADDRESS: "0x9a3DBCa554e9f6b9257aAa24010DA8377C57c17e",
      BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS: "0x42699A7612A82f1d9C36148af9C77354759b210b",
    };
    const saved = Object.fromEntries(Object.keys(env).map(k => [k, process.env[k]]));
    Object.assign(process.env, env);
    const config = resolveBlockchainConfig();
    expect(config.mode).toBe("BESU");
    expect(config.chainId).toBe(4224);
    for (const key of Object.keys(env)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  });
});

describe("BesuBlockchainService configuration safety", () => {
  it("refuses mutating operations when not configured (no silent fake success)", async () => {
    const unconfigured = {
      mode: "MOCK",
      rpcUrl: "http://localhost:8545",
      chainId: 4224,
      privateKey: null,
      identityContractAddress: null,
      assetContractAddress: null,
      accessControlContractAddress: null,
    } as BlockchainConfig;
    const service = new BesuBlockchainService(unconfigured);
    await expect(
      service.submitTransaction({
        action: "ASSET_TRANSFER",
        payload: { assetId: "ASSET-1", toCustodianWallet: "0xabc" },
      })
    ).rejects.toThrow(/not configured/i);
  });

  it("reports disconnected status with an error reason when unreachable", async () => {
    const unreachable = {
      mode: "BESU",
      rpcUrl: "http://localhost:59999",
      chainId: 4224,
      privateKey: "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63",
      identityContractAddress: "0xa50a51c09a5c451C52BB714527E1974b686D8e77",
      assetContractAddress: "0x9a3DBCa554e9f6b9257aAa24010DA8377C57c17e",
      accessControlContractAddress: "0x42699A7612A82f1d9C36148af9C77354759b210b",
    } as BlockchainConfig;
    const service = new BesuBlockchainService(unreachable);
    const status = await service.getNetworkStatus();
    expect(status.connected).toBe(false);
    expect(status.mode).toBe("BESU");
    expect(status.error).toBeTruthy();
  });
});

describe("MockBlockchainService contract", () => {
  it("never claims to be a real chain", async () => {
    const service = new MockBlockchainService();
    const status = await service.getNetworkStatus();
    expect(status).toMatchObject({ connected: false, mode: "MOCK" });
  });
});
