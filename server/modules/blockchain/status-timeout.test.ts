import { describe, expect, it, vi } from "vitest";

/**
 * REGRESSION (found in live RC verification): a HUNG chain RPC (paused
 * validator container, network partition) used to stall /health and /ready
 * for the JSON-RPC provider's default timeout (60s+), making the whole API
 * unresponsive during a chain outage.
 *
 * getNetworkStatus must now bound every status RPC round-trip at
 * STATUS_RPC_TIMEOUT_MS (5s) and degrade to connected:false with a clear
 * timeout error instead of hanging.
 */
describe("bounded chain status (grey-failure resilience)", () => {
  it("getNetworkStatus reports connected:false instead of hanging on an unresponsive RPC", async () => {
    vi.resetModules();
    // Point the provider at a firewalled/black-hole address on localhost:
    // the port accepts nothing and no listener exists, so connections fail
    // fast — but to exercise the TIMEOUT path specifically we stub the
    // provider's RPC calls to never settle.
    const never = new Promise<never>(() => {});
    const { BesuBlockchainService } = await import("./besu-blockchain.service");
    const service = new BesuBlockchainService({
      mode: "BESU",
      rpcUrl: "http://127.0.0.1:1/",
      chainId: 4224,
      privateKey:
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
      identityContractAddress: "0x0000000000000000000000000000000000000001",
      assetContractAddress: "0x0000000000000000000000000000000000000002",
      accessControlContractAddress: "0x0000000000000000000000000000000000000003",
    });
    // Force the initialized state and a provider whose RPCs never resolve.
    const anyService = service as unknown as {
      provider: unknown;
      initPromise: Promise<void> | null;
      ensureInitialized: () => Promise<void>;
    };
    anyService.initPromise = Promise.resolve();
    anyService.provider = {
      getBlockNumber: () => never,
      getNetwork: () => never,
      send: () => never,
    };
    void anyService.ensureInitialized;

    const started = Date.now();
    const status = await service.getNetworkStatus();
    const elapsed = Date.now() - started;

    expect(status.connected).toBe(false);
    expect(status.mode).toBe("BESU");
    expect(status.error).toContain("timed out");
    // Bounded: must degrade within seconds, not the 60s+ provider default.
    expect(elapsed).toBeLessThan(10_000);
    expect(elapsed).toBeGreaterThanOrEqual(4_000);
  });
});
