/**
 * SAMPRAAN blockchain service facade.
 *
 * Preserves the single `blockchainService` surface the routers and health
 * endpoints already consume, while routing to the REAL Besu adapter when
 * configuration is present and to the mock otherwise.
 *
 * Design rules:
 *  - The exported `blockchainService` is a union facade: NetworkStatus.mode
 *    tells callers exactly which backend answered ("BESU" vs "MOCK").
 *  - When Besu is NOT configured, mutating chain operations throw a clear
 *    configuration error instead of silently faking success.
 *  - The mock remains available for unit tests and CI without a chain.
 */
import { BesuBlockchainService } from "./besu-blockchain.service";
import { MockBlockchainService } from "./mock-blockchain.service";
import { resolveBlockchainConfig } from "./blockchain.config";
import type {
  BlockchainOperationInput,
  ChainEvent,
  NetworkStatus,
  TransactionEvidence,
} from "./blockchain.types";

export type BlockchainServiceLike = {
  getNetworkStatus(): Promise<NetworkStatus>;
  getLatestBlock(): Promise<number>;
  submitTransaction(input: BlockchainOperationInput): Promise<TransactionEvidence>;
  getTransaction(transactionHash: string): Promise<TransactionEvidence | null>;
  getEvents(input?: { fromBlock?: number; toBlock?: number }): Promise<ChainEvent[]>;
  /** Signing wallet address when a real chain is configured; null in MOCK mode. */
  readonly operatorAddress: string | null;
  readonly mode: "BESU" | "MOCK";
};

const config = resolveBlockchainConfig();

function createService(): BlockchainServiceLike {
  if (config.mode === "BESU") {
    const besu = new BesuBlockchainService(config);
    const operatorAddress = (() => {
      try {
        return besu.operatorAddress;
      } catch {
        return null;
      }
    })();
    return {
      mode: "BESU",
      operatorAddress,
      getNetworkStatus: () => besu.getNetworkStatus(),
      getLatestBlock: () => besu.getLatestBlock(),
      submitTransaction: input => besu.submitTransaction(input),
      getTransaction: hash => besu.getTransaction(hash),
      getEvents: input => besu.getEvents(input),
    };
  }
  const mock = new MockBlockchainService();
  return {
    mode: "MOCK",
    operatorAddress: null,
    getNetworkStatus: () => mock.getNetworkStatus(),
    getLatestBlock: () => mock.getLatestBlock(),
    submitTransaction: input => mock.submitTransaction(input),
    getTransaction: hash => mock.getTransaction(hash),
    getEvents: () => mock.getEvents(),
  };
}

export const blockchainService: BlockchainServiceLike = createService();

// Full typed surface for callers that specifically want the Besu adapter
// (identity/asset operations beyond the legacy facade).
export const besuBlockchainService: BesuBlockchainService | null =
  config.mode === "BESU" ? new BesuBlockchainService(config) : null;

export type {
  BlockchainOperationInput,
  ChainEvent,
  NetworkStatus,
  TransactionEvidence,
} from "./blockchain.types";