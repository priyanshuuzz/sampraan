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

// AUDIT FIX (BUG-036 — duplicate operator signers): the Besu adapter is now
// instantiated EXACTLY ONCE and the facade delegates to it. Previously BOTH
// `blockchainService` (legacy facade — transfers) and `besuBlockchainService`
// (typed adapter — mint/assign/anchor) constructed their OWN adapter with its
// own NonceManager and submitMutex over the SAME operator key. Two concurrent
// nonce allocators then handed the SAME account nonce to two transactions;
// the first mined, the second was rejected by the pool with "Nonce too low"
// — an intermittent mint/assign/transfer failure reproduced live by the
// acceptance suite.
export const besuBlockchainService: BesuBlockchainService | null =
  config.mode === "BESU" ? new BesuBlockchainService(config) : null;

function createService(): BlockchainServiceLike {
  if (besuBlockchainService) {
    const besu = besuBlockchainService;
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
  // Note: the mock chain has no events by construction; the input window is
  // intentionally ignored in MOCK mode (an empty array is the truthful answer).
}

export const blockchainService: BlockchainServiceLike = createService();
// (The typed surface above now shares the SINGLE adapter instance created at
// the top of this module — there is exactly one NonceManager per process.)

export type {
  BlockchainOperationInput,
  ChainEvent,
  NetworkStatus,
  TransactionEvidence,
} from "./blockchain.types";