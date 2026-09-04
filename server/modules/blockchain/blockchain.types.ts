/**
 * Shared blockchain adapter types for SAMPRAAN.
 *
 * The chain is the authoritative state-transition/provenance evidence layer;
 * PostgreSQL remains the application/read model. These types capture what the
 * backend needs from ANY blockchain adapter (Besu today, mocks in tests).
 */

export type BlockchainMode = "BESU" | "MOCK";

export type TransactionStatus = "CONFIRMED" | "FAILED";

export interface NetworkStatus {
  connected: boolean;
  mode: BlockchainMode;
  network: string;
  latestBlock: number;
  chainId?: number;
  nodeVersion?: string;
  error?: string;
}

export interface TransactionEvidence {
  transactionHash: string;
  blockNumber: number;
  blockHash?: string;
  status: TransactionStatus;
  contractAddress?: string;
  from?: string;
  to?: string;
  gasUsed?: number;
  events?: ChainEvent[];
}

export interface ChainEvent {
  name: string;
  address: string;
  blockNumber: number;
  transactionHash: string;
  args: Record<string, unknown>;
}

export type ChainAction =
  | "IDENTITY_REGISTER"
  | "IDENTITY_STATUS_CHANGE"
  | "ASSET_REGISTER"
  | "ASSET_ASSIGN"
  | "ASSET_TRANSFER"
  | "ASSET_STATUS_CHANGE";

export interface BlockchainOperationInput {
  action: ChainAction;
  payload: Record<string, unknown>;
}
