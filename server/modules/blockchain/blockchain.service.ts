import { randomUUID } from "node:crypto";

/**
 * Mock blockchain adapter.
 *
 * Deliberately reports connected: false / mode: "MOCK" so no caller can mistake
 * this for a real Hyperledger Besu network. Real Besu integration is a later
 * SAMPRAAN phase and must replace this adapter without changing its surface.
 */

export interface NetworkStatus {
  connected: boolean;
  mode: "MOCK";
  network: string;
  latestBlock: number;
}

export interface MockTransaction {
  transactionHash: string;
  blockNumber: number;
  status: "CONFIRMED";
}

export class MockBlockchainService {
  private block = 18402;
  private transactions = new Map<string, MockTransaction>();

  async getNetworkStatus(): Promise<NetworkStatus> {
    return {
      connected: false,
      mode: "MOCK",
      network: "SAMPRAAN-DEMO-QBFT",
      latestBlock: this.block,
    };
  }

  async getLatestBlock(): Promise<number> {
    return this.block;
  }

  async submitTransaction(_input: {
    action: string;
    payload: unknown;
  }): Promise<MockTransaction> {
    const transactionHash = `0xmock_${randomUUID().replaceAll("-", "")}`;
    const transaction: MockTransaction = {
      transactionHash,
      blockNumber: ++this.block,
      status: "CONFIRMED",
    };
    this.transactions.set(transactionHash, transaction);
    return transaction;
  }

  async getTransaction(transactionHash: string): Promise<MockTransaction | null> {
    return this.transactions.get(transactionHash) ?? null;
  }

  async getEvents(): Promise<unknown[]> {
    return [];
  }
}

export const blockchainService = new MockBlockchainService();
