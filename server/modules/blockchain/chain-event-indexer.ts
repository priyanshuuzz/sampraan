/**
 * SAMPRAAN chain event indexer (focused, minimal).
 *
 * Projects SAMPRAAN smart-contract events into the existing audit_events
 * read model (source: "CHAIN_READ_MODEL"), so on-chain provenance is
 * queryable through the same audit API the application already uses.
 *
 * This is deliberately NOT an enterprise event platform: it reads the latest
 * window of blocks, maps recognized events to audit rows, and skips what it
 * has already indexed (idempotent by transaction hash).
 */
import { createAuditEvent } from "../../db";
import { besuBlockchainService } from "./blockchain.service";
import type { ChainEvent } from "./blockchain.types";

const INDEXED_ACTIONS: Record<string, string> = {
  IdentityRegistered: "IDENTITY_REGISTERED_ON_CHAIN",
  IdentityStatusChanged: "IDENTITY_STATUS_CHANGED_ON_CHAIN",
  AssetRegistered: "ASSET_REGISTERED_ON_CHAIN",
  AssetAssigned: "ASSET_ASSIGNED_ON_CHAIN",
  AssetTransferred: "ASSET_TRANSFERRED_ON_CHAIN",
  AssetStatusChanged: "ASSET_STATUS_CHANGED_ON_CHAIN",
  RoleGranted: "ROLE_GRANTED_ON_CHAIN",
  RoleRevoked: "ROLE_REVOKED_ON_CHAIN",
};

export interface IndexerResult {
  indexed: number;
  skipped: number;
  latestBlock: number;
}

export class ChainEventIndexer {
  private indexedTxHashes = new Set<string>();

  /**
   * Scan recent chain events and project them into the audit read model.
   * Returns how many new audit rows were created.
   */
  async indexRecentEvents(windowBlocks = 500): Promise<IndexerResult> {
    if (!besuBlockchainService) {
      return { indexed: 0, skipped: 0, latestBlock: 0 };
    }

    const status = await besuBlockchainService.getNetworkStatus();
    if (!status.connected) {
      return { indexed: 0, skipped: 0, latestBlock: 0 };
    }

    const latestBlock = status.latestBlock;
    const fromBlock = Math.max(0, latestBlock - windowBlocks);
    const events = await besuBlockchainService.getEvents({
      fromBlock,
      toBlock: latestBlock,
    });

    let indexed = 0;
    let skipped = 0;
    for (const event of events) {
      if (this.indexedTxHashes.has(event.transactionHash)) {
        skipped++;
        continue;
      }
      const projected = this.project(event);
      if (!projected) {
        skipped++;
        this.indexedTxHashes.add(event.transactionHash);
        continue;
      }
      await createAuditEvent(projected);
      this.indexedTxHashes.add(event.transactionHash);
      indexed++;
    }

    return { indexed, skipped, latestBlock };
  }

  /**
   * Map a parsed chain event to an audit_events insert (without PII —
   * only digests and addresses that are already on-chain).
   */
  private project(event: ChainEvent) {
    const action = INDEXED_ACTIONS[event.name];
    if (!action) return null;

    const args = event.args as Record<string, unknown>;
    const resourceId =
      typeof args.assetIdDigest === "string"
        ? args.assetIdDigest
        : typeof args.didDigest === "string"
          ? args.didDigest
          : event.transactionHash;

    return {
      actorIdentityId: null,
      action,
      resourceType: "CHAIN",
      resourceId,
      decision: "ALLOW" as const,
      reason: `On-chain event ${event.name} at block ${event.blockNumber}`,
      transactionHash: event.transactionHash,
      blockNumber: event.blockNumber,
      metadata: { source: "chain-indexer", contract: event.address, args },
    };
  }
}

export const chainEventIndexer = new ChainEventIndexer();
