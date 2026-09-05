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
import { describeError } from "../../common/error-handler";
import { createAuditEvent, listIndexedChainTxHashes } from "../../db";
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

    // BUG-030: the in-memory dedup set alone loses its state on every
    // process restart, and each restart then re-projects the whole recent
    // window (observed live: one tx duplicated 4x). Seed the dedup set from
    // the audit read model so indexing is durable/idempotent across
    // restarts.
    try {
      const persisted = await listIndexedChainTxHashes();
      for (const hash of persisted) this.indexedTxHashes.add(hash);
    } catch {
      // When the DB is unavailable, fall back to memory-only dedup for this
      // scan — the audit rows cannot be written anyway in that case.
    }

    let events;
    try {
      events = await besuBlockchainService.getEvents({
        fromBlock,
        toBlock: latestBlock,
      });
    } catch (error) {
      // BUG-005/QA #6: a range failure must surface as a clear, actionable
      // error instead of crashing the indexer loop or producing garbage.
      const reason = describeError(error);
      throw new Error(
        `Chain event scan failed for blocks ${fromBlock}..${latestBlock}: ${reason}`
      );
    }

    let indexed = 0;
    let skipped = 0;
    for (const event of events) {
      // Dedup: BOTH the raw transaction hash (persisted rows store this) and
      // the composite event key (same tx can legitimately emit several
      // distinct events) must be checked. A re-scan of the same block window
      // — including after a process restart — must never duplicate rows.
      const rawHash = event.transactionHash;
      const key = `${event.transactionHash}:${event.name}:${String(event.args?.tokenId ?? event.args?.wallet ?? "")}`;
      if (this.indexedTxHashes.has(rawHash) || this.indexedTxHashes.has(key)) {
        skipped++;
        continue;
      }
      const projected = this.project(event);
      if (!projected) {
        skipped++;
        this.indexedTxHashes.add(key);
        this.indexedTxHashes.add(rawHash);
        continue;
      }
      await createAuditEvent(projected);
      this.indexedTxHashes.add(key);
      this.indexedTxHashes.add(rawHash);
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
      // Mark the row as chain-derived so the audit API can distinguish
      // application decisions from on-chain projections.
      source: "CHAIN_READ_MODEL" as const,
      metadata: { source: "chain-indexer", contract: event.address, args },
    };
  }
}

export const chainEventIndexer = new ChainEventIndexer();
