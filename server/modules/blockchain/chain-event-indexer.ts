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
import { createAuditEvent, listIndexedChainEventKeys, listIndexedChainTxHashes } from "../../db";
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
  /** In-memory per-event dedup (txHash:name:token) for the current process. */
  private indexedEventKeys = new Set<string>();
  /** Per-event durable dedup key persisted inside the audit row metadata. */
  private static eventKey(event: ChainEvent): string {
    return `${event.transactionHash}:${event.name}:${String(
      event.args?.tokenId ?? event.args?.wallet ?? ""
    )}`;
  }
  /** Guard against overlapping scans: two ticks racing past the in-memory
   * dedup set (e.g. a slow insert + fast blocks) would double-project events.
   * A scan only starts when the previous one has fully settled.
   */
  private scanMutex: Promise<IndexerResult> = Promise.resolve({ indexed: 0, skipped: 0, latestBlock: 0 });
  private indexing = false;

  /**
   * Scan recent chain events and project them into the audit read model.
   * Returns how many new audit rows were created.
   */
  async indexRecentEvents(windowBlocks = 500): Promise<IndexerResult> {
    if (this.indexing) {
      return { indexed: 0, skipped: 0, latestBlock: 0 };
    }
    this.indexing = true;
    try {
      return await this.runScan(windowBlocks);
    } finally {
      this.indexing = false;
    }
  }

  private async runScan(windowBlocks = 500): Promise<IndexerResult> {
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
    // window (observed live: one tx duplicated 4x). Seed the per-event dedup
    // from the persisted metadata keys so indexing is durable/idempotent
    // across restarts.
    try {
      const persisted = await listIndexedChainEventKeys();
      for (const key of persisted) this.indexedEventKeys.add(key);
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

    // Durable dedup data, loaded once per scan and treated READ-ONLY for
    // the rest of the scan (mutating it mid-loop is what previously caused
    // same-tx sibling events to be skipped):
    //  - persistedKeys: exact per-event keys (metadata.eventKey) written by
    //    every scan since the per-event dedup fix — authoritative.
    //  - legacyTxHashes: tx-level hashes from PRE-fix rows (no eventKey in
    //    their metadata). A tx whose row already exists must not have that
    //    event re-projected, so its hash is used purely as a skip marker.
    const persistedKeys = await listIndexedChainEventKeys().catch(() => new Set<string>());
    const legacyTxHashes = await listIndexedChainTxHashes().catch(() => new Set<string>());

    let indexed = 0;
    let skipped = 0;
    for (const event of events) {
      // Dedup is PER EVENT (txHash:name:token). One transaction can
      // legitimately emit several distinct contract events (the ERC-721
      // Transfer next to AssetRegistered/AssetTransferred) and each
      // RECOGNIZED event must be projected exactly once.
      const key = ChainEventIndexer.eventKey(event);
      if (this.indexedEventKeys.has(key) || persistedKeys.has(key)) {
        skipped++;
        continue;
      }
      const projected = this.project(event);
      if (!projected) {
        // Unrecognized event (e.g. ERC-721 Transfer): never projected, so
        // no dedup state is needed — and critically, recording its tx hash
        // must never gate a sibling event.
        skipped++;
        continue;
      }
      // Legacy row already covers this tx (pre-eventKey metadata): its
      // recognized event(s) are already represented in the read model.
      if (legacyTxHashes.has(event.transactionHash)) {
        skipped++;
        continue;
      }
      await createAuditEvent(projected);
      this.indexedEventKeys.add(key);
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
      // application decisions from on-chain projections. eventKey makes the
      // projection idempotent per EVENT (a tx can emit several events).
      source: "CHAIN_READ_MODEL" as const,
      metadata: { source: "chain-indexer", contract: event.address, eventKey: ChainEventIndexer.eventKey(event), args },
    };
  }
}

export const chainEventIndexer = new ChainEventIndexer();
