/**
 * SAMPRAAN asset provenance service (LOOP 9).
 *
 * Aggregates the COMPLETE chronological history of an asset from REAL
 * sources only:
 *  - the blockchain evidence (mint/transfer tx hashes + block numbers
 *    already recorded in audit_events by the authorization boundary and the
 *    custom chain event indexer), and
 *  - the custody read model (asset_custody rows written ONLY after a
 *    confirmed on-chain transfer).
 *
 * Nothing here invents history: rows without transaction evidence are
 * labeled by their true source ("APPLICATION"), and chain rows carry their
 * real tx hash / block number. The blockchain remains authoritative for
 * chain state; this service is a read-only aggregator.
 */
import { getAssetById, listAssetAuditEvents, listAssetCustody, getIdentityById } from "../../db";
import type { AuditEvent } from "../../../drizzle/schema";

export interface ProvenanceEntry {
  kind: "MINT" | "ASSIGNMENT" | "TRANSFER" | "STATUS_CHANGE" | "EVENT";
  timestamp: string | null;
  actorIdentityId: string | null;
  actorDid: string | null;
  transactionHash: string | null;
  blockNumber: number | null;
  decision: string | null;
  reason: string | null;
  source: string;
}

export interface AssetProvenance {
  asset: {
    id: string;
    assetId: string;
    name: string;
    type: string;
    classification: string;
    status: string;
    tokenId: string | null;
  };
  creator: { identityId: string; did: string; displayName: string; walletAddress: string | null } | null;
  creatorWalletAddress: string | null;
  currentCustodian: { identityId: string; did: string; displayName: string } | null;
  previousCustodians: { identityId: string; did: string; displayName: string; from: string | null; to: string | null }[];
  mint: { transactionHash: string | null; blockNumber: number | null; timestamp: string | null } | null;
  transfers: ProvenanceEntry[];
  history: ProvenanceEntry[];
  /** On-chain state read live from Besu when available (never fabricated). */
  onChain: { custodian: string | null; status: string | null } | null;
}

const MINT_ACTIONS = new Set(["ASSET_CREATED", "ASSET_REGISTERED_ON_CHAIN"]);
const TRANSFER_ACTIONS = new Set(["ASSET_TRANSFERRED", "ASSET_TRANSFERRED_ON_CHAIN"]);
const ASSIGN_ACTIONS = new Set(["ASSET_ASSIGNED", "ASSET_ASSIGNED_ON_CHAIN"]);
const STATUS_ACTIONS = new Set(["ASSET_ACTIVATED", "ASSET_REVOKED", "ASSET_SUSPENDED", "ASSET_STATUS_CHANGED_ON_CHAIN"]);

export async function buildAssetProvenance(input: {
  assetRowId: string;
  /** Optional live on-chain state read by the caller (custodian/status). */
  onChain?: { custodian: string | null; status: string | null } | null;
  /** Operator key for deriving identity reference wallets (server-only). */
  deriveWallet?: (did: string) => string | null;
}): Promise<AssetProvenance | null> {
  const asset = await getAssetById(input.assetRowId);
  if (!asset) return null;

  const [events, custody] = await Promise.all([
    listAssetAuditEvents(asset.assetId, 200),
    listAssetCustody(asset.id),
  ]);

  const didFor = async (identityId: string | null): Promise<string | null> => {
    if (!identityId) return null;
    const identity = await getIdentityById(identityId);
    return identity?.did ?? null;
  };
  const identityBrief = async (identityId: string | null) => {
    if (!identityId) return null;
    const identity = await getIdentityById(identityId);
    if (!identity) return null;
    return {
      identityId: identity.id,
      did: identity.did,
      displayName: identity.displayName,
      walletAddress: input.deriveWallet?.(identity.did) ?? null,
    };
  };

  const history: ProvenanceEntry[] = events.map((event: AuditEvent) => ({
    kind: MINT_ACTIONS.has(event.action)
      ? "MINT"
      : TRANSFER_ACTIONS.has(event.action)
        ? "TRANSFER"
        : ASSIGN_ACTIONS.has(event.action)
          ? "ASSIGNMENT"
          : STATUS_ACTIONS.has(event.action)
            ? "STATUS_CHANGE"
            : "EVENT",
    timestamp: event.timestamp ? new Date(event.timestamp).toISOString() : null,
    actorIdentityId: event.actorIdentityId,
    actorDid: null, // resolved lazily below for actor rows that matter
    transactionHash: event.transactionHash ?? null,
    blockNumber: event.blockNumber ?? null,
    decision: event.decision ?? null,
    reason: event.reason ?? null,
    source: event.source,
  }));
  // Attach actor DIDs for the entries that have an actor (bounded work).
  const actorIds = new Set(history.map(h => h.actorIdentityId).filter((v): v is string => Boolean(v)));
  const didById = new Map<string, string>();
  for (const id of actorIds) {
    const did = await didFor(id);
    if (did) didById.set(id, did);
  }
  for (const entry of history) {
    entry.actorDid = entry.actorIdentityId ? didById.get(entry.actorIdentityId) ?? null : null;
  }

  const mintEvent = history.find(h => h.kind === "MINT") ?? null;
  const transfers = history.filter(h => h.kind === "TRANSFER" || h.kind === "ASSIGNMENT");

  const creator = await identityBrief(asset.ownerIdentityId);
  const currentCustodian = await identityBrief(asset.custodianIdentityId);

  // Previous custodians come from the custody read model (closed intervals).
  const previousCustodians: { identityId: string; did: string; displayName: string; from: string | null; to: string | null }[] = [];
  for (const row of custody) {
    if (row.custodianIdentityId === asset.custodianIdentityId && !row.endedAt) continue;
    const brief = await identityBrief(row.custodianIdentityId);
    if (brief && !previousCustodians.some(p => p.identityId === brief.identityId)) {
      previousCustodians.push({ identityId: brief.identityId, did: brief.did, displayName: brief.displayName, from: row.startedAt ? new Date(row.startedAt).toISOString() : null, to: row.endedAt ? new Date(row.endedAt).toISOString() : null });
    }
  }

  return {
    asset: {
      id: asset.id,
      assetId: asset.assetId,
      name: asset.name,
      type: asset.type,
      classification: asset.classification,
      status: asset.status,
      tokenId: asset.tokenId ?? null,
    },
    creator: creator ? { identityId: creator.identityId, did: creator.did, displayName: creator.displayName, walletAddress: creator.walletAddress } : null,
    creatorWalletAddress: creator?.walletAddress ?? null,
    currentCustodian: currentCustodian ? { identityId: currentCustodian.identityId, did: currentCustodian.did, displayName: currentCustodian.displayName } : null,
    previousCustodians: previousCustodians.filter((p): p is NonNullable<typeof p> => Boolean(p)),
    mint: mintEvent
      ? { transactionHash: mintEvent.transactionHash, blockNumber: mintEvent.blockNumber, timestamp: mintEvent.timestamp }
      : null,
    transfers,
    history: history.sort((a, b) => new Date(a.timestamp ?? 0).getTime() - new Date(b.timestamp ?? 0).getTime()),
    onChain: input.onChain ?? null,
  };
}
