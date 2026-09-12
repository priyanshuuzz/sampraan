/**
 * SAMPRAAN graph module (LOOP 11).
 *
 * The Graph-style indexing/query layer for SAMPRAAN. Deliberately split in
 * two halves so the deployment can grow without the core app ever depending
 * on it:
 *
 *  1. `subgraph/` — a real SAMPRAAN subgraph (subgraph.yaml, schema.graphql,
 *     AssemblyScript mappings) using the ACTUAL event names emitted by the
 *     deployed contracts. Deployable to a local graph-node (see
 *     subgraph/README.md). Requires graph-node + IPFS + Postgres sidecars.
 *
 *  2. THIS client — an always-available query surface with the same entity
 *     shape, served by decoding REAL contract events straight from the Besu
 *     RPC via ethers. It exists so provenance/identity queries work on any
 *     laptop with just the 4-validator network running, and so the core
 *     application NEVER depends on graph-node availability.
 *
 * AUTHORIZATION RULE: this module is query-only. It NEVER participates in
 * ALLOW/DENY/CHALLENGE decisions — the policy engine and smart contracts
 * remain the only authorities.
 */
import { Contract, JsonRpcProvider, type EventLog } from "ethers";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

export interface GraphIdentity {
  wallet: string;
  didDigest: string;
  status: number;
  registeredAt: number;
  lastChangedAt: number;
  blockNumber: number;
  transactionHash: string;
}

export interface GraphAsset {
  tokenId: string;
  assetIdDigest: string;
  classificationDigest: string;
  status: number;
  custodian: string;
  creator: string | null;
  mintTransactionHash: string | null;
  mintBlockNumber: number | null;
  mintedAt: number | null;
}

export interface GraphTransfer {
  tokenId: string;
  fromCustodian: string;
  toCustodian: string;
  operator: string;
  transactionHash: string;
  blockNumber: number;
  timestamp: number;
  kind: "ASSIGNMENT" | "TRANSFER";
}

export interface GraphProvenance {
  asset: GraphAsset | null;
  transfers: GraphTransfer[];
  identityEvents: GraphTransfer[]; // empty for assets; kept for query-shape parity
}

const STATUS_NAMES = ["NONE", "PENDING", "ACTIVE", "SUSPENDED", "REVOKED"] as const;
const IDENTITY_STATUS_NAMES = ["NONE", "ACTIVE", "SUSPENDED", "REVOKED"] as const;

/**
 * Scan window: QBFT produces blocks fast and this Besu RPC caps eth_getLogs
 * ranges (~5k blocks observed live), so the window stays under the cap. The
 * subgraph (graph-node) is the full-history indexer; this client covers the
 * recent window by design.
 */
const DEFAULT_WINDOW = 5_000;

export class GraphQueryService {
  private provider: JsonRpcProvider | null = null;
  private assetRegistry: Contract | null = null;
  private identityRegistry: Contract | null = null;
  private accessControl: Contract | null = null;
  private addresses: Record<string, string> = {};
  private initAttempted = false;

  private ensureContracts(): boolean {
    if (this.assetRegistry && this.identityRegistry) return true;
    if (this.initAttempted) return false;
    this.initAttempted = true;
    try {
      const deploymentPath = resolve(process.cwd(), "blockchain/deployment.json");
      if (!existsSync(deploymentPath)) return false;
      const deployment = JSON.parse(readFileSync(deploymentPath, "utf8"));
      const rpcUrl: string | undefined = process.env.BLOCKCHAIN_RPC_URL ?? deployment.rpcUrl;
      if (!rpcUrl || !deployment.contracts?.SampraanAssetRegistry) return false;
      this.addresses = deployment.contracts;
      // HTTP JSON-RPC (static call + log queries only). A websocket provider
      // here kept a live socket whose 'error' event crashed the API process
      // when the Besu WS port was unreachable — unacceptable for an
      // advisory query layer. JsonRpcProvider is connectionless per request.
      this.provider = new JsonRpcProvider(rpcUrl, undefined, { staticNetwork: true });
      const assetArtifact = JSON.parse(
        readFileSync(resolve(process.cwd(), "blockchain/artifacts/SampraanAssetRegistry.json"), "utf8"),
      );
      const identityArtifact = JSON.parse(
        readFileSync(resolve(process.cwd(), "blockchain/artifacts/SampraanIdentityRegistry.json"), "utf8"),
      );
      const accessArtifact = JSON.parse(
        readFileSync(resolve(process.cwd(), "blockchain/artifacts/SampraanAccessControl.json"), "utf8"),
      );
      this.assetRegistry = new Contract(deployment.contracts.SampraanAssetRegistry, assetArtifact.abi, this.provider);
      this.identityRegistry = new Contract(deployment.contracts.SampraanIdentityRegistry, identityArtifact.abi, this.provider);
      this.accessControl = new Contract(deployment.contracts.SampraanAccessControl, accessArtifact.abi, this.provider);
      return true;
    } catch {
      this.provider = null;
      this.assetRegistry = null;
      this.identityRegistry = null;
      return false;
    }
  }

  /** Is the graph/query layer usable right now? (Advisory: never gates auth.) */
  async status(): Promise<{ available: boolean; mode: "graph-query" | "unavailable"; contracts: Record<string, string>; latestBlock?: number }> {
    if (!this.ensureContracts() || !this.assetRegistry || !this.provider) {
      return { available: false, mode: "unavailable", contracts: this.addresses };
    }
    try {
      const latestBlock = await this.provider.getBlockNumber();
      return { available: true, mode: "graph-query", contracts: this.addresses, latestBlock };
    } catch {
      return { available: false, mode: "unavailable", contracts: this.addresses };
    }
  }

  /** Asset entity by its off-chain assetId (resolved via the contract's digest index). */
  async getAsset(assetId: string): Promise<GraphAsset | null> {
    if (!this.ensureContracts() || !this.assetRegistry || !this.provider) return null;
    try {
      const { keccak256, toUtf8Bytes } = await import("ethers");
      const digest = keccak256(toUtf8Bytes(assetId));
      // resolveAssetId(bytes32) is the contract's deterministic digest→token index.
      const tokenId: bigint = await this.assetRegistry.resolveAssetId(digest);
      if (tokenId === 0n) return null;
      const record = await this.assetRegistry.getAsset(tokenId);
      const mint = await this.findMint(tokenId);
      return {
        tokenId: tokenId.toString(),
        assetIdDigest: String(record.assetIdDigest),
        classificationDigest: String(record.classificationDigest),
        status: Number(record.status),
        custodian: String(record.custodian),
        creator: mint?.creator ?? null,
        mintTransactionHash: mint?.transactionHash ?? null,
        mintBlockNumber: mint?.blockNumber ?? null,
        mintedAt: mint?.timestamp ?? null,
      };
    } catch {
      return null;
    }
  }

  /** Full transfer/assignment history for a tokenId from REAL AssetAssigned/AssetTransferred events. */
  async getTransferHistory(tokenId: string): Promise<GraphTransfer[]> {
    if (!this.ensureContracts() || !this.assetRegistry || !this.provider) return [];
    try {
      const latest = await this.provider.getBlockNumber();
      const from = Math.max(0, latest - DEFAULT_WINDOW);
      const statusFilter = this.assetRegistry.filters.AssetStatusChanged?.(BigInt(tokenId));
      void statusFilter;
      const [assigned, transferred] = await Promise.all([
        this.assetRegistry.queryFilter(this.assetRegistry.filters.AssetAssigned(BigInt(tokenId)), from, latest),
        this.assetRegistry.queryFilter(this.assetRegistry.filters.AssetTransferred(BigInt(tokenId)), from, latest),
      ]);
      const entries: GraphTransfer[] = [];
      for (const log of [...assigned, ...transferred] as EventLog[]) {
        const args = log.args as unknown as Record<string, unknown>;
        const block = await this.provider!.getBlock(log.blockNumber);
        entries.push({
          tokenId: String(args.tokenId),
          fromCustodian: String(args.fromCustodian ?? ""),
          toCustodian: String(args.toCustodian),
          operator: String(args.operator),
          transactionHash: log.transactionHash,
          blockNumber: log.blockNumber,
          timestamp: block?.timestamp ? Number(block.timestamp) : 0,
          kind: log.eventName === "AssetAssigned" ? "ASSIGNMENT" : "TRANSFER",
        });
      }
      return entries.sort((a, b) => a.blockNumber - b.blockNumber);
    } catch {
      return [];
    }
  }

  /** Asset provenance in the same shape the subgraph would serve. */
  async getProvenance(assetId: string): Promise<GraphProvenance> {
    const asset = await this.getAsset(assetId);
    if (!asset) return { asset: null, transfers: [], identityEvents: [] };
    const transfers = await this.getTransferHistory(asset.tokenId);
    return { asset, transfers, identityEvents: [] };
  }

  /** Identity entity by reference wallet from REAL IdentityRegistered/StatusChanged events. */
  async getIdentity(wallet: string): Promise<{ identity: GraphIdentity | null; events: GraphTransfer[] }> {
    if (!this.ensureContracts() || !this.identityRegistry || !this.provider) return { identity: null, events: [] };
    try {
      const latest = await this.provider.getBlockNumber();
      const from = Math.max(0, latest - DEFAULT_WINDOW);
      const registered = await this.identityRegistry.queryFilter(this.identityRegistry.filters.IdentityRegistered(wallet), from, latest);
      const statusChanged = await this.identityRegistry.queryFilter(this.identityRegistry.filters.IdentityStatusChanged(wallet), from, latest);
      if (registered.length === 0) return { identity: null, events: [] };
      const reg = registered[registered.length - 1] as EventLog;
      const args = reg.args as unknown as Record<string, unknown>;
      const identity: GraphIdentity = {
        wallet,
        didDigest: String(args.didDigest),
        status: 1,
        registeredAt: Number(args.registeredAt),
        lastChangedAt: Number(args.registeredAt),
        blockNumber: reg.blockNumber,
        transactionHash: reg.transactionHash,
      };
      const events: GraphTransfer[] = [];
      for (const log of statusChanged as EventLog[]) {
        const sArgs = log.args as unknown as Record<string, unknown>;
        const block = await this.provider!.getBlock(log.blockNumber);
        events.push({
          tokenId: "",
          fromCustodian: IDENTITY_STATUS_NAMES[Number(sArgs.oldStatus)] ?? String(sArgs.oldStatus),
          toCustodian: IDENTITY_STATUS_NAMES[Number(sArgs.newStatus)] ?? String(sArgs.newStatus),
          operator: wallet,
          transactionHash: log.transactionHash,
          blockNumber: log.blockNumber,
          timestamp: block?.timestamp ? Number(block.timestamp) : 0,
          kind: "TRANSFER",
        });
        identity.status = Number(sArgs.newStatus);
        identity.lastChangedAt = block?.timestamp ? Number(block.timestamp) : identity.lastChangedAt;
      }
      return { identity, events };
    } catch {
      return { identity: null, events: [] };
    }
  }

  /** Role events from the access-control contract (RoleGranted/RoleRevoked). */
  async getRoleEvents(windowBlocks = 4_000): Promise<{ action: "RoleGranted" | "RoleRevoked"; role: string; account: string; transactionHash: string; blockNumber: number }[]> {
    if (!this.ensureContracts() || !this.accessControl || !this.provider) return [];
    try {
      const latest = await this.provider.getBlockNumber();
      const from = Math.max(0, latest - windowBlocks);
      const [granted, revoked] = await Promise.all([
        this.accessControl.queryFilter(this.accessControl.filters.RoleGranted(), from, latest),
        this.accessControl.queryFilter(this.accessControl.filters.RoleRevoked(), from, latest),
      ]);
      const out: { action: "RoleGranted" | "RoleRevoked"; role: string; account: string; transactionHash: string; blockNumber: number }[] = [];
      for (const log of [...granted, ...revoked] as EventLog[]) {
        const args = log.args as unknown as Record<string, unknown>;
        out.push({
          action: log.eventName === "RoleGranted" ? "RoleGranted" : "RoleRevoked",
          role: String(args.role),
          account: String(args.account),
          transactionHash: log.transactionHash,
          blockNumber: log.blockNumber,
        });
      }
      return out.sort((a, b) => a.blockNumber - b.blockNumber);
    } catch {
      return [];
    }
  }

  private async findMint(tokenId: bigint): Promise<{ creator: string; transactionHash: string; blockNumber: number; timestamp: number } | null> {
    if (!this.assetRegistry || !this.provider) return null;
    try {
      const latest = await this.provider.getBlockNumber();
      const from = Math.max(0, latest - DEFAULT_WINDOW);
      const logs = (await this.assetRegistry.queryFilter(this.assetRegistry.filters.AssetRegistered(BigInt(tokenId)), from, latest)) as EventLog[];
      if (logs.length === 0) return null;
      const log = logs[0];
      const args = log.args as unknown as Record<string, unknown>;
      const block = await this.provider!.getBlock(log.blockNumber);
      return {
        creator: String(args.custodian),
        transactionHash: log.transactionHash,
        blockNumber: log.blockNumber,
        timestamp: block?.timestamp ? Number(block.timestamp) : 0,
      };
    } catch {
      return null;
    }
  }
}

export const graphQueryService = new GraphQueryService();
