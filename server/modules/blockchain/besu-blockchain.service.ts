/**
 * SAMPRAAN Besu blockchain adapter â€” REAL chain integration.
 *
 * Replaces the mock behavior with a production-shaped service:
 *  - provider + signer initialization (ethers v6)
 *  - contract bindings (access control, identity, asset registries)
 *  - network health/status
 *  - identity registration / status updates
 *  - asset mint / assign / transfer / status updates
 *  - transaction submission + receipt handling with full evidence
 *  - event reading for audit projection
 *
 * SECURITY MODEL:
 *  The backend authorization engine (authorization.service.ts) decides whether
 *  a request SHOULD be submitted. This adapter then executes it on-chain where
 *  the smart contract INDEPENDENTLY re-verifies role, identity status, and asset
 *  state before the transition. The backend is never the final authorization
 *  authority for protected state transitions â€” the contract is.
 *
 * No private keys are logged, persisted, or transmitted anywhere except to
 * sign in-memory transactions.
 */
import {
  Interface,
  JsonRpcProvider,
  Wallet,
  keccak256,
  toUtf8Bytes,
  type InterfaceAbi,
  type Log,
  type TransactionReceipt,
} from "ethers";
import { resolveBlockchainConfig, type BlockchainConfig } from "./blockchain.config";
import {
  createAccessControlContract,
  createAssetRegistryContract,
  createIdentityRegistryContract,
  getSampraanAccessControlABI,
  getSampraanAssetRegistryABI,
  getSampraanIdentityRegistryABI,
  type SampraanAccessControlHandle,
  type SampraanAssetRegistryHandle,
  type SampraanIdentityRegistryHandle,
} from "./contracts";
import type {
  BlockchainOperationInput,
  ChainEvent,
  NetworkStatus,
  TransactionEvidence,
} from "./blockchain.types";

const IDENTITY_STATUS_CODES = { ACTIVE: 1, SUSPENDED: 2, REVOKED: 3 } as const;

export class BesuBlockchainService {
  readonly config: BlockchainConfig;
  private provider: JsonRpcProvider | null = null;
  private signer: Wallet | null = null;
  private identityContract: SampraanIdentityRegistryHandle | null = null;
  private assetContract: SampraanAssetRegistryHandle | null = null;
  private accessControlContract: SampraanAccessControlHandle | null = null;
  private initPromise: Promise<void> | null = null;

  constructor(config: BlockchainConfig = resolveBlockchainConfig()) {
    this.config = config;
  }

  /**
   * Lazy single initialization so importing this module never requires a
   * reachable chain. Fails clearly when configuration is incomplete.
   */
  private async ensureInitialized(): Promise<void> {
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.initialize();
    return this.initPromise;
  }

  private async initialize(): Promise<void> {
    const { mode, rpcUrl, chainId, privateKey } = this.config;
    if (mode !== "BESU" || !privateKey) {
      throw new Error(
        `Besu blockchain is not configured (mode=${mode}). Set BLOCKCHAIN_PRIVATE_KEY and the contract addresses, or run "pnpm run blockchain:deploy", to enable the real chain.`
      );
    }

    this.provider = new JsonRpcProvider(rpcUrl, chainId, { staticNetwork: true });
    this.signer = new Wallet(privateKey, this.provider);

    // BUG-014: verify the connected network actually IS the configured chain
    // before binding contract addresses. Without this, a mis-pointed RPC
    // (or a replayed deployment.json against a different network) would
    // silently produce calls to non-existent contracts on the wrong chain,
    // surfacing as opaque revert errors instead of a clear mismatch message.
    const network = await this.provider.getNetwork();
    if (Number(network.chainId) !== chainId) {
      this.initPromise = null;
      throw new Error(
        `Chain ID mismatch: RPC at ${rpcUrl} reports chain ${Number(network.chainId)}, expected ${chainId}. Refusing to bind SAMPRAAN contracts to the wrong network. Check BLOCKCHAIN_CHAIN_ID / BLOCKCHAIN_RPC_URL.`
      );
    }

    this.accessControlContract = createAccessControlContract(
      this.requireAddress(this.config.accessControlContractAddress, "access control"),
      this.signer
    );
    this.identityContract = createIdentityRegistryContract(
      this.requireAddress(this.config.identityContractAddress, "identity"),
      this.signer
    );
    this.assetContract = createAssetRegistryContract(
      this.requireAddress(this.config.assetContractAddress, "asset"),
      this.signer
    );
  }

  private requireAddress(value: string | null, what: string): string {
    if (!value) {
      throw new Error(`Missing ${what} contract address (BLOCKCHAIN_*_CONTRACT_ADDRESS).`);
    }
    return value;
  }

  // ----------------------------------------------------------------
  // Network health / status
  // ----------------------------------------------------------------

  async getNetworkStatus(): Promise<NetworkStatus> {
    try {
      await this.ensureInitialized();
      const provider = this.provider!;
      const [blockNumber, network, clientVersion] = await Promise.all([
        provider.getBlockNumber(),
        provider.getNetwork(),
        provider
          .send("web3_clientVersion", [])
          .catch(() => undefined) as Promise<string | undefined>,
      ]);
      return {
        connected: true,
        mode: "BESU",
        network: "SAMPRAAN-LOCAL-QBFT",
        latestBlock: blockNumber,
        chainId: Number(network.chainId),
        nodeVersion: clientVersion ?? undefined,
      };
    } catch (error) {
      return {
        connected: false,
        mode: "BESU",
        network: "SAMPRAAN-LOCAL-QBFT",
        latestBlock: 0,
        chainId: this.config.chainId,
        error: error instanceof Error && error.message
          ? error.message
          : String(error),
      };
    }
  }

  async getLatestBlock(): Promise<number> {
    await this.ensureInitialized();
    return this.provider!.getBlockNumber();
  }

  /**
   * Signing wallet address. Derived from configuration alone so it never
   * requires a reachable chain.
   */
  get operatorAddress(): string {
    if (this.signer) return this.signer.address;
    if (!this.config.privateKey) {
      throw new Error("Besu service has no operator key configured");
    }
    return new Wallet(this.config.privateKey).address;
  }

  // ----------------------------------------------------------------
  // Identity operations
  // ----------------------------------------------------------------

  /**
   * Register a SAMPRAAN identity reference on-chain. The raw DID stays
   * off-chain; only its keccak256 digest is anchored.
   */
  async registerIdentity(input: {
    did: string;
    walletAddress: string;
    publicKeyDigest?: string;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const didDigest = keccak256(toUtf8Bytes(input.did));
    const publicKeyDigest =
      input.publicKeyDigest ?? keccak256(toUtf8Bytes(`pk:${input.did}`));
    const tx = await this.identityContract!.registerIdentity(
      input.walletAddress,
      didDigest,
      publicKeyDigest
    );
    return this.awaitEvidence(tx, "IDENTITY_REGISTER");
  }

  async setIdentityStatus(input: {
    walletAddress: string;
    status: keyof typeof IDENTITY_STATUS_CODES;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const statusCode = IDENTITY_STATUS_CODES[input.status];
    if (!statusCode) {
      throw new Error(`Invalid identity status: ${input.status}`);
    }
    const tx = await this.identityContract!.setStatus(
      input.walletAddress,
      statusCode
    );
    return this.awaitEvidence(tx, "IDENTITY_STATUS_CHANGE");
  }

  async getIdentity(walletAddress: string): Promise<{
    didDigest: string;
    publicKeyDigest: string;
    status: number;
    registeredAt: bigint;
    statusChangedAt: bigint;
  } | null> {
    await this.ensureInitialized();
    const record = await this.identityContract!.getIdentity(walletAddress);
    if (record.status === 0n) return null;
    return {
      didDigest: record.didDigest,
      publicKeyDigest: record.publicKeyDigest,
      status: Number(record.status),
      registeredAt: record.registeredAt,
      statusChangedAt: record.statusChangedAt,
    };
  }

  async resolveDid(did: string): Promise<string> {
    await this.ensureInitialized();
    return this.identityContract!.resolveDid(keccak256(toUtf8Bytes(did)));
  }

  // ----------------------------------------------------------------
  // Asset operations
  // ----------------------------------------------------------------

  /**
   * Register (mint) an enterprise asset on-chain. Metadata/classification
   * are passed as digests; the actual content stays off-chain.
   */
  async registerAsset(input: {
    assetId: string;
    custodianWallet: string;
    classification: string;
    metadataReference: string;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tx = await this.assetContract!.registerAsset(
      keccak256(toUtf8Bytes(input.assetId)),
      input.custodianWallet,
      keccak256(toUtf8Bytes(input.classification)),
      keccak256(toUtf8Bytes(input.metadataReference))
    );
    return this.awaitEvidence(tx, "ASSET_REGISTER");
  }

  async assignAsset(input: {
    assetId: string;
    custodianWallet: string;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    const tx = await this.assetContract!.assignAsset(tokenId, input.custodianWallet);
    return this.awaitEvidence(tx, "ASSET_ASSIGN");
  }

  /**
   * Controlled custody transfer. Executed only after the backend policy
   * engine has ALLOWed the request; the contract re-verifies everything.
   */
  async transferAsset(input: {
    assetId: string;
    toCustodianWallet: string;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    const tx = await this.assetContract!.transferCustody(
      tokenId,
      input.toCustodianWallet
    );
    return this.awaitEvidence(tx, "ASSET_TRANSFER");
  }

  async setAssetStatus(input: {
    assetId: string;
    status: "ACTIVATE" | "SUSPEND" | "RESTORE" | "REVOKE";
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    const contract = this.assetContract!;
    const tx = await {
      ACTIVATE: () => contract.activateAsset(tokenId),
      SUSPEND: () => contract.suspendAsset(tokenId),
      RESTORE: () => contract.restoreAsset(tokenId),
      REVOKE: () => contract.revokeAsset(tokenId),
    }[input.status]();
    return this.awaitEvidence(tx, "ASSET_STATUS_CHANGE");
  }

  async getAsset(assetId: string): Promise<{
    tokenId: bigint;
    assetIdDigest: string;
    classificationDigest: string;
    metadataDigest: string;
    status: number;
    custodian: string;
  } | null> {
    await this.ensureInitialized();
    const tokenId = await this.assetContract!.resolveAssetId(
      keccak256(toUtf8Bytes(assetId))
    );
    if (tokenId === 0n) return null;
    const record = await this.assetContract!.getAsset(tokenId);
    return {
      tokenId,
      assetIdDigest: record.assetIdDigest,
      classificationDigest: record.classificationDigest,
      metadataDigest: record.metadataDigest,
      status: record.status,
      custodian: record.custodian,
    };
  }

  private async requireAssetToken(assetId: string): Promise<bigint> {
    const tokenId = await this.assetContract!.resolveAssetId(
      keccak256(toUtf8Bytes(assetId))
    );
    if (tokenId === 0n) {
      throw new Error(`Asset ${assetId} is not registered on-chain`);
    }
    return tokenId;
  }

  // ----------------------------------------------------------------
  // Transaction evidence / receipts
  // ----------------------------------------------------------------

  async getTransaction(transactionHash: string): Promise<TransactionEvidence | null> {
    await this.ensureInitialized();
    const receipt: TransactionReceipt | null =
      await this.provider!.getTransactionReceipt(transactionHash);
    if (!receipt) return null;
    return this.receiptToEvidence(receipt);
  }

  /**
   * Read on-chain events emitted by the SAMPRAAN contracts between two
   * blocks. Used by the audit/indexer projection.
   */
  async getEvents(input?: {
    fromBlock?: number;
    toBlock?: number;
  }): Promise<ChainEvent[]> {
    await this.ensureInitialized();
    const provider = this.provider!;
    const latest = await provider.getBlockNumber();
    const fromBlock = input?.fromBlock ?? Math.max(0, latest - 100);
    const toBlock = input?.toBlock ?? latest;

    const addresses = [
      this.config.identityContractAddress,
      this.config.assetContractAddress,
    ].filter((a): a is string => Boolean(a));
    if (addresses.length === 0) return [];

    const logs = await provider.getLogs({
      fromBlock,
      toBlock,
      address: addresses,
    });

    const events: ChainEvent[] = [];
    for (const log of logs) {
      const parsed = this.parseLog(log);
      if (parsed) events.push(parsed);
    }
    return events;
  }

  // ----------------------------------------------------------------
  // Generic operation surface (compatible with the former mock API)
  // ----------------------------------------------------------------

  /**
   * Submit a typed SAMPRAAN operation. Routes to the contract method that
   * matches the action; returns transaction evidence on success and throws
   * a safe, descriptive error when the chain rejects the operation.
   */
  async submitTransaction(
    input: BlockchainOperationInput
  ): Promise<TransactionEvidence> {
    const { action, payload } = input;
    const p = payload as Record<string, string>;
    switch (action) {
      case "IDENTITY_REGISTER":
        return this.registerIdentity({
          did: p.did,
          walletAddress: p.walletAddress,
          publicKeyDigest: p.publicKeyDigest,
        });
      case "IDENTITY_STATUS_CHANGE":
        return this.setIdentityStatus({
          walletAddress: p.walletAddress,
          status: p.status as keyof typeof IDENTITY_STATUS_CODES,
        });
      case "ASSET_REGISTER":
        return this.registerAsset({
          assetId: p.assetId,
          custodianWallet: p.custodianWallet,
          classification: p.classification,
          metadataReference: p.metadataReference,
        });
      case "ASSET_ASSIGN":
        return this.assignAsset({
          assetId: p.assetId,
          custodianWallet: p.custodianWallet,
        });
      case "ASSET_TRANSFER":
        return this.transferAsset({
          assetId: p.assetId,
          toCustodianWallet: p.toCustodianWallet,
        });
      case "ASSET_STATUS_CHANGE":
        return this.setAssetStatus({
          assetId: p.assetId,
          status: p.status as "ACTIVATE" | "SUSPEND" | "RESTORE" | "REVOKE",
        });
      default:
        throw new Error(`Unsupported blockchain action: ${String(action)}`);
    }
  }

  // ----------------------------------------------------------------
  // Internal evidence helpers
  // ----------------------------------------------------------------

  private async awaitEvidence(
    tx: { wait: (confirmations?: number) => Promise<unknown> },
    action: string
  ): Promise<TransactionEvidence> {
    const receipt = (await tx.wait(1)) as TransactionReceipt | null;
    if (!receipt) {
      throw new Error(`Transaction for ${action} was not mined`);
    }
    if (receipt.status !== 1) {
      // The chain rejected the operation: report failure safely.
      throw new Error(
        `On-chain ${action} reverted in transaction ${receipt.hash} (block ${receipt.blockNumber})`
      );
    }
    return this.receiptToEvidence(receipt);
  }

  private receiptToEvidence(receipt: TransactionReceipt): TransactionEvidence {
    return {
      transactionHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      blockHash: receipt.blockHash,
      status: receipt.status === 1 ? "CONFIRMED" : "FAILED",
      contractAddress: receipt.contractAddress ?? undefined,
      from: receipt.from,
      to: receipt.to ?? undefined,
      gasUsed: Number(receipt.gasUsed),
      events: (receipt.logs ?? []).map(log => this.parseLog(log)).filter(
        (e): e is ChainEvent => e !== null
      ),
    };
  }

  private parseLog(log: Log): ChainEvent | null {
    const candidates: Array<[InterfaceAbi, string | null]> = [
      [getSampraanIdentityRegistryABI(), this.config.identityContractAddress],
      [getSampraanAssetRegistryABI(), this.config.assetContractAddress],
      [getSampraanAccessControlABI(), this.config.accessControlContractAddress],
    ];
    for (const [abi, address] of candidates) {
      if (!address) continue;
      if (log.address.toLowerCase() !== address.toLowerCase()) continue;
      try {
        const iface = new Interface(abi);
        const parsed = iface.parseLog({ topics: log.topics, data: log.data });
        if (!parsed) continue;
        const args: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(parsed.args as Record<string, unknown>)) {
          if (typeof value === "bigint") {
            args[key] = value.toString();
          } else if (value !== null && typeof value === "object" && "toString" in value) {
            args[key] = String(value);
          } else {
            args[key] = value;
          }
        }
        return {
          name: parsed.name ?? "Unknown",
          address: log.address,
          blockNumber: log.blockNumber,
          transactionHash: log.transactionHash,
          args,
        };
      } catch {
        continue;
      }
    }
    return null;
  }
}
