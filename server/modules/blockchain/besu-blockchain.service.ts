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
  NonceManager,
  Wallet,
  keccak256,
  toUtf8Bytes,
  type InterfaceAbi,
  type Log,
  type TransactionReceipt,
} from "ethers";
import { resolveBlockchainConfig, type BlockchainConfig } from "./blockchain.config";
import { deriveIdentityWallet } from "./anchoring.service";
import {
  createAccessControlContract,
  createAssetRegistryContract,
  createGovernanceContract,
  createIdentityRegistryContract,
  getSampraanAccessControlABI,
  getSampraanAssetRegistryABI,
  getSampraanGovernanceABI,
  getSampraanIdentityRegistryABI,
  type SampraanAccessControlHandle,
  type SampraanAssetRegistryHandle,
  type SampraanGovernanceHandle,
  type SampraanIdentityRegistryHandle,
} from "./contracts";
import type {
  BlockchainOperationInput,
  ChainEvent,
  NetworkStatus,
  TransactionEvidence,
} from "./blockchain.types";

const IDENTITY_STATUS_CODES = { ACTIVE: 1, SUSPENDED: 2, REVOKED: 3 } as const;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTES32 = "0x0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Upper bound for any single RPC round-trip used by health/status surfaces.
 * A HUNG validator (paused container, network partition, grey failure)
 * otherwise blocks /health, /ready and every chain-touching request for
 * the provider default timeout (60s+). Degraded state must be reported in
 * seconds, not minutes.
 */
const STATUS_RPC_TIMEOUT_MS = 5_000;

/** Reject with a clear error after ms. */
function withTimeout<T>(task: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(what + " timed out after " + ms + "ms (chain RPC unresponsive)")),
      ms
    );
    task.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      }
    );
  });
}

export class BesuBlockchainService {
  readonly config: BlockchainConfig;
  private provider: JsonRpcProvider | null = null;
  private signer: NonceManager | null = null;
  private identityContract: SampraanIdentityRegistryHandle | null = null;
  private assetContract: SampraanAssetRegistryHandle | null = null;
  private accessControlContract: SampraanAccessControlHandle | null = null;
  private governanceContract: SampraanGovernanceHandle | null = null;
  private governanceApprover: SampraanGovernanceHandle | null = null;
  private initPromise: Promise<void> | null = null;
  /** Serializes submit→mine→evidence cycles; see initialize() BUG-034 note. */
  private submitMutex: Promise<unknown> = Promise.resolve();

  constructor(config: BlockchainConfig = resolveBlockchainConfig()) {
    this.config = config;
  }

  /**
   * Run `task` so that at most ONE signed submit-to-receipt cycle is in flight
   * for the shared operator key at any time. Failures do not poison the
   * chain: the next caller starts a fresh link.
   *
   * AUDIT FIX (BUG-036 hardening): each cycle starts with a nonce reset so the
   * send reads a FRESH pending count from the chain instead of a cache that
   * may predate pool events (dropped txs, a second process sharing the
   * operator key). A send rejected with a nonce error (the tx provably never
   * entered the pool) is retried exactly once against the refreshed count,
   * self-healing instead of failing the user operation.
   */
  enqueueSubmit<T>(task: () => Promise<T>): Promise<T> {
    const attempt = async (): Promise<T> => {
      this.signer?.reset();
      try {
        return await task();
      } catch (error) {
        if (BesuBlockchainService.isNonceError(error)) {
          this.signer?.reset();
          return await task();
        }
        throw error;
      }
    };
    const run = this.submitMutex.then(attempt, attempt);
    this.submitMutex = run.catch(() => undefined);
    return run;
  }

  /**
   * A send-time nonce rejection: the transaction never entered the pool, so
   * retrying after a nonce refresh cannot double-submit. Matches the ethers
   * error code plus the raw Besu/Geth messages that arrive wrapped differently.
   */
  private static isNonceError(error: unknown): boolean {
    if (!error || typeof error !== "object") return false;
    const code = (error as { code?: unknown }).code;
    if (code === "NONCE_EXPIRED" || code === "NONCE_COLLISION" || code === -32001) return true;
    const message =
      typeof (error as { message?: unknown }).message === "string"
        ? (error as { message: string }).message.toLowerCase()
        : "";
    return /nonce (has already been used|too low)|already known|replacement transaction/.test(message);
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
    // BUG-034 (presentation reliability): every SAMPRAAN operation — identity
    // anchor + asset mint + activation during a single create flow, or a
    // manager transfer racing the periodic indexer — is signed by the SAME
    // operator key. With a bare Wallet, two concurrent sends both fetch the
    // same pending nonce, so one replaces the other ("replacement transaction
    // underpriced" / "already known" / intermittent mint failures).
    // NonceManager serializes nonce allocation for this signer instance; the
    // submitMutex below additionally serializes whole submit→receipt cycles
    // so evidence is recorded in submission order.
    this.signer = new NonceManager(new Wallet(privateKey, this.provider));

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
    // GOVERNANCE (multisig + timelock): bound only when deployed/configured.
    // `governanceApprover` uses a SECOND signer key so the backend can drive
    // the full 2-of-N propose→approve→execute cycle; it is null when no
    // second key is configured (propose still works via the operator).
    if (this.config.governanceContractAddress) {
      this.governanceContract = createGovernanceContract(
        this.config.governanceContractAddress,
        this.signer
      );
      if (this.config.secondSignerPrivateKey) {
        this.governanceApprover = createGovernanceContract(
          this.config.governanceContractAddress,
          new NonceManager(new Wallet(this.config.secondSignerPrivateKey, this.provider))
        );
      }
    }
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
      // Bounded: a hung RPC must degrade to connected:false within seconds,
      // never stall the health/readiness surface for the provider default.
      await withTimeout(this.ensureInitialized(), STATUS_RPC_TIMEOUT_MS, "chain initialization");
      const provider = this.provider!;
      const [blockNumber, network, clientVersion] = await withTimeout(
        Promise.all([
          provider.getBlockNumber(),
          provider.getNetwork(),
          provider
            .send("web3_clientVersion", [])
            .catch(() => undefined) as Promise<string | undefined>,
        ]),
        STATUS_RPC_TIMEOUT_MS,
        "chain status query"
      );
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
          : error instanceof Error && error.name
            ? `${error.name}${(error as Error & { code?: unknown }).code ? ` (${(error as Error & { code?: unknown }).code})` : ""}`
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
    // NonceManager exposes the wrapped signer via its `signer` property.
    const inner = this.signer?.signer as Wallet | undefined;
    if (inner) return inner.address;
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
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.identityContract!.registerIdentity(
        input.walletAddress,
        didDigest,
        publicKeyDigest
      );
      evidence = await this.awaitEvidence(tx, "IDENTITY_REGISTER");
    });
    return evidence!;
  }

  /**
   * Promote an on-chain identity from PENDING to VERIFIED.
   *
   * The GOVERNANCE revision of the identity registry registers identities as
   * PENDING: registration alone grants no protected-operation rights, and the
   * contract refuses to make a PENDING identity an asset custodian or a
   * transfer recipient (CustodianNotActive / RecipientNotActive). Promotion is
   * a separate, attributed, reason-carrying step.
   *
   * Deliberately NOT idempotent-in-the-loose-sense: it is a no-op (returns
   * null) unless the current on-chain state is exactly PENDING, so a SUSPENDED
   * or DEACTIVATED identity is never silently re-activated from here.
   */
  async verifyIdentityOnChain(input: {
    walletAddress: string;
    reason?: string;
  }): Promise<TransactionEvidence | null> {
    await this.ensureInitialized();
    const PENDING = 1n;
    const current = await this.identityContract!.getIdentity(
      input.walletAddress
    );
    if (current.status !== PENDING) return null;
    const reason =
      input.reason?.trim() || "identity verified by platform provisioning";
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.identityContract!.verifyIdentity(
        input.walletAddress,
        reason
      );
      evidence = await this.awaitEvidence(tx, "IDENTITY_STATUS_CHANGE");
    });
    return evidence!;
  }

  async setIdentityStatus(input: {
    walletAddress: string;
    status: keyof typeof IDENTITY_STATUS_CODES;
    reason?: string;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const reason = input.reason?.trim() || `status change to ${input.status}`;
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      // The GOVERNANCE revision of the identity registry replaced the raw
      // setStatus(code) surface with explicit, reason-carrying transitions
      // whose preconditions are enforced on-chain. Map the caller's target
      // state onto the CURRENT on-chain state (a revoke of a PENDING
      // identity, for example, must fail — deactivation is governance-only,
      // so “revoke” is interpreted as best-effort suspend when possible).
      const current = await this.identityContract!.getIdentity(input.walletAddress);
      if (current.status === 0n) {
        throw new Error(`Identity ${input.walletAddress} is not registered on-chain`);
      }
      const VERIFIED = 2n;
      const suspended = input.status === "SUSPENDED" || input.status === "REVOKED";
      let tx;
      if (suspended && current.status === VERIFIED) {
        tx = await this.identityContract!.suspendIdentity(input.walletAddress, reason);
      } else if (!suspended) {
        // Target ACTIVE: PENDING→verify, SUSPENDED→reactivate.
        if (current.status === 1n) {
          tx = await this.identityContract!.verifyIdentity(input.walletAddress, reason);
        } else {
          tx = await this.identityContract!.reactivateIdentity(input.walletAddress, reason);
        }
      } else {
        throw new Error(
          `Identity ${input.walletAddress} cannot be suspended from on-chain state ${current.status} (already inactive, or deactivation requires a governance proposal)`
        );
      }
      evidence = await this.awaitEvidence(tx, "IDENTITY_STATUS_CHANGE");
    });
    return evidence!;
  }

  /**
   * GOVERNANCE: propose an identity DEACTIVATION (terminal state). On-chain
   * this is reachable ONLY through the multisig — there is no direct admin
   * path by design.
   */
  async proposeDeactivateIdentity(input: {
    walletAddress: string;
    reason: string;
  }): Promise<{ proposalId: bigint }> {
    // Deactivation is TERMINAL — route through the same audited multisig
    // path as every other high-risk operation (binds exact parameters,
    // requires quorum + timelock, cannot execute twice).
    const { proposalId } = await this.proposeGovernanceAction({
      kind: "DEACTIVATE_IDENTITY",
      account: input.walletAddress,
      reason: input.reason,
    });
    return { proposalId };
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
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.registerAsset(
        keccak256(toUtf8Bytes(input.assetId)),
        input.custodianWallet,
        keccak256(toUtf8Bytes(input.classification)),
        keccak256(toUtf8Bytes(input.metadataReference))
      );
      evidence = await this.awaitEvidence(tx, "ASSET_REGISTER");
    });
    return evidence!;
  }

  async assignAsset(input: {
    assetId: string;
    custodianWallet: string;
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.assignAsset(tokenId, input.custodianWallet);
      evidence = await this.awaitEvidence(tx, "ASSET_ASSIGN");
    });
    return evidence!;
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
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.transferCustody(
        tokenId,
        input.toCustodianWallet
      );
      evidence = await this.awaitEvidence(tx, "ASSET_TRANSFER");
    });
    return evidence!;
  }

  async setAssetStatus(input: {
    assetId: string;
    status: "ACTIVATE" | "SUSPEND" | "RESTORE" | "REVOKE";
  }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    const contract = this.assetContract!;
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await {
        ACTIVATE: () => contract.activateAsset(tokenId),
        SUSPEND: () => contract.suspendAsset(tokenId),
        RESTORE: () => contract.restoreAsset(tokenId),
        REVOKE: () => contract.revokeAsset(tokenId),
      }[input.status]();
      evidence = await this.awaitEvidence(tx, "ASSET_STATUS_CHANGE");
    });
    return evidence!;
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
  // GOVERNANCE (multisig + timelock) — propose/approve/cancel/execute
  // ----------------------------------------------------------------

  private requireGovernance(): SampraanGovernanceHandle {
    if (!this.governanceContract) {
      throw new Error(
        "Governance contract is not configured (BLOCKCHAIN_GOVERNANCE_CONTRACT_ADDRESS / deployment.json missing SampraanGovernance)."
      );
    }
    return this.governanceContract;
  }

  /** Extract the proposal id from a ProposalCreated log in a receipt. */
  private extractProposalId(receipt: TransactionReceipt): bigint {
    for (const log of receipt.logs ?? []) {
      const parsed = this.parseLog(log);
      if (parsed && parsed.name === "ProposalCreated") {
        const pid = (parsed.args as Record<string, unknown>).proposalId;
        if (typeof pid !== "undefined" && pid !== null) return BigInt(String(pid));
      }
    }
    throw new Error("ProposalCreated event not found in transaction receipt");
  }

  /**
   * Propose a high-risk governance operation. Parameters are BOUND at
   * proposal time on-chain; approvals attach to this exact binding.
   */
  async proposeGovernanceAction(input: {
    kind: "GRANT_ROLE" | "REVOKE_ROLE" | "BURN_NFT" | "FORCE_TRANSFER" | "PAUSE_REGISTRY" | "UNPAUSE_REGISTRY" | "DEACTIVATE_IDENTITY";
    target?: string;
    role?: string;
    account?: string;
    assetId?: string;
    reason: string;
  }): Promise<{ proposalId: bigint; executableAt: bigint; requiredApprovals: bigint }> {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    const accessControlAddress = this.requireAddress(this.config.accessControlContractAddress, "access control");
    const assetRegistryAddress = this.requireAddress(this.config.assetContractAddress, "asset");
    const identityRegistryAddress = this.requireAddress(this.config.identityContractAddress, "identity");
    const kinds = { GRANT_ROLE: 1, REVOKE_ROLE: 2, BURN_NFT: 3, FORCE_TRANSFER: 4, PAUSE_REGISTRY: 5, UNPAUSE_REGISTRY: 6, DEACTIVATE_IDENTITY: 7 } as const;
    const kind = kinds[input.kind];
    const target =
      input.target ??
      (input.kind === "BURN_NFT" || input.kind === "FORCE_TRANSFER" || input.kind === "PAUSE_REGISTRY" || input.kind === "UNPAUSE_REGISTRY"
        ? assetRegistryAddress
        : input.kind === "DEACTIVATE_IDENTITY"
          ? identityRegistryAddress
          : accessControlAddress);
    if ((input.kind === "BURN_NFT" || input.kind === "FORCE_TRANSFER") && !input.assetId) {
        throw new Error(`${input.kind} requires an assetId`);
    }
    if ((input.kind === "GRANT_ROLE" || input.kind === "REVOKE_ROLE" || input.kind === "DEACTIVATE_IDENTITY") && !input.account) {
      throw new Error(`${input.kind} requires an account`);
    }
    let proposalId = 0n;
    await this.enqueueSubmit(async () => {
      const tokenId = input.assetId ? await this.requireAssetToken(input.assetId) : 0n;
      const tx = await gov.propose(
        kind,
        target,
        input.role ?? ZERO_BYTES32,
        input.account ?? ZERO_ADDRESS,
        tokenId,
        input.reason
      );
      const receipt = (await tx.wait(1)) as TransactionReceipt | null;
      if (!receipt || receipt.status !== 1) throw new Error(`Governance proposal was not mined`);
      proposalId = this.extractProposalId(receipt);
    });
    const state = await gov.proposalState(proposalId);
    return { proposalId, executableAt: state.executableAt, requiredApprovals: state.requiredApprovals };
  }

  /** Second-signer approval (auditor fixture key). No-op-safe when absent. */
  async approveGovernanceProposal(input: { proposalId: bigint; reason?: string }): Promise<{ approvals: bigint; requiredApprovals: bigint }> {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    if (!this.governanceApprover) {
      throw new Error("No second governance signer key configured (BLOCKCHAIN_AUDITOR_PRIVATE_KEY); cannot approve");
    }
    // The approver key is an independent signer with its own NonceManager,
    // so the operator submit-mutex does not apply; a single in-flight
    // approval is enforced by the on-chain AlreadyApproved guard anyway.
    const tx = await this.governanceApprover.approve(input.proposalId, input.reason ?? "");
    await this.awaitEvidence(tx, "GOVERNANCE_APPROVE");
    const state = await gov.proposalState(input.proposalId);
    return { approvals: state.approvals, requiredApprovals: state.requiredApprovals };
  }

  /** Cancel a pending proposal (signer-gated on-chain). */
  async cancelGovernanceProposal(input: { proposalId: bigint; reason: string }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await gov.cancel(input.proposalId, input.reason);
      evidence = await this.awaitEvidence(tx, "GOVERNANCE_CANCEL");
    });
    return evidence!;
  }

  /**
   * Execute a proposal that reached quorum AND whose timelock elapsed.
   * On-chain reverts for: below quorum (NotApprovedEnough), early execution
   * (TimelockNotElapsed), double execution (AlreadyExecuted), cancelled
   * (ProposalNotPending) — the contract is the enforcement authority.
   */
  async executeGovernanceProposal(input: { proposalId: bigint }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await gov.execute(input.proposalId);
      evidence = await this.awaitEvidence(tx, "GOVERNANCE_EXECUTE");
    });
    return evidence!;
  }

  async getGovernanceProposal(input: { proposalId: bigint }) {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    const [core, state] = await Promise.all([gov.proposalCore(input.proposalId), gov.proposalState(input.proposalId)]);
    return {
      proposalId: Number(input.proposalId),
      kind: Number(core.kind),
      target: core.target,
      role: core.role,
      account: core.account,
      tokenId: core.tokenId.toString(),
      reason: core.reason,
      createdAt: Number(state.createdAt),
      approvals: Number(state.approvals),
      requiredApprovals: Number(state.requiredApprovals),
      executableAt: Number(state.executableAt),
      executed: state.executed,
      cancelled: state.cancelled,
      operatorApproved: await gov.proposalHasApproval(input.proposalId, this.operatorAddress),
    };
  }

  async listGovernanceProposals(input?: { limit?: number }) {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    const count = Number(await gov.proposalCount());
    const limit = Math.min(input?.limit ?? 50, 200);
    const start = Math.max(1, count - limit + 1);
    const jobs: Promise<Awaited<ReturnType<BesuBlockchainService["getGovernanceProposal"]>>>[] = [];
    for (let id = count; id >= start; id--) {
      jobs.push(this.getGovernanceProposal({ proposalId: BigInt(id) }));
    }
    return Promise.all(jobs);
  }

  async getGovernanceStatus() {
    await this.ensureInitialized();
    const gov = this.requireGovernance();
    const [signers, quorum, delay, count] = await Promise.all([
      gov.signerCount(),
      gov.quorumRequired(),
      gov.timelockDelaySeconds(),
      gov.proposalCount(),
    ]);
    return {
      signerCount: Number(signers),
      quorumRequired: Number(quorum),
      timelockDelaySeconds: Number(delay),
      proposalCount: Number(count),
      secondSignerConfigured: Boolean(this.governanceApprover),
    };
  }

  // ----------------------------------------------------------------
  // AUDITOR evidence surfaces (flag-only; never ownership/permission changes)
  // ----------------------------------------------------------------

  async flagAnomaly(input: { targetWallet: string; assetId: string | null; reason: string }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const tokenId = input.assetId ? await this.requireAssetToken(input.assetId) : 0n;
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.flagAnomaly(input.targetWallet, tokenId, input.reason);
      evidence = await this.awaitEvidence(tx, "ANOMALY_FLAG");
    });
    return evidence!;
  }

  async raiseDispute(input: { assetId: string; evidenceHash: string; reason: string }): Promise<TransactionEvidence & { disputeId: bigint }> {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    let evidence: TransactionEvidence;
    let disputeId = 0n;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.raiseDispute(tokenId, input.evidenceHash, input.reason);
      evidence = await this.awaitEvidence(tx, "DISPUTE_RAISE");
      disputeId = this.extractDisputeId(evidence);
    });
    return { ...evidence!, disputeId };
  }

  async resolveDispute(input: { disputeId: bigint; upheld: boolean; reason: string }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.resolveDispute(input.disputeId, input.upheld, input.reason);
      evidence = await this.awaitEvidence(tx, "DISPUTE_RESOLVE");
    });
    return evidence!;
  }

  async storeAuditReportHash(input: { reportHash: string }): Promise<TransactionEvidence & { reportId: bigint }> {
    await this.ensureInitialized();
    let evidence: TransactionEvidence;
    let reportId = 0n;
    await this.enqueueSubmit(async () => {
      const tx = await this.assetContract!.storeAuditReportHash(input.reportHash);
      evidence = await this.awaitEvidence(tx, "AUDIT_REPORT_STORE");
      for (const e of evidence!.events ?? []) {
        const args = e.args as Record<string, unknown> | undefined;
        if (e.name === "AuditReportHashStored" && args && typeof args.reportId !== "undefined") {
          reportId = BigInt(args.reportId as string);
        }
      }
    });
    return { ...evidence!, reportId };
  }

  /** §13 auditor verification reads (public views on the registry). */
  async verifyAssetAuthenticity(tokenId: bigint): Promise<boolean> {
    await this.ensureInitialized();
    return this.assetContract!.verifyAuthenticity(tokenId);
  }

  async verifyAssetOwnership(tokenId: bigint, wallet: string): Promise<boolean> {
    await this.ensureInitialized();
    return this.assetContract!.verifyOwnership(tokenId, wallet);
  }

  async getOwnershipHistory(input: { assetId: string }) {
    await this.ensureInitialized();
    const tokenId = await this.requireAssetToken(input.assetId);
    const length = Number(await this.assetContract!.getCustodyHistoryLength(tokenId));
    const records: Array<{ fromCustodian: string; toCustodian: string; operator: string; at: bigint }> = [];
    for (let i = 0; i < length; i++) {
      records.push(await this.assetContract!.getCustodyRecord(tokenId, i));
    }
    return records;
  }

  /**
   * DID document update (versioned on-chain). Submitted by the operator via
   * updateDidDocumentHashFor — the SESSION-AUTHENTICATED controller path:
   * identity wallets are server-derived references and hold no keys, so the
   * backend IS the authenticated controller channel.
   */
  async updateDidDocument(input: { did: string; documentHash: string; reason: string }): Promise<TransactionEvidence> {
    await this.ensureInitialized();
    const operatorKey = this.config.privateKey;
    if (!operatorKey) throw new Error("Operator key not configured");
    const walletAddress = deriveIdentityWallet(operatorKey, input.did);
    let evidence: TransactionEvidence;
    await this.enqueueSubmit(async () => {
      const tx = await this.identityContract!.updateDidDocumentHashFor(walletAddress, input.documentHash, input.reason);
      evidence = await this.awaitEvidence(tx, "DID_DOCUMENT_UPDATE");
    });
    return evidence!;
  }

  /**
   * AUDITOR-key flag/dispute/report submission: uses the SECOND signer when
   * it is an actual auditor key (the contract enforces AUDITOR_ROLE for
   * flagAnomaly/raiseDispute/storeAuditReportHash). Falls back to null when
   * no second signer is configured — callers then fail with a clear error.
   */
  private async withAuditorSigner<T>(task: (auditor: SampraanAssetRegistryHandle) => Promise<T>): Promise<T> {
    await this.ensureInitialized();
    if (!this.config.secondSignerPrivateKey) {
      throw new Error("Auditor signer is not configured (BLOCKCHAIN_AUDITOR_PRIVATE_KEY)");
    }
    const auditorAsset = createAssetRegistryContract(
      this.requireAddress(this.config.assetContractAddress, "asset"),
      new NonceManager(new Wallet(this.config.secondSignerPrivateKey, this.provider))
    );
    return task(auditorAsset);
  }

  async auditorFlagAnomaly(input: { targetWallet: string; assetId: string | null; reason: string }): Promise<TransactionEvidence> {
    const tokenId = input.assetId ? await this.requireAssetToken(input.assetId) : 0n;
    let evidence: TransactionEvidence;
    await this.withAuditorSigner(async auditor => {
      const tx = await auditor.flagAnomaly(input.targetWallet, tokenId, input.reason);
      evidence = await this.awaitEvidence(tx, "ANOMALY_FLAG");
    });
    return evidence!;
  }

  async auditorRaiseDispute(input: { assetId: string; evidenceHash: string; reason: string }): Promise<TransactionEvidence & { disputeId: bigint }> {
    const tokenId = await this.requireAssetToken(input.assetId);
    let evidence: TransactionEvidence;
    let disputeId = 0n;
    await this.withAuditorSigner(async auditor => {
      const tx = await auditor.raiseDispute(tokenId, input.evidenceHash, input.reason);
      evidence = await this.awaitEvidence(tx, "DISPUTE_RAISE");
      disputeId = this.extractDisputeId(evidence);
    });
    return { ...evidence!, disputeId };
  }

  async auditorStoreAuditReportHash(input: { reportHash: string }): Promise<TransactionEvidence & { reportId: bigint }> {
    let evidence: TransactionEvidence;
    let reportId = 0n;
    await this.withAuditorSigner(async auditor => {
      const tx = await auditor.storeAuditReportHash(input.reportHash);
      evidence = await this.awaitEvidence(tx, "AUDIT_REPORT_STORE");
      for (const e of evidence.events ?? []) {
        const args = e.args as Record<string, unknown> | undefined;
        if (e.name === "AuditReportHashStored" && args && typeof args.reportId !== "undefined") {
          reportId = BigInt(args.reportId as string);
        }
      }
    });
    return { ...evidence!, reportId };
  }

  private extractDisputeId(evidence: TransactionEvidence): bigint {
    for (const e of evidence.events ?? []) {
      if (e.name === "DisputeRaised") {
        const args = e.args as Record<string, unknown>;
        if (typeof args.disputeId !== "undefined") return BigInt(args.disputeId as string);
      }
    }
    throw new Error("DisputeRaised event not found in receipt");
  }

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
      this.config.accessControlContractAddress,
      this.config.governanceContractAddress,
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
      // GOVERNANCE events (ProposalCreated/Approved/Executed/Cancelled) join
      // the indexed read model — idempotent by (transactionHash, logIndex).
      ...(this.config.governanceContractAddress
        ? [[getSampraanGovernanceABI(), this.config.governanceContractAddress] as [InterfaceAbi, string]]
        : []),
    ];
    for (const [abi, address] of candidates) {
      if (!address) continue;
      if (log.address.toLowerCase() !== address.toLowerCase()) continue;
      try {
        const iface = new Interface(abi);
        const parsed = iface.parseLog({ topics: log.topics, data: log.data });
        if (!parsed) continue;
        // ethers v6 stores NAMED Result properties non-enumerably, so
        // Object.entries/keys on the Result itself only surface positional
        // indices ("0","1",...). extractProposalId and the chain-event
        // indexer read named keys (proposalId, tokenId, wallet, didDigest),
        // which silently never existed — ProposalCreated receipts parsed
        // fine yet the id extraction still threw. Convert via the Result
        // API instead: toObject() yields named keys, toArray() positional.
        const convert = (value: unknown): unknown => {
          if (typeof value === "bigint") return value.toString();
          if (value !== null && typeof value === "object" && "toString" in value && !Array.isArray(value)) return String(value);
          return value;
        };
        const args: Record<string, unknown> = {};
        const named =
          typeof (parsed.args as { toObject?: unknown }).toObject === "function"
            ? (parsed.args.toObject() as Record<string, unknown>)
            : null;
        if (named && Object.keys(named).length > 0) {
          for (const [key, value] of Object.entries(named)) args[key] = convert(value);
        } else {
          const positional =
            typeof (parsed.args as { toArray?: unknown }).toArray === "function"
              ? (parsed.args.toArray() as unknown[])
              : [];
          positional.forEach((value, index) => {
            args[String(index)] = convert(value);
          });
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
