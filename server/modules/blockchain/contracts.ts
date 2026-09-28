/**
 * SAMPRAAN contract ABIs and typed deployment handles for backend use,
 * loaded from the deterministic compile output in blockchain/artifacts.
 *
 * ethers v6 Contract instances are structurally typed at runtime; here we
 * expose thin typed facade classes so the backend gets full type safety
 * for exactly the methods SAMPRAAN uses, without fighting BaseContract
 * variance.
 */
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { Contract, type InterfaceAbi, type Signer } from "ethers";
import { resolveProjectRoot } from "./paths";

const artifactsDir = (): string =>
  path.join(resolveProjectRoot(), "blockchain", "artifacts");

function loadAbi(contractName: string): InterfaceAbi {
  const filePath = path.join(artifactsDir(), `${contractName}.json`);
  if (!existsSync(filePath)) {
    throw new Error(
      `Contract artifact ${contractName} not found. Run "pnpm run contracts:compile".`
    );
  }
  return JSON.parse(readFileSync(filePath, "utf8")).abi as InterfaceAbi;
}

/**
 * ABIs are loaded lazily (BUG-001 regression safety): a missing artifacts
 * directory must only fail the blockchain features that actually need an ABI
 * — never crash the whole server at import time in environments running
 * without a compiled contract suite (e.g. MOCK-mode deployments, first boots).
 */
const lazyAbi = (name: string) => {
  let abi: InterfaceAbi | null = null;
  return () => {
    if (!abi) abi = loadAbi(name);
    return abi;
  };
};

export const getSampraanAccessControlABI = lazyAbi("SampraanAccessControl");
export const getSampraanIdentityRegistryABI = lazyAbi("SampraanIdentityRegistry");
export const getSampraanAssetRegistryABI = lazyAbi("SampraanAssetRegistry");
export const getSampraanGovernanceABI = lazyAbi("SampraanGovernance");

interface ContractLike {
  connect: (signer: Signer) => unknown;
  [key: string]: unknown;
}

function bind(contract: Contract): ContractLike {
  return contract as unknown as ContractLike;
}

function call<T>(fn: unknown, ...args: unknown[]): Promise<T> {
  return (fn as (...a: unknown[]) => Promise<T>)(...args);
}

export class SampraanAccessControlHandle {
  private readonly contract: ContractLike;
  constructor(address: string, abi: InterfaceAbi, signer: Signer) {
    this.contract = bind(new Contract(address, abi, signer));
  }

  IDENTITY_ADMIN_ROLE(): Promise<string> {
    return call<string>(this.contract.IDENTITY_ADMIN_ROLE);
  }

  ASSET_MANAGER_ROLE(): Promise<string> {
    return call<string>(this.contract.ASSET_MANAGER_ROLE);
  }

  AUDITOR_ROLE(): Promise<string> {
    return call<string>(this.contract.AUDITOR_ROLE);
  }

  hasRole(role: string, account: string): Promise<boolean> {
    return call<boolean>(this.contract.hasRole, role, account);
  }

  grantRole(role: string, account: string): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.grantRole, role, account);
  }
}

export interface IdentityRecord {
  didDigest: string;
  publicKeyDigest: string;
  status: bigint;
  registeredAt: bigint;
  statusChangedAt: bigint;
}

export class SampraanIdentityRegistryHandle {
  private readonly contract: ContractLike;
  constructor(address: string, abi: InterfaceAbi, signer: Signer) {
    this.contract = bind(new Contract(address, abi, signer));
  }

  registerIdentity(
    wallet: string,
    didDigest: string,
    publicKeyDigest: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.registerIdentity, wallet, didDigest, publicKeyDigest);
  }

  // GOVERNANCE LIFECYCLE: the old setStatus(wallet, code) was replaced by
  // explicit, reason-carrying lifecycle transitions enforced on-chain.
  verifyIdentity(
    wallet: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.verifyIdentity, wallet, reason);
  }

  suspendIdentity(
    wallet: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.suspendIdentity, wallet, reason);
  }

  reactivateIdentity(
    wallet: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.reactivateIdentity, wallet, reason);
  }

  updateDidDocumentHash(
    documentHash: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.updateDidDocumentHash, documentHash, reason);
  }

  updateDidDocumentHashFor(
    wallet: string,
    documentHash: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.updateDidDocumentHashFor, wallet, documentHash, reason);
  }

  getLifecycleCount(wallet: string): Promise<bigint> {
    return call<bigint>(this.contract.lifecycleCount, wallet);
  }

  getLifecycleEvent(
    wallet: string,
    index: number
  ): Promise<{ fromStatus: bigint; toStatus: bigint; actor: string; reason: string; at: bigint }> {
    return call(this.contract.getLifecycleEvent, wallet, index);
  }

  getIdentity(wallet: string): Promise<IdentityRecord> {
    return call<IdentityRecord>(this.contract.getIdentity, wallet);
  }

  resolveDid(didDigest: string): Promise<string> {
    return call<string>(this.contract.resolveDid, didDigest);
  }

  isActive(wallet: string): Promise<boolean> {
    return call<boolean>(this.contract.isActive, wallet);
  }
}

export interface AssetRecord {
  assetIdDigest: string;
  classificationDigest: string;
  metadataDigest: string;
  status: number;
  custodian: string;
  registeredAt: bigint;
  statusChangedAt: bigint;
}

export class SampraanAssetRegistryHandle {
  private readonly contract: ContractLike;
  constructor(address: string, abi: InterfaceAbi, signer: Signer) {
    this.contract = bind(new Contract(address, abi, signer));
  }

  registerAsset(
    assetIdDigest: string,
    custodian: string,
    classificationDigest: string,
    metadataDigest: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(
      this.contract.registerAsset,
      assetIdDigest,
      custodian,
      classificationDigest,
      metadataDigest
    );
  }

  assignAsset(
    tokenId: bigint,
    custodian: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.assignAsset, tokenId, custodian);
  }

  transferCustody(
    tokenId: bigint,
    toCustodian: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.transferCustody, tokenId, toCustodian);
  }

  activateAsset(tokenId: bigint): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.activateAsset, tokenId);
  }

  suspendAsset(tokenId: bigint): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.suspendAsset, tokenId);
  }

  restoreAsset(tokenId: bigint): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.restoreAsset, tokenId);
  }

  revokeAsset(tokenId: bigint): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.revokeAsset, tokenId);
  }

  getAsset(tokenId: bigint): Promise<AssetRecord> {
    return call<AssetRecord>(this.contract.getAsset, tokenId);
  }

  resolveAssetId(assetIdDigest: string): Promise<bigint> {
    return call<bigint>(this.contract.resolveAssetId, assetIdDigest);
  }

  assetStatus(tokenId: bigint): Promise<number> {
    return call<number>(this.contract.assetStatus, tokenId);
  }

  custodianOf(tokenId: bigint): Promise<string> {
    return call<string>(this.contract.custodianOf, tokenId);
  }

  totalAssets(): Promise<bigint> {
    return call<bigint>(this.contract.totalAssets);
  }

  // Governance-only dispatch (multisig + timelock; NEVER callable directly
  // by the operator — the contract reverts unless msg.sender is governance).
  governanceBurnNFT(
    tokenId: bigint,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.governanceBurnNFT, tokenId, reason);
  }

  governanceForceTransfer(
    tokenId: bigint,
    toCustodian: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.governanceForceTransfer, tokenId, toCustodian, reason);
  }

  governancePause(): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.governancePause);
  }

  governanceUnpause(): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.governanceUnpause);
  }

  paused(): Promise<boolean> {
    return call<boolean>(this.contract.paused);
  }

  isAssetDisputed(tokenId: bigint): Promise<boolean> {
    return call<boolean>(this.contract.isAssetDisputed, tokenId);
  }

  flagAnomaly(
    target: string,
    tokenId: bigint,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.flagAnomaly, target, tokenId, reason);
  }

  raiseDispute(
    tokenId: bigint,
    evidenceHash: string,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.raiseDispute, tokenId, evidenceHash, reason);
  }

  resolveDispute(
    disputeId: bigint,
    upheld: boolean,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.resolveDispute, disputeId, upheld, reason);
  }

  storeAuditReportHash(
    reportHash: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.storeAuditReportHash, reportHash);
  }

  verifyOwnership(tokenId: bigint, wallet: string): Promise<boolean> {
    return call<boolean>(this.contract.verifyOwnership, tokenId, wallet);
  }

  verifyAuthenticity(tokenId: bigint): Promise<boolean> {
    return call<boolean>(this.contract.verifyAuthenticity, tokenId);
  }

  getCustodyHistoryLength(tokenId: bigint): Promise<bigint> {
    return call<bigint>(this.contract.getCustodyHistoryLength, tokenId);
  }

  getCustodyRecord(
    tokenId: bigint,
    index: number
  ): Promise<{ fromCustodian: string; toCustodian: string; operator: string; at: bigint }> {
    return call(this.contract.getCustodyRecord, tokenId, index);
  }

  disputeCount(): Promise<bigint> {
    return call<bigint>(this.contract.disputeCount);
  }

  getDispute(disputeId: bigint): Promise<{
    tokenId: bigint;
    raisedBy: string;
    evidenceHash: string;
    reason: string;
    open: boolean;
    upheld: boolean;
    resolutionReason: string;
    raisedAt: bigint;
    resolvedAt: bigint;
  }> {
    return call(this.contract.getDispute, disputeId);
  }

  anomalyCount(): Promise<bigint> {
    return call<bigint>(this.contract.anomalyCount);
  }

  getAnomaly(anomalyId: bigint): Promise<{ target: string; tokenId: bigint; flaggedBy: string; reason: string; at: bigint }> {
    return call(this.contract.getAnomaly, anomalyId);
  }

  auditReportCount(): Promise<bigint> {
    return call<bigint>(this.contract.auditReportCount);
  }

  getAuditReport(reportId: bigint): Promise<{ auditor: string; reportHash: string; at: bigint }> {
    return call(this.contract.getAuditReport, reportId);
  }
}

export function createAccessControlContract(
  address: string,
  signer: Signer
): SampraanAccessControlHandle {
  return new SampraanAccessControlHandle(address, getSampraanAccessControlABI(), signer);
}

export interface GovernanceProposalCore {
  kind: bigint;
  target: string;
  role: string;
  account: string;
  tokenId: bigint;
  reason: string;
}

export interface GovernanceProposalState {
  createdAt: bigint;
  approvals: bigint;
  requiredApprovals: bigint;
  executableAt: bigint;
  executed: boolean;
  cancelled: boolean;
}

export class SampraanGovernanceHandle {
  private readonly contract: ContractLike;
  constructor(address: string, abi: InterfaceAbi, signer: Signer) {
    this.contract = bind(new Contract(address, abi, signer));
  }

  // Views
  signerCount(): Promise<bigint> {
    return call<bigint>(this.contract.signerCount);
  }

  isSigner(account: string): Promise<boolean> {
    return call<boolean>(this.contract.isSigner, account);
  }

  quorumRequired(): Promise<bigint> {
    return call<bigint>(this.contract.quorumRequired);
  }

  timelockDelaySeconds(): Promise<bigint> {
    return call<bigint>(this.contract.timelockDelaySeconds);
  }

  proposalCount(): Promise<bigint> {
    return call<bigint>(this.contract.proposalCount);
  }

  proposalCore(proposalId: bigint): Promise<GovernanceProposalCore> {
    return call(this.contract.proposalCore, proposalId);
  }

  proposalState(proposalId: bigint): Promise<GovernanceProposalState> {
    return call(this.contract.proposalState, proposalId);
  }

  proposalHasApproval(proposalId: bigint, signer: string): Promise<boolean> {
    return call<boolean>(this.contract.proposalHasApproval, proposalId, signer);
  }

  // Mutations (all signer-gated on-chain)
  propose(
    kind: number,
    target: string,
    role: string,
    account: string,
    tokenId: bigint,
    reason: string
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.propose, kind, target, role, account, tokenId, reason);
  }

  approve(proposalId: bigint, reason: string): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.approve, proposalId, reason);
  }

  cancel(proposalId: bigint, reason: string): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.cancel, proposalId, reason);
  }

  execute(proposalId: bigint): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.execute, proposalId);
  }
}

export function createGovernanceContract(
  address: string,
  signer: Signer
): SampraanGovernanceHandle {
  return new SampraanGovernanceHandle(address, getSampraanGovernanceABI(), signer);
}

export function createIdentityRegistryContract(
  address: string,
  signer: Signer
): SampraanIdentityRegistryHandle {
  return new SampraanIdentityRegistryHandle(address, getSampraanIdentityRegistryABI(), signer);
}

export function createAssetRegistryContract(
  address: string,
  signer: Signer
): SampraanAssetRegistryHandle {
  return new SampraanAssetRegistryHandle(address, getSampraanAssetRegistryABI(), signer);
}
