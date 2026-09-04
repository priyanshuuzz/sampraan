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

const root = path.resolve(import.meta.dirname, "..", "..", "..");
const artifactsDir = path.join(root, "blockchain", "artifacts");

function loadAbi(contractName: string): InterfaceAbi {
  const filePath = path.join(artifactsDir, `${contractName}.json`);
  if (!existsSync(filePath)) {
    throw new Error(
      `Contract artifact ${contractName} not found. Run "pnpm run contracts:compile".`
    );
  }
  return JSON.parse(readFileSync(filePath, "utf8")).abi as InterfaceAbi;
}

export const SampraanAccessControlABI = loadAbi("SampraanAccessControl");
export const SampraanIdentityRegistryABI = loadAbi("SampraanIdentityRegistry");
export const SampraanAssetRegistryABI = loadAbi("SampraanAssetRegistry");

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

  setStatus(
    wallet: string,
    status: number
  ): Promise<{ wait: (c?: number) => Promise<unknown> }> {
    return call(this.contract.setStatus, wallet, status);
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
}

export function createAccessControlContract(
  address: string,
  signer: Signer
): SampraanAccessControlHandle {
  return new SampraanAccessControlHandle(address, SampraanAccessControlABI, signer);
}

export function createIdentityRegistryContract(
  address: string,
  signer: Signer
): SampraanIdentityRegistryHandle {
  return new SampraanIdentityRegistryHandle(address, SampraanIdentityRegistryABI, signer);
}

export function createAssetRegistryContract(
  address: string,
  signer: Signer
): SampraanAssetRegistryHandle {
  return new SampraanAssetRegistryHandle(address, SampraanAssetRegistryABI, signer);
}
