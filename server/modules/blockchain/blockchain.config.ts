/**
 * Blockchain adapter configuration.
 *
 * Environment-driven, explicit, and fail-safe: when Besu configuration is
 * incomplete the adapter factory falls back to MOCK mode and every real-chain
 * operation throws a clear configuration error instead of silently pretending
 * a real blockchain exists.
 */
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { resolveProjectRoot } from "./paths";

export interface BlockchainConfig {
  mode: "BESU" | "MOCK";
  rpcUrl: string;
  chainId: number;
  privateKey: string | null;
  identityContractAddress: string | null;
  assetContractAddress: string | null;
  accessControlContractAddress: string | null;
}

export interface DeploymentRecord {
  network: string;
  chainId: number;
  rpcUrl: string;
  contracts: {
    SampraanAccessControl: string;
    SampraanIdentityRegistry: string;
    SampraanAssetRegistry: string;
  };
}

const deploymentFile = (): string =>
  path.join(resolveProjectRoot(), "blockchain", "deployment.json");

function readDeployment(): DeploymentRecord | null {
  try {
    const file = deploymentFile();
    if (!existsSync(file)) return null;
    return JSON.parse(readFileSync(file, "utf8")) as DeploymentRecord;
  } catch {
    return null;
  }
}

function isConfigured(address: string | undefined | null): address is string {
  return typeof address === "string" && /^0x[0-9a-fA-F]{40}$/.test(address);
}

function isPrivateKey(value: string | undefined | null): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

/**
 * Resolve blockchain configuration from the environment, then from the last
 * deterministic deployment record (blockchain/deployment.json written by
 * pnpm run blockchain:deploy). BESU mode is only enabled when ALL required
 * values are present; anything missing degrades to MOCK with the reason
 * reported through NetworkStatus.error.
 */
export function resolveBlockchainConfig(): BlockchainConfig {
  const deployment = readDeployment();

  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL ?? deployment?.rpcUrl ?? "http://localhost:8545";
  const chainId = Number(
    process.env.BLOCKCHAIN_CHAIN_ID ?? deployment?.chainId ?? 4224
  );
  const privateKey = isPrivateKey(process.env.BLOCKCHAIN_PRIVATE_KEY)
    ? process.env.BLOCKCHAIN_PRIVATE_KEY
    : null;
  const identityContractAddress =
    process.env.BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS ??
    deployment?.contracts.SampraanIdentityRegistry ??
    null;
  const assetContractAddress =
    process.env.BLOCKCHAIN_ASSET_CONTRACT_ADDRESS ??
    deployment?.contracts.SampraanAssetRegistry ??
    null;
  const accessControlContractAddress =
    process.env.BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS ??
    deployment?.contracts.SampraanAccessControl ??
    null;

  const besuReady =
    isPrivateKey(privateKey) &&
    isConfigured(identityContractAddress) &&
    isConfigured(assetContractAddress) &&
    isConfigured(accessControlContractAddress);

  return {
    mode: besuReady ? "BESU" : "MOCK",
    rpcUrl,
    chainId,
    privateKey,
    identityContractAddress,
    assetContractAddress,
    accessControlContractAddress,
  };
}
