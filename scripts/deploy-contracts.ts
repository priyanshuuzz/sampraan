/**
 * Deterministic SAMPRAAN contract deployment to the local Besu QBFT network.
 *
 * Flow:
 *   1. Connect to the Besu RPC endpoint (BLOCKCHAIN_RPC_URL, default http://localhost:8545).
 *   2. Deploy SampraanAccessControl, SampraanIdentityRegistry, SampraanAssetRegistry.
 *   3. Grant AUDITOR_ROLE to the auditor account (read-only role).
 *   4. Register the deployer as a chain identity reference (bootstrap identity).
 *   5. Write blockchain/deployment.json with contract addresses + chain metadata.
 *   6. Print a ready-to-use .env snippet for the backend.
 *
 * The deployer account comes from BLOCKCHAIN_PRIVATE_KEY (or a DEMO/LOCAL fallback
 * genesis alloc account when absent — only on the local QBFT chain).
 *
 * Run: pnpm run blockchain:deploy
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { JsonRpcProvider, ContractFactory, Wallet, keccak256, toUtf8Bytes, formatEther } from "ethers";

// DEMO/LOCAL ONLY: first funded account from the Besu QBFT tutorial genesis alloc.
// This is a publicly documented dev key, never a production secret.
const DEMO_LOCAL_DEPLOYER_KEY =
  "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";
const DEMO_LOCAL_AUDITOR_KEY =
  "0xc87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3";
const EXPECTED_CHAIN_ID = 4224;

const root = path.resolve(import.meta.dirname, "..");
const artifactsDir = path.join(root, "blockchain", "artifacts");
const deploymentFile = path.join(root, "blockchain", "deployment.json");

function loadArtifact(name: string) {
  const filePath = path.join(artifactsDir, `${name}.json`);
  if (!existsSync(filePath)) {
    throw new Error(
      `Artifact ${name}.json not found. Run "pnpm run contracts:compile" first.`
    );
  }
  const artifact = JSON.parse(readFileSync(filePath, "utf8"));
  return { abi: artifact.abi as unknown[], bytecode: artifact.bytecode as string };
}

async function main() {
  const rpcUrl = process.env.BLOCKCHAIN_RPC_URL ?? "http://localhost:8545";
  const chainIdEnv = Number(process.env.BLOCKCHAIN_CHAIN_ID ?? EXPECTED_CHAIN_ID);
  const isProduction = process.env.NODE_ENV === "production";
  const privateKey =
    process.env.BLOCKCHAIN_PRIVATE_KEY ?? DEMO_LOCAL_DEPLOYER_KEY;

  // BUG-013 (QA finding #10): the demo genesis fallback key is a PUBLICLY
  // DOCUMENTED development key from the Besu QBFT tutorial. Deploying with
  // it in production would hand the entire contract suite (admin roles, the
  // identity and asset registries) to anyone who has read the tutorial. Any
  // real environment must provide its own key explicitly.
  if (
    isProduction &&
    (!process.env.BLOCKCHAIN_PRIVATE_KEY ||
      privateKey === DEMO_LOCAL_DEPLOYER_KEY)
  ) {
    throw new Error(
      "Refusing to deploy with the DEMO/LOCAL genesis key under NODE_ENV=production. Set BLOCKCHAIN_PRIVATE_KEY to a real operator key."
    );
  }
  if (!process.env.BLOCKCHAIN_PRIVATE_KEY) {
    console.warn(
      "[DEPLOY] WARNING: using the DEMO/LOCAL genesis deployer key (development only). Set BLOCKCHAIN_PRIVATE_KEY for any real deployment."
    );
  }

  const provider = new JsonRpcProvider(rpcUrl, chainIdEnv, {
    staticNetwork: true,
  });

  // Fail fast and clearly when the network is not reachable.
  let network;
  try {
    network = await provider.getNetwork();
  } catch (error) {
    throw new Error(
      `Cannot reach Besu at ${rpcUrl}. Start the network with "docker compose -f blockchain/network/docker-compose.yml up -d". (${String(error)})`
    );
  }
  if (Number(network.chainId) !== chainIdEnv) {
    throw new Error(
      `Chain ID mismatch: RPC reports ${Number(network.chainId)}, expected ${chainIdEnv}. Refusing to deploy.`
    );
  }

  const deployer = new Wallet(privateKey, provider);
  const auditor = new Wallet(process.env.BLOCKCHAIN_AUDITOR_PRIVATE_KEY ?? DEMO_LOCAL_AUDITOR_KEY, provider);
  const deployerBalance = await provider.getBalance(deployer.address);
  console.log(`Connected to Besu  chainId=${chainIdEnv}  rpc=${rpcUrl}`);
  console.log(`Deployer  ${deployer.address}  balance=${formatEther(deployerBalance)} ETH`);
  console.log(`Auditor   ${auditor.address}`);
  if (deployerBalance === 0n) {
    throw new Error(
      "Deployer account has no balance. Fund it or point BLOCKCHAIN_PRIVATE_KEY at a funded account."
    );
  }

  const accessControlArtifact = loadArtifact("SampraanAccessControl");
  const identityArtifact = loadArtifact("SampraanIdentityRegistry");
  const assetArtifact = loadArtifact("SampraanAssetRegistry");

  // 1. Access control
  const acFactory = new ContractFactory(
    accessControlArtifact.abi,
    accessControlArtifact.bytecode,
    deployer
  );
  const accessControl = await acFactory.deploy();
  await accessControl.waitForDeployment();
  const accessControlAddress = await accessControl.getAddress();
  console.log(`SampraanAccessControl        ${accessControlAddress}`);

  // 2. Identity registry
  const identityFactory = new ContractFactory(
    identityArtifact.abi,
    identityArtifact.bytecode,
    deployer
  );
  const identityRegistry = await identityFactory.deploy(accessControlAddress);
  await identityRegistry.waitForDeployment();
  const identityRegistryAddress = await identityRegistry.getAddress();
  console.log(`SampraanIdentityRegistry     ${identityRegistryAddress}`);

  // 3. Asset registry
  const assetFactory = new ContractFactory(
    assetArtifact.abi,
    assetArtifact.bytecode,
    deployer
  );
  const assetRegistry = await assetFactory.deploy(
    accessControlAddress,
    identityRegistryAddress
  );
  await assetRegistry.waitForDeployment();
  const assetRegistryAddress = await assetRegistry.getAddress();
  console.log(`SampraanAssetRegistry       ${assetRegistryAddress}`);

  // 4. Grant the auditor address its read-only role.
  const AUDITOR_ROLE = await accessControl.AUDITOR_ROLE();
  const grantTx = await accessControl.grantRole(AUDITOR_ROLE, auditor.address);
  await grantTx.wait();
  console.log(`Granted AUDITOR_ROLE to     ${auditor.address}`);

  // 5. Bootstrap: register deployer + auditor as ACTIVE chain identity references
  //    (DID digests are deterministic placeholders for the demo identity set).
  const deployerDid = `did:ethr:${deployer.address.toLowerCase()}`;
  const auditorDid = `did:ethr:${auditor.address.toLowerCase()}`;
  const didDigest = (did: string) => keccak256(toUtf8Bytes(did));

  const regDeployer = await identityRegistry.registerIdentity(
    deployer.address,
    didDigest(deployerDid),
    keccak256(toUtf8Bytes(`pk:${deployer.address.toLowerCase()}`))
  );
  await regDeployer.wait();
  console.log(`Registered identity ${deployerDid}`);

  const regAuditor = await identityRegistry.registerIdentity(
    auditor.address,
    didDigest(auditorDid),
    keccak256(toUtf8Bytes(`pk:${auditor.address.toLowerCase()}`))
  );
  await regAuditor.wait();
  console.log(`Registered identity ${auditorDid}`);

  const deployment = {
    network: "SAMPRAAN-LOCAL-QBFT",
    chainId: chainIdEnv,
    rpcUrl,
    deployedAt: new Date().toISOString(),
    deployerAddress: deployer.address,
    auditorAddress: auditor.address,
    contracts: {
      SampraanAccessControl: accessControlAddress,
      SampraanIdentityRegistry: identityRegistryAddress,
      SampraanAssetRegistry: assetRegistryAddress,
    },
  };
  writeFileSync(deploymentFile, JSON.stringify(deployment, null, 2) + "\n");
  console.log(`\nWrote ${path.relative(root, deploymentFile)}`);

  console.log(`\nBackend environment (add to .env or export):`);
  console.log(`  BLOCKCHAIN_RPC_URL=${rpcUrl}`);
  console.log(`  BLOCKCHAIN_CHAIN_ID=${chainIdEnv}`);
  console.log(`  BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS=${identityRegistryAddress}`);
  console.log(`  BLOCKCHAIN_ASSET_CONTRACT_ADDRESS=${assetRegistryAddress}`);
  console.log(`  BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS=${accessControlAddress}`);
  console.log(
    `  BLOCKCHAIN_PRIVATE_KEY=<your operator key - NOT the demo genesis key in production>`
  );
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
