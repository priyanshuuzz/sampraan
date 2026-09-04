/**
 * Deterministic Solidity compile step for SAMPRAAN contracts.
 *
 * Uses the locally-pinned solc npm package (no external compiler download) so
 * the build is reproducible. The pinned solcjs WASM build does not support
 * import callbacks, so every transitive dependency (including OpenZeppelin)
 * is inlined into the standard-JSON input: local sources under their natural
 * relative keys and OpenZeppelin sources under a virtual "oz/" prefix, with
 * "@openzeppelin/contracts/" imports rewritten to that prefix.
 *
 * Run: pnpm run contracts:compile
 */
import { mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import solc from "solc";

const root = path.resolve(import.meta.dirname, "..");
const contractsDir = path.join(root, "contracts");
const artifactsDir = path.join(root, "blockchain", "artifacts");
const ozContractsRoot = path.join(root, "node_modules", "@openzeppelin", "contracts");

const ROOT_SOURCES = [
  "SampraanAccessControl.sol",
  "SampraanIdentityRegistry.sol",
  "SampraanAssetRegistry.sol",
] as const;

interface SolcInput {
  language: "Solidity";
  sources: Record<string, { content: string }>;
  settings: {
    optimizer: { enabled: boolean; runs: number };
    evmVersion: string;
    outputSelection: Record<string, Record<string, string[]>>;
  };
}

const OZ_PREFIX = "@openzeppelin/contracts/";
const VIRTUAL_OZ = "oz/";
const IMPORT_RE = /import\s+(?:\{[^}]*\}\s+from\s+)?["']([^"']+)["']/g;

function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

function collectSources(): Record<string, { content: string }> {
  const sources: Record<string, { content: string }> = {};
  const seen = new Set<string>();

  function addFile(diskPath: string, sourceKey: string) {
    const key = toPosix(sourceKey);
    if (seen.has(key)) return;
    seen.add(key);
    const rawContent = readFileSync(diskPath, "utf8");
    // Rewrite OpenZeppelin imports to the virtual prefix.
    const content = rawContent.split(OZ_PREFIX).join(VIRTUAL_OZ);
    sources[key] = { content };

    let match: RegExpExecArray | null;
    IMPORT_RE.lastIndex = 0;
    while ((match = IMPORT_RE.exec(content)) !== null) {
      const imported = match[1];
      if (imported.startsWith(VIRTUAL_OZ)) {
        const rel = imported.slice(VIRTUAL_OZ.length);
        addFile(path.join(ozContractsRoot, rel), VIRTUAL_OZ + rel);
      } else if (!path.isAbsolute(imported)) {
        const childDisk = path.resolve(path.dirname(diskPath), imported);
        const childKey = toPosix(path.posix.join(path.posix.dirname(key), imported));
        addFile(childDisk, childKey);
      }
    }
  }

  for (const source of ROOT_SOURCES) {
    addFile(path.join(contractsDir, source), source);
  }
  return sources;
}

async function main() {
  const sources = collectSources();

  const input: SolcInput = {
    language: "Solidity",
    sources,
    settings: {
      // "paris" targets the pre-Shanghai EVM (no PUSH0). This is deliberately
      // chosen for maximum compatibility with any Besu/QBFT milestone
      // configuration while keeping identical semantics for our contracts.
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "paris",
      outputSelection: {
        "*": {
          "*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"],
        },
      },
    },
  };

  const compiled = JSON.parse(solc.compile(JSON.stringify(input)));

  const errors = (compiled.errors ?? []) as Array<{ severity: string; formattedMessage: string }>;
  const realErrors = errors.filter(e => e.severity === "error");
  if (realErrors.length > 0) {
    for (const error of realErrors) console.error(error.formattedMessage);
    throw new Error(`Solidity compilation failed with ${realErrors.length} error(s)`);
  }
  for (const warning of errors) {
    if (warning.severity === "warning") console.warn("[solc]", warning.formattedMessage);
  }

  rmSync(artifactsDir, { recursive: true, force: true });
  mkdirSync(artifactsDir, { recursive: true });

  const written: string[] = [];
  for (const [fileName, contractData] of Object.entries(
    compiled.contracts as Record<string, Record<string, unknown>>
  )) {
    for (const [contractName, data] of Object.entries(contractData)) {
      const artifact = {
        contractName,
        source: fileName,
        abi: (data as { abi: unknown }).abi,
        bytecode:
          "0x" + ((data as { evm: { bytecode: { object: string } } }).evm.bytecode.object),
        deployedBytecode:
          "0x" +
          ((data as { evm: { deployedBytecode: { object: string } } }).evm.deployedBytecode.object),
      };
      const outPath = path.join(artifactsDir, `${contractName}.json`);
      writeFileSync(outPath, JSON.stringify(artifact, null, 2) + "\n");
      written.push(path.relative(root, outPath));
    }
  }

  console.log(`Compiled ${written.length} SAMPRAAN contract(s) to blockchain/artifacts:`);
  for (const file of written.sort()) console.log(`  ${file}`);
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});
