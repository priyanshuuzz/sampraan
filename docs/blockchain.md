# SAMPRAAN Blockchain Layer — Hyperledger Besu QBFT

> **This is a permissioned enterprise blockchain prototype for asset
> provenance and on-chain authorization enforcement. It is NOT a public NFT
> marketplace, has no cryptocurrency/token economics, and no public
> marketplace behavior.**

## Architecture Overview

```
DID / Identity (off-chain W3C DIDs, did:ethr references)
        ↓
SAMPRAAN Authorization (backend policy engine — advisory)
        ↓
Smart Contract Authorization (on-chain RBAC + state validation — FINAL AUTHORITY)
        ↓
Asset State Transition (identity/asset registries)
        ↓
Blockchain Transaction (QBFT consensus, 4 validators)
        ↓
Event (IdentityRegistered, AssetTransferred, ...)
        ↓
Audit / Indexer / Read Model (MySQL audit_events, source: CHAIN_READ_MODEL)
```

### Division of responsibility

| Layer | Role |
|---|---|
| **Blockchain (Besu/QBFT)** | Authoritative state-transition and provenance evidence layer. Anchors identity lifecycle status and controlled asset custody as tamper-evident on-chain records. |
| **MySQL 8** | Application/read model. Full application data, DID documents, asset metadata, audit query projections. The database is NOT moved on-chain. |
| **Off-chain storage** | Sensitive documents, firmware binaries, PII. Only keccak256 digests are stored on-chain. |

## Why Besu + QBFT

- **Hyperledger Besu** is an enterprise-grade permissioned EVM client: full
  Ethereum tooling (Solidity, OpenZeppelin, ethers.js) with permissioned
  network controls — exactly the SIH requirement (identity, access control,
  asset management on a controlled network).
- **QBFT** (Quorum Istanbul BFT) gives immediate finality (no reorgs — critical
  for evidence), CFT/BFT tolerance with 4+ validators, and deterministic
  block times (2 s in our genesis), which keeps demos and tests reproducible.
- EVM compatibility lets SAMPRAAN reuse audited OpenZeppelin primitives
  (ERC-721, AccessControl) instead of inventing new crypto.

## Smart Contracts

| Contract | File | Responsibility |
|---|---|---|
| `SampraanAccessControl` | `contracts/SampraanAccessControl.sol` | On-chain RBAC registry. Roles: `IDENTITY_ADMIN_ROLE` (identity ops), `ASSET_MANAGER_ROLE` (asset ops), `AUDITOR_ROLE` (read-only). Admin manages roles only — least privilege by construction. |
| `SampraanIdentityRegistry` | `contracts/SampraanIdentityRegistry.sol` | Anchors SAMPRAAN identity references: keccak256(DID) → wallet address, public-key digest, ACTIVE/SUSPENDED/REVOKED lifecycle. No PII on-chain. |
| `SampraanAssetRegistry` | `contracts/SampraanAssetRegistry.sol` | Controlled ERC-721 asset registry. Each asset is a unique token carrying only digests (asset ID, classification, metadata reference). Custody transfer via `transferCustody` only — `approve`/`setApprovalForAll`/`transferFrom`/`safeTransferFrom` are permanently disabled. |

### Identity model (DID integration)

SAMPRAAN identities are W3C DIDs managed off-chain (`did_records` table,
`did:ethr:...` method). The chain stores only:

- `didDigest` — keccak256 of the DID string (the DID itself stays off-chain)
- `publicKeyDigest` — keccak256 of the associated verification material
- lifecycle status (ACTIVE / SUSPENDED / REVOKED) and timestamps

Concepts are deliberately distinct: the **W3C DID concept** (off-chain
document), the **did:ethr method** (address-derived identifiers), and the
**blockchain address** (wallet that acts for the identity on-chain).

### On-chain authorization enforcement (SECURITY CRITICAL)

The backend policy engine (`authorization.service.ts`) decides whether a
request should be submitted. The smart contract then **independently
re-verifies** the caller's role, actor identity status, and asset state
before any transition. AI/security intelligence is advisory only; the chain
is the final authority on protected state transitions:

- unauthorized role cannot mint / register / transfer
- revoked identity cannot receive or hold active custody
- suspended/revoked assets are frozen (no transfers)
- every state transition validates status and zero-address checks
- all marketplace primitives are disabled — custody changes only via the
  guarded `transferCustody` path

### Events (audit projection source)

`IdentityRegistered`, `IdentityStatusChanged`, `AssetRegistered`,
`AssetAssigned`, `AssetTransferred`, `AssetStatusChanged`, plus
OpenZeppelin `RoleGranted`/`RoleRevoked`/`Transfer`. Events carry digests
and addresses only — never PII or sensitive content.

## Running the Local Network

Prerequisites: Docker with Docker Compose.

```bash
# Start the 4-validator QBFT network (RPC on http://localhost:8545)
pnpm run blockchain:start

# Verify consensus is producing blocks
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Stop the network
pnpm run blockchain:stop

# Full reset (also wipes chain state volumes)
docker compose -f blockchain/network/docker-compose.yml down -v
```

Network files live in `blockchain/network/`:

- `qbftConfigFile.json` — QBFT genesis definition (chain ID 4224, 2 s blocks)
- `generated/genesis.json` — genesis produced by
  `besu operator generate-blockchain-config` (includes validator extraData)
- `generated/keys/<address>/key{,.pub}` — validator node keys (DEMO/LOCAL ONLY; **gitignored** — regenerate with `besu operator generate-blockchain-config --config-file=qbftConfigFile.json --to=generated --private-key-file-name=key`)
- `config/config-validator-*.toml` — per-validator mining/p2p config
- `config/static-nodes.json` — the four deterministic enode peer addresses
- `docker-compose.yml` — 4 validators on a fixed `172.28.0.0/16` subnet
  (validator-1 also exposes RPC :8545 and WS :8546)

Funded accounts (from the public Besu QBFT tutorial — DEMO/LOCAL ONLY keys):

| Account | Address | Use |
|---|---|---|
| Deployer/operator | `0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73` | deploys contracts, holds all admin roles |
| Auditor | `0x627306090abaB3A6e1400e9345bC60c78a8BEf57` | holds AUDITOR_ROLE (read-only) |
| Second identity | `0xf17f52151EbEF6C7334FAD080c5704D77216b732` | test custodian |

> These private keys are publicly documented development keys. They appear in
> this repository ONLY because this is a local demo chain. **Never use them on
> any real network.**

## Deploying Contracts

With the network running:

```bash
pnpm run contracts:compile     # solc 0.8.30 → blockchain/artifacts/*.json
pnpm run blockchain:deploy     # deploys + configures roles + writes blockchain/deployment.json
```

The deploy script:

1. connects to Besu (refuses on chain-ID mismatch),
2. deploys `SampraanAccessControl` → `SampraanIdentityRegistry` → `SampraanAssetRegistry`,
3. grants `AUDITOR_ROLE` to the auditor account,
4. registers deployer + auditor as bootstrap ACTIVE identities,
5. writes `blockchain/deployment.json` (contract addresses, chain metadata),
6. prints a ready-to-use `.env` snippet.

The backend reads contract addresses from `blockchain/deployment.json`
automatically; explicit `BLOCKCHAIN_*_CONTRACT_ADDRESS` env vars override it.

## Configuring the Backend

```bash
cp .env.example .env
# Fill in BLOCKCHAIN_PRIVATE_KEY (operator key)
pnpm run dev
```

Environment variables (see `.env.example`):

| Variable | Meaning |
|---|---|
| `BLOCKCHAIN_RPC_URL` | Besu JSON-RPC endpoint (default http://localhost:8545) |
| `BLOCKCHAIN_CHAIN_ID` | Expected chain ID (default 4224) |
| `BLOCKCHAIN_PRIVATE_KEY` | Operator signing key — required for BESU mode |
| `BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS` | Override identity registry address |
| `BLOCKCHAIN_ASSET_CONTRACT_ADDRESS` | Override asset registry address |
| `BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS` | Override access control address |

**Fail-safe behavior:** when configuration is incomplete the service falls
back to MOCK mode and every mutating chain operation throws a clear
configuration error — the backend never silently pretends a real blockchain
is available. `NetworkStatus.mode` (`"BESU" | "MOCK"`) tells every caller
exactly which backend answered.

## Backend Integration

- `server/modules/blockchain/besu-blockchain.service.ts` — the real adapter
  (provider, signer, contract handles, evidence extraction, event parsing)
- `server/modules/blockchain/blockchain.service.ts` — facade preserving the
  original `blockchainService` surface consumed by `routers.ts` and health
  endpoints; routes to Besu or the mock by configuration
- `server/modules/blockchain/chain-event-indexer.ts` — projects on-chain
  events into the existing `audit_events` read model
  (`source: CHAIN_READ_MODEL`)
- `server/routers.ts` — `assets.authorizeTransfer` now:
  1. evaluates policy (backend),
  2. submits to the chain where the contract re-verifies everything,
  3. records a successful transfer audit event **with transactionHash +
     blockNumber + blockHash evidence**,
  4. on chain rejection records `BLOCKCHAIN_TRANSACTION_FAILED` and returns
     a safe error — never a misleading success.

## Running Tests

```bash
pnpm test    # full suite (live Besu tests self-skip if the chain is down)
pnpm run check
pnpm run build
```

Test coverage (all verified against the live QBFT chain):

- **Identity:** authorized registration succeeds; unauthorized fails;
  revocation works and blocks protected operations
- **Asset:** authorized mint succeeds and emits events; unauthorized mint
  reverts; revoked identities cannot receive assets
- **Roles:** admin works; auditor cannot mint; non-admin cannot grant roles
- **Lifecycle:** assign → activate → transfer → suspend (transfers blocked) →
  restore; revoked assets frozen permanently; unauthorized transfer reverts
- **Evidence:** receipts retrievable by hash; block hash/number match
- **Backend adapter:** provider connection, real submission, receipt parsing,
  event reading, safe failure on unregistered assets
- **Configuration:** MOCK fallback; BESU enablement; unreachable-node error
  reporting; unconfigured service refuses mutations

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot reach Besu at ...` | Start the network: `pnpm run blockchain:start` |
| `Chain ID mismatch` | The compose network has chain ID 4224; check `BLOCKCHAIN_CHAIN_ID` |
| Deploy fails, RPC works | Recompile artifacts: `pnpm run contracts:compile` |
| Live tests skip silently | Expected without Docker; start the chain to run them |
| Validators not peering | Fixed subnet must be free; `docker compose down -v` then restart |
| `Invalid opcode: 0x5f` | Contract compiled for a newer EVM than the chain — this repo pins `evmVersion=paris` for compatibility |

## Security Notes

- Validator keys and genesis accounts are **DEMO/LOCAL ONLY** development
  keys, clearly labeled; never reuse in production.
- No real private keys are committed; the operator key comes from the
  environment and is never logged.
- No PII, no private keys, no sensitive documents on-chain — only keccak256
  digests and addresses.
- Contracts are deliberately immutable (no upgradeability proxies) for the
  SIH prototype: simpler attack surface, deterministic behavior.
- Marketplace primitives (`approve`, `setApprovalForAll`, raw transfers) are
  permanently disabled in `SampraanAssetRegistry`.
