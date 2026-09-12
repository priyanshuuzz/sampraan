# SAMPRAAN Subgraph (LOOP 11)

Indexes REAL events from the deployed SAMPRAAN contracts into The Graph:

| Contract | Events |
|---|---|
| SampraanAssetRegistry | `AssetRegistered`, `AssetAssigned`, `AssetTransferred`, `AssetStatusChanged` |
| SampraanIdentityRegistry | `IdentityRegistered`, `IdentityStatusChanged` |
| SampraanAccessControl | `RoleGranted`, `RoleRevoked` |

Event signatures match the deployed contracts exactly (see
`blockchain/artifacts/*.json`). Contract addresses in `subgraph.yaml` come
from `blockchain/deployment.json` — update them after a redeploy.

## Entities

- `Asset` — token id, digests, status, current custodian, creator, mint tx/block
- `AssetTransfer` — MINT / ASSIGNMENT / TRANSFER rows with tx hash + block
- `Identity` — reference wallet, didDigest, lifecycle status
- `BlockchainEvent` — raw event stream across all three contracts

## Local deployment (VERIFIED LIVE)

The graph stack lives in `docker-compose.graph.yml` and attaches to the
EXISTING `sampraan-chain` docker network so graph-node indexes the Besu
validators directly:

```bash
# 1. Besu QBFT network (4 validators) — already running
pnpm blockchain:start

# 2. Graph stack (IPFS + Postgres + graph-node)
docker compose -f graph/docker-compose.graph.yml up -d
# Postgres is initialized with POSTGRES_INITDB_ARGS="--locale=C" — graph-node
# refuses any other collation.

# 3. Build + deploy the subgraph (run from inside graph/)
cd graph && pnpm install
cd graph && pnpm exec graph codegen
cd graph && pnpm exec graph build
cd graph && pnpm exec graph create sampraan --node http://localhost:8020
cd graph && pnpm exec graph deploy sampraan --node http://localhost:8020 \
  --ipfs http://localhost:5001 --version-label v1.0.0
```

Query endpoint: `http://localhost:8000/subgraphs/name/sampraan`
(indexing status: `http://localhost:8030/graphql`).

Verified live on the QBFT network: a REAL admin mint (token 53, block 52498,
tx `0x7b5035c1…`) followed by a REAL custody assignment and a REAL policy-
authorized transfer (tx `0x5ccf4ad5…`, block 52505) were all indexed by
graph-node within seconds and returned by GraphQL queries with exact tx
hashes, custodians and block numbers.

Query example after deployment:

```graphql
{ assetTransfers(first: 5, orderBy: blockNumber, orderDirection: desc) {
    kind asset { id } fromCustodian toCustodian transactionHash blockNumber
} }
```

## Availability contract (IMPORTANT)

The core application NEVER depends on this subgraph. When graph-node is not
running, the server exposes the same entity shapes through
`server/modules/graph/graph.service.ts` (tRPC `graph.*` procedures), which
decodes the same REAL events straight from the Besu RPC. The Graph layer is
query/indexing infrastructure only — it never decides ALLOW/DENY/CHALLENGE.
