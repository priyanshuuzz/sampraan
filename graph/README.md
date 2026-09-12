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

## Local deployment (requires graph-node + IPFS + Postgres)

The dev stack (`docker compose -f blockchain/network/docker-compose.yml up -d`)
provides Besu only. To run a full graph-node locally add the standard
graph-node/ipfs/postgres services, then:

```bash
pnpm graph:codegen   # graph codegen --output-dir graph/generated graph/subgraph.yaml
pnpm graph:build     # graph build graph/subgraph.yaml
pnpm graph:create    # graph create --node http://localhost:8020 sampraan
pnpm graph:deploy    # graph deploy --node http://localhost:8020 --ipfs http://localhost:5001 sampraan graph/subgraph.yaml
```

Query example after deployment:

```graphql
{ assets { id status custodian { id } creator mintTransactionHash transfers { kind transactionHash blockNumber } } }
```

## Availability contract (IMPORTANT)

The core application NEVER depends on this subgraph. When graph-node is not
running, the server exposes the same entity shapes through
`server/modules/graph/graph.service.ts` (tRPC `graph.*` procedures), which
decodes the same REAL events straight from the Besu RPC. The Graph layer is
query/indexing infrastructure only — it never decides ALLOW/DENY/CHALLENGE.
