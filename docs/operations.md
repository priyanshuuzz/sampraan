# SAMPRAAN Operations — Production Deployment, Backup, Restore, Rollback

This document describes the *reproducible* production procedure for the
SAMPRAAN release candidate. All commands assume the repository root.

---

## 1. Topology

| Component        | Managed by                        | Lifecycle |
|------------------|-----------------------------------|-----------|
| Besu QBFT chain  | `blockchain/network/docker-compose.yml` (4 validators) | infrastructure — independent of app deploys |
| MySQL 8.4        | `docker-compose.production.yml`   | app-adjacent, persistent volume `sampraan-mysql-data` |
| Application      | `docker-compose.production.yml` (`Dockerfile`, non-root) | immutable image per build |

The application is **stateless**: all durable state lives in MySQL (source
of truth for the read model) and on the Besu chain (tamper-evident evidence
layer). No container restart loses data.

## 2. First deployment (cold start)

```bash
# 0. Prerequisites: Docker, docker compose v2, pnpm 10, Node 22.
cp .env.example .env   # then fill REAL secrets (see section 7)

# 1. Bring up the QBFT validator network.
pnpm run blockchain:start
# Verify consensus (expect 3 peers, block height advancing):
curl -X POST http://localhost:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'

# 2. Deploy the smart contracts with a REAL operator key.
BLOCKCHAIN_PRIVATE_KEY=<operator-key> pnpm run blockchain:deploy
# This writes blockchain/deployment.json (contract addresses) — commit or
# record it; the backend reads it automatically.

# 3. Build and start the app + MySQL.
docker compose -f docker-compose.production.yml up -d --build

# 4. Apply the database schema (drizzle migrations are append-only).
docker compose -f docker-compose.production.yml exec app \
  pnpm drizzle-kit migrate
# Or from the host against the published port:
#   DATABASE_URL=mysql://... pnpm drizzle-kit migrate

# 5. Verify.
curl -f http://localhost:3000/health   # api OK, database CONNECTED
curl -f http://localhost:3000/ready    # 200 with DB connected
```

## 3. Routine deploy (update)

```bash
git pull
docker compose -f docker-compose.production.yml build app
docker compose -f docker-compose.production.yml up -d app
# Apply any new migrations:
docker compose -f docker-compose.production.yml exec app pnpm drizzle-kit migrate
```

Startup is **fail-closed**: with a missing/weak `JWT_SECRET` or an occupied
`PORT` the server refuses to boot (no silent downgrade, no port hopping).

## 4. Backup

```bash
./scripts/ops/backup.sh            # → ./backups/sampraan-mysql-<ts>.sql.gz
```

What is and is NOT covered:

- **MySQL**: full logical dump (single transaction, no locks) — identities,
  assets, audit events, authorization decisions, sessions, security alerts.
- **Deployment manifest**: contract addresses + chain id snapshot.
- **Besu chain state**: intentionally NOT in the app backup. Chain data is
  append-only and reproducible; validators hold their own volumes
  (`nodedata-*`). For full-chain backup, snapshot the validator volumes:
  ```bash
  for v in nodedata-1 nodedata-2 nodedata-3 nodedata-4; do
    docker run --rm -v blockchain_network_$v:/data -v $PWD/backups:/backup \
      alpine tar czf /backup/$v-$(date -u +%Y%m%d).tar.gz -C /data .
  done
  ```
  Restoring validators from a mix of snapshots is unsafe — restore ALL FOUR
  from the same point in time or replay from genesis.

Take a backup **before every deploy and every migration**.

## 5. Restore

```bash
./scripts/ops/restore.sh backups/sampraan-mysql-<ts>.sql.gz
# Overwrite an occupied database (writes a safety dump first):
./scripts/ops/restore.sh backups/sampraan-mysql-<ts>.sql.gz --force
```

After a database restore, the event indexer re-syncs automatically: it
tracks the last indexed block and projects new chain events on its 30s
schedule; no manual reconciliation is needed for the audit read model.

## 6. Rollback

Application rollback (previous image):

```bash
./scripts/ops/rollback-app.sh sampraan-app:<previous-sha>
```

Database rollback policy (important):

- Drizzle migrations are **append-only**; the project deliberately has no
  `migrate down`.
- If a bad release shipped a destructive migration: stop the app
  (`docker compose ... stop app`), restore the **pre-deploy** backup
  (section 5), then roll the app back (section 6) — in that order.
- Never attempt to hand-edit schema forward; write a compensating migration.

Contract rollback: **does not exist by design**. Smart-contract state
transitions are final on-chain; a regression is handled by deploying new
contract addresses and re-pointing the app (`BLOCKCHAIN_*_CONTRACT_ADDRESS`
env vars / a fresh `blockchain:deploy`), which supersedes — never rewrites —
the old evidence trail.

## 7. Required production environment

| Variable | Notes |
|---|---|
| `NODE_ENV=production` | set by compose; drives fail-closed checks |
| `PORT` | default 3000; the app refuses to hop ports in production |
| `DATABASE_URL` | MySQL connection string (compose injects service host) |
| `JWT_SECRET` | **>= 32 chars, random**; startup fails without it |
| `VITE_APP_ID` | app binding for session tokens (rejects foreign-app tokens) |
| `OAUTH_SERVER_URL` | identity provider base URL |
| `OWNER_OPEN_ID` | platform user that receives the admin role |
| `BLOCKCHAIN_RPC_URL` | validator-1 RPC (compose network: `http://sampraan-validator-1:8545`) |
| `BLOCKCHAIN_CHAIN_ID` | must match genesis (default 4224); mismatch refuses to bind |
| `BLOCKCHAIN_PRIVATE_KEY` | operator key — grant it chain roles at deploy |
| `CORS_ORIGIN` | allowed origin; unset CORS fails CLOSED |

**Never** commit `.env`. Never reuse the documented demo genesis keys in
production — the deploy script explicitly refuses them under
`NODE_ENV=production`.

## 8. Health, readiness, monitoring

- `GET /health` — liveness: process, DB configured/connected, chain status.
- `GET /ready` — readiness: **503** until the DB actually connects; use for
  load-balancer gating and the compose healthcheck.
- Structured request logs: one JSON line per request
  (`event=http_request`) with method, path, status, duration, request id.
- Indexer telemetry: `[Indexer]` lines report projected events and failures.
- Container healthchecks run `/ready` every 30s.

## 9. Known operational limits (honest disclosure)

- Rate limiting is in-process memory; behind multiple replicas, each node
  keeps its own buckets (documented limitation for single-node RC).
- Rate limiting is keyed by client IP. Behind a reverse proxy, set
  `TRUST_PROXY=1` so the limiter keys on `X-Forwarded-For` — without it,
  every client behind the proxy shares one collective bucket (safe, but
  one abusive client can exhaust it for everyone). Only enable it when a
  proxy actually fronts the app: with direct exposure it would let
  clients spoof their rate-limit identity.
- Session revocation is per-database; all app replicas share it via MySQL.
- The 30s indexer interval means chain events appear in the audit read
  model with up to 30s lag (evidence itself is immediate on-chain).
- Anchoring is best-effort at creation time by design (chain outage never
  blocks identity/asset creation); every attempt is audited, and failed
  anchors surface as `BLOCKCHAIN_ANCHOR_FAILED` events for re-run.
