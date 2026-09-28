# SAMPRAAN — Deployment (Railway / Render)

This document describes how to run SAMPRAAN as a **production-style service** on
Railway or Render, what must be provisioned **outside** the application, and how
to verify a deployment instead of assuming it worked.

> Honest scope note: SAMPRAAN's blockchain layer is a **Hyperledger Besu QBFT
> network** and its read model is **MySQL**. Railway/Render do not host either of
> those as part of this application, and this repository does **not** pretend
> otherwise: the chain is an external dependency and the database must be
> reachable MySQL. See "External dependencies" below.

---

## 1. Deployment topology

| Component | Runs where | Lifecycle |
| --- | --- | --- |
| **Application** (Node 22, Express 5 + tRPC + Vite SPA) | Railway/Render service from `Dockerfile` | immutable image per build; **stateless** |
| **Database** (MySQL 8.x) | Railway MySQL plugin, or any managed MySQL | durable; backed up independently |
| **Blockchain** (Besu QBFT, 4 validators) | a VM / long-running host (`blockchain/network/`) | infrastructure; independent of app deploys |
| **IPFS** (optional content store) | Kubo node, own host/service | durable if used for encrypted content |
| **graph-node + IPFS + Postgres** (optional read layer) | own host (`graph/`) | optional; the app never depends on it |

The application container is **stateless**: durable state lives in MySQL and on
chain. Because of that, scaling replicas is safe **only** when
`IPFS_API_URL` is configured — otherwise asset content lands on the container
filesystem (mounted as a volume in the image, which is per-instance).

### External dependencies (cannot be provisioned by these files)

1. **MySQL connection string** (`DATABASE_URL`, `mysql://…`). Render's managed
   Postgres is **not** compatible with this build (drizzle-orm/mysql2).
2. **Besu QBFT RPC endpoint** (`BLOCKCHAIN_RPC_URL`, `BLOCKCHAIN_CHAIN_ID`).
   The app must be able to reach it; it anchors identities/assets/transfers and
   reads governance proposals from it.
3. **Operator signing key** (`BLOCKCHAIN_PRIVATE_KEY`) holding the required
   on-chain roles. Without it the chain adapter runs in MOCK mode and **no
   transaction is submitted** — the API reports this honestly.
4. **Asset content master key** (`ASSET_CONTENT_MASTER_KEY`), 32 random bytes
   as 64 hex chars. This is durable secret material: rotating it makes existing
   encrypted content unreadable unless wrapped keys are re-wrapped.
5. **HTTPS termination.** Railway and Render terminate TLS for you. Keep
   `TRUST_PROXY=1` so rate limiting keys on the real client IP and cookies are
   marked `Secure` (the app sets HSTS and secure cookies when it sees
   `x-forwarded-proto: https`).

---

## 2. Railway

`railway.json` is committed and drives the deployment:

| Setting | Value |
| --- | --- |
| Builder | Dockerfile |
| Start command | `node dist/index.js` |
| **Pre-deploy command** | `node dist/migrate.js` |
| Health check | `/ready` (120 s timeout) |
| Restart policy | `ON_FAILURE` (10 retries) |
| Replicas | 1 (see the IPFS note above before scaling) |

Steps:

1. **Create the project** and add the **MySQL** plugin.
2. **Deploy from the repository** — Railway picks up `railway.json`.
3. **Set the service variables** (Settings → Variables). Minimum:
   ```
   NODE_ENV=production
   DATABASE_URL=${{MySQL.MYSQL_URL}}   # or the plugin's connection URL
   JWT_SECRET=<48 random bytes, base64url>
   VITE_APP_ID=sampraan
   ASSET_CONTENT_MASTER_KEY=<64 hex chars>
   APP_URL=https://<your-service>.up.railway.app
   TRUST_PROXY=1
   BLOCKCHAIN_RPC_URL=https://<your-besu-host>:8545
   BLOCKCHAIN_CHAIN_ID=4224
   BLOCKCHAIN_PRIVATE_KEY=<operator key>
   ```
4. **Deploy.** The pre-deploy command applies migrations; a failed migration
   fails the deploy instead of leaving the app serving against a stale schema.
5. **Verify** (see §5).

Optional extras: `CORS_ORIGIN` (only if a UI is served from another origin),
`OAUTH_SERVER_URL` + `VITE_OAUTH_PORTAL_URL` (external IdP login).

**`IPFS_API_URL` is NOT optional in production**: startup fails closed without
it — asset content REQUIRES the organization's self-hosted Kubo node
(e.g. `http://<kubo-host>:5001/api/v0`). There is no third-party-IPFS and no
silent local-filesystem fallback; a missing or unreachable node is a hard
deployment failure by design.

## 3. Render

`render.yaml` is committed as a Blueprint:

1. **New → Blueprint → this repository.**
2. Render prompts for the `sync: false` secrets (`DATABASE_URL`, `JWT_SECRET`,
   `VITE_APP_ID`, `ASSET_CONTENT_MASTER_KEY`, `APP_URL`, chain credentials).
3. Set `DATABASE_URL` to your **external** MySQL URL. (Do not create a Render
   Postgres database for this application.)
4. Deploy. Migrations run via `preDeployCommand: node dist/migrate.js`; the
   health check is `/ready`.

## 4. Local production dry run (no platform required)

Reproduce the platform behaviour locally — production env, external-shaped URLs,
secure cookies, proxy headers:

```bash
# 1. Provision a database (fresh or existing) and set DATABASE_URL.
export NODE_ENV=production
export DATABASE_URL='mysql://user:pass@host:3306/sampraan'
export JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))")"
export VITE_APP_ID=sampraan
export ASSET_CONTENT_MASTER_KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
export TRUST_PROXY=1
export PORT=8080
export APP_URL=http://localhost:8080

# 2. Apply migrations (production runner — no drizzle-kit needed).
pnpm run build
node dist/migrate.js

# 3. Start exactly as the platform does, and verify.
node dist/index.js &
node scripts/smoke-health.mjs
```

`pnpm run check:env` prints the effective configuration with every secret
redacted, and reports blocking problems for the target environment.

### Docker

```bash
docker build -t sampraan-app:rc .
docker run --rm -p 3000:3000 --env-file .env sampraan-app:rc          # start
docker run --rm --env-file .env sampraan-app:rc node dist/migrate.js  # migrate
```

---

## 5. Verifying a deployment (do this before calling it live)

```bash
SAMPRAAN_BASE_URL=https://<your-host> node scripts/smoke-health.mjs
```

The smoke test asserts, against the RUNNING service:

* `/health` → 200, `api=OK`, `database=CONNECTED`, crypto-assurance posture present;
* `/ready` → 200, `database=CONNECTED`, **`schema=MIGRATED`** (a deployment
  pointed at an unmigrated database fails here rather than serving 500s);
* the SPA shell is served, with CSP / `nosniff` / `frame-deny` headers and no
  `x-powered-by`;
* the tRPC endpoint answers a real procedure;
* a **protected** procedure refuses an anonymous caller.

Then run the deeper end-to-end verifiers against the same base URL:

```bash
pnpm run verify:acceptance            # full role flow through the live API
node scripts/verify-session-isolation.mjs   # parallel sessions stay isolated
node server/verify-security.mjs       # DID challenge/replay, step-up, policy
node server/verify-did-hardening.mjs  # DID key lifecycle + PQC assurance matrix
node server/verify-adversarial.mjs    # forged/expired/replayed credentials
node scripts/verify-migrations.mjs    # (with FRESH_DATABASE_URL) cold-start apply
```

`/ready` is the **only** endpoint backed by a load-balancer gate. Readiness
gates on the **database and its schema**; the chain is deliberately excluded
because anchoring is best-effort by design (a chain outage must not drain the
service from the load balancer). Chain status is still reported for diagnostics.

---

## 6. Migrations

* Migrations are **append-only** and live in `drizzle/` with `meta/_journal.json`.
* The production runner is `node dist/migrate.js` (built from `server/migrate.ts`).
  It uses `drizzle-orm`'s migrator, which ships in production dependencies —
  unlike `drizzle-kit`, which is a devDependency and is **not** in the image.
* It is **safe to re-run**: applied migrations are skipped.
* It **fails non-zero** on error, so Railway/Render mark the deploy failed.
* `drizzle-kit generate` is a development-time concern only (creating a new
  migration); never part of a deploy.

### Baselining an existing database

Drizzle's migrator orders by the folder timestamp recorded in
`__drizzle_migrations`, and never re-checks whether the schema already exists.
If a database was created with `drizzle-kit push` (a direct schema sync) its
history is empty, and a later `migrate` will try to re-apply existing DDL.

```bash
node scripts/ops/mark-migration-applied.mjs --list
node scripts/ops/mark-migration-applied.mjs <tag> --confirm <tag>
```

The tool prints the statements it is about to ASSERT as already present, refuses
to overwrite an existing record, and writes exactly the row the migrator would
have written. Use it only when the schema genuinely exists.

### Proving migrations on a clean database

```bash
FRESH_DATABASE_URL=mysql://user:pass@host:3306/sampraan_fresh \
  pnpm run verify:migrations
```

This applies every migration to the empty database through the production
runner, asserts the required tables/enums/uniqueness constraints, and re-runs to
prove idempotency (18 checks).

---

## 7. Zero-downtime and rollback

| Change | Procedure |
| --- | --- |
| Application code | deploy a new image; the platform health-gates on `/ready` |
| Database schema | **additive** migration shipped with the release (pre-deploy command) |
| Contract logic | contracts are deliberately non-upgradeable: deploy **new addresses** and update `blockchain/deployment.json`. The old evidence trail is never rewritten. |
| Bad release | redeploy the previous image (`scripts/ops/rollback-app.sh`); a destructive migration is handled by restoring the pre-deploy backup — there is no `migrate down`. |
| Secrets leak | rotate `JWT_SECRET` (invalidates all sessions), `ASSET_CONTENT_MASTER_KEY` (re-wrap content keys), and the operator key (re-grant its on-chain roles). |

Backups: `scripts/ops/backup.sh` (MySQL dump + deployment manifest + sha256
manifest) and `scripts/ops/restore.sh`. Take a backup **before every deploy and
migration** — see `docs/operations.md`.
