# SAMPRAAN

**S**ecure **A**sset **M**anagement, **P**rovenance, **RBAC** **A**nd **I**dentity **O**n-chain **N**etwork

SAMPRAAN is a permissioned-blockchain platform for enterprise digital asset management that combines decentralized identity (W3C DID references), smart-contract-enforced access control (on-chain RBAC), controlled asset registration and custody transfer (restricted ERC-721), and a tamper-evident, auditable authorization trail — built on a Hyperledger Besu QBFT network with a MySQL read model.

> **Status:** release candidate (`fd9c89f`). This is a deployment-ready codebase with a reproducible production path (Docker, migrations, backup/restore/rollback), not a claim of proven production operation. Known limitations are listed in [Limitations](#limitations--production-notes).

---

## SIH 2026 Context

Built for **Smart India Hackathon 2026**, **Problem Statement 26125** — **Bharat Electronics Limited (BEL)**, theme **Blockchain & Cybersecurity**.

### A. From the problem statement

- Permissioned blockchain for enterprise digital asset management (no public chain, no token economics).
- Decentralized identity for asset custodians and operators.
- Smart-contract-enforced access control and authorization — the chain, not the UI, is the authority.
- Asset provenance: registration, custody assignment, transfer, and lifecycle (suspend/restore/revoke) as on-chain, auditable events.
- Read-only auditing of the authorization trail.

### B. Additional engineering capabilities implemented by SAMPRAAN (beyond the SIH statement)

- A backend policy engine (server-side, deterministic ALLOW/DENY/CHALLENGE) that runs _before_ chain submission — defense in depth, not a replacement for the contract check.
- An event indexer that projects on-chain events into a MySQL read model for querying alongside application audit events.
- Server-side session revocation, appId-bound JWT sessions, and immediate privilege stripping for revoked/suspended identities.
- Security-intelligence surfaces (alert registry, risk scoring views) that are explicitly **advisory only** — they never grant or bypass authorization.
- Production hardening: non-root container, fail-closed startup checks, backup/restore/rollback runbooks.

> IoT device identity/oracle integration is **not** an SIH requirement for this statement and is **not** implemented; it appears only as future work.

---

## Core Capabilities

| Capability                          | Implementation                                                                                                                                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DID / identity lifecycle**        | Off-chain W3C DIDs (`did_records` table); on-chain `SampraanIdentityRegistry` anchors keccak256(DID) → wallet + ACTIVE/SUSPENDED/REVOKED status. Admin-driven status changes mirror on-chain and revoke the derived DID record.       |
| **Cryptographic authentication**    | OAuth2 authorization-code flow with CSRF `state` nonce cookie; jose HS256 JWT sessions (7-day TTL) bound to `appId`; `httpOnly`, `SameSite=Lax`, `secure` (when HTTPS) cookies; Bearer fallback for cookie-blocked browsers.          |
| **Roles**                           | `ADMIN`, `MANAGER`, `AUDITOR`, `USER` in the read model (roles/permissions tables); on-chain `DEFAULT_ADMIN_ROLE`, `IDENTITY_ADMIN_ROLE`, `ASSET_MANAGER_ROLE`, `AUDITOR_ROLE` in `SampraanAccessControl`.                            |
| **RBAC + policy enforcement**       | Backend `AuthorizationService` (identity status → permission → classification rules) evaluated server-side from session + DB; result recorded as `authorization_decisions` + audit event. Frontend checks are UX only.                |
| **Enterprise asset registry**       | MySQL `assets` table with 5-level classification enum (PUBLIC…CRITICAL), owner/custodian separation, integrity hash; classification constrained at the **database layer**, not just the API.                                          |
| **NFT-backed asset representation** | `SampraanAssetRegistry` — ERC-721 (OpenZeppelin) with marketplace primitives (`approve`, `setApprovalForAll`, `transferFrom`, `safeTransferFrom`) **permanently disabled**; custody changes only via the guarded `transferCustody()`. |
| **Restricted minting**              | `registerAsset()` requires `ASSET_MANAGER_ROLE` on-chain; API-side asset creation is an admin-only tRPC procedure; each mint anchors on-chain (digests only).                                                                         |
| **Asset assignment / custody**      | `assignAsset()` and `transferCustody()` enforce role, asset-status, and both custodian identities being ACTIVE — all on-chain. Custody history tracked in `asset_custody`.                                                            |
| **Blockchain audit evidence**       | Every confirmed transfer records `transactionHash`, `blockNumber`, `blockHash`, `gasUsed` in `audit_events`; chain rejection records `BLOCKCHAIN_TRANSACTION_FAILED` — never a misleading success.                                    |
| **Event indexing**                  | `chain-event-indexer.ts` runs every 30s, projects recognized contract events into `audit_events` (`source: CHAIN_READ_MODEL`), idempotent across restarts via persisted tx-hash dedup.                                                |
| **Security intelligence**           | `security_alerts` registry (severity, status, riskScore) surfaced through an advisory Intelligence/Alerts workspace; never part of the authorization decision.                                                                        |
| **Identity revocation**             | Admin `identities.setStatus` → read model + DID record + on-chain anchor, and the session gate rejects the next authenticated request from a REVOKED/SUSPENDED linked identity.                                                       |
| **Session revocation**              | Logout revokes the server-side session row (cookie _and_ Bearer channels); tracked sessions are rejected immediately, before JWT expiry.                                                                                              |
| **Production security controls**    | CSP/HSTS/nosniff/frame-deny headers; fail-closed CORS; memory-bounded rate limiting (120 req/min/IP); 1 MB body cap; error masking of unexpected internals; non-root Docker user; fail-closed startup on weak `JWT_SECRET`.           |

---

## Architecture

### Request path (write/authorization)

```
Browser (React 19 SPA — wouter, Tailwind 4, shadcn-style UI)
        │  tRPC v11 over HTTP (superjson, httpBatchLink)
        ▼
Express 5 server (server/_core/index.ts)
        │  securityHeaders → corsPolicy → rateLimit → requestLogger → 1MB body cap
        ▼
tRPC procedures (server/routers.ts) — publicProcedure / protectedProcedure / adminProcedure
        │  session verify (jose JWT + server-side revocation + linked-identity status)
        ▼
Authorization / policy layer (authorization.service.ts)
        │  deterministic ALLOW / DENY / CHALLENGE; decision + audit rows persisted
        ▼
Smart contracts (SampraanAccessControl · SampraanIdentityRegistry · SampraanAssetRegistry)
        │  contract INDEPENDENTLY re-verifies role, identity status, asset state
        ▼
Hyperledger Besu QBFT network (4 validators, chain ID 4224, 2s blocks, immediate finality)
```

### Evidence path (read/audit)

```
Smart-contract events (IdentityRegistered, AssetTransferred, RoleGranted, …)
        ▼
Chain event indexer (chain-event-indexer.ts — 30s schedule, tx-hash dedup)
        ▼
MySQL read model (audit_events, source = CHAIN_READ_MODEL)
        ▼
Audit Evidence workspace / dashboards (protected tRPC queries)
```

**Division of responsibility** (confirmed by the code): the **blockchain is the trusted state-transition and evidence layer** — it independently re-verifies every protected transition and holds the tamper-evident record. **MySQL is the read model** — full application data, DID documents, asset metadata, audit query projections. The database is never moved on-chain, and chain data is never assumed without on-chain verification.

---

## Technology Stack

Verified against `package.json` / `pnpm-lock.yaml` at the release candidate:

| Layer            | Technology                                                                                                                                                                                                |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend         | React 19.2, TypeScript 5.9, Vite 8, wouter 3 (routing), Tailwind CSS 4, shadcn-style component set (53 components in `client/src/components/ui`), Radix UI primitives, TanStack Query 5, sonner, recharts |
| API              | Node.js 22, Express 5, tRPC 11 (server + client), superjson, Zod 4                                                                                                                                        |
| Auth             | jose 6 (HS256 JWT), OAuth2 authorization-code flow, `cookie` parsing                                                                                                                                      |
| Database         | MySQL 8.4, Drizzle ORM 0.45 + drizzle-kit 0.31 (append-only migrations)                                                                                                                                   |
| Blockchain       | Hyperledger Besu 25.10.0 (QBFT consensus, 4 validators), ethers 6                                                                                                                                         |
| Smart contracts  | Solidity 0.8.30 (solc pinned via npm, `evmVersion=paris`), OpenZeppelin Contracts 5.3 (`AccessControl`, `ERC721`)                                                                                         |
| Tooling          | pnpm 10 (workspace + patchedDependencies), Vitest 5, Prettier 3, esbuild (server bundle), Docker + Docker Compose                                                                                         |
| E2E verification | Python + Playwright helper scripts (`scripts/frontend-verify.py`, `scripts/ui-flow-a.py`) — local verification tools, not part of `pnpm test`                                                             |

Not used (do not expect): PostgreSQL, NestJS, Prisma, Next.js.

---

## Repository Structure

```
sampraan/
├── client/                  # React SPA
│   ├── index.html
│   └── src/
│       ├── App.tsx          # wouter routes: / → Home, 404 fallback
│       ├── main.tsx         # tRPC client + QueryClientProvider
│       ├── pages/           # Home.tsx (landing + auth gate + workspace), NotFound.tsx
│       ├── components/      # DashboardLayout, ErrorBoundary, ui/ (shadcn-style set)
│       ├── hooks/           # useSampraanData (tRPC queries + demo fallback)
│       └── lib/             # sampraan.ts (display helpers), trpc.ts, utils.ts
├── server/
│   ├── _core/               # Express bootstrap, security middleware, sdk/oauth/session, vite/static
│   ├── common/              # security.ts (headers/CORS/rate-limit), error-handler.ts
│   ├── modules/
│   │   ├── authorization/   # policy engine (ALLOW/DENY/CHALLENGE)
│   │   ├── blockchain/      # Besu adapter, facade, config, contracts.ts, chain-event-indexer, anchoring
│   │   ├── db/              # duplicate-key error mapping
│   │   └── trust-domain/    # in-memory demo domain (delegates to policy engine)
│   ├── routers.ts           # tRPC appRouter (health, auth, identities, assets, audit, alerts, blockchain)
│   ├── db.ts                # Drizzle data layer + session tracking/revocation
│   └── seed-demo.mjs        # fictional demo data
├── contracts/               # Solidity: SampraanAccessControl, SampraanIdentityRegistry, SampraanAssetRegistry + interfaces
├── blockchain/
│   ├── artifacts/           # deterministic compile output (ABI + bytecode)
│   ├── deployment.json      # contract addresses from the last deploy
│   └── network/             # QBFT config, genesis, docker-compose (4 validators)
├── drizzle/                 # migrations (0000–0002) + schema.ts
├── scripts/
│   ├── compile-contracts.ts # solc standard-JSON build (OZ inlined)
│   ├── deploy-contracts.ts  # deploy + role grants + deployment.json
│   ├── provision-admin.mjs  # local demo: admin user + session token
│   ├── provision-user.mjs   # local demo: linked user + session token
│   ├── reset-custody.mjs    # one-shot on-chain custody reset (demo)
│   ├── ops/                 # backup.sh, restore.sh, rollback-app.sh, mysql-backup.cnf
│   └── frontend-verify.py / ui-flow-a.py  # Playwright verification helpers
├── docs/                    # operations.md, blockchain.md, integration-notes.md, openapi.yaml
├── Dockerfile               # multi-stage, non-root, reproducible
├── docker-compose.production.yml   # app + MySQL 8.4
└── package.json / pnpm-lock.yaml / pnpm-workspace.yaml
```

---

## Local Development

### Prerequisites

- **Node.js 22** and **pnpm 10** (`corepack enable`)
- **Docker** with Docker Compose v2 (for the Besu network and MySQL)
- A MySQL 8.4 instance reachable for the app (local container or otherwise)

### Install

```bash
pnpm install --frozen-lockfile
```

### Environment

```bash
cp .env.example .env
# Fill in the values (see Environment Variables below)
```

### Database

Create a MySQL database and set `DATABASE_URL`, then apply the schema:

```bash
pnpm run db:push        # drizzle-kit generate && drizzle-kit migrate
```

Optionally seed fictional demo data (roles, permissions, identities, one asset, one alert):

```bash
pnpm run seed:demo
```

### Blockchain (local permissioned network)

```bash
pnpm run blockchain:start    # 4 Besu QBFT validators, RPC on http://localhost:8545
pnpm run contracts:compile   # solc 0.8.30 → blockchain/artifacts/*.json
pnpm run blockchain:deploy   # deploys contracts, grants roles, writes blockchain/deployment.json
pnpm run blockchain:stop     # stop the network
```

> The deploy script falls back to a publicly documented Besu tutorial genesis key **only on the local demo chain** and refuses that key under `NODE_ENV=production`. Set `BLOCKCHAIN_PRIVATE_KEY` for any real deployment.

### Run

```bash
pnpm run dev        # dev server with Vite HMR — http://localhost:3000
```

Production build / start:

```bash
pnpm run build      # vite build (client) + esbuild (server) → dist/
pnpm run start      # NODE_ENV=production node dist/index.js
```

Other scripts: `pnpm run check` (tsc --noEmit), `pnpm run format` (Prettier), `pnpm test` (Vitest).

### Frontend access

Open **http://localhost:3000**. Unauthenticated visitors see the landing page and a workspace demo mode; signing in via the OAuth gate (`VITE_OAUTH_PORTAL_URL` configured) enters the live workspace. Local demo sessions can be minted with `node scripts/provision-admin.mjs` / `provision-user.mjs` (dev-only helpers).

---

## Environment Variables

From `.env.example`, `docker-compose.production.yml`, and `docs/operations.md`:

| Variable                                     | Required                        | Purpose                                                                                     |
| -------------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------- |
| `DATABASE_URL`                               | yes                             | MySQL connection string, e.g. `mysql://user:pass@localhost:3306/sampraan`                   |
| `JWT_SECRET`                                 | yes (prod)                      | Session signing secret — **≥ 32 random chars**; production refuses to boot without it       |
| `VITE_APP_ID`                                | yes (prod)                      | Binds session tokens to this app; foreign-app tokens are rejected                           |
| `OAUTH_SERVER_URL`                           | prod                            | Identity provider base URL for token exchange                                               |
| `OWNER_OPEN_ID`                              | optional                        | Platform user that receives the admin role at first login                                   |
| `VITE_OAUTH_PORTAL_URL`                      | optional (client)               | OAuth portal URL used by the sign-in button                                                 |
| `BLOCKCHAIN_RPC_URL`                         | default `http://localhost:8545` | Besu JSON-RPC endpoint                                                                      |
| `BLOCKCHAIN_CHAIN_ID`                        | default `4224`                  | Expected chain ID; a mismatch refuses to bind contracts                                     |
| `BLOCKCHAIN_PRIVATE_KEY`                     | for BESU mode                   | Operator signing key — **never commit a real key**                                          |
| `BLOCKCHAIN_IDENTITY_CONTRACT_ADDRESS`       | optional                        | Override identity registry address (defaults to `blockchain/deployment.json`)               |
| `BLOCKCHAIN_ASSET_CONTRACT_ADDRESS`          | optional                        | Override asset registry address                                                             |
| `BLOCKCHAIN_ACCESS_CONTROL_CONTRACT_ADDRESS` | optional                        | Override access control address                                                             |
| `CORS_ORIGIN`                                | prod                            | Comma-separated allowlist; **unset = fail closed** (no cross-origin headers emitted)        |
| `TRUST_PROXY`                                | behind proxy                    | `1` to key rate limits on `X-Forwarded-For` — set **only** when a real proxy fronts the app |
| `PORT`                                       | default `3000`                  | Production refuses to hop to another port                                                   |
| `MYSQL_ROOT_PASSWORD` `MYSQL_PASSWORD`       | compose (required)              | MySQL credentials for the production compose stack                                          |
| `MYSQL_USER` `MYSQL_DATABASE`                | compose (default `sampraan`)    | MySQL user/database                                                                         |
| `APP_PORT`                                   | compose (default `3000`)        | Host port published for the app container                                                   |

**Secrets policy:** never commit `.env`, private keys, or tokens. Use placeholders when documenting:

```
JWT_SECRET=<generate-a-strong-random-secret>
BLOCKCHAIN_PRIVATE_KEY=<your-operator-key>
```

---

## Production Deployment

The repository ships a complete production path. Full detail in [`docs/operations.md`](docs/operations.md).

### Topology

| Component                      | Managed by                                                               | Lifecycle                                             |
| ------------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------- |
| Besu QBFT chain (4 validators) | `blockchain/network/docker-compose.yml`                                  | infrastructure — independent of app deploys           |
| MySQL 8.4                      | `docker-compose.production.yml`                                          | app-adjacent, persistent volume `sampraan-mysql-data` |
| Application                    | `docker-compose.production.yml` (`Dockerfile`, non-root user `sampraan`) | immutable image per build                             |

The application container is **stateless**; durable state lives in MySQL and on-chain.

### Cold start (from `docs/operations.md`)

```bash
# 0. Prerequisites: Docker, docker compose v2, pnpm 10, Node 22.
cp .env.example .env        # fill REAL secrets

# 1. Bring up the QBFT validator network.
pnpm run blockchain:start

# 2. Deploy the smart contracts with a REAL operator key.
BLOCKCHAIN_PRIVATE_KEY=<operator-key> pnpm run blockchain:deploy

# 3. Build and start the app + MySQL.
docker compose -f docker-compose.production.yml up -d --build

# 4. Apply the database schema.
docker compose -f docker-compose.production.yml exec app pnpm drizzle-kit migrate

# 5. Verify.
curl -f http://localhost:3000/health
curl -f http://localhost:3000/ready
```

### Health / readiness

- `GET /health` — public liveness: process, DB configured/connected, chain status (bounded 5s RPC timeout so a hung chain cannot stall the probe).
- `GET /ready` — readiness: **503 until the DB connects**; used by the compose healthcheck (every 30s) and load-balancer gating. Chain status is reported but deliberately does not gate readiness (anchoring is best-effort by design).

### Provided vs. operator-provisioned

**Provided by the repository:** application image (multi-stage, non-root, healthchecked), MySQL service with healthcheck and backup config, the QBFT validator network definition, migrations, backup/restore/rollback scripts, fail-closed startup validation.

**Operator must provision externally:** a real operator key (`BLOCKCHAIN_PRIVATE_KEY`) with funded balance and chain roles, an identity provider (`OAUTH_SERVER_URL`) or an equivalent auth source, real secrets (`JWT_SECRET`, MySQL passwords), and — for internet-facing deployments — **HTTPS termination via a reverse proxy** (the app sets HSTS and secure cookies when it sees `x-forwarded-proto: https`; set `TRUST_PROXY=1` in that topology). Validator key rotation and monitoring/alerting infrastructure are also operator responsibilities.

### Backup / restore / rollback

```bash
./scripts/ops/backup.sh                                   # MySQL dump + deployment manifest + sha256 manifest
./scripts/ops/restore.sh backups/sampraan-mysql-<ts>.sql.gz       # refuses an occupied DB without --force
./scripts/ops/rollback-app.sh sampraan-app:<previous-tag>  # redeploys the previous image, waits for /ready
```

Policies (documented in `docs/operations.md`): take a backup **before every deploy and migration**; drizzle migrations are **append-only** (no `migrate down`) — a destructive migration is handled by restoring the pre-deploy backup; contract rollback **does not exist by design** — regressions are handled by deploying new addresses, which supersedes but never rewrites the old evidence trail. Besu chain state is intentionally outside the app backup; validator volumes are snapshotted separately (all four from the same point in time).

---

## Security Model

Properties **verified in the code and tests**:

- **Server-side authorization** — role, permissions, identity status, and asset classification are resolved from the session and the database; client-asserted values are never trusted (`routers.security.test.ts` proves classification/step-up/role assertions cannot influence a decision).
- **Smart-contract authorization** — the contract re-verifies role, actor identity status, and asset state on every protected transition; it never trusts the backend's decision (see next section).
- **Session revocation** — sessions are tracked server-side on login; logout revokes both cookie and Bearer channels; a revoked row rejects the very next request, before JWT expiry.
- **Secure cookies** — `httpOnly`, `SameSite=Lax`, `secure` under HTTPS/proxy; the OAuth state cookie is a one-time `__Host-` prefixed nonce.
- **CORS fails closed** — no `CORS_ORIGIN`, no cross-origin response is blessed.
- **CSP** — `default-src 'self'`; scripts locked to `'self'` in production; `object-src 'none'`; `base-uri`/`form-action` `'self'`.
- **HSTS** — `max-age=31536000; includeSubDomains` in production or over TLS.
- **Rate limiting** — 120 req/min per IP, memory-bounded (max 10k keys, swept buckets) so it cannot be a memory-exhaustion vector; 429 with `Retry-After`.
- **Body-size limits** — JSON and URL-encoded bodies capped at 1 MB.
- **Production secret validation** — startup fails closed on a missing/short `JWT_SECRET` or missing `VITE_APP_ID`; production refuses to bind a different port.
- **Chain ID verification** — the Besu adapter refuses to bind contracts when the RPC's chain ID does not match `BLOCKCHAIN_CHAIN_ID`.
- **Deployment-key protections** — the deploy script refuses the demo genesis key under `NODE_ENV=production`; validator node keys are gitignored (removed from tracking in `de67231`).
- **Non-root container** — the runtime image runs as user `sampraan`, prod-only dependencies, no build toolchain, no source, no secrets baked in.
- **Error masking** — unexpected tRPC internals are replaced with a generic message after server-side logging; `x-powered-by` disabled.
- **Dependency audits** — `pnpm audit --prod` reports **no known production vulnerabilities** at this commit. (The full audit including devDependencies currently reports transitive advisories — e.g. `tar` via `@tailwindcss/oxide` and `tmp` via `solc` — which do not ship in the production image.)

No security claim here is absolute: this is a hardened release candidate, not a formally audited product.

---

## Smart-Contract Authorization (the SIH minimum demo flow)

Authorization is **not** enforced by hiding UI controls. The frontend can only _name_ an asset; role, permissions, classification, and identity status always come from the server session and the database, and the smart contract re-verifies everything independently.

On-chain checks in `SampraanAssetRegistry.transferCustody()`:

- caller holds `ASSET_MANAGER_ROLE` (else `NotAssetManager`/`NotAuthorizedOperator`)
- asset is registered and `ACTIVE` — suspended/revoked assets are frozen (`AssetNotActive`)
- current custodian identity is still `ACTIVE` (`CustodianNotActive`)
- recipient identity is registered and `ACTIVE` (`RecipientNotActive`)
- zero-address and same-custodian guards

`SampraanIdentityRegistry` gates every identity mutation behind `IDENTITY_ADMIN_ROLE`, and `SampraanAccessControl` protects role grants behind `DEFAULT_ADMIN_ROLE`.

### The demo flow (verified by live-chain tests)

**Auditor path — rejected:**

```
Auditor attempts the transfer
  → backend policy engine: role/permission check
  → if submitted: smart contract rejects (caller lacks ASSET_MANAGER_ROLE)
  → ownership/custody remains unchanged — no transaction is mined
  → denial recorded as an audit event (AUTHORIZATION_DENIED)
```

**Manager path — accepted:**

```
Manager (with asset:transfer permission) attempts the same transfer
  → backend policy engine: ALLOW (decision + audit rows persisted)
  → real blockchain transaction submitted to Besu QBFT
  → AssetTransferred event emitted; transaction confirmed (receipt awaited)
  → audit event updated with transactionHash + blockNumber + blockHash evidence
  → indexer projects the event into the read model; DB custodian updated
```

Test coverage confirming this behavior (against the live QBFT chain, `besu-contracts.test.ts`): _unauthorized caller cannot transfer custody_, _auditor (no mutation role) cannot mint assets_, _unauthorized mint reverts_, _revoked asset is frozen permanently_, _identity revocation works and blocks protected operations_.

---

## Auditability

- **On-chain (immutable evidence):** every protected state transition — identity registration/status change, asset mint/assign/transfer/status change, role grants/revokes — emits an event carrying only digests and addresses. QBFT gives immediate finality (no reorgs), so confirmed evidence cannot be rewritten. Transaction receipts are retrievable by hash.
- **Off-chain (read model):** `audit_events` stores application decisions (authorization allows/denies/challenges, admin lifecycle actions, anchor outcomes, chain failures) with actor attribution resolved server-side, plus chain-derived rows (`source = CHAIN_READ_MODEL`) projected by the indexer. The audit API distinguishes application decisions from on-chain projections, and rows carry `transactionHash`/`blockNumber` when a real chain confirmed the operation.

The read model can be rebuilt from the chain; the chain is the evidence of record.

---

## Privacy / Data Handling

SAMPRAAN stores **only keccak256 digests and wallet addresses on-chain**:

- Identities: the DID string itself stays off-chain (`did_records`); the chain holds only `keccak256(DID)`, a public-key digest, and a lifecycle status.
- Assets: only digests of the asset ID, classification, and a metadata/integrity reference. Document contents, firmware binaries, and metadata stay off-chain.
- Events: digests and addresses only — never PII, private keys, or sensitive content.

This is a **permissioned** network: four known QBFT validators under deterministic configuration, no public access, no token economics. Sensitive employee/PII data should never be placed directly on a blockchain — public or permissioned — and this design deliberately keeps it off-chain with only integrity anchors on-chain.

---

## Testing

```bash
pnpm test          # full suite (Vitest)
```

Current verified state at the release candidate: **23 test files, 293 tests, all passing** — including 13 live Besu QBFT smart-contract tests. Live-chain tests deploy their own contract suite and self-skip when the chain is unreachable, so `pnpm test` also passes in CI without Docker.

| Category                    | Files                                                                                                                                             | Coverage                                                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Unit                        | `authorization.service`, `trust-domain`, `security`, `cookies`, `error-handler`, `sampraan` (client helpers), `db-errors`, `paths`, `besu-config` | Policy engine, CORS/headers/rate-limit, cookie policy, display helpers, no-DB degradation                                            |
| Session/auth                | `sdk`, `sdk.session`, `oauth`, `auth.logout`, `auth.session-tracking`, `audit.attribution`                                                        | JWT sign/verify, appId binding, foreign secret, tamper/expiry/garbage, CSRF nonce, revocation, actor attribution                     |
| Integration (tRPC)          | `routers.test`, `routers.security.test`, `regression.bugfix`, `db.test`                                                                           | Full procedure paths with the DB layer mocked: client-bypass attempts, step-up behavior, custody read-model sync, duplicate handling |
| Smart contract (live chain) | `besu-contracts` (13)                                                                                                                             | Identity/asset/role authorization, lifecycle freeze, transfer rejection, evidence retrieval                                          |
| Blockchain adapter          | `besu-adapter`, `blockchain.service`, `status-timeout`                                                                                            | Provider connection, submission, receipt parsing, hung-RPC degradation                                                               |
| E2E (local, optional)       | `scripts/frontend-verify.py`, `scripts/ui-flow-a.py`                                                                                              | Playwright-driven UI proofs of the transfer flow and custody state — run manually, not part of `pnpm test`                           |

Also run: `pnpm run check` (typecheck), `pnpm run build`, `pnpm run contracts:compile`.

---

## Demo Guide (SIH evaluation)

Prerequisites: the Besu network running, contracts deployed, database migrated + seeded, and demo sessions provisioned (`node scripts/provision-admin.mjs`, `node scripts/provision-user.mjs <openId> <did>`).

1. **Login as the Auditor** (a user linked to an identity with no mutation role/permission).
2. Open **Access Control** and select the sensitive asset.
3. Click **EVALUATE VIA BACKEND** to attempt the transfer.
4. Show the **rejection** — the policy engine DENIES (the Auditor identity holds no mutating permission), the panel reads DENIED / OFF CHAIN, custody is unchanged, no transaction is mined, and an `AUTHORIZATION_DENIED` audit row appears. (The contract-level check is additionally proven by the live-chain tests: _unauthorized caller cannot transfer custody_, _auditor cannot mint assets_ — both revert in `SampraanAssetRegistry` itself.)
5. **Login as the Manager** (identity holding `asset:transfer`).
6. Transfer the **same asset** — the policy engine returns ALLOW (a MANAGER identity holding `asset:transfer` on a non-`HIGHLY_SENSITIVE` asset; on the seeded `HIGHLY_SENSITIVE` asset the engine returns `CHALLENGE` for every role because no server-verified step-up exists — see [Limitations](#limitations--production-notes)).
7. Show the successful **Besu transaction** — real `transactionHash` and block number in the CHAIN ANCHOR panel.
8. Show the **transaction/block/event evidence** — the receipt, the `AssetTransferred` event, and the indexed read-model row in Audit Evidence.
9. Show the **audit trail update** — decision, evidence row, and updated custodian in the asset registry.
10. Optionally demonstrate **identity revocation**: an admin suspends/revokes an identity in the Identity page; its session is rejected on the next request and the lifecycle change is anchored on-chain.

If the acting identity already holds on-chain custody, the UI reports **ALREADY IN CUSTODY — NO TRANSFER NEEDED** rather than an error (an honest, evidence-backed result). No browser-console JWT injection, fake transaction hashes, or demo-only bypasses are used in the normal flow — every step above goes through the real backend and the real chain.

---

## Limitations / Production Notes

Honest disclosure of what the release candidate does **not** do:

- **No server-verified step-up authentication.** The policy engine returns `CHALLENGE` (POLICY-STEP-UP) for highly sensitive transfers for **every role, including admin**, because no server-verified step-up mechanism exists; a client-asserted flag is never trusted (`docs/integration-notes.md`).
- **Rate limiting is in-process memory.** Behind multiple replicas each node keeps its own buckets; keys are per-IP (`TRUST_PROXY=1` required behind a proxy, which must be set only when a real proxy fronts the app).
- **Indexer lag.** Chain events reach the audit read model on a 30s schedule (evidence itself is immediate on-chain).
- **Anchoring is best-effort at creation time** by design — a chain outage never blocks identity/asset creation; failed anchors surface as `BLOCKCHAIN_ANCHOR_FAILED` events for re-run.
- **Seed data does not link identities to platform users** (`identities.linkedUserId`), so a freshly seeded database denies transfers (fail-closed) until an operator links them — the deliberate, documented default (`docs/integration-notes.md`).
- **Authorization decision `policyId` is stored as null** for inline policy labels (they are not UUIDs and the column is FK-bound); labels are preserved in audit metadata instead.
- **Live OAuth E2E was not verifiable in the development environment** (no external IdP credentials); the session/verification layer is covered by unit tests and the live path is documented as unverified.
- **Contracts are deliberately non-upgradeable** (no proxies) — simpler attack surface, deterministic behavior; a regression means deploying new addresses.
- **DevDependency audit findings** exist (transitive `tar`, `tmp`, etc.); they are excluded from the production image but are not yet patched at the devDependency level.
- **No formal security audit** has been performed on this codebase.

---

## Roadmap (future work — not implemented)

- Server-side step-up authentication for highly sensitive assets (closing the POLICY-STEP-UP CHALLENGE gap).
- External OAuth/enterprise IdP configuration guidance and verification.
- HSM-backed key management for the operator and validator keys.
- Horizontally shared rate limiting (e.g. Redis-backed) for multi-replica deployments.
- IoT/device identity and custody attestation.
- Physical asset verification / oracle integration for chain-anchored attestations.

---

## License

No license file is currently committed to this repository; `package.json` declares `"license": "MIT"`, but the repo carries no `LICENSE` text. Licensing should be considered **not yet formally specified** until a license file is added.

---

## Contributing / Development Notes

- The repository is a pnpm workspace — always install with `pnpm install --frozen-lockfile`.
- Patches (`patches/wouter@3.7.1.patch`) and security overrides live in `pnpm-workspace.yaml` (pnpm 10 reads them there, not from `package.json`).
- Keep drizzle migrations append-only; write compensating migrations rather than editing history.
- Run `pnpm run check`, `pnpm test`, and `pnpm run contracts:compile` before proposing changes.
- No branch/PR policy is documented in the repository; coordinate with the team before opening PRs against `main`.
