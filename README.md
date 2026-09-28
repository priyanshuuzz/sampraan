# SAMPRAAN

**S**ecure **A**sset **M**anagement, **P**rovenance, **RBAC** **A**nd **I**dentity **O**n-chain **N**etwork

SAMPRAAN is a permissioned-blockchain platform for enterprise digital asset management: decentralized identity (W3C DID), smart-contract-enforced access control, a restricted ERC-721 asset registry with governed custody transfer, AES-256-GCM encrypted asset content stored on a self-hosted Kubo IPFS node, policy-driven post-quantum (ML-DSA-65) cryptographic assurance, and a tamper-evident audit/provenance trail — running on Hyperledger Besu QBFT with a MySQL read model.

> **Status:** release candidate, deployment-ready. A reproducible local production path (build → migrate → start → health/readiness) is verified end-to-end below; Railway/Render configurations ship in this repository but a hosted deployment has **not** been performed.

---

## SIH 2026 Context

Built for **Smart India Hackathon 2026**, **Problem Statement 26125** — **Bharat Electronics Limited (BEL)**, theme **Blockchain & Cybersecurity**.

### A. From the problem statement

- Permissioned blockchain for enterprise digital asset management (no public chain, no token economics).
- Decentralized identity for asset custodians and operators.
- Smart-contract-enforced access control — the chain, not the UI, is the authority.
- Asset provenance: registration, custody assignment, transfer, and lifecycle (suspend/restore/revoke) as on-chain, auditable events.
- Read-only auditing of the authorization trail.

### B. Additional engineering capabilities implemented by SAMPRAAN

- AES-256-GCM envelope-encrypted asset content with per-object data keys, stored on the operator's **own Kubo (IPFS) node** — never a third-party pinning service.
- Governance lifecycle: maker-checker proposals, 2-of-N multisig approval, timelock, and execute-once semantics for high-risk operations, enforced by the `SampraanGovernance` contract.
- Policy-driven post-quantum cryptographic assurance (ML-DSA-65) layered on the ECDSA/secp256k1 chain baseline.
- Server-side deterministic risk scoring and step-up authentication (DID-key-signed challenges, single-use, purpose-bound).
- DID hardening: purpose/audience-bound challenges, replay protection, key rotation and revocation.
- Session isolation and server-side revocation, appId-bound JWT sessions.
- Event indexer projecting on-chain events into the MySQL read model.
- Production hardening: non-root container, fail-closed startup checks, Railway/Render deployment configurations, backup/restore/rollback runbooks.

> IoT device identity/oracle integration is **not** an SIH requirement for this statement and is **not** implemented; it appears only as future work.

---

## Architecture

```
Frontend (React 19 SPA — wouter, Tailwind 4, tRPC client)
        │  tRPC v11 over HTTP (superjson, httpBatchLink)
        ▼
Backend/API (Express 5 + tRPC 11, Node 22)  ── authorization/policy layer (RBAC+ABAC, risk, step-up)
        │                    │
        │                    ├── MySQL 8.4 (read model: identities, assets, content versions, audit, sessions)
        │                    ├── Self-hosted Kubo IPFS (encrypted asset content blobs; operator-controlled node)
        │                    └── Besu QBFT JSON-RPC (contracts: AccessControl, IdentityRegistry, AssetRegistry, Governance)
        ▼
Chain event indexer (30s schedule, tx-hash dedup) → MySQL audit read model
        ▼
Graph/query layer (optional: graph-node + subgraph; the app also decodes events directly from RPC)
```

### Content storage — encryption BEFORE IPFS

Sensitive asset content is **AES-256-GCM encrypted before it is handed to IPFS**:

```
plaintext ──► AES-256-GCM (per-object data key, wrapped by ASSET_CONTENT_MASTER_KEY)
        ──► encrypted blob ──► self-hosted Kubo (operator's own node, pinned)
        ──► CID ──► database reference (asset_content_versions.storageReference) + provenance
```

- IPFS is **self-hosted Kubo** (`IPFS_API_URL`); no public IPFS gateway is required and none is used.
- The IPFS CID is a **storage/content reference only — it is NOT an authorization mechanism**. Knowing a CID grants nothing.
- **Authorization occurs before content retrieval/decryption**: RBAC/ABAC + classification + step-up policy are evaluated server-side before the blob is fetched from Kubo and decrypted.

### Division of responsibility

The **blockchain is the trusted state-transition and evidence layer** — contracts independently re-verify every protected transition. **MySQL is the read model** — application data, DID documents, content-version metadata, audit projections. The database is never moved on-chain; chain data is never assumed without on-chain verification.

---

## Technology Stack

| Layer            | Technology                                                                                                                                                             |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Frontend         | React 19, TypeScript 5.9, Vite 8, wouter 3, Tailwind CSS 4, shadcn-style UI, Radix primitives, TanStack Query 5                                                         |
| API              | Node.js 22, Express 5, tRPC 11, superjson, Zod 4                                                                                                                       |
| Auth             | jose 6 (HS256 JWT, appId-bound), OAuth2 authorization-code flow, DID-signed step-up challenges (ethers 6, secp256k1)                                                    |
| Database         | MySQL 8.4, Drizzle ORM + drizzle-kit (append-only migrations)                                                                                                          |
| Blockchain       | Hyperledger Besu 25.10 (QBFT, 4 validators), ethers 6                                                                                                                  |
| Smart contracts  | Solidity 0.8.30 (solc pinned), OpenZeppelin Contracts 5.3 (`AccessControl`, `ERC721`)                                                                                  |
| Content storage  | AES-256-GCM (Node crypto), self-hosted Kubo IPFS HTTP RPC (`IPFS_API_URL`)                                                                                             |
| PQC assurance    | `@noble/post-quantum` — ML-DSA-65, policy-driven (`registered` key provider in production)                                                                             |
| Tooling          | pnpm 10, Vitest 5, esbuild, Docker + Docker Compose                                                                                                                    |
| E2E verification | Python + Playwright harnesses (`scripts/e2e-browser.py`, `scripts/e2e-session-isolation.py`) + Node live verifiers (`server/verify-*.mjs`, `scripts/verify-*.mts`)      |

Not used: PostgreSQL, NestJS, Prisma, Next.js, any third-party IPFS pinning service.

---

## Security

- **AES-256-GCM envelope encryption.** Every content version gets a fresh 32-byte data key; the data key encrypts the blob (AES-256-GCM, random 12-byte nonce, auth tag), and the data key itself is wrapped with `ASSET_CONTENT_MASTER_KEY`. The master key never touches stored data; decrypting requires both the master key (server env) and the wrapped key (DB row).
- **Per-object flow.** plaintext → AES-256-GCM encrypt → encrypted blob → Kubo add (pinned) → CID stored in DB with `contentHash = sha256(plaintext)`; read path: authorize → fetch CID → unwrap key → decrypt → verify hash → serve (`disposition: view`).
- **Encrypted blobs in Kubo.** Only ciphertext leaves the server. Verified live: the plaintext marker never appears in raw Kubo bytes for the stored CID; the CID is derived from ciphertext, so V1/V2 of the same asset have distinct CIDs.
- **Integrity verification.** `content.verifyIntegrity` re-fetches the blob, decrypts, and compares against the stored `contentHash`; tampering with Kubo data (or a wrong CID) fails verification and retrieval.
- **DID challenge/nonce/replay protection.** Sensitive operations require a server-issued, purpose- and audience-bound, identity-bound challenge signed with the identity's DID key; challenges are single-use — replay and cross-purpose reuse are rejected (live-verified).
- **ECDSA/secp256k1 baseline.** Chain transactions and DID authentication use secp256k1 ECDSA (ethers 6). This is the EVM baseline.
- **ML-DSA-65 policy-driven PQC assurance.** On top of the ECDSA baseline, high-risk/irreversible operations can require an ML-DSA-65 signature from a **registered** public key (production default: `registered` only; dev derivation refused in production). **ML-DSA does not replace ECDSA** — SAMPRAAN uses policy-driven cryptographic assurance: the policy engine decides per operation which algorithms/signatures are required, and ECDSA remains the chain signature scheme.
- **RBAC.** Roles `ADMIN`, `MANAGER`, `AUDITOR`, `USER` in the read model; on-chain `DEFAULT_ADMIN_ROLE`, `IDENTITY_ADMIN_ROLE`, `ASSET_MANAGER_ROLE`, `AUDITOR_ROLE` in `SampraanAccessControl`. Every mutating procedure re-checks role server-side; the contract re-checks on-chain.
- **ABAC.** Asset classification (5 levels, PUBLIC→CRITICAL) is resolved server-side from the DB — client-asserted classification/ownership never influences a decision (test-proven). Classification constrains who may read/edit/transfer.
- **Deterministic risk scoring.** Risk policy derives a score from action, classification, and identity state; score + policy decide ALLOW / DENY / CHALLENGE deterministically. Security-intelligence surfaces (alerts, risk views) are advisory only and never grant authorization.
- **Step-up authentication.** High-risk reads/edits/transfers require a fresh DID-key-signed step-up challenge (single-use, purpose-bound, short TTL). Verified live: a valid step-up unlocks exactly one purpose-bound action; replay is rejected.
- **Multisig (2-of-N) + timelock.** Governance operations route through the `SampraanGovernance` contract: proposer (maker) → distinct approvers reach quorum → timelock delay → execute. The contract enforces distinct-actor approval (no self-approval).
- **Maker-checker.** Asset mint and high-risk flows are maker-checker end-to-end: the maker cannot approve their own proposal (403, live-verified), and state transitions are guarded (412 on invalid transitions).
- **Controlled transfer.** ERC-721 marketplace primitives (`approve`, `setApprovalForAll`, `transferFrom`, `safeTransferFrom`) are permanently disabled in `SampraanAssetRegistry`; custody changes only via the guarded `transferCustody()` (role + both custodians ACTIVE + asset ACTIVE on-chain) and the governed transfer workflow (request → recipient accept → admin approve → execute, with step-up where policy requires).
- **Audit/provenance.** Application decisions and chain evidence in `audit_events` (transactionHash, blockNumber, blockHash); top-level provenance query reconstructs an asset's full history from application + chain events (16-entry verified trail in E2E). The read model can be rebuilt from the chain.
- **Session security.** Server-side session tracking + revocation (logout kills cookie and Bearer channels immediately), appId-bound JWTs, `httpOnly` `SameSite=Lax` cookies, no token in JS-visible storage (browser-verified).
- **Platform hardening.** CSP, HSTS (under TLS/proxy), nosniff, frame-deny; fail-closed CORS; memory-bounded rate limiting (120 req/min/IP, 429 + Retry-After); 1 MB body cap with a dedicated parser for the 20 MiB content upload (deterministic 413); error masking; non-root Docker user; fail-closed startup on weak secrets.

---

## IPFS / Kubo

Actual flow:

```
plaintext ──► AES-256-GCM ──► encrypted blob ──► self-hosted Kubo (add + pin) ──► CID ──► database/provenance reference
```

- `IPFS_API_URL` — the Kubo HTTP RPC API endpoint (e.g. `http://127.0.0.1:5001/api/v0`). Bare `host:port` is normalized to `/api/v0` automatically.
- **Production requires a reachable self-hosted Kubo API.** Startup and content operations fail closed without it — there is no silent local-filesystem fallback and no third-party IPFS provider in production.
- No public IPFS gateways are used or recommended; content is ciphertext anyway, but the node is the operator's own.
- **Railway/Render do not host Kubo.** Kubo must run on infrastructure controlled by the operator (same host, private network, or a reachable self-hosted server), and `IPFS_API_URL` must point at it. One Kubo container can be run adjacent to the app; the repository does not manage the Kubo lifecycle for you.
- Readiness reports Kubo status: `GET /ready` returns `kubo:{configured,reachable,cid}` from a real bounded add→cat round-trip probe (memoized 15s). Kubo is reported, not a hard gate — but content operations fail closed when it is down (verified: upload and retrieval fail with no fake success).
- No IPFS credentials are used — the operator's node, operator's network.

---

## Blockchain

- **Hyperledger Besu** permissioned network, **QBFT** consensus (4 validators, 2s blocks, immediate finality — no reorgs), local chain ID **4224** (configurable via `BLOCKCHAIN_CHAIN_ID`; a mismatch refuses to bind contracts).
- Contracts (Solidity 0.8.30, OpenZeppelin 5.3): `SampraanAccessControl` (roles), `SampraanIdentityRegistry` (DID→wallet + status), `SampraanAssetRegistry` (restricted ERC-721), `SampraanGovernance` (multisig + timelock target).
- **Real transaction receipts**: every protected transition submits a real transaction and waits for the receipt; `transactionHash`, `blockNumber`, `blockHash`, `gasUsed` are recorded as audit evidence. Chain rejection records `BLOCKCHAIN_TRANSACTION_FAILED` — never a misleading success.
- **Event indexing**: `chain-event-indexer.ts` (30s schedule) projects contract events into `audit_events` (source `CHAIN_READ_MODEL`), idempotent across restarts via persisted tx-hash dedup.
- **Provenance**: full per-asset history (registration, mint, activation, assignment, custody transfers, content versions, governed actions) from application + chain events; custody read-model sync after on-chain transfer is live-verified.
- **NFT ownership/custody**: each asset is an ERC-721 token in `SampraanAssetRegistry`; marketplace transfers are permanently disabled — custody moves only through the guarded, governed path. Governed mint activates the asset on-chain post-execute (verified: first post-mint transfer succeeds).
- Only digests and addresses go on-chain — never PII or content bytes.

---

## Identity

- **DID**: off-chain W3C DID documents (`did_records`); on-chain `keccak256(DID)` → wallet + status anchor in `SampraanIdentityRegistry`.
- **Identity lifecycle**: register → verify/activate → suspend → reactivate → revoke; every status change mirrors on-chain and immediately strips session access (next request is rejected).
- **Key rotation & revocation**: identity signing keys rotate with versioned DID documents; revoked keys fail signature verification; revocation is enforced in challenge verification and step-up.
- **Verification**: DID-signed authentication challenges (purpose/audience-bound) and step-up challenges; verification happens server-side against the current key material.
- **Suspension/deactivation**: suspended/revoked identities cannot pass the session gate, receive step-up challenges, or act on-chain (contract also enforces identity status).
- **Replay protection**: single-use nonces for authentication and step-up challenges; concurrent and cross-purpose replays rejected (live-verified).

---

## Roles

| Role        | Authorization boundary                                                                                                                                                                                                                             |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ADMIN**   | Full platform administration: identity lifecycle (verify/suspend/revoke), role/permission management, governance approvals (checker), identity status changes, system configuration. Cannot bypass maker-checker (cannot approve own proposals — 403). |
| **MANAGER** | Asset operations within scope: create/request assets, mint proposals (maker), execute governed actions after approval, custody assignment and controlled transfers (with step-up where policy requires). No user/role administration.                |
| **AUDITOR** | Read-only: audit trail, provenance, compliance views, integrity verification. No mutation rights anywhere — attempts are denied server-side and audited (live-verified 403s).                                                                       |
| **USER**    | Self-service: view assets assigned to them, accept inbound custody transfers, view content they are granted access to (grant-scoped). No administrative or minting capability.                                                                       |

Role resolution is server-side only (session → DB); frontend checks are UX only. On-chain, the contracts re-verify roles independently.

---

## Governance

High-risk actions route through a governed pipeline enforced by the `SampraanGovernance` contract:

- **Maker-checker**: a proposer (maker) creates a request; a distinct actor (checker/admin) must approve — self-approval is rejected on-chain and at the API (403, live-verified).
- **Multisig quorum**: 2-of-N approval on the governance contract before execution; approvals are distinct-actor and tracked on-chain.
- **Timelock**: approved proposals wait out a timelock delay before execution, giving a window to detect and react to compromised keys.
- **High-risk actions**: asset mint (creates the asset + activates on-chain), governed custody transfer, and other irreversible operations.
- **Replay protection + execute-once**: a proposal executes exactly once — re-execution reverts (contract state machine), and API state guards return deterministic 412s on invalid transitions (verified live: replay of mint.execute → 412).
- Governed mint execution anchors the asset on-chain **and activates it** in the same flow (post-execute `setAssetStatus(ACTIVATE)`, audited; failure records `BLOCKCHAIN_TRANSACTION_FAILED`).

---

## Asset Lifecycle

```
Create/request (manager; classification set server-side)
   → approval (maker-checker / governed as policy requires)
   → mint (governance: request → multisig approve → timelock → execute; asset row created, NFT minted)
   → on-chain activation (setAssetStatus ACTIVATE post-execute, audited)
   → assignment (custodian assignment, both identities ACTIVE on-chain)
   → controlled transfer (governed: request → recipient accept → admin approve → execute;
                          or guarded transferCustody() with step-up where policy requires)
   → provenance/audit (every step: application audit event + on-chain event + indexer projection)
```

Content lifecycle rides alongside: encrypted versions (V1, V2, …) are added under the same authorization policy; each version gets its own CID, key, and integrity hash; grants authorize per-version decryption.

---

## Testing

All numbers below were re-run and confirmed passing on this commit (dev :3000 and production build :8321):

| Suite                                                       | Result     | Command                                                                    |
| ----------------------------------------------------------- | ---------- | -------------------------------------------------------------------------- |
| Unit/integration (Vitest)                                   | **548/548** (40 files) | `pnpm test`                                                    |
| Adversarial security matrix (live)                          | **63/63**  | `node --env-file=.env server/verify-adversarial.mjs`                        |
| DID hardening (live: challenge/replay/step-up/rotation)     | ALL PASS   | `node --env-file=.env server/verify-did-hardening.mjs`                      |
| Governance lifecycle (live: maker-checker, state guards)    | **19/19**  | `node --env-file=.env server/verify-governance.mjs`                          |
| IPFS evidence (live Kubo: ciphertext-only, tamper, fail-closed) | **22/22** | `pnpm exec tsx --env-file=.env scripts/verify-ipfs-evidence.mts`         |
| Asset E2E (mint→activate→content→transfer, dev **and** prod) | ALL PASS  | `node --env-file=.env server/verify-asset-e2e.mjs [base-url]`               |
| Session isolation (browser, 2 contexts)                     | **13/13**  | `python scripts/e2e-session-isolation.py`                                   |
| Browser E2E (real UI logins, no console errors)             | **18/18**  | `python scripts/e2e-browser.py`                                             |
| Acceptance flow (dev **and** prod)                          | ALL PASS   | `pnpm run verify:acceptance`                                                 |
| Security live checks (DID/step-up binding, graph/provenance) | ALL PASS  | `node --env-file=.env server/verify-security.mjs`                            |
| Fresh-DB migrations (true cold-start proof)                 | **18/18**  | `FRESH_DATABASE_URL=… node scripts/verify-migrations.mjs`                    |
| Production dry run (build→start→health→SIGTERM)             | **PASS**   | `bash scripts/ops/prod-dryrun.sh`                                            |
| Dependency audit (prod)                                     | clean      | `pnpm audit --prod` → no known vulnerabilities                              |
| Typecheck                                                   | clean      | `pnpm run check`                                                             |

What the live suites prove: Kubo is actually reachable and stores **only ciphertext** (plaintext marker absent in raw Kubo bytes; byte-exact authorized decryption; tampered/invalid CID retrieval fails; Kubo-down fails closed); blockchain transactions confirm with real receipts (transfer tx + custody sync); the indexer projects events into the read model; browser sessions are isolated with no JWT in JS-visible storage and no console errors.

---

## Deployment

The application runs on **Railway** or **Render** (configs ship in-repo: `railway.json`, `render.yaml`, `Dockerfile`, `docker-compose.production.yml`).

**Required external dependencies (operator-provisioned, not hosted by Railway/Render):**

- **MySQL 8.x** — Railway MySQL plugin or an external MySQL host (Render Postgres is NOT compatible).
- **Besu/QBFT RPC** — a reachable JSON-RPC endpoint of your permissioned network.
- **Self-hosted Kubo** — your own IPFS node, reachable at `IPFS_API_URL` (operator-controlled infrastructure).
- **Graph infrastructure** — optional; the app queries Besu RPC directly without it.

**Required environment variables** (all documented in `.env.example`):

| Variable                  | Required      | Purpose                                                                    |
| ------------------------- | ------------- | -------------------------------------------------------------------------- |
| `DATABASE_URL`            | yes (prod)    | MySQL connection string (`mysql://…`)                                       |
| `JWT_SECRET`              | yes (prod)    | Session signing secret, ≥ 32 random chars; startup fails closed without it   |
| `VITE_APP_ID`             | yes (prod)    | Binds session tokens to this deployment                                     |
| `ASSET_CONTENT_MASTER_KEY`| yes (prod)    | 64 hex chars (32 bytes) AES-256-GCM master key wrapping per-object data keys |
| `IPFS_API_URL`            | yes (prod)    | Self-hosted Kubo RPC API; production refuses to start without it            |
| `APP_URL`                 | recommended   | Public origin of the deployment                                             |
| `TRUST_PROXY`             | behind proxy  | `1` only when a real reverse proxy fronts the app                           |
| `BLOCKCHAIN_RPC_URL`      | for chain     | Besu JSON-RPC endpoint                                                      |
| `BLOCKCHAIN_CHAIN_ID`     | for chain     | Expected chain ID (default `4224`); mismatch refuses to bind                |
| `BLOCKCHAIN_PRIVATE_KEY`  | for chain     | Operator signing key (the tutorial demo key is refused in production)       |
| `PORT`                    | auto (Railway/Render) | The platform injects it; production refuses to hop ports            |

Production startup is **fail-closed** on missing `DATABASE_URL`/`JWT_SECRET`/`VITE_APP_ID`/`ASSET_CONTENT_MASTER_KEY`/`IPFS_API_URL`. Check effective config with `pnpm run check:env` (secrets redacted).

### Docker (self-managed)

```bash
docker compose -f docker-compose.production.yml up -d --build
docker compose -f docker-compose.production.yml exec app pnpm drizzle-kit migrate
curl -f http://localhost:3000/health && curl -f http://localhost:3000/ready
```

---

## Local Development

```bash
corepack enable && pnpm install --frozen-lockfile   # install
cp .env.example .env                                 # then fill values

pnpm run check            # typecheck (tsc --noEmit)
pnpm test                 # unit/integration suite
pnpm run contracts:compile  # solc → blockchain/artifacts
pnpm run blockchain:start   # 4-validator Besu QBFT network (docker)
pnpm run blockchain:deploy  # deploy contracts + roles → blockchain/deployment.json
pnpm run db:push            # drizzle migrations
pnpm run seed:demo          # demo users/identities/assets

pnpm run dev              # dev server → http://localhost:3000

pnpm run build            # vite build + esbuild server → dist/
pnpm run start            # production start (NODE_ENV=production)
pnpm run start:migrate    # apply migrations from the production bundle
```

Health / readiness / verification:

```bash
curl -f http://localhost:3000/health     # liveness
curl -f http://localhost:3000/ready      # readiness (schema + kubo + chain)
pnpm run health:smoke                    # smoke check
pnpm exec tsx --env-file=.env scripts/verify-ipfs-evidence.mts   # IPFS verification
node --env-file=.env server/verify-asset-e2e.mjs                  # asset E2E (real chain+DB)
node --env-file=.env server/verify-asset-e2e.mjs http://127.0.0.1:8321  # against the production build
```

Demo logins (seeded by `pnpm run seed:demo`): `admin@sampraan.dev`, `manager@sampraan.dev`, `auditor@sampraan.dev`, `user@sampraan.dev` — passwords printed by the seed script.

---

## Production Verification

- **`GET /health`** — public liveness: process, DB connection, chain status (bounded 5s RPC timeout), crypto-assurance posture, and which integrations are configured. Never leaks secrets.
- **`GET /ready`** — readiness: `503` until the database connects **and the schema is migrated** (`schema: MIGRATED`); additionally reports a live Kubo round-trip (`kubo.reachable` + a real CID from an add→cat probe) and chain status. Used by the compose healthcheck and load-balancer gating. Verified output on this commit:

```json
{"ready":true,"database":"CONNECTED","schema":"MIGRATED",
 "kubo":{"configured":true,"reachable":true,"cid":"bafkrei…"},
 "blockchain":{"connected":true,"mode":"BESU","chainId":4224,"latestBlock":120160,…}}
```

---

## Known External Dependencies

**IMPLEMENTED AND VERIFIED** (all evidence above was executed on this commit, against a real 4-validator Besu QBFT chain, MySQL 8.4, and a self-hosted Kubo node):

- Full asset lifecycle: maker-checker mint → on-chain activation → assignment → governed transfer → provenance.
- AES-256-GCM encrypted content on self-hosted Kubo (ciphertext-only evidence, tamper detection, fail-closed when Kubo is down).
- DID lifecycle + key rotation/revocation + replay-protected step-up (ECDSA baseline + ML-DSA-65 registered-only policy).
- RBAC/ABAC policy engine, deterministic risk scoring, maker-checker governance with multisig quorum + timelock + execute-once.
- Event indexer, audit/provenance, session isolation and revocation.
- Migrations (fresh cold-start proof), production build/start/health/readiness, graceful SIGTERM.

**REQUIRES OPERATOR CONFIGURATION** (code ready, values must be supplied by the operator):

- Production secrets: `JWT_SECRET`, `ASSET_CONTENT_MASTER_KEY`, `BLOCKCHAIN_PRIVATE_KEY` (real operator key with chain roles), MySQL credentials.
- Production `IPFS_API_URL` pointing at an operator-controlled Kubo node; production Besu RPC for the permissioned chain.
- Railway/Render project setup (MySQL plugin / external MySQL, env vars) and HTTPS termination in front of the app.
- Optional: OAuth2 identity provider (`OAUTH_SERVER_URL`) for enterprise IdP login; graph-node deployment for the subgraph query layer.

**NOT VERIFIED DUE TO EXTERNAL CREDENTIALS:**

- A hosted **Railway/Render deployment** has not been executed — the configs are validated locally (dry run PASS) but "deployed on Railway/Render" is **not** claimed.
- Live enterprise IdP (OAuth2) login with a real external IdP.
- Graph-node subgraph deployment on external infrastructure (local graph-node stack runs; the app works without it).

---

## Limitations / Production Notes

- No formal third-party security audit has been performed.
- Rate limiting is in-process memory (per-replica buckets); use a shared limiter for multi-replica scale-out.
- Indexer lag: chain events reach the read model on a 30s schedule (on-chain evidence itself is immediate).
- Anchoring is best-effort at creation time by design; failures surface as `BLOCKCHAIN_ANCHOR_FAILED` audit events.
- DevDependency-level audit advisories exist (transitive, not shipped in the production image); `pnpm audit --prod` is clean.
- Contracts are deliberately non-upgradeable (no proxies); a regression means deploying new addresses.

## License

`package.json` declares `MIT`; no LICENSE file is committed.
