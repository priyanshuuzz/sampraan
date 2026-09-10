# SAMPRAAN — Architecture Diagrams (Mermaid)

> Generated from the actual codebase: `client/`, `server/`, `drizzle/`,
> `contracts/`, `blockchain/network/`, `docker-compose.production.yml`.
> All diagrams below render with Mermaid v11 (validated in this repo).

---

## 1. System Architecture (main diagram)

```mermaid
flowchart TB
    %% ============ CLIENT ============
    subgraph CLIENT["CLIENT — React 19 + Vite SPA (client/src)"]
        direction TB
        UI["Workspace UI · Home dashboard<br/>Command Center · Identity · Access Control<br/>Assets · Audit · Alerts<br/>(wouter · shadcn/ui · Tailwind)"]
        HOOKS["useSampraanData hooks + useAuth<br/>TanStack Query · 30s refetch · dev demo fallback"]
        TCLIENT["tRPC client · createTRPCReact&lt;AppRouter&gt;<br/>superjson · httpBatchLink"]
        UI --> HOOKS --> TCLIENT
    end

    %% ============ SERVER ============
    subgraph SERVER["API SERVER — Express 5 + tRPC v11 (server/)"]
        direction TB

        subgraph EDGE["HTTP edge (server/_core)"]
            direction TB
            SEC["securityHeaders · corsPolicy · rateLimit<br/>requestLogger · 1MB body cap"]
            HEALTH["/health · /ready<br/>(readiness DB-gated, chain best-effort)"]
            OAUTHCB["GET /api/oauth/callback<br/>state-nonce CSRF check"]
            STORPROXY["GET /manus-storage/*key<br/>presigned download proxy"]
            SDK["sdk.ts — OAuth client + jose JWT sessions<br/>authenticateRequest gate (revocable, identity-aware)"]
        end

        TRPCMOUNT["tRPC middleware — /api/trpc<br/>createContext resolves user + role"]

        subgraph APPROUTER["appRouter (server/routers.ts)"]
            direction TB
            RAUTH["auth · identities<br/>(create · setStatus — admin only)"]
            RASSET["assets<br/>(create · setStatus · authorizeTransfer)"]
            RREAD["audit · alerts · observatory<br/>blockchain status/tx/events · health<br/>system · demo (dev only)"]
        end

        subgraph MODS["Domain modules (server/modules)"]
            direction TB
            AUTHZ["authorization.service — policy engine<br/>ALLOW / DENY / CHALLENGE<br/>(role · permission · classification · step-up)"]
            ANCHOR["anchoring.service<br/>per-DID derived wallets · anchorIdentity · anchorAsset"]
            BCHAIN["blockchain.service facade — mode BESU or MOCK"]
            BESUAD["besu-blockchain.service<br/>ethers v6 provider + operator signer<br/>register · status · mint · assign · transferCustody"]
            MOCKAD["mock-blockchain.service — unit tests / CI"]
            INDEXER["chain-event-indexer — 30s scheduler<br/>idempotent by tx hash"]
        end

        DBLAYER["server/db.ts — Drizzle ORM (mysql2)"]
    end

    %% ============ DATA ============
    DB[("MySQL 8 — application read model (drizzle/schema.ts)<br/>users · identities · public_keys · did_records<br/>roles · permissions · policies · identity_roles<br/>assets · asset_ownership · asset_custody<br/>audit_events · authorization_decisions<br/>security_alerts · sessions")]

    %% ============ CHAIN ============
    subgraph CHAIN["HYPERLEDGER BESU QBFT — 4 validators (blockchain/network)"]
        direction TB
        RPC["JSON-RPC :8545 · WS :8546 (validator-1)<br/>chainId 4224 · 2s blocks · immediate finality"]
        subgraph CONTRACTS["Solidity contracts (OpenZeppelin-based)"]
            AC["SampraanAccessControl<br/>on-chain RBAC — final authority"]
            IR["SampraanIdentityRegistry<br/>keccak256(DID) → wallet · lifecycle"]
            AR["SampraanAssetRegistry<br/>controlled ERC-721 · transferCustody only"]
        end
        RPC --> AC
        RPC --> IR
        RPC --> AR
    end

    OAUTHPORTAL["Manus OAuth portal — ExchangeToken · GetUserInfo"]
    FORGE["Forge storage API — presigned URLs"]

    %% ============ FLOWS ============
    TCLIENT -->|"HTTPS · /api/trpc"| SEC
    SEC --> TRPCMOUNT
    HEALTH -.->|"db + chain status"| DBLAYER
    OAUTHCB --> SDK
    SDK -->|"code → token → profile"| OAUTHPORTAL
    SDK -->|"upsertUser · track session"| DBLAYER
    STORPROXY --> FORGE

    TRPCMOUNT --> RAUTH
    TRPCMOUNT --> RASSET
    TRPCMOUNT --> RREAD

    RAUTH --> AUTHZ
    RAUTH --> ANCHOR
    RASSET --> AUTHZ
    RASSET --> ANCHOR
    RREAD --> BCHAIN
    RAUTH --> DBLAYER
    RASSET --> DBLAYER
    RREAD --> DBLAYER

    AUTHZ -->|"policies · roles · permissions"| DBLAYER
    ANCHOR -->|"audit anchor outcome"| DBLAYER
    BCHAIN -->|"BESU mode"| BESUAD
    BCHAIN -.->|"MOCK mode"| MOCKAD
    ANCHOR -->|"anchor tx"| BESUAD
    INDEXER -->|"getEvents window"| BESUAD
    INDEXER -->|"project chain events"| DBLAYER
    BESUAD -->|"send tx · read logs"| RPC
    DBLAYER -->|"SQL"| DB
```

---

## 2. Authentication & Session Flow

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (React SPA)
    participant S as Express server (server/_core)
    participant M as Manus OAuth portal
    participant D as MySQL

    B->>B: startLogin() — nonce + __Host-oauth_state cookie
    B->>M: GET /app-auth (appId · redirectUri · state)
    M-->>B: user signs in → redirect ?code&state
    B->>S: GET /api/oauth/callback?code&state
    S->>S: state nonce == cookie nonce (CSRF guard)
    S->>M: ExchangeToken(code)
    M-->>S: access token
    S->>M: GetUserInfo(token)
    M-->>S: openId · name · email
    S->>D: upsertUser(users)
    S->>S: createSessionToken — jose JWT · 7 day TTL
    S->>D: insert sessions row (revocable)
    S-->>B: Set-Cookie app_session_id (Secure)
    Note over B,S: Every tRPC call runs authenticateRequest —<br/>verifies JWT, sessions row and identity status<br/>(logout revokes both cookie and bearer token)
```

---

## 3. Asset Transfer Authorization Flow (assets.authorizeTransfer)

```mermaid
sequenceDiagram
    autonumber
    participant U as Operator (browser)
    participant C as React client
    participant S as tRPC server
    participant A as authorization.service
    participant D as MySQL (Drizzle)
    participant B as besu-blockchain.service
    participant V as Besu QBFT validators
    participant T as SampraanAssetRegistry

    U->>C: request transfer of an asset
    C->>S: trpc.assets.authorizeTransfer(assetId)
    S->>S: authenticateRequest — session + identity status
    S->>D: load asset · identities · roles · permissions · policies
    S->>A: evaluate(request)
    A-->>S: ALLOW / DENY / CHALLENGE (+ policyId · reason)
    alt DENY or CHALLENGE
        S->>D: createAuditEvent(decision · reason)
        S-->>C: decision — no chain transaction
    else ALLOW
        S->>B: transferCustody(asset · custodian)
        B->>V: eth_sendRawTransaction (operator-signed)
        V->>V: QBFT consensus — immediate finality
        V-->>B: receipt (txHash · blockNumber)
        B-->>S: TransactionEvidence
        S->>D: applyCustodyTransfer + createAuditEvent(txHash)
        Note over T,V: contract independently re-verifies role,<br/>identity status and asset state —<br/>the chain is the FINAL authority
        S-->>C: ALLOW + on-chain evidence
    end
    C-->>U: decision panel + chain proof
```

---

## 4. Deployment Topology (Docker)

```mermaid
flowchart LR
    USER["Operator browser"] -->|"http :3000"| APP

    subgraph PROD["docker-compose.production.yml"]
        APP["sampraan-app container — node dist/index.js<br/>Express 5 · tRPC · serves Vite build (dist/public)<br/>healthcheck: curl /ready"]
        MYSQL[("sampraan-mysql-prod — mysql:8.4<br/>volume: sampraan-mysql-data")]
        APP -->|"mysql:3306 · internal network"| MYSQL
    end

    subgraph CHAINC["blockchain/network/docker-compose.yml — separate lifecycle"]
        direction TB
        V1["validator-1<br/>RPC :8545 · WS :8546 · P2P :30303"]
        V2["validator-2"]
        V3["validator-3"]
        V4["validator-4"]
        V1 <--> V2
        V1 <--> V3
        V2 <--> V4
        V3 <--> V4
    end

    APP -->|"sampraan-chain network · BLOCKCHAIN_RPC_URL"| V1
```

---

### Notes

- **Backend = advisory, chain = final.** The backend policy engine
  (`authorization.service`) decides whether a request *should* be submitted;
  the smart contracts independently re-verify role, identity status and asset
  state on-chain before any state transition.
- **MySQL is the application/read model** — full application data, DID
  documents, audit query projections; the DB is not moved on-chain. Only
  keccak256 digests ever reach the chain (no PII).
- **Anchoring is best-effort** at the creation boundary: a chain outage never
  blocks identity/asset creation, but every anchor attempt (ANCHORED /
  SKIPPED / FAILED) is written to `audit_events`.
- **The chain-event-indexer** runs every 30 s in the API server, projecting
  contract events into `audit_events` (source: `CHAIN_READ_MODEL`), seeded
  from the read model so it stays idempotent across restarts.
- **Blockchain mode**: without `BLOCKCHAIN_RPC_URL` the facade routes to the
  mock service (tests/CI); with it, the real Besu adapter is used.
- **Ops tooling**: `scripts/ops/backup.sh`, `restore.sh`, `rollback-app.sh`
  (MySQL backups, restore, app rollback — see `docs/operations.md`).
