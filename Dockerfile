# SAMPRAAN production image — multi-stage, non-root, reproducible.
#
# Build:  docker build -t sampraan-app:rc .
# Run:    see docker-compose.production.yml (app + mysql) or docs/deployment.md
#         (Railway / Render).
#
# The image builds the client with Vite and bundles the server + the migration
# runner with esbuild (pnpm build), then copies ONLY runtime artifacts into a
# slim Node image: no dev toolchain, no source, no secrets baked in.
#
# MIGRATIONS: the runtime stage installs production dependencies only, so
# `drizzle-kit` (a devDependency) is NOT available here. Migrations therefore
# run through the bundled runner — `node dist/migrate.js` — which uses
# `drizzle-orm`'s migrator from `dependencies`. That is the command wired into
# the compose service, the Railway pre-deploy command and the Render
# preDeployCommand.

# ---------------------------------------------------------------- Stage 1
# Dependencies: install with a cached layer keyed on the lockfile only.
FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY patches/ ./patches/
RUN pnpm install --frozen-lockfile --ignore-scripts

# ---------------------------------------------------------------- Stage 2
# Build: compile the Solidity suite, the client bundle and the server bundle.
FROM node:22-alpine AS build
WORKDIR /app
RUN corepack enable
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# CONTRACTS: the backend needs blockchain/artifacts at runtime; compile the
# Solidity suite so a fresh clone produces identical ABIs.
RUN pnpm run contracts:compile && pnpm run build

# ---------------------------------------------------------------- Stage 3
# Runtime: slim, non-root, no build toolchain.
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN apk add --no-cache curl && addgroup -S sampraan && adduser -S sampraan -G sampraan

# Production node_modules only (no devDependencies).
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY patches/ ./patches/
RUN corepack enable && pnpm install --frozen-lockfile --prod --ignore-scripts && pnpm store prune

# Runtime artifacts:
#   dist/                    server bundle (index.js) + migration runner (migrate.js) + client
#   blockchain/artifacts     compiled ABIs (needed by the chain adapter)
#   blockchain/deployment.json  contract addresses (no secrets; git-tracked)
#   drizzle/                 migration SQL + journal (needed by migrate.js)
COPY --from=build /app/dist ./dist
COPY --from=build /app/blockchain/artifacts ./blockchain/artifacts
COPY --from=build /app/blockchain/deployment.json ./blockchain/deployment.json
COPY --from=build /app/drizzle ./drizzle

# Local encrypted asset-content fallback directory. Multi-replica deployments
# should use IPFS_API_URL instead of this path (a container filesystem is
# ephemeral unless a volume is mounted here).
RUN mkdir -p /app/.sampraan-content && chown -R sampraan:sampraan /app/.sampraan-content
ENV ASSET_CONTENT_STORAGE_DIR=/app/.sampraan-content
VOLUME ["/app/.sampraan-content"]

USER sampraan
EXPOSE 3000

# Liveness: /health is coarse (process + DB + chain status).
# Readiness (/ready) additionally fails closed (503) until the database
# connects AND the required schema is migrated.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/ready || exit 1

# Fail-closed startup: validateSecurityEnv refuses to boot without a strong
# JWT_SECRET, a bound VITE_APP_ID and a DATABASE_URL in production, and the
# port binding refuses to hop to a different port.
CMD ["node", "dist/index.js"]
