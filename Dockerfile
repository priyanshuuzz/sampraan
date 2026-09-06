# SAMPRAAN production image — multi-stage, non-root, reproducible.
#
# Build:  docker build -t sampraan-app:rc .
# Run:    see docker-compose.production.yml (app + mysql + besu network)
#
# The image builds the client with Vite and bundles the server with esbuild
# (pnpm build), then copies ONLY the runtime artifacts into a slim Node
# image. No dev toolchain, no source, no secrets baked in.

# ---------------------------------------------------------------- Stage 1
# Dependencies: install with a cached layer keyed on the lockfile only.
FROM node:22-alpine AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY patches/ ./patches/
RUN pnpm install --frozen-lockfile --ignore-scripts

# ---------------------------------------------------------------- Stage 2
# Build: compile the client bundle and the server bundle.
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

# Production node_modules only (no devDependencies): install pruned set.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY patches/ ./patches/
RUN corepack enable && pnpm install --frozen-lockfile --prod --ignore-scripts && pnpm store prune

# Runtime artifacts: server bundle, static client, contract ABIs, and
# the deployment manifest (contract addresses — no secrets; git-tracked)
# so the adapter can resolve BESU mode without extra environment variables.
COPY --from=build /app/dist ./dist
COPY --from=build /app/blockchain/artifacts ./blockchain/artifacts
COPY --from=build /app/blockchain/deployment.json ./blockchain/deployment.json
COPY --from=build /app/drizzle ./drizzle
COPY --from=build /app/drizzle.config.ts ./drizzle.config.ts
# Migration runner needs the TS config for drizzle-kit metadata.
COPY --from=build /app/tsconfig.json ./tsconfig.json

USER sampraan
EXPOSE 3000

# Liveness/readiness: /health is coarse (process + DB config), /ready fails
# closed (503) until the database actually connects.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/ready || exit 1

# Fail-closed startup: validateSecurityEnv refuses to boot with a missing/
# weak JWT_SECRET in production, and the port binding refuses to hop.
CMD ["node", "dist/index.js"]
