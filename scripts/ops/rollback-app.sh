#!/usr/bin/env bash
# SAMPRAAN application rollback: redeploy the previous image tag.
#
# Usage: ./scripts/ops/rollback-app.sh <previous-image-tag>
#
# Rollback NEVER touches the database schema automatically: if the release
# being rolled back shipped a forward-only drizzle migration, follow the
# schema strategy in docs/operations.md (restore from the pre-deploy backup
# or write a compensating migration). Drizzle migrations are append-only.
set -euo pipefail

PREV="${1:?usage: rollback-app.sh <previous-image-tag>}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"

echo "[rollback] stopping current app..."
docker compose -f "$COMPOSE_FILE" stop app

echo "[rollback] tagging previous image as current..."
docker tag "$PREV" sampraan-app:rc

echo "[rollback] starting previous version..."
docker compose -f "$COMPOSE_FILE" up -d app

echo "[rollback] waiting for readiness..."
for i in $(seq 1 30); do
  if curl -fsS "${APP_URL:-http://localhost:3000}/ready" >/dev/null 2>&1; then
    echo "[rollback] app is ready."
    exit 0
  fi
  sleep 2
done
echo "[rollback] WARNING: app did not become ready within 60s — check logs." >&2
exit 1
