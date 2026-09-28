#!/usr/bin/env bash
# =============================================================================
# SAMPRAAN PRODUCTION DRY RUN
#
# Simulates the Railway/Render release locally so a deploy is not the first time
# production behaviour is exercised:
#
#   NODE_ENV=production · real >=32-char session secret · AES-256-GCM master key
#   TRUST_PROXY=1 (proxy-aware rate limiting + secure cookies) · a NON-default
#   port · the built bundle (`node dist/index.js`, exactly what the platform
#   runs) · health + readiness probes · security-header and auth-gate assertions.
#
# It never prints a secret and never leaves a server running.
#
# Usage:
#   bash scripts/ops/prod-dryrun.sh
#   PORT=8123 DATABASE_URL='mysql://user:pass@host:3306/db' bash scripts/ops/prod-dryrun.sh
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# An inherited PORT=0 or garbage value must not silently break the run (the
# server itself refuses such a port, correctly — but a dry run should simply
# pick a usable one). Only a real 1-65535 value is honoured.
case "${PORT:-}" in
  ''|*[!0-9]*) PORT=8123 ;;
  *) if [ "${PORT}" -lt 1 ] || [ "${PORT}" -gt 65535 ]; then PORT=8123; fi ;;
esac
LOG="${LOG:-prod-dryrun.log}"
BASE="http://127.0.0.1:${PORT}"

echo "=== SAMPRAAN production dry run (port ${PORT}) ==="

if [ ! -f dist/index.js ]; then
  echo "dist/index.js is missing — run 'pnpm run build' first." >&2
  exit 2
fi

# ---- configuration -----------------------------------------------------------
# Reuse the developer's DATABASE_URL when present; otherwise require it.
if [ -z "${DATABASE_URL:-}" ] && [ -f .env ]; then
  DATABASE_URL="$(node -e "const {config}=require('dotenv');const p=config({quiet:true}).parsed||{};process.stdout.write(p.DATABASE_URL||'')")"
fi
if [ -z "${DATABASE_URL:-}" ]; then
  echo "DATABASE_URL is not set and not present in .env — readiness cannot pass." >&2
  exit 2
fi
export DATABASE_URL

# Secrets are GENERATED per run: this simulates a real production environment
# rather than a developer's .env, and guarantees no real secret is involved.
export NODE_ENV=production
export PORT
export TRUST_PROXY="${TRUST_PROXY:-1}"
export VITE_APP_ID="${VITE_APP_ID:-sampraan}"
export APP_URL="${APP_URL:-$BASE}"
export APP_VERSION="${APP_VERSION:-1.0.0-dryrun}"
export JWT_SECRET="${JWT_SECRET:-$(node -e "process.stdout.write(require('crypto').randomBytes(48).toString('base64url'))")}"
export ASSET_CONTENT_MASTER_KEY="${ASSET_CONTENT_MASTER_KEY:-$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")}"
# Production posture: only holder-registered ML-DSA-65 public keys are trusted.
export PQC_KEY_PROVIDER="${PQC_KEY_PROVIDER:-registered}"

echo "Secrets: generated for this run (JWT_SECRET ${#JWT_SECRET} chars, ASSET_CONTENT_MASTER_KEY ${#ASSET_CONTENT_MASTER_KEY} hex chars)"

# ---- start -------------------------------------------------------------------
node dist/index.js > "$LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$SERVER_PID" 2>/dev/null || break
      sleep 0.25
    done
    kill -9 "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# ---- wait for readiness (bounded) -------------------------------------------
READY=0
for _ in $(seq 1 40); do
  if curl -fsS "${BASE}/health" > /dev/null 2>&1; then READY=1; break; fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
  sleep 0.5
done

if [ "$READY" -ne 1 ]; then
  echo ""
  echo "Server did not become reachable. Startup log:" >&2
  cat "$LOG" >&2
  exit 1
fi

echo ""
echo "--- startup log ---"
sed -n '1,25p' "$LOG"

# ---- IPFS (self-hosted Kubo) verification ------------------------------------
# The production posture REQUIRES IPFS_API_URL; production resolves no storage
# provider without it. When the local Kubo container is reachable we also prove
# the real path: add → CID → pinned → cat round-trips byte-for-byte.
IPFS_API_URL="${IPFS_API_URL:-$(node -e "const {config}=require('dotenv');process.stdout.write((config({quiet:true}).parsed||{}).IPFS_API_URL||'')")}"
if [ -z "$IPFS_API_URL" ]; then
  echo ""
  echo "  FAIL  IPFS_API_URL is not set — production asset content requires the self-hosted Kubo node"
  SMOKE=1
else
  echo ""
  echo "--- self-hosted Kubo IPFS ($IPFS_API_URL) ---"
  if curl -fsS -X POST "$IPFS_API_URL/id" --max-time 5 > /dev/null 2>&1; then
    echo "  PASS  Kubo API reachable"
    PAYLOAD="sampraan-dryrun-$(date +%s)-$RANDOM"
    ADD=$(curl -fsS -X POST -F "file=@-;filename=dryrun.txt" "$IPFS_API_URL/add?pin=true&cid-version=1" --max-time 15 <<< "$PAYLOAD" 2>/dev/null || true)
    CID=$(node -e "try{process.stdout.write(JSON.parse(process.argv[1]).Hash||'')}catch{process.stdout.write('')}" "$ADD" 2>/dev/null || true)
    if [ -n "$CID" ]; then
      echo "  PASS  add → CID $CID"
      PIN=$(curl -fsS -X POST "$IPFS_API_URL/pin/ls?arg=$CID" --max-time 10 2>/dev/null | node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{try{const j=JSON.parse(d);process.stdout.write(Object.keys(j.Keys||{}).length>0?'pinned':'NOT_PINNED')}catch{process.stdout.write('UNKNOWN')}})")
      [ "$PIN" = "pinned" ] && echo "  PASS  object is pinned" || { echo "  FAIL  object not pinned ($PIN)"; SMOKE=1; }
      BACK=$(curl -fsS -X POST "$IPFS_API_URL/cat?arg=$CID" --max-time 15 2>/dev/null || true)
      [ "$BACK" = "$PAYLOAD" ] && echo "  PASS  cat round-trip byte-for-byte" || { echo "  FAIL  cat round-trip mismatch"; SMOKE=1; }
    else
      echo "  FAIL  add did not return a CID"
      SMOKE=1
    fi
  else
    echo "  FAIL  Kubo API unreachable at $IPFS_API_URL — start the sampraan-ipfs container"
    SMOKE=1
  fi
fi

# ---- smoke test --------------------------------------------------------------
echo ""
SAMPRAAN_BASE_URL="$BASE" node scripts/smoke-health.mjs
SMOKE=$?

# ---- graceful shutdown check -------------------------------------------------
echo ""
echo "--- graceful shutdown (SIGTERM) ---"
kill -TERM "$SERVER_PID" 2>/dev/null || true
for _ in $(seq 1 40); do
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.25
done
if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "  FAIL  server did not exit within 10s of SIGTERM"
  SMOKE=1
else
  echo "  PASS  server exited cleanly on SIGTERM"
  tail -3 "$LOG" | sed 's/^/        /'
fi

echo ""
if [ "$SMOKE" -eq 0 ]; then
  echo "PRODUCTION DRY RUN: PASS"
else
  echo "PRODUCTION DRY RUN: FAIL (see above; full log: $LOG)"
fi
exit "$SMOKE"
