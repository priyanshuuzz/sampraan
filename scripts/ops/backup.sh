#!/usr/bin/env bash
# SAMPRAAN backup: MySQL logical dump + deployment manifest snapshot.
#
# Usage:  ./scripts/ops/backup.sh [output-dir]
#
# Produces:
#   <dir>/sampraan-mysql-<ts>.sql.gz   — full logical dump (all tables,
#                                        single-transaction, no locks)
#   <dir>/deployment-<ts>.json         — contract addresses + chain id
#   <dir>/backup-manifest-<ts>.txt     — sha256 of every artifact
#
# The Besu chain state is NOT in this backup by design: chain data is
# append-only and reproducible from genesis + the deployment manifest +
# re-indexed events. Validators keep their own volumes; see
# docs/operations.md for the full chain backup story.
set -euo pipefail

OUT_DIR="${1:-./backups}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
CONTAINER="${MYSQL_CONTAINER:-sampraan-mysql-prod}"

mkdir -p "$OUT_DIR"

echo "[backup] dumping MySQL from container '$CONTAINER'..."
docker exec "$CONTAINER" sh -c \
  'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines --triggers --databases sampraan' \
  | gzip > "$OUT_DIR/sampraan-mysql-$TS.sql.gz"

echo "[backup] snapshotting deployment manifest..."
if [ -f blockchain/deployment.json ]; then
  cp blockchain/deployment.json "$OUT_DIR/deployment-$TS.json"
else
  echo "[backup] WARNING: blockchain/deployment.json missing (chain not deployed from this checkout)" >&2
fi

echo "[backup] writing manifest..."
( cd "$OUT_DIR" && sha256sum sampraan-mysql-$TS.sql.gz deployment-$TS.json 2>/dev/null ) \
  > "$OUT_DIR/backup-manifest-$TS.txt"

echo "[backup] done:"
cat "$OUT_DIR/backup-manifest-$TS.txt"
