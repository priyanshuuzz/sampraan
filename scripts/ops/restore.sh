#!/usr/bin/env bash
# SAMPRAAN restore: load a MySQL dump produced by backup.sh.
#
# Usage:  ./scripts/ops/restore.sh <dump.sql.gz>
#
# Safety:
#   - Refuses to run against a database that already has SAMPRAAN tables
#     unless --force is passed (prevents accidental overwrite).
#   - Writes a pre-restore safety dump first.
set -euo pipefail

DUMP="${1:?usage: restore.sh <dump.sql.gz> [dest-container]}"
FORCE="${2:-}"
CONTAINER="${MYSQL_CONTAINER:-sampraan-mysql-prod}"

[ -f "$DUMP" ] || { echo "restore: dump file not found: $DUMP" >&2; exit 1; }

# Pre-restore safety dump.
SAFETY="./backups/pre-restore-$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
mkdir -p ./backups
echo "[restore] writing pre-restore safety dump to $SAFETY"
docker exec "$CONTAINER" sh -c \
  'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --databases sampraan' \
  | gzip > "$SAFETY"

# Occupancy check.
TABLES=$(docker exec "$CONTAINER" sh -c \
  'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema="sampraan""')
if [ "$TABLES" != "0" ] && [ "$FORCE" != "--force" ]; then
  echo "restore: target database already contains $TABLES table(s)." >&2
  echo "restore: pass --force as the second argument to overwrite." >&2
  exit 2
fi

echo "[restore] loading $DUMP into $CONTAINER..."
gunzip -c "$DUMP" | docker exec -i "$CONTAINER" sh -c \
  'mysql -uroot -p"$MYSQL_ROOT_PASSWORD"'

echo "[restore] done. Verify with: docker exec $CONTAINER mysql -uroot -p\$MYSQL_ROOT_PASSWORD -e 'SELECT COUNT(*) FROM sampraan.identities'"
