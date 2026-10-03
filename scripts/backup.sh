#!/usr/bin/env bash
# PostgreSQL holds the platform state (programs, scope, assets, graph, jobs, policies, audit).
# Elasticsearch data is rebuildable history and is not part of this backup.
#   scripts/backup.sh                 -> data/backups/bugbounty-<timestamp>.dump (pg_dump custom format)
#   scripts/backup.sh restore FILE    -> restore into the running database (asks for confirmation)
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
mkdir -p data/backups

if [[ "${1:-}" == "restore" ]]; then
  file="${2:?usage: backup.sh restore FILE}"
  [[ -f "$file" ]] || { echo "no such file: $file" >&2; exit 1; }
  read -r -p "Restore $file over database ${POSTGRES_DB}? Existing objects are replaced. Type 'restore': " a
  [[ "$a" == "restore" ]] || { echo aborted; exit 1; }
  docker compose exec -T postgres pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists \
    --no-owner < "$file"
  echo "restored $file"
  exit 0
fi

out="data/backups/bugbounty-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc > "$out"
chmod 600 "$out"
echo "backup written: $out ($(du -h "$out" | cut -f1))"
