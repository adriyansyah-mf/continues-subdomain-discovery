#!/usr/bin/env bash
# One-shot Kibana setup (compose service `kibana-setup`; idempotent, overwrite=true):
# imports data views and dashboards from kibana/**/*.ndjson via the saved objects API.
set -euo pipefail
KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
ROOT="${KIBANA_CONFIG_DIR:-/bb/kibana}"
: "${ELASTIC_PASSWORD:?}"

for _ in $(seq 1 120); do
  curl -s -f -u "elastic:${ELASTIC_PASSWORD}" "${KIBANA_URL}/api/status" >/dev/null && break
  sleep 3
done

shopt -s nullglob
for f in "$ROOT"/data-views/*.ndjson "$ROOT"/saved-objects/*.ndjson "$ROOT"/dashboards/*.ndjson; do
  echo "importing $f"
  out="$(curl -sS -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: bb' \
        -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" --form "file=@${f}")"
  echo "$out" | grep -q '"success":true' || { echo "import failed for $f: $out" >&2; exit 1; }
done
curl -sS -f -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: bb' -H 'Content-Type: application/json' \
  -X POST "${KIBANA_URL}/api/kibana/settings" -d '{"changes":{"defaultIndex":"bb-all"}}' >/dev/null
echo "kibana bootstrap complete"
