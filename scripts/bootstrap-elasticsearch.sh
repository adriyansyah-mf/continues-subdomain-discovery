#!/usr/bin/env bash
# One-shot Elasticsearch setup (runs in the `es-setup` compose service; idempotent):
#   * sets the kibana_system password
#   * creates least-privilege users: logstash_writer (write bb-*), bb_monitor (read bb-*)
#   * installs ILM policies, the bb-base component template and all index templates
set -euo pipefail

ES_URL="${ELASTICSEARCH_URL:-http://elasticsearch:9200}"
ROOT="${ES_CONFIG_DIR:-/bb/elasticsearch}"
: "${ELASTIC_PASSWORD:?}" "${KIBANA_SYSTEM_PASSWORD:?}" "${LOGSTASH_WRITER_PASSWORD:?}" "${ES_MONITOR_PASSWORD:?}"

es() {  # es METHOD PATH [JSON-FILE|-]
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -f -u "elastic:${ELASTIC_PASSWORD}" -X "$method" -H 'Content-Type: application/json' "${ES_URL}${path}")
  if [[ -n "$body" ]]; then args+=(--data-binary "@${body}"); fi
  curl "${args[@]}" >/dev/null || { echo "FAILED: $method $path" >&2; return 1; }
}

echo "waiting for elasticsearch at ${ES_URL}"
for _ in $(seq 1 120); do
  if curl -s -f -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null; then
    break
  fi
  sleep 2
done

echo "setting kibana_system password"
printf '{"password":"%s"}' "$KIBANA_SYSTEM_PASSWORD" | es POST /_security/user/kibana_system/_password -

echo "creating roles and users"
cat <<JSON | es PUT /_security/role/bb_logstash_writer -
{"cluster":["monitor"],
 "indices":[{"names":["bb-*"],"privileges":["create_index","create_doc","index","write","view_index_metadata"]}]}
JSON
cat <<JSON | es PUT /_security/role/bb_reader -
{"cluster":["monitor"],"indices":[{"names":["bb-*"],"privileges":["read","view_index_metadata"]}]}
JSON
printf '{"password":"%s","roles":["bb_logstash_writer"],"full_name":"Logstash writer"}' "$LOGSTASH_WRITER_PASSWORD" \
  | es POST /_security/user/logstash_writer -
printf '{"password":"%s","roles":["bb_reader"],"full_name":"Orchestrator monitor"}' "$ES_MONITOR_PASSWORD" \
  | es POST /_security/user/bb_monitor -

echo "installing ILM policies"
for f in "$ROOT"/ilm/*.json; do es PUT "/_ilm/policy/$(basename "$f" .json)" "$f"; done

echo "installing component templates"
for f in "$ROOT"/mappings/*.json; do es PUT "/_component_template/$(basename "$f" .json)" "$f"; done

echo "installing index templates"
for f in "$ROOT"/templates/*.json; do es PUT "/_index_template/$(basename "$f" .json)" "$f"; done

echo "elasticsearch bootstrap complete"
