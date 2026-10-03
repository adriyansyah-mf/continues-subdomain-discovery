#!/usr/bin/env bash
# Verify every platform service. Exit code 0 only if all required services are healthy.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; [[ -f .env ]] && source .env; set +a

ok=0
check() {  # name, command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then printf '  %-15s \e[32mhealthy\e[0m\n' "$name"; else printf '  %-15s \e[31mUNHEALTHY\e[0m\n' "$name"; ok=1; fi
}
dc() { docker compose exec -T "$@"; }

echo "Platform health:"
check elasticsearch bash -c "curl -s -u elastic:${ELASTIC_PASSWORD} http://127.0.0.1:${ES_PORT:-19200}/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"
check kibana bash -c "curl -s http://127.0.0.1:${KIBANA_PORT:-15601}/api/status | grep -q '\"level\":\"available\"'"
check logstash dc logstash curl -sf http://localhost:9600/_node/pipelines
check postgres dc postgres pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}"
check redis dc -e REDISCLI_AUTH="${REDIS_PASSWORD}" redis redis-cli ping
check orchestrator curl -sf "http://127.0.0.1:${API_PORT:-18000}/ready"
for w in scheduler httpx-worker tlsx-worker dns-worker certstream-worker mapcidr-worker katana-worker uncover-worker bbot-worker cve-monitor notifier; do
  check "$w" bash -c "docker compose ps --status running --format '{{.Service}}' | grep -qx $w"
done
echo
curl -s "http://127.0.0.1:${API_PORT:-18000}/ready" || true
echo
exit $ok
