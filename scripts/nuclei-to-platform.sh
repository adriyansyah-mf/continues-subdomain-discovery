#!/usr/bin/env bash
# Bridge EXTERNAL Nuclei findings into the platform's Elasticsearch, with the platform's schema.
#
# Nuclei is run by YOU, outside the platform, against targets YOU are authorised to scan. The
# platform never launches Nuclei. Use `bbctl program targets <program> --out targets.txt` to get a
# scope-verified target list first.
#
#   nuclei -l targets.txt -jsonl -silent -severity medium,high,critical -rl 10 \
#     | scripts/nuclei-to-platform.sh [PROGRAM_NAME]
#
# Reads Nuclei JSONL on stdin, converts each finding to the unified event schema and LPUSHes it to
# the Redis list the `nuclei` Logstash pipeline consumes, so it lands in bb-nuclei-* with the same
# fields the dashboards expect. Requires: jq, a running stack.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
PROGRAM="${1:-}"
NUCLEI_VERSION="$(nuclei -version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo unknown)"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

jq -c --arg program "$PROGRAM" --arg ver "$NUCLEI_VERSION" '
  {
    "@timestamp": (.timestamp // (now | todateiso8601)),
    "event": {"kind":"event","category":"vulnerability","type":"NUCLEI_FINDING","action":"NUCLEI_FINDING"},
    "bb": {"index":"bb-nuclei","schema_version":"1"},
    "source": {"name":"nuclei-external","type":"active"},
    "scan": {"tool":"nuclei","tool_version":$ver},
    "asset": {"type":"url","value":(."matched-at" // .host)},
    "host": (if .ip then {"ip":.ip} else {} end),
    "nuclei": {
      "template_id": ."template-id",
      "template_name": (.info.name // null),
      "template_path": ."template-path",
      "severity": (.info.severity // "unknown"),
      "type": .type,
      "matched_at": ."matched-at",
      "url": ."matched-at",
      "host": .host,
      "ip": .ip,
      "matcher": ."matcher-name",
      "matcher_status": ."matcher-status",
      "extracted_results": ."extracted-results",
      "tags": (.info.tags // []),
      "description": (.info.description // null),
      "reference": (.info.reference // []),
      "cve_ids": (.info.classification."cve-id" // []),
      "cwe_ids": (.info.classification."cwe-id" // []),
      "curl_command": ."curl-command"
    }
  }
  | if $program != "" then . + {"program":{"name":$program}} else . end
  | del(.. | nulls)
' > "$TMP"

count="$(grep -c . "$TMP" || true)"
if [ "${count:-0}" -eq 0 ]; then
  echo "no findings on stdin"
  exit 0
fi
# One exec; the loop runs inside the redis container reading the piped events (no stdin races).
docker compose exec -T redis sh -c '
  n=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    redis-cli -a "$REDIS_PASSWORD" --no-auth-warning RPUSH bb:events:nuclei "$line" >/dev/null
    n=$((n + 1))
  done
  echo "forwarded $n finding(s) to the nuclei pipeline"
' < "$TMP"
echo "see Kibana 'Vulnerability Monitoring' (bb-nuclei-*)"
