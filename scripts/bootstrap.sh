#!/usr/bin/env bash
# Helper for first-run setup.
#   bootstrap.sh env   create .env from .env.example with random secrets (never overwrites)
#   bootstrap.sh lab   create the 'local-lab' program scoped to the dev lab target
set -euo pipefail
cd "$(dirname "$0")/.."

rand() { python3 -c 'import secrets;print(secrets.token_urlsafe(32))'; }

case "${1:-}" in
  env)
    if [[ -f .env ]]; then echo ".env exists - leaving it untouched"; exit 0; fi
    cp .env.example .env
    for key in ELASTIC_PASSWORD KIBANA_SYSTEM_PASSWORD LOGSTASH_WRITER_PASSWORD ES_MONITOR_PASSWORD \
               POSTGRES_PASSWORD REDIS_PASSWORD BB_BOOTSTRAP_ADMIN_KEY KIBANA_ENCRYPTION_KEY; do
      value="$(rand)"
      sed -i "s|^${key}=.*|${key}=${value}|" .env
    done
    chmod 600 .env
    echo ".env created with random secrets (mode 600)"
    ;;
  lab)
    ./bbctl program create "Local Lab" --slug local-lab --platform custom --policy discovery \
      --description "Authorized local lab target from compose.dev.yaml" || true
    ./bbctl scope add local-lab lab-target.bb.test --type domain || true
    ./bbctl scope add local-lab 10.89.250.0/24 --type cidr || true
    ./bbctl scope add local-lab 10.89.250.66 --type ipv4 --mode exclude --description "exclusion demo" || true
    ./bbctl scope list --program local-lab
    ;;
  *)
    echo "usage: $0 env|lab" >&2; exit 2;;
esac
