# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Elasticsearch never healthy, logs `flood stage disk watermark … exceeded` and `failed to retrieve password hash for reserved user [elastic]` | disk above 95%: set absolute `ES_DISK_WATERMARK_*` in `.env` (see deployment.md) and `docker compose up -d elasticsearch` |
| `es-setup` fails | wrong `ELASTIC_PASSWORD` after the volume was created with another one: either restore it or `make reset` |
| Kibana "server is not ready yet" | kibana_system password not set yet — check `docker compose logs es-setup` |
| Events missing from Elasticsearch | `docker compose exec redis redis-cli -a … llen bb:events:<pipeline>` (backlog?) and look in `bb-errors-*` (`error.type` says why: `INDEX_NOT_ALLOWED`, `MISSING_REQUIRED_FIELD`, `MALFORMED_EVENT`, `ELASTICSEARCH_REJECTED`) |
| Job stays `PENDING` | Redis unreachable or `next_attempt_at` in the future (retry backoff); scheduler logs show dispatch |
| Job `BLOCKED` `PRIVATE_ADDRESS` | target resolves to private/reserved space not explicitly in scope; add the IP/CIDR to scope or set `ALLOW_PRIVATE_TARGETS=true` (not recommended) |
| Job `BLOCKED` `POLICY_DISABLED` | the scanner is disabled in the program's default policy; pass `--policy` |
| Job `OUT_OF_SCOPE` | `bbctl scope check <target> -p <program>` explains the decision |
| `httpx` exits with `No such option '-e'` | the Python httpx CLI was called instead of ProjectDiscovery httpx; workers use `/opt/pd/bin/httpx` (`HTTPX_BINARY`) |
| Code change not visible in orchestrator | rebuild via `make build` (the image is built by the `migrate` service) |
| API 503 `database unavailable` | PostgreSQL down: by design nothing is scanned or created |
| `bbctl` tables truncated | set `COLUMNS=200` |
| Notification not delivered | `bbctl notify deliveries` (status, attempts, last_error); `bbctl notify test <channel>`; missing secret → "secret X is not set"; private/http destination → set `NOTIFY_ALLOW_PRIVATE_DESTINATIONS=true` only for lab receivers |
| Same alert not repeated | intended: deliveries are deduplicated per policy and fact |
| CertStream `connected` but `messages` stays empty | upstream is silent; the worker reconnects after `CERTSTREAM_IDLE_TIMEOUT`. Use the self-hosted server (`COMPOSE_PROFILES=ct-server`, `CERTSTREAM_URL=ws://certstream-server:8080/`) |
