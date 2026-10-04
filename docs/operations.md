# Operations

## CLI (`./bbctl …` runs inside the orchestrator container)

```
bbctl health
bbctl program list | create NAME [...] | update P [...] | delete P | targets P [--kind host|url --out FILE]
bbctl scope list [-p P] | add P VALUE [--type --mode include|exclude] | remove SCOPE_ID | check TARGET [-p P]
bbctl asset list [-p P --type --q] | show ASSET_ID
bbctl scan run -p P -t TARGET... [-a ASSET_ID...] -s SCANNER... [--policy --priority --force]
bbctl scan status [SCAN_ID] | cancel SCAN_ID | jobs [--status --scanner]
bbctl worker status | pause SCANNER | resume SCANNER      # status includes per-queue pools (pending/busy)
bbctl policy list | show NAME | create NAME CONFIG.json | update NAME CONFIG.json | delete NAME --yes
                     # via ./bbctl (read-only container) pass the file on stdin:  ./bbctl policy update recon - < recon.json
bbctl schedule list | enable NAME [--program --policy] | disable NAME
bbctl notify types | channels | add-channel | remove-channel | test | policies | add-policy | remove-policy | deliveries
bbctl dlq list QUEUE | replay QUEUE [--limit] | purge QUEUE --yes
bbctl maintenance list | add --start ISO --end ISO --reason TEXT [-p PROGRAM] [--scanner NAME]
bbctl bootstrap bounty-targets
bbctl sync ipranges                  # provider IP ranges (also daily via the scheduler)
bbctl sync asn                       # IP -> ASN ranges from iptoasn.com (also daily)
bbctl sync kev                       # CISA KEV now (also every 6 h)
bbctl sync epss                      # queued EPSS import (also daily)
bbctl sync cve [--force]             # queued CPE->CVE correlation (--force ignores the NVD cache)
bbctl stats
```

A locally installed CLI (`pip install -e apps/orchestrator`) works with `BB_API_URL` and
`BB_API_KEY` set.

## API

`GET /health`, `GET /ready`, `GET /metrics` (Prometheus) are unauthenticated. Everything else
needs `X-API-Key`. Roles: **viewer** (read), **operator** (programs, scope, scans, schedules,
scanner pause, maintenance), **admin** (policies, API keys). OpenAPI at `/docs`.

```
GET/POST /programs        GET/PATCH/DELETE /programs/{id|slug}
GET/POST /programs/{p}/scope    PATCH/DELETE /scope/{id}    POST /scope/check
GET /assets   GET/PATCH /assets/{id}   GET /assets/{id}/relationships
POST/GET /scans   GET /scans/{id}   POST /scans/{id}/cancel
GET /jobs   GET /jobs/{id}   POST /jobs/{id}/cancel
GET/POST /policies   PUT /policies/{name}
GET /schedules   PATCH /schedules/{name}
PUT /scanners/{name}        (pause/resume)
GET/POST /maintenance-windows
POST /api-keys              (admin; returns the key once)
POST /sync/bounty-targets   POST /sync/ipranges   POST /sync/asn   POST /sync/kev   POST /sync/epss (202)   POST /sync/cve (202)
GET /stats   GET /workers   GET /queues[?dlq=<queue>]   GET /audit
POST /queues/{queue}/dlq/replay   DELETE /queues/{queue}/dlq (admin)
GET /notifications/types   GET/POST /notifications/channels   PATCH/DELETE /notifications/channels/{name}
POST /notifications/channels/{name}/test   GET/POST /notifications/policies   DELETE /notifications/policies/{id}
GET /notifications/deliveries
```

## Bounty-targets import

`bbctl bootstrap bounty-targets` downloads `domains.txt`, validates/normalizes/deduplicates it
(bare IPs become ipv4/ipv6 scope; unparseable lines are rejected and sampled in the response),
records `import_runs` (source, URL, SHA-256, time) and `source_records` (first/last seen), and
diffs against the previous import: new values → scope entries + assets (`NEW_DOMAIN` /
`NEW_SUBDOMAIN` events), vanished values → scope entries deactivated (never deleted), unchanged
file → only `last_seen` updated. The aggregate program is created **inactive** with the `passive`
policy: activate (and preferably split into per-program scope) only after reviewing each
program's rules. No jobs are queued automatically by the import.

## Pausing

* program: `bbctl program update P --inactive`
* scanner: `bbctl worker pause httpx`
* asset: `PATCH /assets/{id} {"paused": true}`
* window: `POST /maintenance-windows {program?, scanner?, asset_id?, start, end, reason}`

New jobs matching a pause/window are created as `BLOCKED` with the reason. Jobs already queued
are re-checked by the worker at start and blocked the same way; running jobs finish (or use
`scan cancel`, which kills the tool process).

## Dead-letter queues

Jobs land in `bb:dlq:<queue>` after their last retry, or immediately for non-retryable errors.
`bbctl dlq replay <queue>` resets each dead-lettered `FAILED` job to `PENDING` (retry count 0,
"replayed from DLQ by …"). The scheduler then re-dispatches it, so every scope, pause and policy
check runs again. `bbctl dlq replay notifications` re-attempts failed deliveries. `purge` is admin
only. All three actions are audited.

## Backups

PostgreSQL is the state; back it up (`make backup` → `data/backups/*.dump`, mode 600;
`make restore FILE=…` asks for confirmation). Elasticsearch data is history that can be rebuilt
from new scans and is not included.

## Observability

* Structured JSON logs on stdout for every service (`docker compose logs -f <service>`).
* `/metrics`: `scanner_jobs_total{scanner,status}`, `scanner_jobs_running`, `scanner_jobs_failed_total`,
  `scanner_job_duration_seconds_avg`, `assets_discovered_total{asset_type}`, `assets_scanned_total`,
  `scope_blocked_total`, `queue_depth{queue}`, `dlq_depth{queue}`, `worker_health{queue}`,
  `certificates_seen_total`, `cve_matches_total{status}`, `kev_matches_total`, `notifications_total{status}`,
  `scanner_queue_wait_seconds{scanner}`, `worker_busy{queue}`.
  Prometheus itself is not deployed.
* Kibana dashboards: Attack Surface Overview, Certificate Monitoring, Web Technology,
  Vulnerability Monitoring (empty until phase 4), Attack Surface Changes, Recon Operations.
  Regenerate with `python3 kibana/build_dashboards.py` then `docker compose up kibana-setup`.
* Queue/DLQ: `bbctl worker status`, `GET /queues?dlq=httpx`.

## Updating tool versions

Bump the version in `.env` (and the `ARG` default in `workers/common/Dockerfile`), then
`make build && docker compose up -d`. The installer verifies the release checksum. Run
`make test` (parsers are tested against recorded output in `tests/fixtures/`) and a lab scan.
Every job records `tool_version` and `config_hash`.

nuclei templates are pinned the same way: `NUCLEI_TEMPLATES_VERSION` plus the tag's commit SHA
in `NUCLEI_TEMPLATES_COMMIT` (from the GitHub API `git/ref/tags/<tag>`; the installer refuses a
clone whose HEAD differs). The adapter also cross-checks the image's release marker against the
env at every job, so a stale mix of pins fails closed instead of scanning with unknown
templates.
