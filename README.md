# Bug Bounty Asset Intelligence Platform

Scope-enforced, continuous attack-surface monitoring for **authorized** bug bounty programs.
PostgreSQL holds the platform state, Elasticsearch holds observations, and Kibana is the UI.
Scanners are interchangeable workers behind a queue.

> Status: **Phases 1–6 implemented**: foundation; discovery (bounty-targets importer, CertStream, httpx,
> tlsx, DNS, normalization, dedup, change detection); recon (mapcidr, katana, uncover, BBOT, provider
> IP-range enrichment); phase 4 vulnerability (nuclei worker, CISA KEV, EPSS, NVD CPE→CVE correlation).
> Phase 5 (operations): notifications, DLQ replay/purge, maintenance-window CLI, backups, log rotation,
> worker liveness checks, extra metrics. Phase 6: cluster-wide concurrency limits and horizontal
> worker scaling. Remaining gaps: [Roadmap](#roadmap--known-limitations).

> Full status, test results and known limitations: [docs/final-report.md](docs/final-report.md).

## 1. What it does

* Manages bug bounty **programs** and their **scope database (CDB)**: include/exclude rules for
  domains, wildcards, CIDRs, IPs, ASNs and URLs.
* Evaluates every target with a **ScopeEngine** (exclusion > explicit inclusion > wildcard
  inclusion > deny) and enforces it at several independent layers. It **fails closed**.
* Runs scans as **jobs** (idempotent, retried with backoff, dead-lettered) through Redis queues
  to stateless workers.
* Normalizes scanner output into a unified, ECS-style **event schema** with full provenance
  (program → scope rule → asset → scan → job → tool version). Raw output is preserved.
* Maintains canonical **assets**, the **program↔asset** many-to-many relation, and an **asset
  graph** (resolves-to, CNAME, NS/MX, URL, technology, certificate…).
* Detects **changes** (DNS/IP, HTTP status/title/technology, certificate/TLS, expiry, new
  assets) and records **snapshots** without overwriting history.
* Imports **arkadiyt/bounty-targets-data** with provenance and diffing.
* Ships six **Kibana dashboards**, plus metrics and an audit log.

## 2. Architecture

```
            Kibana (UI)  ◄──  Elasticsearch  ◄──  Logstash (11 pipelines + DLQ)
                                                     ▲   reads bb:events:<pipeline>
   bbctl / API ─► Orchestrator (FastAPI) ─► PostgreSQL (CDB, assets, graph, jobs, audit)
                    │ ScopeEngine layer 1            ▲
                    ▼                                │
                 Redis queues ─► workers (httpx, tlsx, dns, …) ─ scope layers 2/2b/3 ─► events
                    ▲
                 Scheduler (leader-elected: dispatch, retries, reaper, schedules)
```

Details: [docs/architecture.md](docs/architecture.md).

## 3. Repository structure

```
apps/orchestrator/      FastAPI app, models, scope engine, services, scheduler, bbctl (package `app`)
workers/common/         ScannerAdapter interface, WorkerRunner, ScopeGuard, subprocess runner, Dockerfile
workers/{httpx,tlsx,dns,mapcidr,katana,uncover}/   job adapters (shared scanner image)
workers/bbot/           BBOT adapter + its own image;  workers/certstream/  passive CT stream
workers/cve_monitor/    KEV / EPSS / NVD correlation service
workers/nuclei/         template scanning (pinned templates); ipranges sync lives in the scheduler
migrations/             Alembic
elasticsearch/          ILM policies, bb-base component template, index templates
logstash/               pipelines.yml, per-stream pipelines, logstash.yml
kibana/                 data views, generated dashboards, build_dashboards.py
configs/lab/            local lab target (dev overlay)
scripts/                bootstrap, health check, ES/Kibana setup, tool installer
tests/unit, tests/integration, tests/fixtures
docs/                   architecture, data model, scope engine, graph, workers, policies, ingestion, ops
```

## 4. Requirements

Docker + Compose v2, about 6 GB of free RAM, `make`, `python3` (to generate `.env`). For
local tests: [uv](https://github.com/astral-sh/uv) (`make venv`).

## 5. Quick start

```bash
make env            # .env with random secrets (never overwritten)
make build
make up-dev         # stack + isolated lab target   (core only: docker compose up -d)
make health
./bbctl bootstrap bounty-targets
./bbctl program list
./bbctl scope list
./bbctl asset list
make lab-program    # program 'local-lab' scoped to lab-target.bb.test / 10.89.250.0/24
./bbctl scan run -p local-lab -t lab-target.bb.test -s httpx -s tlsx -s dns
./bbctl scan status <scan-id>
```

Then open Kibana at http://127.0.0.1:15601 (user `elastic`, password from `.env`) →
Dashboards. API docs: http://127.0.0.1:18000/docs.

## 6. Environment

All configuration is in `.env` ([.env.example](.env.example)): pinned image and tool versions,
secrets, ports, global rate-limit caps (`HTTPX_RATE_LIMIT`, …) and resource limits
(`MAX_CONCURRENCY`, `MAX_CONCURRENT_SCANS`, `MAX_CIDR_SIZE`, `MAX_IPS_PER_JOB`,
`MAX_URLS_PER_CRAWL`, `MAX_CRAWL_DEPTH`, `MAX_SCAN_DURATION`, `ALLOW_PRIVATE_TARGETS`). On a
nearly full disk, set absolute `ES_DISK_WATERMARK_*` values (docs/deployment.md).

## 7. Docker Compose

`compose.yaml` holds the core services (elasticsearch, es-setup, kibana, kibana-setup, logstash,
postgres, redis, migrate, orchestrator, scheduler, httpx/tlsx/dns workers). It uses health-check
ordering, named volumes and pinned versions; platform containers run non-root, read-only with all
capabilities dropped. `compose.dev.yaml` adds DB ports and the lab network/target. Workers
scale with `docker compose up -d --scale httpx-worker=5`.

## 8. Bootstrap

`bbctl bootstrap bounty-targets` downloads, validates, normalizes, deduplicates, imports and
records the source (URL, SHA-256, time, first/last seen per entry), and diffs against the previous
import. The aggregate program is created **inactive** with the `passive` policy, because importing
public scope is not the same as accepting each program's rules. Nothing is scanned automatically.

## 9–10. Programs and scope

```bash
./bbctl program create "Acme" --slug acme --platform hackerone --policy discovery
./bbctl scope add acme '*.acme.com'
./bbctl scope add acme admin.acme.com --mode exclude
./bbctl scope add acme 203.0.113.0/24 --type cidr
./bbctl scope check https://api.acme.com/x -p acme      # explains the decision
```

Every scope change is audited. Rules: [docs/scope-engine.md](docs/scope-engine.md).

## 11. Scan policies

Policies (passive, discovery, conservative-web, crawl, vulnerability, full) are stored in PostgreSQL
and validated against a strict schema and global caps. See [docs/scan-policies.md](docs/scan-policies.md).

## 12. Worker architecture

`ScannerAdapter` (execute → process) plus a generic `WorkerRunner` (claim, scope layers, limits,
timeout, events, retry, DLQ). See [docs/scanner-workers.md](docs/scanner-workers.md).

## 13–14. Elasticsearch indices and Logstash pipelines

`bb-{assets,domains,ips,urls,http,tls,dns,certstream,bbot,katana,nuclei,cve,kev,changes,audit,scans,jobs,errors}-YYYY.MM`
and `bb-{httpx,tlsx,katana,nuclei,bbot}-raw-*`, with explicit mappings (`dynamic: false`) and ILM
retention of 30/60/90/730 days. Logstash runs one pipeline per stream, routes invalid data to
`bb-errors-*`, and re-indexes Elasticsearch rejections from the DLQ. See [docs/ingestion.md](docs/ingestion.md).

## 15. Kibana dashboards

Attack Surface Overview · Certificate Monitoring · Web Technology · Vulnerability Monitoring
(empty until phase 4) · Attack Surface Changes · Recon Operations. They are defined as code in
`kibana/build_dashboards.py` and imported by `kibana-setup`. Useful searches:
`program.name:"Local Lab" and technology.name:"nginx"`, `event.type:"TECHNOLOGY_ADDED"`,
`tls.fingerprint:…`, `event.type:SCOPE_BLOCKED`.

## 16. CVE / KEV / EPSS

The `cve-monitor` service syncs **CISA KEV** (every 6 h; `KEV_ADDED`/`KEV_UPDATED`/`KEV_REMOVED`) and
**EPSS** (daily, ~380k scores). Once a day, or on `bbctl sync cve`, it **correlates** assets:

asset → fingerprinted technology **with a version** → CPE (curated vendor/product table) → NVD CPE match →
CVE → KEV / EPSS.

Results land in `bb-cve-*` as **potential** correlations, carrying separate technology, version and
CPE-mapping confidences, plus `NEW_CVE`/`KEV_ADDED` change events. A fingerprint never counts as
proof that the vulnerable version is running, and version-less technologies are never correlated.
CVSS, EPSS and KEV stay independent fields; no risk score is computed. An `NVD_API_KEY` is
optional (it raises the rate limit). Details: [docs/vulnerability-intel.md](docs/vulnerability-intel.md).

## 17. Notifications

The `notifier` service delivers policy-matched events (NEW_KEV, NEW_CVE, NEW_ASSET/SUBDOMAIN/IP,
TLS_EXPIRING/CHANGED, TECHNOLOGY_CHANGED, SCAN_FAILURE, DLQ_EVENT) to Slack, Discord, Telegram, a
generic (optionally HMAC-signed) webhook, or email:

- **Secrets:** referenced by name and never stored.
- **Destinations:** HTTPS only, no private addresses.
- **Delivery:** deduplicated per fact, retried with backoff, rate-limited per channel, audited.
- **Execution:** never runs commands.

See [docs/notifications.md](docs/notifications.md).

## 18. Scaling

- **Replicas:** workers are stateless, so `docker compose up -d --scale httpx-worker=3`. The scheduler is leader-elected and the API is stateless.
- **Limits:** cluster-wide per scanner, per program and per target host (`MAX_CONCURRENT_SCANS`, `PROGRAM_MAX_CONCURRENT`, `PER_HOST_MAX_CONCURRENT`).
- **Fair share:** at most `DISPATCH_MAX_QUEUED_PER_PROGRAM` jobs per program and scanner wait in the queue at once.
- **Priority:** high-priority lanes for jobs with priority ≥ 7.
- **Graceful shutdown:** a stopping worker finishes its current job.
- **Autoscaling signals:** queue wait, busy workers and per-queue pools in `/metrics` and `GET /workers`.

See [docs/deployment.md](docs/deployment.md#scaling).

## 19. Troubleshooting

See [docs/troubleshooting.md](docs/troubleshooting.md).

## 20–21. Security model and scope enforcement

* Fails closed: no PostgreSQL means no jobs (HTTP 503). Scope that is unloadable or corrupt means
  nothing is scanned. When Redis is down, jobs wait as `PENDING` and never run locally.
* Layer 1 is the orchestrator. Layer 2 is the worker re-check against fresh rules. Layer 2b
  validates DNS resolution: private and reserved IPs are refused unless explicitly in scope, and
  validated IPs are pinned to defeat DNS rebinding. Layer 3 validates every scanner result. Layer 4
  enforces CIDR limits; layer 5 enforces rate limits, concurrency and wall-clock limits.
* `SCOPE_BLOCKED` is recorded in the audit log and emitted as an event, with target, program,
  scope, scanner, layer and reason.
* There is no free-form flag passthrough: tool argv is built from validated fields, with no
  shell. Cross-host redirects are never followed. Intrusive nuclei tags are excluded by default;
  `dos`, `bruteforce` and `default-login` templates are always excluded and cannot be re-enabled.
* httpx, katana and nuclei send a fixed, honest User-Agent (`BB_USER_AGENT`) instead of their
  default random browser User-Agents, plus the optional `BB_REQUEST_HEADER` identification header.
* API keys are stored as SHA-256 hashes, with RBAC (viewer/operator/admin). Every privileged
  action is audited (PostgreSQL, replicated to `bb-audit-*`).
* Elasticsearch runs with security enabled and least-privilege users. Secrets live in `.env` or
  Docker secrets and are never hardcoded. Host ports bind to 127.0.0.1.
* No stealth, WAF bypass, rate-limit evasion, credential attacks or exploitation features.

## 22. Development workflow

```bash
make venv                 # .venv with dev deps (Python 3.12)
make test                 # unit tests
make test-integration     # against the running dev stack
make lint                 # ruff + ruff format --check + mypy
make format
make migrate              # apply migrations (new ones: alembic revision --autogenerate)
make build && docker compose up -d   # after code changes
```

## Roadmap / known limitations

* **Port scanning** (NEW_PORT/PORT_REMOVED producer) is not part of the current worker set.
* Cloud attribution covers the providers published by lord-alfred/ipranges; ASN attribution covers every routed IP (iptoasn.com).
* **nuclei** runs a curated baseline (`exposure,misconfig,takeover`, medium+), never the whole
  bundle by default. A selection that cannot finish within the job deadline at the policy rate limit
  is `BLOCKED / RESOURCE_LIMIT_EXCEEDED` before any traffic is sent. See `workers/nuclei/README.md`.
* **Tool-internal requests without custom headers:** katana's known-files fetch (`robots.txt`,
  `sitemap.xml`) and nuclei's initial scheme probe of a bare host (one `HEAD /`) ignore `-H`, so
  those few requests carry the tool's default User-Agent and no `BB_REQUEST_HEADER`. Set
  `katana.known_files: []` and scan URL targets with nuclei if a program requires every request to
  be tagged.
* CPE mapping covers the curated products in `app/services/technology.py::VENDOR_PRODUCT`; others are only
  correlated when a source supplies a CPE (lower mapping confidence).
* Dashboards use aggregation-based panels, including time-series line charts (new assets, changes, jobs,
  notifications); Lens versions are optional polish.
* **Scaling (phase 6) remaining:**
  * automatic replica management (the platform exposes the signals and enforces cluster-wide limits);
  * request-rate budgets per program/host (today: per-job tool rate limit × per-host concurrency).
* ASN scope entries do not authorize IPs. The single-node Elasticsearch runs without TLS (dev).
  `bb-scans-*` is reserved but not yet written.
