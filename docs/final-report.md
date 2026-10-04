# Final report

State on 2026-10-04: commits `ba36fed`, `9571d19` and later, on `master`. Every number below
was taken from the running dev stack (`compose.yaml` + `compose.dev.yaml`). The structure follows
section 91 of the platform specification.

## 1. Architecture summary

PostgreSQL is the source of truth: programs, scope, assets, the graph, jobs, policies, audit and
operational state. Elasticsearch stores observations and events. Kibana is the only UI.

Work flows CDB → ScopeEngine → orchestrator → Redis queues → workers → normalized events → Logstash
→ Elasticsearch → Kibana. Scanners are adapters behind one `ScannerAdapter` interface, so any tool
can be replaced without touching the rest of the system. See [architecture.md](architecture.md).

## 2. Repository tree

```
apps/orchestrator/app/   api/ cli/ models/ queue/ schemas/ scheduler/ scope/ services/{notify,vuln}/ workers/ utils/
workers/                 common/ httpx/ tlsx/ dns/ mapcidr/ katana/ uncover/ bbot/ certstream/ cve_monitor/ notifier/
                         nuclei/         ipranges/ (README: runs in the scheduler)
elasticsearch/           ilm/ (4 policies)  mappings/bb-base.json  templates/ (21)
logstash/                pipelines.yml  pipelines/ (11 streams + dlq)  config/
kibana/                  build_dashboards.py  dashboards/ (7)  data-views/
migrations/versions/     0001 … 0006
configs/                 lab/ (Caddy lab target, webhook sink)  certstream/  <tool READMEs>
scripts/                 bootstrap, healthcheck, backup, ES/Kibana setup, tool installer
tests/                   unit/ (197 tests)  integration/ (16 tests)  fixtures/ (recorded tool output)
docs/                    13 documents (this report included)
```

## 3. Docker services

There are 21 core services in `compose.yaml`:

- **Data and UI:** elasticsearch, es-setup, kibana, kibana-setup, logstash, postgres, redis.
- **Platform:** migrate, orchestrator, scheduler.
- **Workers:** httpx-worker, tlsx-worker, dns-worker, mapcidr-worker, katana-worker,
  uncover-worker, bbot-worker, certstream-worker.
- **Feeds and notifications:** cve-monitor, notifier.
- **Optional:** certstream-server (compose profile `ct-server`).

The dev overlay adds lab-target and webhook-sink.

Every long-running service has a healthcheck. The orchestrator's is defined in its image; the
one-shot setup jobs (`migrate`, `es-setup`, `kibana-setup`), the third-party CT server and the dev
helpers have none. All services have log rotation and pinned versions. Platform containers run as non-root with a read-only root
filesystem, `cap_drop: ALL`, memory limits and a stop grace period.

## 4. PostgreSQL data model

There are 26 tables:

- **Programs and scope:** programs, scope_entries.
- **Assets:** assets, program_assets, asset_relationships, asset_states.
- **Scanning:** scan_policies, scans, scan_jobs, schedules, scanner_controls, maintenance_windows.
- **Access and audit:** api_keys, audit_events.
- **Imports:** import_runs, source_records.
- **Enrichment:** cloud_ranges, asn_ranges.
- **Vulnerability intelligence:** kev_entries, epss_scores, cves, cpe_lookups, vuln_correlations.
- **Notifications:** notification_channels, notification_policies, notification_deliveries.

Current dev data: 37,086 assets, 37,039 scope entries and 130 graph edges.
See [data-model.md](data-model.md).

## 5. Elasticsearch indices

There are 21 index templates over the `bb-base` component template (`dynamic: false`, explicit
mappings). Retention is set by 4 ILM policies: 30, 60, 90 and 730 days.

Indices populated in the dev stack: assets, audit, bbot(+raw), certstream, changes, cve, dns,
errors, http, httpx-raw, ips, jobs, katana(+raw), kev (1,733), notifications, tls, tlsx-raw, urls.

nuclei(+raw) is populated by the lab end-to-end check (git-config bait finding).

Reserved but empty: domains, scans, uncover (populated once an uncover engine
returns results). See [ingestion.md](ingestion.md).

## 6. Scope enforcement flow

Precedence is exclusion > explicit inclusion > wildcard inclusion > deny. Enforcement happens in
layers:

1. The orchestrator checks fresh scope rules.
2. The worker re-checks fresh rules when the job starts.
3. Resolution is validated: private addresses are refused unless explicitly in scope, and the
   validated IPs are pinned (httpx `-allow`, tlsx SNI to the pinned IP).
4. Every result in the scanner output is re-validated.
5. CIDR, rate, concurrency and duration limits apply.

Any failure to load or evaluate scope blocks the scan. Each block is recorded as `SCOPE_BLOCKED`
in the audit log and as an event. See [scope-engine.md](scope-engine.md).

## 7. Worker architecture

`ScannerAdapter.execute` (runs the tool, no DB access) and `process` (normalize, layer-3 checks,
assets/graph/state, events) run inside a generic `WorkerRunner`. The runner handles claiming,
guards, limits, timeouts and cancellation, emits events before committing, then marks success,
retries or dead-letters. Tools run as argv lists, never through a shell, with no free-form flags.
See [scanner-workers.md](scanner-workers.md).

## 8. Queue architecture

- Redis lists hold one queue per scanner, each with a high-priority lane.
- Each worker has a processing list and a heartbeat.
- Idempotency keys are unique per program/target/scanner/policy/time bucket.
- Retries are driven from the DB (`PENDING` + `next_attempt_at`, exponential backoff); DLQs support replay and purge.
- Dispatch is fair-share across programs.
- Cluster-wide slots limit concurrency per scanner, per program and per host.
- The scheduler is leader-elected.

See [deployment.md](deployment.md#scaling).

## 9. Scanner integration status

| Scanner / feed | Status |
|---|---|
| httpx 1.12.0, tlsx 1.4.0, dns (dnspython) | implemented, verified on the lab |
| mapcidr 1.1.97, katana 1.7.0, uncover 1.2.1 | implemented, verified (uncover needs engine API keys) |
| BBOT 3.0.2 (passive + safe by default) | implemented, verified (own image) |
| CertStream (calidog or self-hosted certstream-server-go) | implemented, verified on live CT data |
| bounty-targets-data, lord-alfred/ipranges, iptoasn | implemented, verified |
| CISA KEV, EPSS, NVD | implemented, verified |
| **nuclei** | implemented: templates pinned in the image (tag + commit verified at build), OOB testing disabled, hosts with URL exclusions refused, findings → `bb-nuclei-*` + `detected` CVE correlations ([workers/nuclei/README.md](../workers/nuclei/README.md)) |

## 10. CVE / KEV flow

Asset → technology **with version** (httpx/BBOT) → CPE (curated table or a source-supplied CPE) →
NVD CPE match → CVE. Each correlation is stored as a **potential** match with separate
technology, version and CPE confidences. CVSS, EPSS and KEV are attached side by side, and
NEW_CVE / KEV_ADDED changes are raised. See [vulnerability-intel.md](vulnerability-intel.md).

## 11. Asset graph

Edges produced today: RESOLVES_TO, CNAME_TO, USES_NAMESERVER, USES_MAIL_SERVER, HAS_URL,
USES_TECHNOLOGY, USES_CERTIFICATE, DISCOVERED_FROM, BELONGS_TO_CIDR, BELONGS_TO_ASN and
AFFECTED_BY_CVE. Being in the graph never authorises a scan. See [asset-graph.md](asset-graph.md).

## 12. Change detection

Each facet's last state is stored in PostgreSQL, compared by pure diff functions, and every
observation is appended as a snapshot. The change types produced are:

- **Discovery:** NEW_DOMAIN, NEW_SUBDOMAIN, NEW_IP, NEW_URL, NEW_ENDPOINT, NEW_PORT, PORT_REMOVED.
- **DNS and network:** DNS_CHANGED, A_CHANGED, AAAA_CHANGED, CNAME_CHANGED, MX_CHANGED,
  NS_CHANGED, IP_CHANGED, ASN_CHANGED, CLOUD_PROVIDER_CHANGED.
- **HTTP and technology:** HTTP_STATUS_CHANGED, TITLE_CHANGED, TECHNOLOGY_ADDED,
  TECHNOLOGY_REMOVED, TECHNOLOGY_CHANGED.
- **Certificates and TLS:** NEW_CERTIFICATE, TLS_CHANGED, CERT_CHANGED, FINGERPRINT_CHANGED,
  ISSUER_CHANGED, SAN_CHANGED, TLS_VERSION_CHANGED, CERT_EXPIRING, CERTIFICATE_EXPIRED.
- **Vulnerabilities:** NEW_CVE, KEV_ADDED.
- **Scope:** SCOPE_BLOCKED.

## 13. Kibana dashboard setup

`kibana-setup` imports the data views and 7 dashboards, which are generated as code by
`kibana/build_dashboards.py`: Attack Surface Overview, Certificate Monitoring, Web Technology,
Vulnerability Monitoring, Attack Surface Changes, Recon Discovery and Recon Operations. They include
time-series charts. All 7 were rendered in a headless browser without panel errors.

## 14. CLI usage

`bbctl` groups: health, stats, program, scope, asset, scan, worker, bootstrap, sync, policy,
schedule, notify, dlq, maintenance. Run it as `./bbctl …` inside the container, or install it
locally. See [operations.md](operations.md).

## 15. API endpoints

There are 61 routes: health/ready/metrics, programs, scope (including `/scope/check`), assets and
relationships, scans and jobs, policies, schedules, scanner controls, maintenance windows, API
keys, sync (bounty-targets, ipranges, asn, kev, epss, cve), queues/DLQ, audit, notifications and
workers (including the autoscaler's audited `POST /workers/scale-events`). OpenAPI documentation is at `/docs`.

## 16. Test results

- `make lint`: ruff and mypy are clean (115 source files).
- `make test`: 230 unit tests pass. They cover scope bypass and malformed input, normalization,
  idempotency, policies, the queue and limits, parsers on recorded output, change detection,
  notifications, KEV/EPSS/NVD/CPE and ASN.
- `make test-integration`: 16 tests pass against the live stack. They cover auth/RBAC, scope
  bypass via the API, malformed scope, scan → Logstash → Elasticsearch, idempotency, KEV sync,
  CertStream including websocket reconnect, and correlation explainability.
- Manual end-to-end checks:
  - failure behaviour: Redis down, PostgreSQL down;
  - graceful shutdown;
  - three-replica load test and per-host serialization;
  - autoscaler: two nuclei jobs on one lab host scaled the pool 1 → 2 (audited `worker.scaled`
    first, new replica joined the lab network), the second replica waited for the host slot
    ("no free host slot"), and the pool returned to 1 after both jobs finished;
  - fair share between programs;
  - DLQ replay;
  - notifications with HMAC signatures;
  - katana never requesting an excluded path (confirmed in the lab target's access log);
  - nuclei end to end on the lab target: a host with a URL exclusion is `BLOCKED / EXCLUDED`; the
    whole bundle is `BLOCKED / RESOURCE_LIMIT_EXCEEDED` up front; the `vulnerability` baseline
    (1,149 templates, 330 s) finds the deliberate `.git/config` bait → `bb-nuclei`,
    `bb-nuclei-raw`, `NEW_FINDING` in `bb-changes`, with program/scope/template-version provenance.

## 17. Known limitations

- katana's known-files fetch and nuclei's bare-host scheme probe ignore custom headers (a few
  requests per job without `BB_USER_AGENT` / `BB_REQUEST_HEADER`); see the README roadmap.
- The autoscaler (`scripts/autoscale.py`) manages Docker Compose replicas on the local host only, and
  runs in the foreground (`make autoscale`); run it under systemd or tmux to keep it going.
- Request rates are limited per job (tool rate limit × per-host concurrency). There are no
  per-program or per-host request-rate budgets.
- katana cannot pin connections to validated IPs. DNS-rebinding protection for crawling relies on
  the pre-flight check plus output validation.
- An ASN scope entry does not authorise IPs. CPE mapping covers only the curated products, or
  CPEs supplied by a source.
- The single-node dev Elasticsearch runs without TLS. Kibana dashboards are aggregation-based
  rather than Lens.

## 18. Remaining TODOs

- Optional: a technology-specific nuclei policy driven by httpx fingerprints.
- Optional: Lens dashboards, request-rate budgets, and Vault integration for secrets.

## 19. Deployment instructions

```bash
make env && make build && make up-dev     # or: docker compose up -d
make health
./bbctl bootstrap bounty-targets
make lab-program && ./bbctl scan run -p local-lab -t lab-target.bb.test -s httpx -s tlsx -s dns
```

For production, use Docker secrets, Elasticsearch TLS, a TLS proxy in front of the API, `make backup`
for PostgreSQL, and absolute disk watermarks on full disks. See [deployment.md](deployment.md).

## 20. Security considerations

- **Scope fails closed:** nothing is scanned when scope cannot be verified, excluded targets are
  never scanned, and passive discovery (CertStream, uncover, BBOT, the graph) never authorises a scan.
- **Bounded scanning:** CIDR expansion is limited; there is no WAF bypass and no rate-limit evasion;
  an optional identification header (`BB_REQUEST_HEADER`) is supported; intrusive nuclei tags are
  excluded by default.
- **No command injection paths:** there are no free-form tool flags and no shell. Notifications
  only send HTTPS or SMTP to public destinations.
- **Access control and audit:** API keys are stored hashed, with RBAC (viewer, operator, admin).
  Scope, policy, scan, notification, DLQ and key actions are audited.
- **Secrets:** stored in `.env` (mode 600) or Docker secrets. Notification and NVD secrets are
  referenced by name only.
- **Bulk-imported scope:** the bounty-targets aggregate program is imported **inactive**. Review
  each program's rules before enabling active scanning.
