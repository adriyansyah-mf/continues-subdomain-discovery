# Architecture

## Principle

Scanner tools are workers, not the architecture. The platform is:

```
CDB (PostgreSQL scope) ─► ScopeEngine ─► Orchestrator (API + scheduler) ─► Redis queues
   ─► Workers (adapters around tools) ─► normalized events ─► Redis event lists
   ─► Logstash (one pipeline per stream) ─► Elasticsearch ─► Kibana (the only UI)
```

Compared with the reference project (`pikpikcu/subdomain-monitoring-elasticsearch`), which pipes
tool output through shell pipelines into Filebeat stdin with hardcoded Elasticsearch credentials
and no scope control, this platform:

* keeps canonical state in PostgreSQL and only observations in Elasticsearch;
* runs every scan as a database-backed job with idempotency, retries and a DLQ;
* enforces scope in several independent layers and fails closed;
* replaces regex-routing in Logstash with a typed, versioned event schema;
* uses least-privilege Elasticsearch users created by a setup job.

## Components (implemented)

| Component | Image / module | Role |
|---|---|---|
| `orchestrator` | `apps/orchestrator` (`app.main`) | FastAPI API, auth/RBAC, scope engine, scan planning (scope layer 1), audit |
| `scheduler` | `app.scheduler.service` | leader-elected (Redis lock): dispatch PENDING jobs + retries, reaper, periodic schedules, queue telemetry |
| `migrate` | orchestrator image | `alembic upgrade head` (one-shot) |
| `httpx-worker` | `workers.httpx` | ProjectDiscovery httpx v1.12.0 |
| `tlsx-worker` | `workers.tlsx` | ProjectDiscovery tlsx v1.4.0 |
| `dns-worker` | `workers.dns` | dnspython resolver (A/AAAA/CNAME/MX/NS/TXT) |
| `certstream-worker` | `workers.certstream` | passive CT stream consumer (continuous, reconnecting) |
| `certstream-server` (profile `ct-server`) | certstream-server-go 1.10.1 | optional self-hosted CT stream |
| `mapcidr-worker` | `workers.mapcidr` | bounded CIDR → IP inventory (+ follow-ups) |
| `katana-worker` | `workers.katana` | crawling, URL/endpoint inventory |
| `uncover-worker` | `workers.uncover` | search-engine discovery (API keys from env) |
| `bbot-worker` | `workers.bbot` (own image) | passive BBOT discovery/enrichment |
| `cve-monitor` | `workers.cve_monitor` | CISA KEV, EPSS, NVD CPE→CVE correlation |
| `notifier` | `workers.notifier` | policy-matched notification delivery (docs/notifications.md) |
| `webhook-sink` (dev overlay) | python | local notification receiver for testing |
| `postgres` | postgres 17.11 | canonical state |
| `redis` | redis 8.2.10 | job queues, worker heartbeats, concurrency slots, event buffer for Logstash |
| `logstash` | 8.19.22 | 11 stream pipelines + DLQ pipeline |
| `elasticsearch` | 8.19.22 | observation/event store (security enabled) |
| `kibana` | 8.19.22 | UI: data views + 6 dashboards |
| `es-setup` / `kibana-setup` | one-shot | users/roles, ILM, templates / saved objects |
| `lab-target` (dev overlay) | caddy 2.11.4 | authorized local target on an internal network |

Every scanner in the registry — including the nuclei template scanner (templates pinned in the
image, OOB testing disabled, hosts with URL exclusions refused) — has a worker adapter; see
[scanner-workers.md](scanner-workers.md).

## Data ownership

PostgreSQL is the source of truth for programs, scope, assets, program↔asset links, the asset
graph, last-known asset state (for diffing), policies, schedules, scans, jobs, controls,
maintenance windows, notification config, API keys and the audit log.

Elasticsearch holds observations: raw and normalized scanner output, change events, snapshots,
job state documents, errors and an audit replica. Deleting every `bb-*` index loses history
but not platform state; `es-setup` recreates templates and the next scans repopulate data.

## Request → scan → event flow

1. `POST /scans` (or a schedule) → `ScanService.create_scan`: normalize each target, evaluate the
   ScopeEngine against fresh rules, check program/scanner/asset pause and maintenance windows,
   policy enablement and CIDR limits. Every (target, scanner) pair becomes a `scan_jobs` row:
   `PENDING`, or `OUT_OF_SCOPE` / `BLOCKED` with a reason (+ `SCOPE_BLOCKED` audit/event).
2. The transaction commits, then job ids are `LPUSH`ed to `bb:q:<queue>` and marked `QUEUED`.
   If Redis is down the job stays `PENDING`; the scheduler dispatches it later. Nothing ever
   executes outside the queue.
3. A worker `BLMOVE`s the id, atomically claims the row (`PENDING|QUEUED → RUNNING`), re-checks
   scope (layer 2), resolves and pins target IPs, acquires a global concurrency slot, runs the tool
   with a hard timeout, validates every output host/IP (layer 3), updates assets/graph/state,
   emits events, and marks the job `SUCCESS`.
4. Events go to `bb:events:<pipeline>`; Logstash validates and routes them to `<index>-YYYY.MM`.

## Failure behaviour

| Failure | Behaviour (verified) |
|---|---|
| PostgreSQL down | API returns 503 `database unavailable; no action taken`; `/ready` 503; workers cannot claim jobs |
| Scope rules cannot be loaded/parsed | scan request 503; worker job `BLOCKED` (`SCOPE_UNAVAILABLE`) |
| Redis down | jobs stay `PENDING`; workers idle and retry the connection; dispatched once Redis returns |
| Logstash / Elasticsearch down | events buffer in Redis up to `MAX_EVENT_BACKLOG`; beyond that jobs fail and retry instead of losing change events |
| Worker crash mid-job | heartbeat expires; reaper retries (`PENDING`, retry_count+1) or fails + DLQ |
| Tool error / timeout | exponential backoff retries, then `FAILED`, DLQ entry and `DLQ_EVENT` |
