# Deployment

## Requirements

Docker Engine 24+ with Compose v2, ~6 GB free RAM (Elasticsearch 1 GB heap, Logstash 768 MB,
Kibana ~1 GB, the rest small), a few GB of disk. Host ports bind to 127.0.0.1 only:
API 18000, Elasticsearch 19200, Kibana 15601 (dev overlay: PostgreSQL 15432, Redis 16379).

## First start

```bash
make env          # .env from .env.example with random secrets (mode 600); never overwrites
make build        # orchestrator + worker images
make up-dev       # core stack + lab target   (or: make up / docker compose up -d)
make health
make bootstrap    # bbctl bootstrap bounty-targets
make lab-program  # 'local-lab' program scoped to the lab target
./bbctl scan run -p local-lab -t lab-target.bb.test -s httpx -s tlsx -s dns
```

Start order is enforced with health checks: postgres/redis → migrate → orchestrator, scheduler,
workers; elasticsearch → es-setup → kibana → kibana-setup; es-setup + redis → logstash.

Images rebuild: the orchestrator image is built by the `migrate` service and the worker image by
`httpx-worker`; use `make build` (or `docker compose build`) rather than building a single
service, otherwise `orchestrator`/`scheduler` keep the old image.

## Disk watermarks

Elasticsearch stops allocating shards above the high watermark (default 90% used) and makes
indices read-only at flood stage (95%). On large but nearly full disks set absolute free-space
thresholds in `.env`, e.g. `ES_DISK_WATERMARK_LOW=10gb`, `..._HIGH=5gb`, `..._FLOOD=2gb`.

## Secrets

Development: `.env` (generated, git-ignored). Production: every secret read by the platform
(`POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `ES_MONITOR_PASSWORD`, `BB_BOOTSTRAP_ADMIN_KEY`) can be
supplied as a Docker secret file in `/run/secrets/<NAME>` or via `<NAME>_FILE`
(`app/config.py`). The Elastic images support their own `*_FILE` variables. API keys are stored
only as SHA-256 hashes; notification channels store secret *references*. Vault: not implemented.

## Production notes

* Enable TLS on Elasticsearch HTTP/transport and Kibana (`xpack.security.http.ssl.*`); the compose
  file keeps plain HTTP on the private network for development.
* Raise `number_of_replicas` in `elasticsearch/templates/*.json` on multi-node clusters.
* Put a TLS reverse proxy in front of the API if it is exposed beyond localhost.
* Back up the `pgdata` volume — it is the platform state. Elasticsearch data is rebuildable history.

## Hardening defaults

* Every container: `json-file` logs capped at 10 MB × 3.
* Platform containers: non-root (uid 10001), read-only root filesystem with tmpfs `/tmp`,
  `cap_drop: ALL`, `no-new-privileges`.
* Workers: memory limit `WORKER_MEM_LIMIT` (768 MB), BBOT `BBOT_MEM_LIMIT` (2 GB).
* Liveness: job workers touch `/tmp/worker.alive` every loop; certstream, cve-monitor, notifier and
  scheduler have their own liveness files. All have compose healthchecks.
* Secrets: `.env` (mode 600) in development; Docker secrets / `*_FILE` in production. Notification
  and NVD secrets are referenced by name only.

## Scaling

Workers are stateless queue consumers; add replicas without other changes:

```bash
docker compose up -d --scale httpx-worker=3 --no-recreate
```

**Cluster-wide limits.** All replicas share them through Redis slots with a TTL, so a crashed
worker cannot leak a slot. A job runs only once it holds every slot that applies to it:

| Limit | Setting | Default | Scope |
|---|---|---|---|
| per scanner | `MAX_CONCURRENT_SCANS` | 4 | all jobs of one scanner |
| per program | `PROGRAM_MAX_CONCURRENT` | 8 | all active jobs of one program |
| per target host | `PER_HOST_MAX_CONCURRENT` | 1 | scanners that contact the target (httpx, tlsx, katana) |

A job that cannot get a slot goes back to `PENDING` without consuming a retry, and is retried
after a random 5–15 s delay. Adding replicas beyond `MAX_CONCURRENT_SCANS` does not increase
throughput for that scanner. The effective request rate against one host is the job's policy
`rate_limit` × `PER_HOST_MAX_CONCURRENT`.

**Fair share between programs.** The dispatcher interleaves pending jobs round-robin across
(program, scanner) pairs. Each pair may have at most `DISPATCH_MAX_QUEUED_PER_PROGRAM` (25) jobs
waiting in Redis; the rest stay `PENDING` in PostgreSQL and are dispatched as the queue drains.
Another program's jobs therefore wait behind at most that many jobs per scanner, never behind a
whole large batch. High-priority jobs ignore the cap. Verified: with the httpx worker stopped, a
40-job scan got 25 queued and 15 held, a second program's 3 jobs were queued immediately, and all
43 completed once the worker restarted.

**Priority lanes.** Each queue has a high-priority lane (job priority ≥ 7,
`bbctl scan run --priority 8`) that workers drain before the normal lane. The normal lane's
blocking wait is capped at 2 s, so an urgent job never waits behind a long block.

**Graceful shutdown.** On `SIGTERM` a worker stops taking new jobs and finishes the current one.
Compose gives it `WORKER_STOP_GRACE` (180 s; BBOT `BBOT_STOP_GRACE` 600 s) before killing it.
Tools run in their own process group, so the signal does not interrupt them. A worker killed
anyway is recovered by the scheduler's reaper (retry or DLQ).

**Autoscaling signals.** The platform does not scale itself. It exposes the inputs an operator or
external autoscaler needs:
* `GET /workers` → `pools.<queue>`: `pending`, `high_priority`, `dlq`, `workers`, `busy_workers`
* `/metrics`: `queue_depth{queue}`, `scanner_queue_wait_seconds{scanner}` (age of the oldest
  queued job), `worker_health{queue}`, `worker_busy{queue}`, `scanner_jobs_running{scanner}`

A reasonable policy: add a replica of scanner X while `scanner_queue_wait_seconds{scanner="X"}`
stays above a few minutes and `worker_busy == worker_health`, up to `MAX_CONCURRENT_SCANS`.

**Verified (dev stack, 3 httpx replicas):** 30 jobs split 11/8/11 across replicas, all
successful in about 64 s. httpx, tlsx and katana submitted together against one host ran strictly
one after another. Stopping a worker mid-crawl waited for the job to finish (`SUCCESS`).

The scheduler is safe to replicate (Redis leader lock); the API is stateless.
