from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
from sqlalchemy import func, select

from app.config import get_settings
from app.database import ping_database, session_scope
from app.models import Asset, AuditEvent, KevEntry, NotificationDelivery, ScanJob, VulnCorrelation
from app.queue.redis_queue import RedisQueue, get_redis
from app.utils.time import utcnow

router = APIRouter(tags=["health"])
log = logging.getLogger(__name__)


@router.get("/health")
def health() -> dict:
    """Liveness: the process is up."""
    return {"status": "ok"}


def _check_elasticsearch() -> dict:
    s = get_settings()
    auth = None
    if s.elasticsearch_password is not None:
        auth = (s.elasticsearch_username, s.elasticsearch_password.get_secret_value())
    r = httpx.get(f"{s.elasticsearch_url}/_cluster/health", auth=auth, timeout=5)
    r.raise_for_status()
    return {"status": r.json().get("status")}


@router.get("/ready")
def ready() -> JSONResponse:
    """Readiness: PostgreSQL and Redis are required; Elasticsearch is reported (degraded if down)."""
    checks: dict[str, dict] = {}
    for name, fn in (("postgres", ping_database), ("redis", lambda: get_redis().ping())):
        try:
            fn()
            checks[name] = {"ok": True}
        except Exception as exc:
            checks[name] = {"ok": False, "error": str(exc)[:300]}
    try:
        checks["elasticsearch"] = {"ok": True, **_check_elasticsearch()}
    except Exception as exc:
        checks["elasticsearch"] = {"ok": False, "error": str(exc)[:300]}
    required_ok = checks["postgres"]["ok"] and checks["redis"]["ok"]
    status = "ready" if required_ok and checks["elasticsearch"]["ok"] else ("degraded" if required_ok else "not_ready")
    return JSONResponse({"status": status, "checks": checks}, status_code=200 if required_ok else 503)


@router.get("/metrics")
def metrics() -> Response:
    """Prometheus exposition computed from PostgreSQL/Redis at scrape time."""
    reg = CollectorRegistry()
    jobs = Gauge("scanner_jobs_total", "Jobs by scanner and status", ["scanner", "status"], registry=reg)
    running = Gauge("scanner_jobs_running", "Running jobs by scanner", ["scanner"], registry=reg)
    failed = Gauge("scanner_jobs_failed_total", "Failed jobs by scanner", ["scanner"], registry=reg)
    duration = Gauge(
        "scanner_job_duration_seconds_avg", "Average duration of successful jobs", ["scanner"], registry=reg
    )
    assets = Gauge("assets_discovered_total", "Assets by type", ["asset_type"], registry=reg)
    scanned = Gauge("assets_scanned_total", "Assets scanned at least once", registry=reg)
    blocked = Gauge("scope_blocked_total", "Scope-blocked decisions recorded in the audit log", registry=reg)
    depth = Gauge("queue_depth", "Pending items per queue", ["queue"], registry=reg)
    dlq = Gauge("dlq_depth", "Dead-lettered items per queue", ["queue"], registry=reg)
    workers = Gauge("worker_health", "Workers with a live heartbeat", ["queue"], registry=reg)
    certs = Gauge("certificates_seen_total", "Certificate assets", registry=reg)
    cve_matches = Gauge("cve_matches_total", "Asset/CVE correlations", ["status"], registry=reg)
    kev_matches = Gauge("kev_matches_total", "Correlated CVEs that are in CISA KEV", registry=reg)
    notifications = Gauge("notifications_total", "Notification deliveries", ["status"], registry=reg)
    wait = Gauge(
        "scanner_queue_wait_seconds", "Age of the oldest queued (not yet started) job", ["scanner"], registry=reg
    )
    busy = Gauge("worker_busy", "Workers currently running a job", ["queue"], registry=reg)
    try:
        with session_scope() as s:
            for scanner, status, n in s.execute(
                select(ScanJob.scanner, ScanJob.status, func.count()).group_by(ScanJob.scanner, ScanJob.status)
            ):
                jobs.labels(scanner, status).set(n)
                if status == "RUNNING":
                    running.labels(scanner).set(n)
                if status == "FAILED":
                    failed.labels(scanner).set(n)
            for scanner, avg in s.execute(
                select(ScanJob.scanner, func.avg(func.extract("epoch", ScanJob.finished_at - ScanJob.started_at)))
                .where(ScanJob.status == "SUCCESS")
                .group_by(ScanJob.scanner)
            ):
                duration.labels(scanner).set(float(avg or 0))
            for atype, n in s.execute(select(Asset.asset_type, func.count()).group_by(Asset.asset_type)):
                assets.labels(atype).set(n)
            scanned.set(s.execute(select(func.count()).where(Asset.last_scanned.is_not(None))).scalar_one())
            blocked.set(s.execute(select(func.count()).where(AuditEvent.action == "SCOPE_BLOCKED")).scalar_one())
            certs.set(s.execute(select(func.count()).where(Asset.asset_type == "certificate")).scalar_one())
            for status, n in s.execute(select(VulnCorrelation.status, func.count()).group_by(VulnCorrelation.status)):
                cve_matches.labels(status).set(n)
            kev_matches.set(
                s.execute(
                    select(func.count(func.distinct(VulnCorrelation.cve_id)))
                    .join(KevEntry, KevEntry.cve_id == VulnCorrelation.cve_id)
                    .where(KevEntry.removed_at.is_(None))
                ).scalar_one()
            )
            for status, n in s.execute(
                select(NotificationDelivery.status, func.count()).group_by(NotificationDelivery.status)
            ):
                notifications.labels(status).set(n)
            now = utcnow()
            for scanner, oldest in s.execute(
                select(ScanJob.scanner, func.min(ScanJob.queued_at))
                .where(ScanJob.status == "QUEUED")
                .group_by(ScanJob.scanner)
            ):
                if oldest is not None:
                    wait.labels(scanner).set(max(0.0, (now - oldest).total_seconds()))
    except Exception as exc:
        log.warning("metrics: database unavailable", extra={"error": str(exc)})
    try:
        q = RedisQueue(get_redis())
        for name, d in q.depths().items():
            depth.labels(name).set(d["pending"])
            dlq.labels(name).set(d["dlq"])
        counts: dict[str, int] = {}
        busy_counts: dict[str, int] = {}
        for w in q.workers():
            counts[w.queue] = counts.get(w.queue, 0) + 1
            if w.data.get("current_job"):
                busy_counts[w.queue] = busy_counts.get(w.queue, 0) + 1
        for name, n in counts.items():
            workers.labels(name).set(n)
            busy.labels(name).set(busy_counts.get(name, 0))
    except Exception as exc:
        log.warning("metrics: redis unavailable", extra={"error": str(exc)})
    return Response(generate_latest(reg), media_type=CONTENT_TYPE_LATEST)
