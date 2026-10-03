"""Scheduler service (separate process; safe to run several replicas).

Only the replica holding the Redis leader lock does work. Tasks:
  * dispatch    - enqueue PENDING jobs whose next attempt is due (incl. retries)
  * reaper      - recover RUNNING jobs whose worker died; reset QUEUED jobs lost from Redis
  * schedules   - create periodic scans from the `schedules` table (all disabled by default)
  * telemetry   - publish queue depth / worker counts to bb-jobs-* for Kibana
"""

from __future__ import annotations

import logging
import signal
import socket
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import cast

from apscheduler.schedulers.blocking import BlockingScheduler
from sqlalchemy import select, update

from app.config import get_settings
from app.database import session_scope
from app.models import Asset, Program, ProgramAsset, ScanJob, Schedule
from app.models.enums import JobStatus
from app.queue.redis_queue import RedisQueue, get_redis
from app.services import asn, ipranges
from app.services.audit import SYSTEM
from app.services.events import EventContext, EventEmitter, build_event
from app.services.scans import ScanRequestError, ScanService, dispatch_pending
from app.utils.logging import configure_logging
from app.utils.time import utcnow
from app.workers.registry import get_scanner

log = logging.getLogger("scheduler")

LEADER_KEY = "bb:scheduler:leader"
ALIVE_FILE = Path("/tmp/scheduler.alive")  # noqa: S108 - container tmpfs; liveness probe for the container healthcheck
STALE_QUEUED = timedelta(minutes=30)


class Scheduler:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.redis = get_redis()
        self.queue = RedisQueue(self.redis)
        self.emitter = EventEmitter(self.redis, max_backlog=self.settings.max_event_backlog)
        self.node_id = f"{socket.gethostname()}-{uuid.uuid4().hex[:6]}"

    def is_leader(self) -> bool:
        ttl = self.settings.scheduler_tick_seconds * 3
        try:
            if self.redis.set(LEADER_KEY, self.node_id, nx=True, ex=ttl):
                return True
            if self.redis.get(LEADER_KEY) == self.node_id:
                self.redis.expire(LEADER_KEY, ttl)
                return True
        except Exception as exc:
            log.error("leader election failed (redis unavailable?)", extra={"error": str(exc)})
        return False

    def _guarded(self, name: str, fn) -> None:
        if not self.is_leader():
            return
        try:
            fn()
        except Exception:
            log.exception("scheduler task failed", extra={"task": name})

    # --- tasks -----------------------------------------------------------
    def dispatch(self) -> None:
        with session_scope() as s:
            n = dispatch_pending(s, self.queue, emitter=self.emitter)
        if n:
            log.info("dispatched jobs", extra={"count": n})

    def reap(self) -> None:
        now = utcnow()
        live_workers = {w.worker_id for w in self.queue.workers()}
        grace = timedelta(seconds=self.settings.max_scan_duration + 300)
        recovered = 0
        with session_scope() as s:
            stuck = (
                s.execute(
                    select(ScanJob)
                    .where(
                        ScanJob.status == JobStatus.RUNNING.value,
                        ScanJob.started_at < now - timedelta(seconds=self.settings.worker_heartbeat_seconds * 4),
                    )
                    .with_for_update(skip_locked=True)
                )
                .scalars()
                .all()
            )
            for job in stuck:
                if job.worker_id in live_workers and job.started_at and job.started_at > now - grace:
                    continue
                recovered += 1
                if job.retry_count < job.max_retries:
                    job.status = JobStatus.PENDING.value
                    job.retry_count += 1
                    job.next_attempt_at = now + timedelta(seconds=self.settings.job_retry_base_seconds)
                    job.error = f"worker {job.worker_id} lost while running; retrying"
                else:
                    job.status = JobStatus.FAILED.value
                    job.finished_at = now
                    job.error = f"worker {job.worker_id} lost while running; retries exhausted"
                    self.queue.dead_letter(
                        get_scanner(job.scanner).queue,
                        {"job_id": str(job.id), "scanner": job.scanner, "error": job.error},
                    )
            res = s.execute(
                update(ScanJob)
                .where(ScanJob.status == JobStatus.QUEUED.value, ScanJob.queued_at < now - STALE_QUEUED)
                .values(status=JobStatus.PENDING.value, error="re-dispatched: queue message not consumed")
            )
        dropped = self.queue.drop_orphans()
        if recovered or res.rowcount or dropped:
            log.warning(
                "reaper recovered jobs",
                extra={"running_recovered": recovered, "queued_reset": res.rowcount, "orphans_dropped": dropped},
            )

    def run_schedules(self) -> None:
        now = utcnow()
        with session_scope() as s:
            due = (
                s.execute(
                    select(Schedule)
                    .where(Schedule.enabled.is_(True), (Schedule.next_run_at.is_(None)) | (Schedule.next_run_at <= now))
                    .with_for_update(skip_locked=True)
                )
                .scalars()
                .all()
            )
            for sched in due:
                sched.last_run_at = now
                sched.next_run_at = now + timedelta(seconds=sched.interval_seconds)
                spec = get_scanner(sched.scanner)
                programs = (
                    [s.get(Program, sched.program_id)]
                    if sched.program_id
                    else list(
                        s.execute(
                            select(Program).where(Program.active.is_(True), Program.deleted_at.is_(None))
                        ).scalars()
                    )
                )
                for program in programs:
                    if program is None or not program.active:
                        continue
                    asset_ids = list(
                        s.execute(
                            select(Asset.id)
                            .join(ProgramAsset, ProgramAsset.asset_id == Asset.id)
                            .where(
                                ProgramAsset.program_id == program.id,
                                ProgramAsset.status == "in_scope",
                                Asset.paused.is_(False),
                                Asset.asset_type.in_(_asset_types_for(spec.target_types)),
                            )
                            .limit(self.settings.max_targets_per_scan)
                        ).scalars()
                    )
                    if not asset_ids:
                        continue
                    try:
                        plan = ScanService(s, emitter=self.emitter).create_scan(
                            principal=SYSTEM,
                            program_id=program.id,
                            scanners=[sched.scanner],
                            asset_ids=asset_ids,
                            policy_id=sched.policy_id,
                            trigger=f"schedule:{sched.name}",
                        )
                        log.info(
                            "scheduled scan created",
                            extra={"schedule": sched.name, "program": program.slug, "summary": plan.summary()},
                        )
                    except ScanRequestError as exc:
                        log.warning("scheduled scan skipped", extra={"schedule": sched.name, "error": str(exc)})

    def sync_ipranges(self) -> None:
        """Daily provider-range refresh (enrichment data only)."""
        key = "bb:scheduler:ipranges:last"
        last = float(cast(str | None, self.redis.get(key)) or 0)
        if time.time() - last < self.settings.ipranges_sync_interval:
            return
        with session_scope() as s:
            stats = ipranges.sync_ipranges(s, SYSTEM, repo_url=self.settings.ipranges_repo, emitter=self.emitter)
        self.redis.set(key, time.time())
        log.info("ipranges synced", extra={k: v for k, v in stats.items() if k != "providers"})

    def sync_asn(self) -> None:
        """Daily IP -> ASN refresh (enrichment data only)."""
        key = "bb:scheduler:asn:last"
        last = float(cast(str | None, self.redis.get(key)) or 0)
        if time.time() - last < self.settings.asn_sync_interval:
            return
        with session_scope() as s:
            stats = asn.sync_asn(s, SYSTEM, url=self.settings.asn_feed_url, emitter=self.emitter)
        self.redis.set(key, time.time())
        log.info("asn ranges synced", extra=stats)

    def telemetry(self) -> None:
        depths = self.queue.depths()
        workers = self.queue.workers()
        events = []
        for name, d in depths.items():
            events.append(
                build_event(
                    index="bb-jobs",
                    kind="metric",
                    category="queue",
                    type_="QUEUE_DEPTH",
                    ctx=EventContext(source_name="scheduler", source_type="system"),
                    body={
                        "queue": {
                            "name": name,
                            "pending": d["pending"],
                            "dlq": d["dlq"],
                            "workers": sum(1 for w in workers if w.queue == name),
                            "busy_workers": sum(1 for w in workers if w.queue == name and w.data.get("current_job")),
                        }
                    },
                )
            )
        self.emitter.emit_many("ops", events)

    def run(self) -> None:
        configure_logging("scheduler", self.settings.log_level)
        tick = self.settings.scheduler_tick_seconds
        sched = BlockingScheduler(timezone="UTC")
        sched.add_job(ALIVE_FILE.touch, "interval", seconds=tick, max_instances=1)
        ALIVE_FILE.touch()
        sched.add_job(lambda: self._guarded("dispatch", self.dispatch), "interval", seconds=tick, max_instances=1)
        sched.add_job(lambda: self._guarded("reap", self.reap), "interval", seconds=60, max_instances=1)
        sched.add_job(lambda: self._guarded("schedules", self.run_schedules), "interval", seconds=60, max_instances=1)
        if self.settings.asn_sync_interval > 0:
            sched.add_job(lambda: self._guarded("asn", self.sync_asn), "interval", seconds=3600, max_instances=1)
        if self.settings.ipranges_sync_interval > 0:
            sched.add_job(
                lambda: self._guarded("ipranges", self.sync_ipranges), "interval", seconds=3600, max_instances=1
            )
        sched.add_job(lambda: self._guarded("telemetry", self.telemetry), "interval", seconds=300, max_instances=1)

        def _stop(*_):
            threading.Thread(target=sched.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        log.info("scheduler started", extra={"node_id": self.node_id})
        sched.start()


def _asset_types_for(target_types: frozenset[str]) -> list[str]:
    out = set(target_types)
    if "domain" in out:
        out.add("subdomain")
    return sorted(out)


def main() -> None:
    Scheduler().run()


if __name__ == "__main__":
    main()
