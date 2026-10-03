"""Generic worker loop shared by every scanner.

Per job:
  reserve id from Redis -> claim row (PENDING/QUEUED -> RUNNING, atomic)
  -> layer 2 scope check (fresh rules) -> operational guards -> policy
  -> resource limits -> global concurrency slot -> DNS pinning
  -> adapter.execute (bounded subprocess) -> adapter.process (layer 3)
  -> emit events -> SUCCESS
Failures: exponential backoff retry (PENDING + next_attempt_at) up to
max_retries, then FAILED + dead-letter queue + DLQ_EVENT.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import random
import signal
import socket
import threading
import time
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select, update

from app.config import Settings, get_settings
from app.database import session_scope
from app.models import Program, Scan, ScanJob, ScanPolicy
from app.models.enums import TERMINAL_JOB_STATUSES, BlockReason, JobStatus, ScanStatus
from app.queue.redis_queue import ConcurrencyLimiter, RedisQueue, get_redis
from app.schemas.policy import PolicyConfig
from app.scope.normalize import Target, classify_target
from app.services.audit import Principal, record_audit
from app.services.controls import check_operational_guards
from app.services.events import EventBacklogFullError, EventContext, EventEmitter
from app.services.scans import dispatch_pending, job_event, scope_blocked_event
from app.utils.time import utcnow
from workers.common.adapter import JobContext, NonRetryableError, ScannerAdapter
from workers.common.event import error_event
from workers.common.logging import configure_logging
from workers.common.process import ToolCancelledError
from workers.common.scope_guard import ScopeBlockedError, ScopeGuard

log = logging.getLogger("worker")
ALIVE_FILE = Path("/tmp/worker.alive")  # noqa: S108 - container tmpfs; liveness probe (compose healthcheck)


def target_host(target: Target) -> str | None:
    """Host a job connects to (per-host concurrency key)."""
    if target.kind == "url" and target.url is not None:
        return target.url.host
    if target.kind in ("domain", "ipv4", "ipv6", "cidr"):
        return target.value
    return None


class _Requeue(Exception):
    """Job could not start now (e.g. no concurrency slot); retry later without counting a failure."""


class WorkerRunner:
    def __init__(self, adapter: ScannerAdapter, settings: Settings | None = None):
        self.adapter = adapter
        self.settings = settings or get_settings()
        self.worker_id = f"{adapter.name}-{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.principal = Principal(name=f"worker:{adapter.name}", role="operator")
        self._stop = threading.Event()
        self._current_job: str | None = None
        self.redis = get_redis()
        self.queue = RedisQueue(self.redis)
        self.emitter = EventEmitter(self.redis, max_backlog=self.settings.max_event_backlog)
        self.limiter = ConcurrencyLimiter(
            self.redis, adapter.name, self.settings.max_concurrent_scans, ttl=self.settings.max_scan_duration + 120
        )
        self.tool_version = adapter.tool_version()

    # ------------------------------------------------------------------ loop
    def run_forever(self) -> None:
        configure_logging(f"worker-{self.adapter.name}", self.settings.log_level)
        signal.signal(signal.SIGTERM, lambda *_: self._stop.set())
        signal.signal(signal.SIGINT, lambda *_: self._stop.set())
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        log.info(
            "worker started",
            extra={
                "worker_id": self.worker_id,
                "queue": self.adapter.queue,
                "tool": self.adapter.tool,
                "tool_version": self.tool_version,
            },
        )
        while not self._stop.is_set():
            ALIVE_FILE.touch()
            try:
                job_id = self.queue.reserve(self.adapter.queue, self.worker_id, timeout=5)
            except Exception as exc:
                # Redis down: never fall back to local execution; just wait.
                log.error("queue unavailable", extra={"error": str(exc)})
                time.sleep(5)
                continue
            if job_id is None:
                continue
            self._current_job = job_id
            try:
                self.handle(job_id)
            except Exception:
                log.exception("unhandled error while handling job", extra={"job_id": job_id})
            finally:
                self._current_job = None
                try:
                    self.queue.ack(self.adapter.queue, self.worker_id, job_id)
                except Exception as exc:
                    log.error("ack failed", extra={"job_id": job_id, "error": str(exc)})
        self.queue.deregister(self.worker_id)
        log.info("worker stopped", extra={"worker_id": self.worker_id})

    def _heartbeat_loop(self) -> None:
        interval = self.settings.worker_heartbeat_seconds
        while not self._stop.is_set():
            try:
                self.queue.heartbeat(
                    self.worker_id,
                    self.adapter.queue,
                    ttl=interval * 3,
                    tool=self.adapter.tool,
                    tool_version=self.tool_version,
                    current_job=self._current_job or "",
                )
            except Exception as exc:
                log.warning("heartbeat failed", extra={"error": str(exc)})
            self._stop.wait(interval)

    # ------------------------------------------------------------------ helpers
    def _emit_job(self, job: ScanJob, program_name: str | None) -> None:
        try:
            self.emitter.emit("ops", job_event(job, program_name))
        except Exception as exc:
            log.warning("job event emission failed", extra={"error": str(exc)})

    def _finish(
        self,
        job_id: uuid.UUID,
        status: JobStatus,
        *,
        block_reason: str | None = None,
        error: str | None = None,
        summary: dict | None = None,
    ) -> ScanJob | None:
        """Terminal transition, only from RUNNING (never overwrites a cancellation)."""
        with session_scope() as s:
            values: dict = {"status": status.value, "finished_at": utcnow()}
            if block_reason:
                values["block_reason"] = block_reason
            if error is not None:
                values["error"] = error[:4000] or None  # "" clears errors left by earlier attempts
            if summary is not None:
                values["result_summary"] = summary
            res = s.execute(
                update(ScanJob).where(ScanJob.id == job_id, ScanJob.status == JobStatus.RUNNING.value).values(**values)
            )
            job = s.get(ScanJob, job_id)
            if job is not None and res.rowcount:
                self._complete_scan_if_done(s, job.scan_id)
            return job

    @staticmethod
    def _complete_scan_if_done(s, scan_id: uuid.UUID | None) -> None:
        if scan_id is None:
            return
        open_jobs = s.execute(
            select(func.count()).where(
                ScanJob.scan_id == scan_id, ScanJob.status.not_in([st.value for st in TERMINAL_JOB_STATUSES])
            )
        ).scalar_one()
        if open_jobs == 0:
            scan = s.get(Scan, scan_id)
            if scan is not None and scan.status not in (ScanStatus.CANCELLED.value, ScanStatus.COMPLETED.value):
                scan.status = ScanStatus.COMPLETED.value
                scan.finished_at = utcnow()

    def _is_cancelled(self, job_id: uuid.UUID) -> bool:
        try:
            with session_scope() as s:
                status = s.execute(select(ScanJob.status).where(ScanJob.id == job_id)).scalar_one_or_none()
            return status == JobStatus.CANCELLED.value
        except Exception:
            return False  # transient DB error: the wall-clock timeout still bounds the run

    # ------------------------------------------------------------------ job
    def handle(self, raw_job_id: str) -> None:
        try:
            job_id = uuid.UUID(raw_job_id)
        except ValueError:
            log.error("discarding malformed queue item", extra={"item": raw_job_id[:100]})
            return
        extra = {"job_id": raw_job_id, "worker_id": self.worker_id}

        # --- claim + layer 2 checks (one transaction) ------------------------
        with session_scope() as s:
            claimed = s.execute(
                update(ScanJob)
                .where(
                    ScanJob.id == job_id,
                    ScanJob.scanner == self.adapter.name,
                    ScanJob.status.in_([JobStatus.PENDING.value, JobStatus.QUEUED.value]),
                )
                .values(
                    status=JobStatus.RUNNING.value,
                    started_at=utcnow(),
                    worker_id=self.worker_id,
                    tool_version=self.tool_version,
                    finished_at=None,
                )
                .returning(ScanJob.id)
            ).scalar_one_or_none()
            if claimed is None:
                log.info("job not claimable (missing, wrong scanner or already handled)", extra=extra)
                return
            job = s.get(ScanJob, job_id)
            assert job is not None
            program = s.get(Program, job.program_id)
            assert program is not None
            program_name = program.name
            policy = s.get(ScanPolicy, job.policy_id) if job.policy_id else None
            event_ctx = EventContext(
                program_id=str(program.id),
                program_name=program.name,
                scope_id=str(job.scope_id) if job.scope_id else None,
                scope_status="in",
                asset_id=str(job.asset_id) if job.asset_id else None,
                asset_type=job.target_type,
                asset_value=job.target,
                scan_id=str(job.scan_id) if job.scan_id else None,
                job_id=str(job.id),
                tool=self.adapter.tool,
                tool_version=self.tool_version,
                config_hash=job.config_hash,
                source_name=self.adapter.name,
                source_type="active",
            )
            try:
                target = classify_target(job.target)
                guard = ScopeGuard.load(s, str(program.id), allow_private=self.settings.allow_private_targets)
                decision = guard.check_target(target)
                event_ctx = dataclasses.replace(event_ctx, scope_id=decision.scope_id)
                op = check_operational_guards(s, program=program, scanner=self.adapter.name, asset_id=job.asset_id)
                if not op.ok:
                    raise _Blocked(op.reason or BlockReason.PROGRAM_INACTIVE, op.detail or "")
                if policy is None or not policy.active:
                    raise _Blocked(BlockReason.POLICY_DISABLED, "policy missing or inactive")
                scanner_settings = PolicyConfig.model_validate(policy.config).for_scanner(self.adapter.name)
                if not scanner_settings.enabled:
                    raise _Blocked(BlockReason.POLICY_DISABLED, f"{self.adapter.name} disabled in {policy.name}")
                if (
                    target.kind == "cidr"
                    and target.network is not None
                    and (target.network.num_addresses > min(self.settings.max_cidr_size, self.settings.max_ips_per_job))
                ):
                    raise _Blocked(BlockReason.CIDR_LIMIT_EXCEEDED, f"{target.value} exceeds MAX_CIDR_SIZE")
            except ScopeBlockedError as exc:
                self._record_scope_block(s, job, program, exc)
                job.status = (
                    JobStatus.OUT_OF_SCOPE.value
                    if exc.reason in (BlockReason.NOT_IN_SCOPE, BlockReason.EXCLUDED)
                    else JobStatus.BLOCKED.value
                )
                job.block_reason = exc.reason.value
                job.error = exc.detail[:4000]
                job.finished_at = utcnow()
                self._complete_scan_if_done(s, job.scan_id)
                s.flush()
                self._emit_job(job, program_name)
                log.warning("job blocked by worker scope guard", extra={**extra, "reason": exc.detail})
                return
            except _Blocked as exc:
                job.status = JobStatus.BLOCKED.value
                job.block_reason = exc.reason.value
                job.error = exc.detail[:4000]
                job.finished_at = utcnow()
                self._complete_scan_if_done(s, job.scan_id)
                s.flush()
                self._emit_job(job, program_name)
                log.warning("job blocked", extra={**extra, "reason": exc.detail})
                return
            ctx = JobContext(
                job_id=str(job.id),
                scan_id=str(job.scan_id) if job.scan_id else None,
                program_id=str(program.id),
                program_name=program.name,
                asset_id=str(job.asset_id) if job.asset_id else None,
                scope_id=decision.scope_id,
                target=target,
                settings=scanner_settings,
                guard=guard,
                event_ctx=event_ctx,
                deadline_seconds=min(scanner_settings.max_duration, self.settings.max_scan_duration),
                is_cancelled=lambda: self._is_cancelled(job_id),
                policy_id=str(job.policy_id) if job.policy_id else None,
            )
            retry_count, max_retries = job.retry_count, job.max_retries
            self._emit_job(job, program_name)

        # --- execute ------------------------------------------------------------
        holder = f"{self.worker_id}:{job_id}"
        acquired: list[ConcurrencyLimiter] = []
        try:
            # Cluster-wide limits shared by all replicas: scanner, program, and target host.
            for limiter, what in self._limiters_for(ctx):
                if not limiter.acquire(holder):
                    raise _Requeue(f"no free {what} slot")
                acquired.append(limiter)
            if self.adapter.contacts_target:
                ctx.guard.resolve_and_pin(ctx.target)
            log.info("executing", extra={**extra, "target": ctx.target.value, "tool": self.adapter.tool})
            raw = self.adapter.execute(ctx)
            with session_scope() as s:
                outcome = self.adapter.process(s, ctx, raw)
                # Emit before commit: a failed commit re-runs the job (duplicates are tolerable,
                # silently losing change events is not).
                for pipeline, events in outcome.events.items():
                    for i in range(0, len(events), 500):
                        self.emitter.emit_many(pipeline, events[i : i + 500])
            job_row = self._finish(job_id, JobStatus.SUCCESS, summary=outcome.summary, error="")
            if job_row is not None:
                self._emit_job(job_row, program_name)
            if outcome.followup_job_ids:
                with session_scope() as s:
                    n = dispatch_pending(s, self.queue, job_ids=outcome.followup_job_ids, emitter=self.emitter)
                log.info("follow-up jobs dispatched", extra={**extra, "count": n})
            log.info("job succeeded", extra={**extra, "summary": outcome.summary})
        except ScopeBlockedError as exc:
            with session_scope() as s:
                job = s.get(ScanJob, job_id)
                program = s.get(Program, ctx.program_id)
                if job is not None and program is not None:
                    self._record_scope_block(s, job, program, exc)
            job_row = self._finish(job_id, JobStatus.BLOCKED, block_reason=exc.reason.value, error=exc.detail)
            if job_row is not None:
                self._emit_job(job_row, program_name)
            log.warning("job blocked during execution", extra={**extra, "reason": exc.detail})
        except ToolCancelledError:
            log.info("job cancelled during execution", extra=extra)
        except _Requeue as exc:
            with session_scope() as s:
                s.execute(
                    update(ScanJob)
                    .where(ScanJob.id == job_id, ScanJob.status == JobStatus.RUNNING.value)
                    .values(
                        status=JobStatus.PENDING.value,
                        started_at=None,
                        # jitter spreads deferred jobs so replicas do not retry in lock-step
                        next_attempt_at=utcnow() + timedelta(seconds=5 + random.uniform(0, 10)),  # noqa: S311
                    )
                )
            log.info("job deferred", extra={**extra, "reason": str(exc)})
        except Exception as exc:
            self._fail(job_id, ctx, exc, retry_count, max_retries, program_name)
        finally:
            for limiter in acquired:
                limiter.release(holder)

    def _limiters_for(self, ctx: JobContext) -> list[tuple[ConcurrencyLimiter, str]]:
        ttl = self.settings.max_scan_duration + 120
        out = [(self.limiter, "scanner")]
        if self.settings.program_max_concurrent > 0:
            out.append(
                (
                    ConcurrencyLimiter(
                        self.redis, f"program:{ctx.program_id}", self.settings.program_max_concurrent, ttl
                    ),
                    "program",
                )
            )
        host = target_host(ctx.target)
        if self.adapter.contacts_target and host and self.settings.per_host_max_concurrent > 0:
            out.append(
                (ConcurrencyLimiter(self.redis, f"host:{host}", self.settings.per_host_max_concurrent, ttl), "host")
            )
        return out

    def _record_scope_block(self, s, job: ScanJob, program: Program, exc: ScopeBlockedError) -> None:
        details = {
            "target": job.target,
            "scanner": self.adapter.name,
            "reason": exc.detail,
            "block_reason": exc.reason.value,
            "layer": "worker",
        }
        record_audit(
            s,
            self.principal,
            "SCOPE_BLOCKED",
            target_type="scan_job",
            target_id=job.id,
            program_id=program.id,
            details=details,
        )
        if exc.decision is not None:
            try:
                self.emitter.emit(
                    "changes",
                    scope_blocked_event(
                        exc.decision, program=program, scanner=self.adapter.name, layer="worker", job_id=str(job.id)
                    ),
                )
            except Exception as e:
                log.warning("scope-blocked event emission failed", extra={"error": str(e)})

    def _fail(
        self, job_id: uuid.UUID, ctx: JobContext, exc: Exception, retry_count: int, max_retries: int, program_name: str
    ) -> None:
        message = f"{type(exc).__name__}: {exc}"
        log.error("job failed", extra={"job_id": str(job_id), "error": message, "retry_count": retry_count})
        retryable = not isinstance(exc, NonRetryableError)
        if isinstance(exc, EventBacklogFullError) or (retryable and retry_count < max_retries):
            delay = self.settings.job_retry_base_seconds * (2**retry_count)
            with session_scope() as s:
                s.execute(
                    update(ScanJob)
                    .where(ScanJob.id == job_id, ScanJob.status == JobStatus.RUNNING.value)
                    .values(
                        status=JobStatus.PENDING.value,
                        retry_count=retry_count + 1,
                        error=message[:4000],
                        next_attempt_at=utcnow() + timedelta(seconds=delay),
                        started_at=None,
                    )
                )
            try:
                self.emitter.emit(
                    "ops",
                    error_event(
                        ctx.event_ctx,
                        "SCAN_FAILURE",
                        message,
                        retry_count=retry_count + 1,
                        will_retry=True,
                        retry_in_seconds=delay,
                    ),
                )
            except Exception as e:
                log.warning("error event emission failed", extra={"error": str(e)})
            return
        job = self._finish(job_id, JobStatus.FAILED, error=message)
        payload = {
            "job_id": str(job_id),
            "scanner": self.adapter.name,
            "target": ctx.target.value,
            "program_id": ctx.program_id,
            "error": message,
            "retry_count": retry_count,
            "failed_at": utcnow().isoformat(),
        }
        try:
            self.queue.dead_letter(self.adapter.queue, payload)
        except Exception as e:
            log.error("could not write to DLQ", extra={"error": str(e), "payload": json.dumps(payload)})
        try:
            self.emitter.emit(
                "ops", error_event(ctx.event_ctx, "DLQ_EVENT", message, retry_count=retry_count, will_retry=False)
            )
            if job is not None:
                self.emitter.emit("ops", job_event(job, program_name))
        except Exception as e:
            log.warning("error event emission failed", extra={"error": str(e)})


class _Blocked(Exception):
    def __init__(self, reason: BlockReason, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
