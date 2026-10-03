"""Scan planning and job dispatch (scope guard layer 1).

Flow for every (target, scanner) pair:
  normalize -> ScopeEngine -> operational guards -> policy -> resource limits
  -> idempotency -> PENDING row -> (after commit) Redis enqueue -> QUEUED

Jobs that fail any check are still recorded (BLOCKED / OUT_OF_SCOPE) so the
decision is auditable, but they are never enqueued.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.models import Asset, Program, Scan, ScanJob, ScanPolicy
from app.models.enums import TERMINAL_JOB_STATUSES, BlockReason, JobStatus, ScanStatus
from app.queue.redis_queue import HIGH_PRIORITY, RedisQueue
from app.schemas.policy import PolicyConfig
from app.scope.engine import ScopeDecision, ScopeEngine
from app.scope.normalize import InvalidTarget, Target, classify_target
from app.scope.service import ScopeUnavailableError, load_rules
from app.services.assets import confidence_for, link_program_asset, upsert_asset
from app.services.audit import Principal, record_audit
from app.services.controls import check_operational_guards
from app.services.events import EventContext, EventEmitter, build_event
from app.utils.hashing import sha256_text, stable_hash
from app.utils.time import utcnow
from app.workers.registry import get_scanner

log = logging.getLogger(__name__)


class ScanRequestError(ValueError):
    """The request itself is invalid (unknown program/scanner/policy...)."""


def idempotency_key(
    *,
    target: str,
    scanner: str,
    policy_id: uuid.UUID | None,
    bucket_seconds: int,
    now: datetime,
    program_id: uuid.UUID,
    nonce: str | None = None,
) -> str:
    bucket = int(now.timestamp()) // bucket_seconds
    parts = [str(program_id), target, scanner, str(policy_id or "-"), str(bucket)]
    if nonce:
        parts.append(nonce)
    return sha256_text("|".join(parts))


@dataclass
class PlannedJob:
    job: ScanJob
    duplicate: bool = False


@dataclass
class ScanPlan:
    scan: Scan
    jobs: list[PlannedJob] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for pj in self.jobs:
            key = "DUPLICATE" if pj.duplicate else pj.job.status
            out[key] = out.get(key, 0) + 1
        return out


def resolve_policy(session: Session, program: Program, policy_id: uuid.UUID | None) -> ScanPolicy:
    policy: ScanPolicy | None = None
    if policy_id is not None:
        policy = session.get(ScanPolicy, policy_id)
    elif program.default_scan_policy_id is not None:
        policy = session.get(ScanPolicy, program.default_scan_policy_id)
    else:
        policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == "passive")).scalar_one_or_none()
    if policy is None or not policy.active:
        raise ScanRequestError("scan policy not found or inactive")
    return policy


def _block_job(job: ScanJob, status: JobStatus, reason: BlockReason, detail: str) -> None:
    job.status = status.value
    job.block_reason = reason.value
    job.error = detail[:2000]
    job.finished_at = utcnow()
    # Blocked jobs must never dedupe future, legitimate runs.
    job.idempotency_key = sha256_text(f"blocked|{uuid.uuid4()}")


def job_event(job: ScanJob, program_name: str | None = None) -> dict:
    """Current-state document for bb-jobs-* (doc id = job id, so it is upserted)."""
    duration = None
    if job.started_at and job.finished_at:
        duration = (job.finished_at - job.started_at).total_seconds()
    return build_event(
        index="bb-jobs",
        kind="state",
        category="job",
        type_=f"JOB_{job.status}",
        ctx=EventContext(
            program_id=str(job.program_id),
            program_name=program_name,
            scope_id=str(job.scope_id) if job.scope_id else None,
            asset_id=str(job.asset_id) if job.asset_id else None,
            asset_value=job.target,
            asset_type=job.target_type,
            scan_id=str(job.scan_id) if job.scan_id else None,
            job_id=str(job.id),
            tool=job.scanner,
            tool_version=job.tool_version,
            config_hash=job.config_hash,
            source_name="orchestrator",
            source_type="system",
        ),
        body={
            "job": {
                "id": str(job.id),
                "status": job.status,
                "scanner": job.scanner,
                "priority": job.priority,
                "block_reason": job.block_reason,
                "retry_count": job.retry_count,
                "error": (job.error or "")[:1000] or None,
                "worker_id": job.worker_id,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "duration_seconds": duration,
            },
        },
        doc_id=str(job.id),
    )


def scope_blocked_event(
    decision: ScopeDecision, *, program: Program, scanner: str, layer: str, job_id: str | None = None
) -> dict:
    return build_event(
        index="bb-changes",
        kind="alert",
        category="scope",
        type_="SCOPE_BLOCKED",
        ctx=EventContext(
            program_id=str(program.id),
            program_name=program.name,
            scope_id=decision.scope_id,
            scope_status="excluded" if decision.match_kind == "explicit_exclusion" else "out",
            asset_value=decision.target,
            asset_type=decision.target_type,
            job_id=job_id,
            tool=scanner,
            source_name=layer,
            source_type="system",
        ),
        body={"scope_check": {"allowed": False, "reason": decision.reason, "layer": layer}},
    )


class ScanService:
    def __init__(self, session: Session, *, emitter: EventEmitter | None = None, settings: Settings | None = None):
        self.session = session
        self.emitter = emitter
        self.settings = settings or get_settings()

    def _emit(self, pipeline: str, events: list[dict]) -> None:
        if self.emitter is None or not events:
            return
        try:
            self.emitter.emit_many(pipeline, events)
        except Exception as exc:  # observability only; state is in PostgreSQL
            log.warning("event emission failed", extra={"error": str(exc), "pipeline": pipeline})

    def create_scan(
        self,
        *,
        principal: Principal,
        program_id: uuid.UUID,
        scanners: list[str],
        targets: list[str] | None = None,
        asset_ids: list[uuid.UUID] | None = None,
        policy_id: uuid.UUID | None = None,
        priority: int = 5,
        force: bool = False,
        trigger: str = "manual",
    ) -> ScanPlan:
        s = self.session
        program = s.get(Program, program_id)
        if program is None or program.deleted_at is not None:
            raise ScanRequestError("program not found")
        if not scanners:
            raise ScanRequestError("at least one scanner is required")
        specs = []
        for name in dict.fromkeys(scanners):
            spec = get_scanner(name)
            if not spec.implemented:
                raise ScanRequestError(f"scanner {name!r} is not implemented yet ({spec.description})")
            specs.append(spec)
        policy = resolve_policy(s, program, policy_id)
        policy_cfg = PolicyConfig.model_validate(policy.config)

        raw_targets = list(targets or [])
        # Existing assets keep their own discovery explanation/confidence (not "manual").
        known_assets: dict[str, Asset] = {}
        for aid in asset_ids or []:
            asset = s.get(Asset, aid)
            if asset is None:
                raise ScanRequestError(f"asset {aid} not found")
            raw_targets.append(asset.normalized_value)
            known_assets[asset.normalized_value] = asset
        raw_targets = list(dict.fromkeys(raw_targets))
        if not raw_targets:
            raise ScanRequestError("no targets given")
        if len(raw_targets) > self.settings.max_targets_per_scan:
            raise ScanRequestError(f"too many targets (max {self.settings.max_targets_per_scan})")

        # Layer 1 scope guard. Failing to load scope aborts the whole request.
        try:
            engine = ScopeEngine(load_rules(s, program.id))
        except ScopeUnavailableError:
            raise
        except Exception as exc:
            raise ScopeUnavailableError(str(exc)) from exc

        scan = Scan(
            program_id=program.id,
            policy_id=policy.id,
            scanners=[sp.name for sp in specs],
            trigger=trigger,
            requested_by=principal.name,
            status=ScanStatus.CREATED.value,
        )
        s.add(scan)
        s.flush()
        plan = ScanPlan(scan=scan)
        now = utcnow()
        nonce = str(uuid.uuid4()) if force else None
        blocked_events: list[dict] = []

        for raw in raw_targets:
            target: Target | None
            try:
                target = classify_target(raw)
            except InvalidTarget as exc:
                target = None
                invalid_reason = str(exc)
            decision = engine.is_in_scope(target, program.id) if target else None
            asset_id: uuid.UUID | None = None
            if target is not None and decision is not None and decision.allowed:
                asset = (
                    known_assets.get(raw)
                    or upsert_asset(
                        s, target, confidence=confidence_for("manual", f"submitted for scanning by {principal.name}")
                    )[0]
                )
                link_program_asset(s, program.id, asset, decision)
                asset_id = asset.id

            for spec in specs:
                sc = policy_cfg.for_scanner(spec.name)
                job = ScanJob(
                    id=uuid.uuid4(),
                    scan_id=scan.id,
                    program_id=program.id,
                    asset_id=asset_id,
                    scanner=spec.name,
                    policy_id=policy.id,
                    priority=priority,
                    target=(target.value if target else raw)[:2048],
                    target_type=target.kind if target else None,
                    status=JobStatus.PENDING.value,
                    max_retries=self.settings.job_max_retries,
                    config_hash=stable_hash(sc.model_dump()),
                    created_at=now,
                    result_summary={},
                    retry_count=0,
                )
                if decision is not None:
                    job.scope_id = uuid.UUID(decision.scope_id) if decision.scope_id else None
                    job.scope_reason = decision.reason[:512]

                if target is None:
                    _block_job(job, JobStatus.BLOCKED, BlockReason.INVALID_TARGET, invalid_reason)
                elif decision is None or not decision.allowed:
                    assert decision is not None
                    reason = (
                        BlockReason.EXCLUDED
                        if decision.match_kind == "explicit_exclusion"
                        else BlockReason.NOT_IN_SCOPE
                    )
                    _block_job(job, JobStatus.OUT_OF_SCOPE, reason, decision.reason)
                    record_audit(
                        s,
                        principal,
                        "SCOPE_BLOCKED",
                        target_type="scan_job",
                        target_id=job.id,
                        program_id=program.id,
                        details={
                            "target": job.target,
                            "scanner": spec.name,
                            "reason": decision.reason,
                            "scope_id": decision.scope_id,
                            "layer": "orchestrator",
                        },
                    )
                    blocked_events.append(
                        scope_blocked_event(
                            decision, program=program, scanner=spec.name, layer="orchestrator", job_id=str(job.id)
                        )
                    )
                elif target.kind not in spec.target_types:
                    _block_job(
                        job,
                        JobStatus.BLOCKED,
                        BlockReason.UNSUPPORTED_TARGET,
                        f"{spec.name} does not accept {target.kind} targets",
                    )
                elif not sc.enabled:
                    _block_job(
                        job,
                        JobStatus.BLOCKED,
                        BlockReason.POLICY_DISABLED,
                        f"{spec.name} is disabled in policy {policy.name}",
                    )
                elif (
                    target.kind == "cidr"
                    and target.network is not None
                    and (
                        target.network.num_addresses > self.settings.max_cidr_size
                        or target.network.num_addresses > self.settings.max_ips_per_job
                    )
                ):
                    _block_job(
                        job,
                        JobStatus.BLOCKED,
                        BlockReason.CIDR_LIMIT_EXCEEDED,
                        f"{target.value} has {target.network.num_addresses} addresses "
                        f"(MAX_CIDR_SIZE={self.settings.max_cidr_size})",
                    )
                else:
                    guard = check_operational_guards(s, program=program, scanner=spec.name, asset_id=asset_id)
                    if not guard.ok:
                        assert guard.reason is not None
                        _block_job(job, JobStatus.BLOCKED, guard.reason, guard.detail or guard.reason)
                    else:
                        job.idempotency_key = idempotency_key(
                            target=job.target,
                            scanner=spec.name,
                            policy_id=policy.id,
                            bucket_seconds=sc.time_bucket_seconds,
                            now=now,
                            program_id=program.id,
                            nonce=nonce,
                        )
                if job.status != JobStatus.PENDING.value:
                    s.add(job)
                    plan.jobs.append(PlannedJob(job))
                    continue
                inserted = s.execute(
                    insert(ScanJob)
                    .values(
                        **{
                            c.key: getattr(job, c.key)
                            for c in ScanJob.__table__.columns
                            if getattr(job, c.key) is not None
                        }
                    )
                    .on_conflict_do_nothing(index_elements=["idempotency_key"])
                    .returning(ScanJob.id)
                ).scalar_one_or_none()
                if inserted is None:
                    existing = s.execute(
                        select(ScanJob).where(ScanJob.idempotency_key == job.idempotency_key)
                    ).scalar_one()
                    plan.jobs.append(PlannedJob(existing, duplicate=True))
                else:
                    plan.jobs.append(PlannedJob(s.get(ScanJob, inserted)))  # type: ignore[arg-type]

        s.flush()
        record_audit(
            s,
            principal,
            "scan.started",
            target_type="scan",
            target_id=scan.id,
            program_id=program.id,
            details={
                "scanners": scan.scanners,
                "targets": len(raw_targets),
                "policy": policy.name,
                "trigger": trigger,
                "summary": plan.summary(),
            },
            emitter=self.emitter,
        )
        if all(pj.duplicate or pj.job.status in TERMINAL_JOB_STATUSES for pj in plan.jobs):
            scan.status = ScanStatus.COMPLETED.value
            scan.finished_at = utcnow()
        self._emit("changes", blocked_events)
        self._emit("ops", [job_event(pj.job, program.name) for pj in plan.jobs if not pj.duplicate])
        return plan


def dispatch_pending(
    session: Session,
    queue: RedisQueue,
    *,
    job_ids: list[uuid.UUID] | None = None,
    limit: int = 500,
    emitter: EventEmitter | None = None,
) -> int:
    """Enqueue PENDING jobs whose next attempt is due. Safe to run concurrently with workers.

    The DB row stays PENDING until the Redis push succeeds, so a Redis outage
    simply leaves work pending; nothing is ever executed outside the queue.

    Fair share: candidates are interleaved round-robin across (program, scanner) and each pair
    may have at most DISPATCH_MAX_QUEUED_PER_PROGRAM jobs waiting in Redis. A program that
    submits thousands of jobs therefore cannot starve another program; the excess stays PENDING
    in PostgreSQL and is dispatched as its queued jobs drain. High-priority jobs ignore the cap.
    """
    now = utcnow()
    cap = get_settings().dispatch_max_queued_per_program
    rank = (
        func.row_number()
        .over(
            partition_by=(ScanJob.program_id, ScanJob.scanner),
            order_by=(ScanJob.priority.desc(), ScanJob.created_at),
        )
        .label("rank")
    )
    cand = (
        select(ScanJob.id, ScanJob.priority, rank)
        .where(ScanJob.status == JobStatus.PENDING.value)
        .where((ScanJob.next_attempt_at.is_(None)) | (ScanJob.next_attempt_at <= now))
    )
    if job_ids is not None:
        cand = cand.where(ScanJob.id.in_(job_ids))
    sub = cand.subquery()
    order = [
        row.id for row in session.execute(select(sub.c.id).order_by(sub.c.rank, sub.c.priority.desc()).limit(limit))
    ]
    if not order:
        return 0
    locked = {
        j.id: j
        for j in session.execute(
            select(ScanJob)
            .where(ScanJob.id.in_(order), ScanJob.status == JobStatus.PENDING.value)
            .with_for_update(skip_locked=True)
        ).scalars()
    }
    queued: dict[tuple[uuid.UUID, str], int] = {}
    if cap > 0:
        queued = {
            (pid, scanner): int(n)
            for pid, scanner, n in session.execute(
                select(ScanJob.program_id, ScanJob.scanner, func.count())
                .where(ScanJob.status == JobStatus.QUEUED.value)
                .group_by(ScanJob.program_id, ScanJob.scanner)
            )
        }
    dispatched = 0
    events = []
    for job_id in order:
        job = locked.get(job_id)
        if job is None:
            continue  # taken by a concurrent dispatcher
        key = (job.program_id, job.scanner)
        if cap > 0 and job.priority < HIGH_PRIORITY and queued.get(key, 0) >= cap:
            continue  # fair share: this program already has enough work waiting for this scanner
        spec = get_scanner(job.scanner)
        try:
            queue.enqueue(spec.queue, str(job.id), job.priority)
        except Exception as exc:
            log.warning("redis unavailable; job stays PENDING", extra={"job_id": str(job.id), "error": str(exc)})
            break
        job.status = JobStatus.QUEUED.value
        job.queued_at = now
        queued[key] = queued.get(key, 0) + 1
        dispatched += 1
        events.append(job_event(job))
    session.flush()
    if emitter and events:
        try:
            emitter.emit_many("ops", events)
        except Exception as exc:
            log.warning("job event emission failed", extra={"error": str(exc)})
    return dispatched


def cancel_scan(session: Session, scan_id: uuid.UUID, principal: Principal, emitter: EventEmitter | None = None) -> int:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise ScanRequestError("scan not found")
    res = session.execute(
        update(ScanJob)
        .where(
            ScanJob.scan_id == scan_id,
            ScanJob.status.in_([JobStatus.PENDING.value, JobStatus.QUEUED.value, JobStatus.RUNNING.value]),
        )
        .values(status=JobStatus.CANCELLED.value, finished_at=utcnow(), error="cancelled by " + principal.name)
    )
    scan.status = ScanStatus.CANCELLED.value
    scan.finished_at = utcnow()
    record_audit(
        session,
        principal,
        "scan.cancelled",
        target_type="scan",
        target_id=scan_id,
        program_id=scan.program_id,
        details={"jobs_cancelled": res.rowcount},
        emitter=emitter,
    )
    return int(res.rowcount)
