"""Operational endpoints: stats, workers, queues/DLQ, audit, schedules, scanner pause,
maintenance windows and API key management."""

from __future__ import annotations

import json
import secrets
import uuid
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import admin, get_emitter, get_queue, operator, viewer
from app.database import get_session
from app.models import (
    ApiKey,
    Asset,
    AssetRelationship,
    AuditEvent,
    MaintenanceWindow,
    NotificationDelivery,
    Program,
    ScanJob,
    ScannerControl,
    ScanPolicy,
    Schedule,
    ScopeEntry,
)
from app.queue.redis_queue import QUEUE_NAMES, RedisQueue
from app.schemas.api import ApiKeyIn, AuditOut, MaintenanceIn, ScannerControlIn, ScheduleOut, SchedulePatch
from app.services import programs as program_svc
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.utils.hashing import sha256_text
from app.utils.time import utcnow
from app.workers.registry import SCANNERS

router = APIRouter(tags=["operations"])


@router.get("/stats")
def stats(
    session: Session = Depends(get_session), _: Principal = Depends(viewer), queue: RedisQueue = Depends(get_queue)
) -> dict:
    def count(model, *where) -> int:
        return int(session.execute(select(func.count()).select_from(model).where(*where)).scalar_one())

    jobs = {str(k): int(v) for k, v in session.execute(select(ScanJob.status, func.count()).group_by(ScanJob.status))}
    assets = {
        str(k): int(v) for k, v in session.execute(select(Asset.asset_type, func.count()).group_by(Asset.asset_type))
    }
    try:
        queues: dict[str, Any] = dict(queue.depths())
    except Exception as exc:
        queues = {"error": str(exc)}
    return {
        "programs": {
            "total": count(Program, Program.deleted_at.is_(None)),
            "active": count(Program, Program.deleted_at.is_(None), Program.active.is_(True)),
        },
        "scope_entries": count(ScopeEntry, ScopeEntry.active.is_(True)),
        "assets": {"total": sum(assets.values()), "by_type": assets},
        "relationships": count(AssetRelationship),
        "jobs": jobs,
        "scope_blocked": count(AuditEvent, AuditEvent.action == "SCOPE_BLOCKED"),
        "queues": queues,
    }


@router.get("/workers")
def workers(_: Principal = Depends(viewer), queue: RedisQueue = Depends(get_queue)) -> dict:
    live = queue.workers()
    pools = {
        name: {
            **d,
            "workers": sum(1 for w in live if w.queue == name),
            "busy_workers": sum(1 for w in live if w.queue == name and w.data.get("current_job")),
        }
        for name, d in queue.depths().items()
    }
    return {
        "pools": pools,
        "workers": [{"worker_id": w.worker_id, "queue": w.queue, **w.data} for w in live],
        "scanners": [
            {
                "name": s.name,
                "queue": s.queue,
                "implemented": s.implemented,
                "active": s.active,
                "description": s.description,
            }
            for s in SCANNERS.values()
        ],
    }


@router.get("/queues")
def queues(
    _: Principal = Depends(viewer),
    queue: RedisQueue = Depends(get_queue),
    dlq: str | None = Query(None, description="queue name to list dead-lettered items for"),
) -> dict:
    out: dict = {"depths": queue.depths()}
    if dlq:
        if dlq not in QUEUE_NAMES:
            raise HTTPException(422, "unknown queue")
        out["dlq_items"] = queue.dlq_items(dlq)
    return out


@router.get("/audit", response_model=list[AuditOut])
def audit_log(
    session: Session = Depends(get_session),
    _: Principal = Depends(operator),
    action: str | None = None,
    limit: int = Query(100, le=1000),
) -> list[AuditEvent]:
    stmt = select(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    return list(session.execute(stmt.order_by(AuditEvent.timestamp.desc()).limit(limit)).scalars())


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> list[Schedule]:
    return list(session.execute(select(Schedule).order_by(Schedule.name)).scalars())


@router.patch("/schedules/{name}", response_model=ScheduleOut)
def patch_schedule(
    name: str,
    body: SchedulePatch,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> Schedule:
    sched = session.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none()
    if sched is None:
        raise HTTPException(404, "schedule not found")
    changes = body.model_dump(exclude_unset=True)
    if "enabled" in changes:
        sched.enabled = bool(changes["enabled"])
        if sched.enabled:
            sched.next_run_at = utcnow()
    if changes.get("interval_seconds"):
        sched.interval_seconds = changes["interval_seconds"]
    if "program" in changes:
        sched.program_id = program_svc.get_program(session, changes["program"]).id if changes["program"] else None
    if "policy" in changes:
        if changes["policy"]:
            pol = session.execute(select(ScanPolicy).where(ScanPolicy.name == changes["policy"])).scalar_one_or_none()
            if pol is None:
                raise HTTPException(422, "policy not found")
            sched.policy_id = pol.id
        else:
            sched.policy_id = None
    record_audit(
        session,
        principal,
        "schedule.changed",
        target_type="schedule",
        target_id=sched.id,
        details={k: str(v) for k, v in changes.items()},
        emitter=emitter,
    )
    return sched


@router.put("/scanners/{scanner}")
def control_scanner(
    scanner: str,
    body: ScannerControlIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    if scanner not in SCANNERS:
        raise HTTPException(404, "unknown scanner")
    ctl = session.get(ScannerControl, scanner) or ScannerControl(scanner=scanner)
    ctl.paused = body.paused
    ctl.reason = body.reason
    ctl.updated_at = utcnow()
    session.add(ctl)
    record_audit(
        session,
        principal,
        "scanner.disabled" if body.paused else "scanner.enabled",
        target_type="scanner",
        target_id=scanner,
        details={"reason": body.reason},
        emitter=emitter,
    )
    return {"scanner": scanner, "paused": ctl.paused, "reason": ctl.reason}


@router.post("/maintenance-windows", status_code=201)
def create_window(
    body: MaintenanceIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    if body.end <= body.start:
        raise HTTPException(422, "end must be after start")
    program_id = program_svc.get_program(session, body.program).id if body.program else None
    w = MaintenanceWindow(
        program_id=program_id,
        scanner=body.scanner,
        asset_id=body.asset_id,
        start=body.start,
        end=body.end,
        reason=body.reason,
    )
    session.add(w)
    session.flush()
    record_audit(
        session,
        principal,
        "maintenance.created",
        target_type="maintenance_window",
        target_id=w.id,
        program_id=program_id,
        details=body.model_dump(mode="json"),
        emitter=emitter,
    )
    return {"id": str(w.id)}


@router.get("/maintenance-windows")
def list_windows(session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> list[dict]:
    rows = session.execute(select(MaintenanceWindow).order_by(MaintenanceWindow.start.desc()).limit(200)).scalars()
    return [
        {
            "id": str(w.id),
            "program_id": str(w.program_id) if w.program_id else None,
            "scanner": w.scanner,
            "asset_id": str(w.asset_id) if w.asset_id else None,
            "start": w.start,
            "end": w.end,
            "reason": w.reason,
        }
        for w in rows
    ]


@router.post("/api-keys", status_code=201)
def create_api_key(
    body: ApiKeyIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    if session.execute(select(ApiKey).where(ApiKey.name == body.name)).scalar_one_or_none():
        raise HTTPException(409, "key name exists")
    plaintext = "bb_" + secrets.token_urlsafe(32)
    key = ApiKey(id=uuid.uuid4(), name=body.name, key_hash=sha256_text(plaintext), role=body.role, active=True)
    session.add(key)
    record_audit(
        session,
        principal,
        "api_key.created",
        target_type="api_key",
        target_id=key.id,
        details={"name": body.name, "role": body.role},
        emitter=emitter,
    )
    return {"name": body.name, "role": body.role, "api_key": plaintext, "note": "shown once; store it securely"}


@router.post("/queues/{queue_name}/dlq/replay")
def replay_dlq(
    queue_name: str,
    limit: int = Query(50, ge=1, le=1000),
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    queue: RedisQueue = Depends(get_queue),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    """Re-run dead-lettered work. Jobs go back to PENDING (re-dispatched by the scheduler, so every scope,
    pause and policy check applies again); notifications are re-attempted by the notifier."""
    if queue_name not in QUEUE_NAMES:
        raise HTTPException(422, "unknown queue")
    replayed, skipped = 0, 0
    for _ in range(limit):
        raw = queue.r.rpop(f"bb:dlq:{queue_name}")
        if raw is None:
            break
        item = json.loads(cast(str, raw))
        if queue_name == "notifications":
            delivery = session.get(NotificationDelivery, uuid.UUID(item["delivery_id"]))
            if delivery is None:
                skipped += 1
                continue
            delivery.status, delivery.attempts, delivery.last_error = "pending", 0, None
            queue.r.zadd(
                "bb:notify:retry",
                {json.dumps({"delivery_id": item["delivery_id"], "n": item["notification"]}, sort_keys=True): 0},
            )
            replayed += 1
            continue
        job = session.get(ScanJob, uuid.UUID(item["job_id"])) if item.get("job_id") else None
        if job is None or job.status != "FAILED":
            skipped += 1
            continue
        job.status, job.retry_count, job.next_attempt_at = "PENDING", 0, None
        job.finished_at, job.error = None, f"replayed from DLQ by {principal.name}"
        replayed += 1
    record_audit(
        session,
        principal,
        "dlq.replayed",
        target_type="queue",
        target_id=queue_name,
        details={"replayed": replayed, "skipped": skipped},
        emitter=emitter,
    )
    return {"queue": queue_name, "replayed": replayed, "skipped": skipped}


@router.delete("/queues/{queue_name}/dlq")
def purge_dlq(
    queue_name: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    queue: RedisQueue = Depends(get_queue),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    if queue_name not in QUEUE_NAMES:
        raise HTTPException(422, "unknown queue")
    n = int(cast(int, queue.r.llen(f"bb:dlq:{queue_name}")))
    queue.r.delete(f"bb:dlq:{queue_name}")
    record_audit(
        session,
        principal,
        "dlq.purged",
        target_type="queue",
        target_id=queue_name,
        details={"purged": n},
        emitter=emitter,
    )
    return {"queue": queue_name, "purged": n}
