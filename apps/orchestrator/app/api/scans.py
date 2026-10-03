from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_emitter, get_queue, operator, viewer
from app.database import get_session
from app.models import Scan, ScanJob, ScanPolicy
from app.models.enums import JobStatus
from app.queue.redis_queue import RedisQueue
from app.schemas.api import JobOut, ScanCreatedOut, ScanDetailOut, ScanIn, ScanOut
from app.scope.service import ScopeUnavailableError
from app.services import programs as program_svc
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.services.scans import ScanRequestError, ScanService, cancel_scan, dispatch_pending
from app.utils.time import utcnow

router = APIRouter(tags=["scans", "jobs"])
log = logging.getLogger(__name__)


@router.post("/scans", response_model=ScanCreatedOut, status_code=201)
def create_scan(
    body: ScanIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
    queue: RedisQueue = Depends(get_queue),
) -> ScanCreatedOut:
    try:
        program = program_svc.get_program(session, body.program)
    except program_svc.NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    policy_id = None
    if body.policy:
        policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == body.policy)).scalar_one_or_none()
        if policy is None:
            raise HTTPException(422, f"policy {body.policy!r} not found")
        policy_id = policy.id
    try:
        plan = ScanService(session, emitter=emitter).create_scan(
            principal=principal,
            program_id=program.id,
            scanners=body.scanners,
            targets=body.targets,
            asset_ids=body.asset_ids,
            policy_id=policy_id,
            priority=body.priority,
            force=body.force,
        )
    except ScopeUnavailableError as exc:
        raise HTTPException(503, f"scope state unavailable; refusing to create jobs: {exc}") from exc
    except ScanRequestError as exc:
        raise HTTPException(422, str(exc)) from exc
    # Commit before enqueueing so a worker can never pick up a job id that is not yet visible.
    session.commit()
    new_ids = [pj.job.id for pj in plan.jobs if not pj.duplicate and pj.job.status == JobStatus.PENDING.value]
    if new_ids:
        dispatch_pending(session, queue, job_ids=new_ids, emitter=emitter)
        session.commit()
    for pj in plan.jobs:
        session.refresh(pj.job)
    return ScanCreatedOut(
        scan=ScanOut.model_validate(plan.scan),
        summary=plan.summary(),
        jobs=[JobOut.model_validate(pj.job) for pj in plan.jobs],
        duplicates=[pj.job.id for pj in plan.jobs if pj.duplicate],
    )


@router.get("/scans", response_model=list[ScanOut])
def list_scans(
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    program: str | None = None,
    limit: int = Query(50, le=500),
    offset: int = 0,
) -> list[Scan]:
    stmt = select(Scan)
    if program:
        stmt = stmt.where(Scan.program_id == program_svc.get_program(session, program).id)
    return list(session.execute(stmt.order_by(Scan.created_at.desc()).limit(limit).offset(offset)).scalars())


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(
    scan_id: uuid.UUID, session: Session = Depends(get_session), _: Principal = Depends(viewer)
) -> ScanDetailOut:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    counts = {
        str(k): int(v)
        for k, v in session.execute(
            select(ScanJob.status, func.count()).where(ScanJob.scan_id == scan_id).group_by(ScanJob.status)
        )
    }
    out = ScanDetailOut.model_validate({**ScanOut.model_validate(scan).model_dump(), "job_counts": counts})
    return out


@router.post("/scans/{scan_id}/cancel")
def cancel(
    scan_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    try:
        n = cancel_scan(session, scan_id, principal, emitter)
    except ScanRequestError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"scan_id": str(scan_id), "jobs_cancelled": n}


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    status: str | None = None,
    scanner: str | None = None,
    scan_id: uuid.UUID | None = None,
    program: str | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
) -> list[ScanJob]:
    stmt = select(ScanJob)
    if status:
        stmt = stmt.where(ScanJob.status == status.upper())
    if scanner:
        stmt = stmt.where(ScanJob.scanner == scanner)
    if scan_id:
        stmt = stmt.where(ScanJob.scan_id == scan_id)
    if program:
        stmt = stmt.where(ScanJob.program_id == program_svc.get_program(session, program).id)
    return list(session.execute(stmt.order_by(ScanJob.created_at.desc()).limit(limit).offset(offset)).scalars())


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: uuid.UUID, session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> ScanJob:
    job = session.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(404, "job not found")
    return job


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(
    job_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> ScanJob:
    job = session.get(ScanJob, job_id, with_for_update=True)
    if job is None:
        raise HTTPException(404, "job not found")
    if job.status in (JobStatus.PENDING.value, JobStatus.QUEUED.value, JobStatus.RUNNING.value):
        job.status = JobStatus.CANCELLED.value
        job.finished_at = utcnow()
        job.error = "cancelled by " + principal.name
        record_audit(
            session,
            principal,
            "scan.cancelled",
            target_type="scan_job",
            target_id=job.id,
            program_id=job.program_id,
            emitter=emitter,
        )
    return job
