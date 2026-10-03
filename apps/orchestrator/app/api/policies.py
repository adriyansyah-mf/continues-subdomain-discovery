from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import admin, get_emitter, viewer
from app.config import get_settings
from app.database import get_session
from app.models import Program, ScanPolicy, Schedule
from app.schemas.api import PolicyIn, PolicyOut
from app.schemas.policy import PolicyConfig, enforce_global_limits
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter

router = APIRouter(tags=["policies"])


def _validate(raw: dict) -> PolicyConfig:
    try:
        cfg = PolicyConfig.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors(include_url=False)) from exc
    violations = enforce_global_limits(cfg, get_settings())
    if violations:
        raise HTTPException(422, {"limit_violations": violations})
    return cfg


@router.get("/policies", response_model=list[PolicyOut])
def list_policies(session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> list[ScanPolicy]:
    return list(session.execute(select(ScanPolicy).order_by(ScanPolicy.name)).scalars())


@router.post("/policies", response_model=PolicyOut, status_code=201)
def create_policy(
    body: PolicyIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> ScanPolicy:
    if session.execute(select(ScanPolicy).where(ScanPolicy.name == body.name)).scalar_one_or_none():
        raise HTTPException(409, "policy already exists")
    cfg = _validate(body.config)
    policy = ScanPolicy(name=body.name, description=body.description, config=cfg.model_dump(), active=True)
    session.add(policy)
    session.flush()
    record_audit(
        session,
        principal,
        "policy.created",
        target_type="policy",
        target_id=policy.id,
        details={"name": body.name, "config": cfg.model_dump()},
        emitter=emitter,
    )
    return policy


@router.put("/policies/{name}", response_model=PolicyOut)
def replace_policy(
    name: str,
    body: PolicyIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> ScanPolicy:
    policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == name)).scalar_one_or_none()
    if policy is None:
        raise HTTPException(404, "policy not found")
    cfg = _validate(body.config)
    before = policy.config
    policy.config = cfg.model_dump()
    policy.description = body.description
    record_audit(
        session,
        principal,
        "policy.changed",
        target_type="policy",
        target_id=policy.id,
        details={"name": name, "before": before, "after": policy.config},
        emitter=emitter,
    )
    return policy


@router.delete("/policies/{name}", status_code=204)
def delete_policy(
    name: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> None:
    """Delete a policy that no program uses as default and no schedule references."""
    policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == name)).scalar_one_or_none()
    if policy is None:
        raise HTTPException(404, "policy not found")
    users = (
        session.execute(
            select(Program.slug).where(Program.default_scan_policy_id == policy.id, Program.deleted_at.is_(None))
        )
        .scalars()
        .all()
    )
    schedules = session.execute(select(Schedule.name).where(Schedule.policy_id == policy.id)).scalars().all()
    if users or schedules:
        raise HTTPException(409, f"policy in use (programs: {list(users)}, schedules: {list(schedules)})")
    record_audit(
        session,
        principal,
        "policy.deleted",
        target_type="policy",
        target_id=policy.id,
        details={"name": name, "config": policy.config},
        emitter=emitter,
    )
    session.delete(policy)
