"""Notification channels, policies, deliveries and channel tests (all changes audited)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import admin, get_emitter, operator, viewer
from app.database import get_session
from app.models import NotificationChannel, NotificationDelivery, NotificationPolicy
from app.services import programs as program_svc
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.services.notify.catalog import NOTIFICATION_TYPES, SEVERITY_RANK, Notification
from app.services.notify.dispatch import send_now
from app.services.notify.providers import PROVIDERS, ConfigError, NotificationError, get_provider

router = APIRouter(prefix="/notifications", tags=["notifications"])


class ChannelIn(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    channel_type: str = Field(description=", ".join(sorted(PROVIDERS)))
    secret_ref: str | None = Field(default=None, description="env var / Docker secret NAME holding the secret")
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class PolicyIn(BaseModel):
    channel: str
    event_types: list[str] = Field(min_length=1)
    program: str | None = None
    min_severity: str | None = None
    enabled: bool = True


def _channel_out(c: NotificationChannel) -> dict:
    return {
        "id": str(c.id),
        "name": c.name,
        "channel_type": c.channel_type,
        "secret_ref": c.secret_ref,
        "config": c.config,
        "enabled": c.enabled,
    }


def _channel(session: Session, name: str) -> NotificationChannel:
    c = session.execute(select(NotificationChannel).where(NotificationChannel.name == name)).scalar_one_or_none()
    if c is None:
        raise HTTPException(404, "channel not found")
    return c


@router.get("/types")
def types(_: Principal = Depends(viewer)) -> dict:
    return {
        "notification_types": NOTIFICATION_TYPES,
        "severities": list(SEVERITY_RANK),
        "channel_types": sorted(PROVIDERS),
    }


@router.get("/channels")
def list_channels(session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> list[dict]:
    return [
        _channel_out(c)
        for c in session.execute(select(NotificationChannel).order_by(NotificationChannel.name)).scalars()
    ]


@router.post("/channels", status_code=201)
def create_channel(
    body: ChannelIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    try:
        get_provider(body.channel_type).validate_config(body.config, body.secret_ref)
    except ConfigError as exc:
        raise HTTPException(422, str(exc)) from exc
    if session.execute(select(NotificationChannel).where(NotificationChannel.name == body.name)).scalar_one_or_none():
        raise HTTPException(409, "channel exists")
    c = NotificationChannel(
        name=body.name,
        channel_type=body.channel_type,
        secret_ref=body.secret_ref,
        config=body.config,
        enabled=body.enabled,
    )
    session.add(c)
    session.flush()
    record_audit(
        session,
        principal,
        "notification.channel_created",
        target_type="notification_channel",
        target_id=c.id,
        details={"name": c.name, "type": c.channel_type, "secret_ref": c.secret_ref},
        emitter=emitter,
    )
    return _channel_out(c)


@router.patch("/channels/{name}")
def toggle_channel(
    name: str,
    enabled: bool,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    c = _channel(session, name)
    c.enabled = enabled
    record_audit(
        session,
        principal,
        "notification.channel_changed",
        target_type="notification_channel",
        target_id=c.id,
        details={"enabled": enabled},
        emitter=emitter,
    )
    return _channel_out(c)


@router.delete("/channels/{name}", status_code=204)
def delete_channel(
    name: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(admin),
    emitter: EventEmitter = Depends(get_emitter),
) -> None:
    c = _channel(session, name)
    record_audit(
        session,
        principal,
        "notification.channel_deleted",
        target_type="notification_channel",
        target_id=c.id,
        details={"name": name},
        emitter=emitter,
    )
    session.delete(c)


@router.post("/channels/{name}/test")
def test_channel(
    name: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    c = _channel(session, name)
    n = Notification(
        type="TEST",
        severity="info",
        event_type="TEST",
        program_id=None,
        program_name=None,
        asset_value=None,
        title="Test notification from bugbounty-platform",
        detail=f"Requested by {principal.name}",
        fact_key=str(uuid.uuid4()),
    )
    try:
        send_now(c, n)
        ok, error = True, None
    except (ConfigError, NotificationError) as exc:
        ok, error = False, str(exc)
    record_audit(
        session,
        principal,
        "notification.channel_tested",
        target_type="notification_channel",
        target_id=c.id,
        details={"ok": ok, "error": error},
        emitter=emitter,
    )
    if not ok:
        session.commit()  # keep the audit record although the request fails
        raise HTTPException(502, f"test delivery failed: {error}")
    return {"channel": name, "delivered": True}


@router.get("/policies")
def list_policies(session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> list[dict]:
    rows = session.execute(
        select(NotificationPolicy, NotificationChannel.name).join(
            NotificationChannel, NotificationChannel.id == NotificationPolicy.channel_id
        )
    ).all()
    return [
        {
            "id": str(p.id),
            "channel": cname,
            "program_id": str(p.program_id) if p.program_id else None,
            "event_types": p.event_types,
            "min_severity": p.min_severity,
            "enabled": p.enabled,
        }
        for p, cname in rows
    ]


@router.post("/policies", status_code=201)
def create_policy(
    body: PolicyIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    unknown = [t for t in body.event_types if t != "*" and t not in NOTIFICATION_TYPES]
    if unknown:
        raise HTTPException(422, f"unknown notification types {unknown}; see GET /notifications/types")
    if body.min_severity and body.min_severity not in SEVERITY_RANK:
        raise HTTPException(422, "invalid min_severity")
    c = _channel(session, body.channel)
    program_id = program_svc.get_program(session, body.program).id if body.program else None
    p = NotificationPolicy(
        program_id=program_id,
        channel_id=c.id,
        event_types=body.event_types,
        min_severity=body.min_severity,
        enabled=body.enabled,
    )
    session.add(p)
    session.flush()
    record_audit(
        session,
        principal,
        "notification.policy_created",
        target_type="notification_policy",
        target_id=p.id,
        program_id=program_id,
        details={"channel": c.name, "event_types": body.event_types, "min_severity": body.min_severity},
        emitter=emitter,
    )
    return {"id": str(p.id)}


@router.delete("/policies/{policy_id}", status_code=204)
def delete_policy(
    policy_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> None:
    p = session.get(NotificationPolicy, policy_id)
    if p is None:
        raise HTTPException(404, "policy not found")
    record_audit(
        session,
        principal,
        "notification.policy_deleted",
        target_type="notification_policy",
        target_id=p.id,
        program_id=p.program_id,
        emitter=emitter,
    )
    session.delete(p)


@router.get("/deliveries")
def deliveries(
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    status: str | None = None,
    limit: int = Query(50, le=500),
) -> list[dict]:
    stmt = select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(NotificationDelivery.status == status)
    return [
        {
            "id": str(d.id),
            "event_type": d.event_type,
            "severity": d.severity,
            "status": d.status,
            "attempts": d.attempts,
            "summary": d.summary,
            "last_error": d.last_error,
            "created_at": d.created_at,
            "sent_at": d.sent_at,
        }
        for d in session.execute(stmt).scalars()
    ]
