"""Shared API dependencies: DB session, API-key authentication and RBAC."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_session
from app.models import ApiKey
from app.models.enums import ROLE_RANK, Role
from app.queue.redis_queue import RedisQueue, get_redis
from app.services.audit import Principal
from app.services.events import EventEmitter
from app.utils.hashing import sha256_text
from app.utils.time import utcnow


def get_principal(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    session: Session = Depends(get_session),
) -> Principal:
    if not x_api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing X-API-Key header")
    key = session.execute(
        select(ApiKey).where(ApiKey.key_hash == sha256_text(x_api_key), ApiKey.active.is_(True))
    ).scalar_one_or_none()
    if key is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
    key.last_used_at = utcnow()
    return Principal(name=key.name, role=key.role)


def require(role: Role) -> Callable[..., Principal]:
    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if ROLE_RANK[Role(principal.role)] < ROLE_RANK[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"requires role {role.value}")
        return principal

    return _dep


viewer = require(Role.VIEWER)
operator = require(Role.OPERATOR)
admin = require(Role.ADMIN)


def get_emitter() -> EventEmitter:
    return EventEmitter(get_redis(), max_backlog=get_settings().max_event_backlog)


def get_queue() -> RedisQueue:
    return RedisQueue(get_redis())
