"""Audit trail. PostgreSQL is authoritative; events are replicated to bb-audit-* best-effort."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.services.events import EventContext, EventEmitter, build_event

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    name: str
    role: str


SYSTEM = Principal(name="system", role="admin")


def record_audit(
    session: Session,
    actor: Principal,
    action: str,
    *,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    program_id: uuid.UUID | str | None = None,
    details: dict[str, Any] | None = None,
    emitter: EventEmitter | None = None,
) -> AuditEvent:
    ev = AuditEvent(
        actor=actor.name,
        actor_role=actor.role,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        program_id=uuid.UUID(str(program_id)) if program_id else None,
        details=details or {},
    )
    session.add(ev)
    session.flush()
    if emitter is not None:
        try:
            emitter.emit(
                "ops",
                build_event(
                    index="bb-audit",
                    kind="event",
                    category="audit",
                    type_=action,
                    ctx=EventContext(
                        program_id=str(program_id) if program_id else None,
                        source_name=actor.name,
                        source_type="audit",
                    ),
                    body={
                        "user": {"name": actor.name, "roles": [actor.role]},
                        "audit": {
                            "id": str(ev.id),
                            "target_type": target_type,
                            "target_id": ev.target_id,
                            "details": details or {},
                        },
                    },
                    doc_id=str(ev.id),
                ),
            )
        except Exception as exc:  # replication only; the PG row is the record
            log.warning("audit replication to elasticsearch failed", extra={"error": str(exc)})
    return ev
