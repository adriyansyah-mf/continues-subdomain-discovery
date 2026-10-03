"""Program and CDB (scope) management. Every mutation is audited."""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import Program, ScanPolicy, ScopeEntry
from app.models.enums import ScopeMode, ScopeType
from app.scope.normalize import InvalidTarget, normalize_scope_value
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.utils.time import utcnow

_SLUG_RE = re.compile(r"[^a-z0-9]+")


class ConflictError(ValueError):
    pass


class NotFoundError(LookupError):
    pass


def slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.lower()).strip("-")
    if not slug:
        raise ValueError("name must contain letters or digits")
    return slug[:128]


def get_program(session: Session, ref: str | uuid.UUID) -> Program:
    """Look a program up by id or slug."""
    program: Program | None = None
    try:
        program = session.get(Program, uuid.UUID(str(ref)))
    except ValueError:
        program = session.execute(select(Program).where(Program.slug == str(ref))).scalar_one_or_none()
    if program is None or program.deleted_at is not None:
        raise NotFoundError(f"program {ref} not found")
    return program


def create_program(
    session: Session,
    principal: Principal,
    *,
    name: str,
    slug: str | None,
    platform: str,
    description: str | None,
    active: bool,
    default_policy: str | None,
    emitter: EventEmitter | None = None,
) -> Program:
    slug = slugify(slug or name)
    if session.execute(select(Program).where(Program.slug == slug)).scalar_one_or_none():
        raise ConflictError(f"program slug {slug!r} already exists")
    policy_id = None
    if default_policy:
        policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == default_policy)).scalar_one_or_none()
        if policy is None:
            raise NotFoundError(f"policy {default_policy!r} not found")
        policy_id = policy.id
    program = Program(
        name=name,
        slug=slug,
        platform=platform,
        description=description,
        active=active,
        default_scan_policy_id=policy_id,
    )
    session.add(program)
    session.flush()
    record_audit(
        session,
        principal,
        "program.created",
        target_type="program",
        target_id=program.id,
        program_id=program.id,
        details={"name": name, "slug": slug, "platform": platform, "active": active},
        emitter=emitter,
    )
    return program


def update_program(
    session: Session,
    principal: Principal,
    program: Program,
    changes: dict[str, Any],
    emitter: EventEmitter | None = None,
) -> Program:
    before = {k: getattr(program, k) for k in changes if k != "default_policy"}
    for key, value in changes.items():
        if key == "default_policy":
            if value is None:
                program.default_scan_policy_id = None
            else:
                policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == value)).scalar_one_or_none()
                if policy is None:
                    raise NotFoundError(f"policy {value!r} not found")
                program.default_scan_policy_id = policy.id
        elif key in ("name", "platform", "description", "active"):
            setattr(program, key, value)
    session.flush()
    record_audit(
        session,
        principal,
        "program.updated",
        target_type="program",
        target_id=program.id,
        program_id=program.id,
        details={"before": before, "after": changes},
        emitter=emitter,
    )
    return program


def delete_program(
    session: Session, principal: Principal, program: Program, emitter: EventEmitter | None = None
) -> None:
    """Soft delete: the program is deactivated and hidden; history is preserved."""
    program.active = False
    program.deleted_at = utcnow()
    record_audit(
        session,
        principal,
        "program.deleted",
        target_type="program",
        target_id=program.id,
        program_id=program.id,
        details={"slug": program.slug},
        emitter=emitter,
    )


def add_scope_entry(
    session: Session,
    principal: Principal,
    program: Program,
    *,
    type_: str,
    value: str,
    mode: str,
    source: str = "manual",
    description: str | None = None,
    emitter: EventEmitter | None = None,
    audit: bool = True,
) -> ScopeEntry:
    try:
        st = ScopeType(type_)
        sm = ScopeMode(mode)
    except ValueError as exc:
        raise InvalidTarget(str(exc)) from exc
    normalized = normalize_scope_value(st, value)
    existing = session.execute(
        select(ScopeEntry).where(
            ScopeEntry.program_id == program.id,
            ScopeEntry.type == st.value,
            ScopeEntry.normalized_value == normalized,
            ScopeEntry.mode == sm.value,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.active:
            raise ConflictError(f"scope entry already exists ({existing.id})")
        existing.active = True
        existing.source = source
        entry = existing
    else:
        entry = ScopeEntry(
            program_id=program.id,
            type=st.value,
            value=value.strip(),
            normalized_value=normalized,
            mode=sm.value,
            source=source,
            description=description,
            active=True,
        )
        session.add(entry)
        try:
            session.flush()
        except IntegrityError as exc:
            raise ConflictError("scope entry already exists") from exc
    if audit:
        record_audit(
            session,
            principal,
            "scope.created",
            target_type="scope_entry",
            target_id=entry.id,
            program_id=program.id,
            details={"type": st.value, "value": normalized, "mode": sm.value, "source": source},
            emitter=emitter,
        )
    return entry


def update_scope_entry(
    session: Session,
    principal: Principal,
    entry: ScopeEntry,
    changes: dict[str, Any],
    emitter: EventEmitter | None = None,
) -> ScopeEntry:
    before = {
        "value": entry.normalized_value,
        "mode": entry.mode,
        "active": entry.active,
        "description": entry.description,
    }
    if "value" in changes and changes["value"] is not None:
        entry.normalized_value = normalize_scope_value(ScopeType(entry.type), changes["value"])
        entry.value = changes["value"].strip()
    if "mode" in changes and changes["mode"] is not None:
        entry.mode = ScopeMode(changes["mode"]).value
    if "active" in changes and changes["active"] is not None:
        entry.active = bool(changes["active"])
    if "description" in changes:
        entry.description = changes["description"]
    try:
        session.flush()
    except IntegrityError as exc:
        raise ConflictError("an identical scope entry already exists") from exc
    record_audit(
        session,
        principal,
        "scope.changed",
        target_type="scope_entry",
        target_id=entry.id,
        program_id=entry.program_id,
        details={
            "before": before,
            "after": {"value": entry.normalized_value, "mode": entry.mode, "active": entry.active},
        },
        emitter=emitter,
    )
    return entry


def delete_scope_entry(
    session: Session, principal: Principal, entry: ScopeEntry, emitter: EventEmitter | None = None
) -> None:
    details = {"type": entry.type, "value": entry.normalized_value, "mode": entry.mode}
    program_id = entry.program_id
    entry_id = entry.id
    session.delete(entry)
    session.flush()
    record_audit(
        session,
        principal,
        "scope.deleted",
        target_type="scope_entry",
        target_id=entry_id,
        program_id=program_id,
        details=details,
        emitter=emitter,
    )
