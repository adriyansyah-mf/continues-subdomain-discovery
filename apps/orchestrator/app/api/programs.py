from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_emitter, operator, viewer
from app.database import get_session
from app.models import Program, ScopeEntry
from app.schemas.api import ProgramIn, ProgramOut, ProgramPatch, ScopeCheckIn, ScopeIn, ScopeOut, ScopePatch
from app.scope.normalize import InvalidTarget, infer_scope_type
from app.scope.service import check_scope
from app.services import programs as svc
from app.services.audit import Principal
from app.services.events import EventEmitter

router = APIRouter(tags=["programs", "scope"])


def _program(session: Session, ref: str) -> Program:
    try:
        return svc.get_program(session, ref)
    except svc.NotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/programs", response_model=list[ProgramOut])
def list_programs(
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    include_inactive: bool = True,
) -> list[Program]:
    stmt = select(Program).where(Program.deleted_at.is_(None)).order_by(Program.name)
    if not include_inactive:
        stmt = stmt.where(Program.active.is_(True))
    return list(session.execute(stmt).scalars())


@router.post("/programs", response_model=ProgramOut, status_code=201)
def create_program(
    body: ProgramIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> Program:
    try:
        return svc.create_program(
            session,
            principal,
            name=body.name,
            slug=body.slug,
            platform=body.platform,
            description=body.description,
            active=body.active,
            default_policy=body.default_policy,
            emitter=emitter,
        )
    except svc.ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (svc.NotFoundError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/programs/{ref}", response_model=ProgramOut)
def get_program(ref: str, session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> Program:
    return _program(session, ref)


@router.patch("/programs/{ref}", response_model=ProgramOut)
def patch_program(
    ref: str,
    body: ProgramPatch,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> Program:
    program = _program(session, ref)
    try:
        return svc.update_program(session, principal, program, body.model_dump(exclude_unset=True), emitter)
    except svc.NotFoundError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.delete("/programs/{ref}", status_code=204)
def delete_program(
    ref: str,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> None:
    svc.delete_program(session, principal, _program(session, ref), emitter)


@router.get("/programs/{ref}/scope", response_model=list[ScopeOut])
def list_scope(
    ref: str,
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    include_inactive: bool = False,
    limit: int = Query(1000, le=50000),
    offset: int = 0,
) -> list[ScopeEntry]:
    program = _program(session, ref)
    stmt = select(ScopeEntry).where(ScopeEntry.program_id == program.id)
    if not include_inactive:
        stmt = stmt.where(ScopeEntry.active.is_(True))
    stmt = stmt.order_by(ScopeEntry.mode.desc(), ScopeEntry.type, ScopeEntry.normalized_value)
    return list(session.execute(stmt.limit(limit).offset(offset)).scalars())


@router.post("/programs/{ref}/scope", response_model=ScopeOut, status_code=201)
def add_scope(
    ref: str,
    body: ScopeIn,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> ScopeEntry:
    program = _program(session, ref)
    try:
        stype = body.type or infer_scope_type(body.value)
        return svc.add_scope_entry(
            session,
            principal,
            program,
            type_=stype.value,
            value=body.value,
            mode=body.mode.value,
            source=body.source,
            description=body.description,
            emitter=emitter,
        )
    except InvalidTarget as exc:
        raise HTTPException(422, f"invalid scope entry: {exc}") from exc
    except svc.ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc


def _scope_entry(session: Session, scope_id: uuid.UUID) -> ScopeEntry:
    entry = session.get(ScopeEntry, scope_id)
    if entry is None:
        raise HTTPException(404, "scope entry not found")
    return entry


@router.patch("/scope/{scope_id}", response_model=ScopeOut)
def patch_scope(
    scope_id: uuid.UUID,
    body: ScopePatch,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> ScopeEntry:
    try:
        return svc.update_scope_entry(
            session, principal, _scope_entry(session, scope_id), body.model_dump(exclude_unset=True), emitter
        )
    except InvalidTarget as exc:
        raise HTTPException(422, f"invalid scope entry: {exc}") from exc
    except svc.ConflictError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.delete("/scope/{scope_id}", status_code=204)
def delete_scope(
    scope_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> None:
    svc.delete_scope_entry(session, principal, _scope_entry(session, scope_id), emitter)


@router.post("/scope/check")
def scope_check(body: ScopeCheckIn, session: Session = Depends(get_session), _: Principal = Depends(viewer)) -> dict:
    """Explain a scope decision ("why is this in scope?") without creating anything."""
    return check_scope(session, body.target, body.program_id).to_dict()


@router.get("/programs/{ref}/targets")
def program_targets(
    ref: str,
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    kind: str = Query("host", description="host | url"),
    limit: int = Query(10000, le=100000),
) -> dict:
    """In-scope, scannable targets for a program, re-verified by the ScopeEngine server-side.

    Only assets whose program link is in_scope, that are not paused/retired, AND that still pass a
    fresh scope check are returned. Intended as the input list for an external tool (e.g. Nuclei);
    the scope guarantee stays on the platform so the external run cannot exceed approved scope.
    """
    from sqlalchemy import select as _select

    from app.models import Asset, ProgramAsset
    from app.scope.engine import ScopeEngine
    from app.scope.normalize import InvalidTarget, classify_target
    from app.scope.service import load_rules

    program = _program(session, ref)
    wanted: tuple[str, ...]
    if kind == "url":
        wanted = ("url",)
    elif kind == "host":
        wanted = ("domain", "subdomain", "ipv4", "ipv6")
    else:
        raise HTTPException(422, "kind must be 'host' or 'url'")

    engine = ScopeEngine(load_rules(session, program.id))
    rows = session.execute(
        _select(Asset.normalized_value, Asset.asset_type)
        .join(ProgramAsset, ProgramAsset.asset_id == Asset.id)
        .where(
            ProgramAsset.program_id == program.id,
            ProgramAsset.status == "in_scope",
            Asset.asset_type.in_(wanted),
            Asset.paused.is_(False),
            Asset.status.notin_(("retired", "blocked")),
        )
        .order_by(Asset.last_seen.desc())
        .limit(limit)
    ).all()

    targets, skipped = [], 0
    for value, _atype in rows:
        try:
            if engine.is_in_scope(classify_target(value), program.id).allowed:
                targets.append(value)
            else:
                skipped += 1
        except InvalidTarget:
            skipped += 1
    return {
        "program": program.slug,
        "kind": kind,
        "count": len(targets),
        "skipped_out_of_scope": skipped,
        "targets": targets,
    }
