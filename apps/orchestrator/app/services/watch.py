"""One-shot "watch this scope" setup: the simple flow a user actually wants.

Given a single scope value (e.g. ``*.ezviz.com``) this creates/reuses a program, adds the scope
(plus the apex, so discovery has a seed), kicks an immediate full pipeline, and installs an enabled
per-program monitor schedule so the scope is re-discovered and re-scanned on an interval forever.
Everything still goes through the normal ScopeEngine + policy checks — this only automates the
setup an operator would otherwise do by hand. Results land in Elasticsearch/Kibana as usual.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Program, ScanPolicy, Schedule
from app.schemas.policy import AUTO_POLICY_NAME
from app.scope.normalize import InvalidTarget, classify_target, normalize_domain, registrable_domain
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.services.programs import ConflictError, add_scope_entry, create_program, get_program, slugify
from app.services.scans import ScanPlan, ScanService

# Scanners the monitor runs per scope-value kind. The apex/host seeds discovery; subdomains that
# BBOT/CertStream find under the scope are picked up by the next cycle automatically.
AUTO_SCANNERS: dict[str, list[str]] = {
    "domain": ["bbot", "dns", "httpx", "tlsx", "katana", "nuclei"],
    "wildcard": ["bbot", "dns", "httpx", "tlsx", "katana", "nuclei"],
    "url": ["httpx", "tlsx", "katana", "nuclei"],
    "ipv4": ["dns", "httpx", "tlsx", "nuclei"],
    "ipv6": ["dns", "httpx", "tlsx", "nuclei"],
    "cidr": ["httpx", "tlsx", "nuclei"],
    "asn": [],  # an ASN is not directly scannable; recorded as scope only
}
DEFAULT_INTERVAL = 6 * 3600


class WatchError(ValueError):
    """Invalid watch request (bad scope value)."""


@dataclass
class WatchResult:
    program: Program
    scope_values: list[str] = field(default_factory=list)
    schedule: Schedule | None = None
    scanners: list[str] = field(default_factory=list)
    plan: ScanPlan | None = None
    reused_program: bool = False


def _auto_policy_id(session: Session) -> uuid.UUID:
    policy = session.execute(select(ScanPolicy).where(ScanPolicy.name == AUTO_POLICY_NAME)).scalar_one_or_none()
    if policy is None:  # seeded on startup; a fresh/again-seeded DB always has it
        raise WatchError(f"policy {AUTO_POLICY_NAME!r} missing (reseed required)")
    return policy.id


def watch_scope(
    session: Session,
    principal: Principal,
    *,
    value: str,
    name: str | None = None,
    interval_seconds: int = DEFAULT_INTERVAL,
    emitter: EventEmitter | None = None,
) -> WatchResult:
    try:
        target = classify_target(value)
    except InvalidTarget as exc:
        raise WatchError(str(exc)) from exc
    scanners = AUTO_SCANNERS.get(target.kind, [])

    # Naming + discovery seed. Wildcard/domain name after the registrable domain; the seed is the
    # apex so BBOT has something to enumerate from.
    apex: str | None = None
    if target.kind in ("wildcard", "domain"):
        base = normalize_domain(value[2:]) if target.kind == "wildcard" else target.value
        apex = registrable_domain(base) or base
        slug_src, display = apex, apex
    elif target.kind == "url" and target.url is not None:
        apex = registrable_domain(target.url.host) or target.url.host
        slug_src, display = apex, target.url.host
    else:
        slug_src, display = target.value, target.value

    slug = slugify(name or slug_src)
    policy_id = _auto_policy_id(session)

    existing = get_program(session, slug) if _program_exists(session, slug) else None
    if existing is not None:
        program, reused = existing, True
    else:
        program = create_program(
            session,
            principal,
            name=name or display,
            slug=slug,
            platform="watch",
            description=f"Auto-managed watch of {value}",
            active=True,
            default_policy=AUTO_POLICY_NAME,
            emitter=emitter,
        )
        reused = False

    scope_values: list[str] = []
    # The scope value itself, plus the apex domain for a wildcard (so the seed is in scope too).
    to_add = [(target.kind, target.value)]
    if target.kind == "wildcard" and apex:
        to_add.append(("domain", apex))
    for type_, val in to_add:
        try:
            add_scope_entry(
                session, principal, program, type_=type_, value=val, mode="include", source="watch", emitter=emitter
            )
            scope_values.append(val)
        except ConflictError:
            scope_values.append(val)  # already in scope: fine, keep going

    result = WatchResult(program=program, scope_values=scope_values, scanners=scanners, reused_program=reused)
    if not scanners:
        return result  # e.g. a bare ASN: scope recorded, nothing to scan yet

    result.schedule = _install_monitor(session, program, scanners, policy_id, interval_seconds)

    # Immediate first run so the user sees activity now, not only after one interval.
    seed = (apex or target.value) if target.kind == "wildcard" else target.value
    result.plan = ScanService(session, emitter=emitter).create_scan(
        principal=principal,
        program_id=program.id,
        scanners=scanners,
        targets=[seed],
        policy_id=policy_id,
        trigger="watch",
    )
    record_audit(
        session,
        principal,
        "watch.created",
        target_type="program",
        target_id=program.id,
        program_id=program.id,
        details={"value": value, "scanners": scanners, "interval_seconds": interval_seconds, "reused": reused},
        emitter=emitter,
    )
    return result


def _program_exists(session: Session, slug: str) -> bool:
    return session.execute(select(Program.id).where(Program.slug == slug)).scalar_one_or_none() is not None


def _install_monitor(
    session: Session, program: Program, scanners: list[str], policy_id: uuid.UUID, interval_seconds: int
) -> Schedule:
    """Enabled per-program monitor schedule; reused/updated if one already exists for this program."""
    from datetime import timedelta

    from app.utils.time import utcnow

    name = f"watch:{program.slug}"
    sched = session.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none()
    # Start the periodic cycle after one interval; the immediate scan below covers "now".
    nxt = utcnow() + timedelta(seconds=interval_seconds)
    if sched is None:
        sched = Schedule(
            name=name,
            scanner=scanners[0],
            scanners=scanners,
            program_id=program.id,
            policy_id=policy_id,
            interval_seconds=interval_seconds,
            enabled=True,
            next_run_at=nxt,
        )
        session.add(sched)
    else:
        sched.scanner, sched.scanners = scanners[0], scanners
        sched.program_id, sched.policy_id = program.id, policy_id
        sched.interval_seconds, sched.enabled, sched.next_run_at = interval_seconds, True, nxt
    session.flush()
    return sched


def watch_summary(r: WatchResult) -> dict[str, Any]:
    return {
        "program": r.program.slug,
        "reused_program": r.reused_program,
        "scope": r.scope_values,
        "scanners": r.scanners,
        "schedule": r.schedule.name if r.schedule else None,
        "interval_seconds": r.schedule.interval_seconds if r.schedule else None,
        "initial_scan": r.plan.summary() if r.plan else {},
    }
