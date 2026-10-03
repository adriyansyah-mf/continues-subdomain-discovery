"""Loads scope rules from PostgreSQL and evaluates targets, failing closed.

Any error while loading or evaluating scope produces a *blocked* decision with
reason ``SCOPE_UNAVAILABLE``; callers must never fall back to scanning.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Program, ScopeEntry
from app.models.enums import BlockReason
from app.scope.engine import ScopeDecision, ScopeEngine, ScopeRule
from app.scope.normalize import Target

log = logging.getLogger(__name__)


class ScopeUnavailableError(RuntimeError):
    pass


def load_rules(session: Session, program_id: uuid.UUID | str | None = None) -> list[ScopeRule]:
    stmt = (
        select(ScopeEntry, Program.name)
        .join(Program, Program.id == ScopeEntry.program_id)
        .where(ScopeEntry.active.is_(True), Program.deleted_at.is_(None))
    )
    if program_id is not None:
        stmt = stmt.where(ScopeEntry.program_id == uuid.UUID(str(program_id)))
    rules: list[ScopeRule] = []
    for entry, program_name in session.execute(stmt).all():
        try:
            rules.append(
                ScopeRule(
                    id=str(entry.id),
                    program_id=str(entry.program_id),
                    type=entry.type,
                    mode=entry.mode,
                    value=entry.normalized_value,
                    program_name=program_name,
                )
            )
        except Exception as exc:
            # A corrupt rule must not silently widen or narrow scope: refuse to evaluate.
            raise ScopeUnavailableError(f"scope entry {entry.id} could not be parsed: {exc}") from exc
    return rules


def _blocked(target: str | Target, reason: str) -> ScopeDecision:
    value = target.value if isinstance(target, Target) else str(target)
    return ScopeDecision(
        allowed=False,
        reason=f"{BlockReason.SCOPE_UNAVAILABLE}: {reason}",
        target=value,
        match_kind="none",
    )


def check_scope(session: Session, target: str | Target, program_id: uuid.UUID | str | None = None) -> ScopeDecision:
    """Fresh, fail-closed scope evaluation against the database."""
    try:
        engine = ScopeEngine(load_rules(session, program_id))
        return engine.is_in_scope(target, program_id)
    except Exception as exc:
        log.error("scope evaluation failed, failing closed", extra={"error": str(exc)})
        return _blocked(target, str(exc))


class CachedScopeEngine:
    """Short-TTL cache for high-volume passive sources (e.g. CertStream).

    If a refresh fails the cache is invalidated (not reused): evaluations then
    fail closed until PostgreSQL is reachable again.
    """

    def __init__(self, session_factory, ttl_seconds: float = 30.0):
        self._session_factory = session_factory
        self._ttl = ttl_seconds
        self._engine: ScopeEngine | None = None
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def _refresh(self) -> ScopeEngine | None:
        with self._lock:
            if self._engine is not None and time.monotonic() - self._loaded_at < self._ttl:
                return self._engine
            try:
                with self._session_factory() as session:
                    self._engine = ScopeEngine(load_rules(session))
                self._loaded_at = time.monotonic()
            except Exception as exc:
                log.error("scope cache refresh failed", extra={"error": str(exc)})
                self._engine = None
            return self._engine

    def is_in_scope(self, target: str | Target, program_id: str | None = None) -> ScopeDecision:
        engine = self._refresh()
        if engine is None:
            return _blocked(target, "scope rules could not be loaded")
        try:
            return engine.is_in_scope(target, program_id)
        except Exception as exc:
            return _blocked(target, str(exc))
