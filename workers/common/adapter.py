"""Scanner adapter interface.

A scanner worker = one ScannerAdapter + the generic WorkerRunner. Adapters are
split in two phases so tool execution never holds a database transaction and
parsing can be unit-tested against recorded output:

  execute(ctx)                -> RawOutput      (runs the tool; no DB access)
  process(session, ctx, raw)  -> ScanOutcome    (normalize, layer-3 scope check,
                                                 assets/graph/state, build events)

Replacing a tool (e.g. httpx) means writing another adapter with the same
``name``; the orchestrator, queue and event pipeline do not change.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.schemas.policy import ScannerSettings
from app.scope.normalize import Target
from app.services.events import EventContext
from workers.common.scope_guard import ScopeGuard


@dataclass
class JobContext:
    job_id: str
    scan_id: str | None
    program_id: str
    program_name: str
    asset_id: str | None
    scope_id: str | None
    target: Target
    settings: ScannerSettings
    guard: ScopeGuard
    event_ctx: EventContext
    deadline_seconds: float
    is_cancelled: Callable[[], bool]
    policy_id: str | None = None


@dataclass
class RawOutput:
    records: list[Any] = field(default_factory=list)  # parsed JSON objects (or dicts built by the adapter)
    malformed: list[str] = field(default_factory=list)  # lines that were not valid JSON
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanOutcome:
    events: dict[str, list[dict]] = field(default_factory=dict)  # pipeline -> events
    summary: dict[str, Any] = field(default_factory=dict)
    # Follow-up jobs created inside process(); the runner enqueues them only after commit.
    followup_job_ids: list[Any] = field(default_factory=list)

    def add(self, pipeline: str, *events: dict) -> None:
        self.events.setdefault(pipeline, []).extend(events)


class NonRetryableError(RuntimeError):
    """Configuration/permanent errors (e.g. missing API key): fail immediately, do not retry."""


class ScannerAdapter(abc.ABC):
    name: str  # scanner name == registry key
    queue: str
    tool: str
    # Whether the tool connects to the target. If so, the runner resolves and pins the
    # target's addresses (and refuses private/reserved ones that are not explicitly in scope).
    contacts_target: bool = True

    @abc.abstractmethod
    def tool_version(self) -> str: ...

    @abc.abstractmethod
    def execute(self, ctx: JobContext) -> RawOutput: ...

    @abc.abstractmethod
    def process(self, session, ctx: JobContext, raw: RawOutput) -> ScanOutcome: ...
