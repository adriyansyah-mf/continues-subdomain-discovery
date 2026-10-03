"""Unified event schema and the emitter that hands events to Logstash.

Transport: every event is RPUSHed (JSON) onto a Redis list ``bb:events:<pipeline>``.
Each Logstash pipeline consumes exactly one list, validates the event and routes
it to ``<bb.index>-YYYY.MM``. Redis therefore also buffers events while Logstash
or Elasticsearch are down (bounded by MAX_EVENT_BACKLOG) instead of losing them.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, cast

import redis

from app.utils.time import iso

EVENTS_KEY_PREFIX = "bb:events:"
NOTIFY_KEY = "bb:notify"  # notifiable events, consumed by the notifier service
NOTIFY_MAX_BACKLOG = 100_000
SCHEMA_VERSION = "1"

# pipeline -> logical indices it may write. Must match logstash/pipelines/*.conf.
PIPELINE_INDICES: dict[str, frozenset[str]] = {
    "assets": frozenset({"bb-assets", "bb-domains", "bb-ips", "bb-urls", "bb-uncover", "bb-uncover-raw"}),
    "certstream": frozenset({"bb-certstream"}),
    "tlsx": frozenset({"bb-tls", "bb-tlsx-raw"}),
    "httpx": frozenset({"bb-http", "bb-httpx-raw"}),
    "dns": frozenset({"bb-dns"}),
    "katana": frozenset({"bb-katana", "bb-katana-raw", "bb-urls"}),
    "nuclei": frozenset({"bb-nuclei", "bb-nuclei-raw"}),
    "bbot": frozenset({"bb-bbot", "bb-bbot-raw"}),
    "cve": frozenset({"bb-cve", "bb-kev"}),
    "changes": frozenset({"bb-changes"}),
    "ops": frozenset({"bb-scans", "bb-jobs", "bb-errors", "bb-audit", "bb-notifications"}),
}


class EventBacklogFullError(RuntimeError):
    """Raised when Logstash has fallen too far behind; callers should retry later."""


@dataclass(frozen=True)
class EventContext:
    """Provenance attached to every event (program -> scope -> asset -> scan -> tool)."""

    program_id: str | None = None
    program_name: str | None = None
    scope_id: str | None = None
    scope_status: str | None = None  # "in" | "out" | "excluded"
    asset_id: str | None = None
    asset_type: str | None = None
    asset_value: str | None = None
    scan_id: str | None = None
    job_id: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    template_version: str | None = None
    config_hash: str | None = None
    source_name: str | None = None
    source_type: str | None = None  # passive | active | import | system | manual
    extra_labels: dict[str, str] = field(default_factory=dict)

    def with_asset(self, asset_id: str | None, asset_type: str | None, value: str | None) -> EventContext:
        return replace(self, asset_id=asset_id, asset_type=asset_type, asset_value=value)


def _drop_none(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


def build_event(
    *,
    index: str,
    kind: str,
    category: str,
    type_: str,
    ctx: EventContext,
    body: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
    doc_id: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "@timestamp": iso(timestamp),
        "event": {"kind": kind, "category": category, "type": type_, "action": type_},
        "bb": _drop_none({"index": index, "doc_id": doc_id, "schema_version": SCHEMA_VERSION}),
    }
    program = _drop_none({"id": ctx.program_id, "name": ctx.program_name})
    if program:
        event["program"] = program
    scope = _drop_none({"id": ctx.scope_id, "status": ctx.scope_status})
    if scope:
        event["scope"] = scope
    asset = _drop_none({"id": ctx.asset_id, "type": ctx.asset_type, "value": ctx.asset_value})
    if asset:
        event["asset"] = asset
    scan = _drop_none(
        {
            "id": ctx.scan_id,
            "job_id": ctx.job_id,
            "tool": ctx.tool,
            "tool_version": ctx.tool_version,
            "template_version": ctx.template_version,
            "config_hash": ctx.config_hash,
        }
    )
    if scan:
        event["scan"] = scan
    source = _drop_none({"name": ctx.source_name, "type": ctx.source_type})
    if source:
        event["source"] = source
    if ctx.extra_labels:
        event["labels"] = dict(ctx.extra_labels)
    for key, value in (body or {}).items():
        if key in event and isinstance(event[key], dict) and isinstance(value, dict):
            event[key] = {**event[key], **value}
        else:
            event[key] = value
    return event


class EventEmitter:
    def __init__(self, client: redis.Redis, max_backlog: int = 500_000):
        self._redis = client
        self._max_backlog = max_backlog

    def emit(self, pipeline: str, event: dict[str, Any]) -> None:
        self.emit_many(pipeline, [event])

    def emit_many(self, pipeline: str, events: list[dict[str, Any]]) -> None:
        if not events:
            return
        allowed = PIPELINE_INDICES.get(pipeline)
        if allowed is None:
            raise ValueError(f"unknown event pipeline {pipeline!r}")
        for ev in events:
            if ev.get("bb", {}).get("index") not in allowed:
                raise ValueError(f"index {ev.get('bb', {}).get('index')!r} not allowed on pipeline {pipeline}")
        key = EVENTS_KEY_PREFIX + pipeline
        if cast(int, self._redis.llen(key)) >= self._max_backlog:
            raise EventBacklogFullError(f"event backlog for {pipeline} exceeds {self._max_backlog}")
        payload = [json.dumps(ev, default=str, separators=(",", ":")) for ev in events]
        self._redis.rpush(key, *payload)
        self._tap_notifications(events)

    def _tap_notifications(self, events: list[dict[str, Any]]) -> None:
        """Copy notifiable events (compact form) for the notifier. Best effort: never blocks ingestion."""
        from app.services.notify.catalog import from_event

        items = []
        for ev in events:
            n = from_event(ev)
            if n is not None:
                items.append(json.dumps(n.to_dict(), separators=(",", ":")))
        if not items:
            return
        try:
            pipe = self._redis.pipeline()
            pipe.lpush(NOTIFY_KEY, *items)
            pipe.ltrim(NOTIFY_KEY, 0, NOTIFY_MAX_BACKLOG - 1)  # bounded: oldest notifications are dropped
            pipe.execute()
        except Exception as exc:  # notifications must never break event ingestion
            logging.getLogger(__name__).warning("notification tap failed", extra={"error": str(exc)})
