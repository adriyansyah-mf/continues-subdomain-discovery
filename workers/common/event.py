"""Event helpers for workers (thin layer over the unified schema in app.services.events)."""

from __future__ import annotations

from typing import Any

from app.services.events import EventContext, build_event
from app.utils.time import utcnow


def raw_event(index: str, ctx: EventContext, raw: dict[str, Any] | str, *, malformed: bool = False) -> dict:
    """Raw scanner output is preserved verbatim (flattened field) for future re-parsing."""
    body: dict[str, Any] = {"raw": raw if isinstance(raw, dict) else {"line": raw}}
    if malformed:
        body["error"] = {"type": "MALFORMED_SCANNER_OUTPUT"}
    return build_event(index=index, kind="event", category="raw", type_="RAW_OUTPUT", ctx=ctx, body=body)


def error_event(ctx: EventContext, error_type: str, message: str, **extra: Any) -> dict:
    return build_event(
        index="bb-errors",
        kind="event",
        category="error",
        type_=error_type,
        ctx=ctx,
        timestamp=utcnow(),
        body={"error": {"type": error_type, "message": message[:4000], **extra}},
    )


def snapshot_event(ctx: EventContext, facets: dict[str, Any]) -> dict:
    """Point-in-time asset snapshot (history is never overwritten: one doc per observation)."""
    return build_event(
        index="bb-assets", kind="state", category="asset", type_="ASSET_SNAPSHOT", ctx=ctx, body={"snapshot": facets}
    )
