"""Which platform events can notify, under which notification type and severity.

Events are emitted by every component through EventEmitter; the emitter "taps" the ones
listed here onto the ``bb:notify`` list consumed by the notifier service. Notification
types follow the platform spec; severities are fixed and documented (docs/notifications.md).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# internal event.type -> (notification type, severity)
EVENT_MAP: dict[str, tuple[str, str]] = {
    "NEW_DOMAIN": ("NEW_ASSET", "info"),
    "NEW_SUBDOMAIN": ("NEW_SUBDOMAIN", "info"),
    "NEW_IP": ("NEW_IP", "info"),
    "NEW_URL": ("NEW_ASSET", "info"),
    "CERT_EXPIRING": ("TLS_EXPIRING", "medium"),
    "CERTIFICATE_EXPIRED": ("TLS_EXPIRING", "high"),
    "TLS_CHANGED": ("TLS_CHANGED", "low"),
    "TECHNOLOGY_ADDED": ("TECHNOLOGY_CHANGED", "low"),
    "TECHNOLOGY_REMOVED": ("TECHNOLOGY_CHANGED", "low"),
    "NEW_CVE": ("NEW_CVE", "medium"),
    "KEV_ADDED": ("NEW_KEV", "critical"),
    "NEW_CRITICAL_FINDING": ("NEW_CRITICAL_FINDING", "critical"),
    "SCAN_FAILURE": ("SCAN_FAILURE", "low"),
    "DLQ_EVENT": ("DLQ_EVENT", "medium"),
}
NOTIFICATION_TYPES = sorted({v[0] for v in EVENT_MAP.values()} | {"TEST"})
TITLES = {
    "NEW_ASSET": "New asset",
    "NEW_SUBDOMAIN": "New subdomain",
    "NEW_IP": "New IP",
    "TLS_EXPIRING": "TLS expiring",
    "TLS_CHANGED": "TLS changed",
    "TECHNOLOGY_CHANGED": "Technology changed",
    "NEW_CVE": "New CVE",
    "NEW_KEV": "Known exploited vulnerability (KEV)",
    "NEW_CRITICAL_FINDING": "New critical finding",
    "SCAN_FAILURE": "Scan failure",
    "DLQ_EVENT": "Job dead-lettered",
}


@dataclass(frozen=True)
class Notification:
    type: str
    severity: str
    event_type: str
    program_id: str | None
    program_name: str | None
    asset_value: str | None
    title: str
    detail: str
    fact_key: str  # identifies the underlying fact (used for deduplication)
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _short(v: Any, n: int = 300) -> str:
    s = v if isinstance(v, str) else ", ".join(map(str, v)) if isinstance(v, list) else str(v)
    return s if len(s) <= n else s[: n - 1] + "…"


def from_event(event: dict[str, Any]) -> Notification | None:
    """Build a compact notification from a platform event (None if not notifiable)."""
    etype = (event.get("event") or {}).get("type")
    if etype not in EVENT_MAP:
        return None
    ntype, severity = EVENT_MAP[etype]
    program = event.get("program") or {}
    asset = event.get("asset") or {}
    change = event.get("change") or {}
    error = event.get("error") or {}
    value = asset.get("value")
    if etype in ("SCAN_FAILURE", "DLQ_EVENT"):
        detail = _short(error.get("message", ""))
        title = f"{TITLES[ntype]}: {(event.get('scan') or {}).get('tool', '?')} on {value or '?'}"
        fact = f"{etype}|{(event.get('scan') or {}).get('job_id')}|{error.get('retry_count')}"
    else:
        current = change.get("current")
        previous = change.get("previous")
        title = f"{TITLES[ntype]}: {value or _short(current, 120)}"
        if previous not in (None, "", []):
            detail = f"{etype}: {_short(previous)} -> {_short(current)}"
        elif current not in (None, "", []):
            detail = f"{etype}: {_short(current)}"
        else:  # summary markers such as TLS_CHANGED carry the specifics in sibling change events
            detail = f"{etype} detected on {value or 'asset'} (field-level changes in bb-changes-*)"
        fact = f"{etype}|{asset.get('id') or value}|{_short(current, 500)}"
    return Notification(
        type=ntype,
        severity=severity,
        event_type=etype,
        program_id=program.get("id"),
        program_name=program.get("name"),
        asset_value=value,
        title=title,
        detail=detail,
        fact_key=hashlib.sha256(fact.encode()).hexdigest(),
        timestamp=event.get("@timestamp"),
    )


def severity_at_least(severity: str, minimum: str | None) -> bool:
    if not minimum:
        return True
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 0)


def render_text(n: Notification) -> str:
    where = f"[{n.program_name}] " if n.program_name else ""
    return f"{where}{n.severity.upper()} {n.title}\n{n.detail}"
