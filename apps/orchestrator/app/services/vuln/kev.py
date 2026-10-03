"""CISA Known Exploited Vulnerabilities catalogue: sync + diff (KEV_ADDED/UPDATED/REMOVED)."""

from __future__ import annotations

import logging
from datetime import date
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import KevEntry
from app.services.audit import Principal, record_audit
from app.services.events import EventContext, EventEmitter, build_event
from app.utils.hashing import stable_hash
from app.utils.time import utcnow

log = logging.getLogger(__name__)
SOURCE = "cisa-kev"
MAX_BYTES = 50 * 1024 * 1024


def _date(v: Any) -> date | None:
    try:
        return date.fromisoformat(str(v)) if v else None
    except ValueError:
        return None


def parse_catalog(doc: dict[str, Any]) -> tuple[str | None, dict[str, dict[str, Any]]]:
    """Return (catalogVersion, {cve_id: normalized entry}); invalid rows are skipped."""
    out: dict[str, dict[str, Any]] = {}
    for v in doc.get("vulnerabilities") or []:
        cve = str(v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        entry = {
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "short_description": v.get("shortDescription"),
            "date_added": v.get("dateAdded"),
            "due_date": v.get("dueDate"),
            "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
            "required_action": v.get("requiredAction"),
            "notes": v.get("notes"),
            "cwes": [str(c) for c in v.get("cwes") or []],
        }
        out[cve] = entry
    return doc.get("catalogVersion"), out


def kev_doc(cve: str, e: dict[str, Any], event_type: str) -> dict:
    return build_event(
        index="bb-kev",
        kind="state",
        category="vulnerability",
        type_=event_type,
        ctx=EventContext(source_name=SOURCE, source_type="feed"),
        body={
            "cve": {"id": cve},
            "kev": {
                "vendor": e.get("vendor"),
                "product": e.get("product"),
                "name": e.get("vulnerability_name"),
                "date_added": e.get("date_added"),
                "due_date": e.get("due_date"),
                "known_ransomware_use": e.get("known_ransomware_use"),
                "required_action": e.get("required_action"),
                "in_catalog": event_type != "KEV_REMOVED",
            },
        },
        doc_id=cve,
    )


def sync_kev(
    session: Session, principal: Principal, *, url: str, emitter: EventEmitter | None = None, fetch=None
) -> dict[str, Any]:
    doc = (fetch or _download)(url)
    catalog_version, entries = parse_catalog(doc)
    if not entries:
        raise ValueError("KEV feed contained no vulnerabilities; refusing to treat it as a full removal")
    now = utcnow()
    existing = {k.cve_id: k for k in session.execute(select(KevEntry)).scalars()}
    baseline = not existing  # first import: no per-entry KEV_ADDED storm
    added, updated, removed, events = [], [], [], []
    for cve, e in entries.items():
        h = stable_hash(e)
        row = existing.get(cve)
        if row is None or row.removed_at is not None:
            if row is None:
                row = KevEntry(cve_id=cve, first_seen=now)
                session.add(row)
            added.append(cve)
            etype = "KEV_ADDED"
        elif row.content_hash != h:
            updated.append(cve)
            etype = "KEV_UPDATED"
        else:
            etype = None
        row.vendor, row.product = e["vendor"], e["product"]
        row.vulnerability_name, row.short_description = e["vulnerability_name"], e["short_description"]
        row.date_added, row.due_date = _date(e["date_added"]), _date(e["due_date"])
        row.known_ransomware_use, row.required_action = e["known_ransomware_use"], e["required_action"]
        row.notes, row.cwes, row.content_hash = e["notes"], e["cwes"], h
        row.catalog_version, row.last_seen, row.removed_at = catalog_version, now, None
        if baseline or etype:
            events.append(kev_doc(cve, e, "KEV_BASELINE" if baseline else str(etype)))
    for cve, row in existing.items():
        if cve not in entries and row.removed_at is None:
            row.removed_at = now
            removed.append(cve)
            events.append(
                kev_doc(
                    cve,
                    {"vendor": row.vendor, "product": row.product, "vulnerability_name": row.vulnerability_name},
                    "KEV_REMOVED",
                )
            )
    stats: dict[str, Any] = {
        "catalog_version": catalog_version,
        "entries": len(entries),
        "added": len(added),
        "updated": len(updated),
        "removed": len(removed),
        "baseline": baseline,
    }
    session.flush()
    record_audit(session, principal, "sync.kev", target_type="kev", details=stats, emitter=emitter)
    if emitter is not None:
        try:
            for i in range(0, len(events), 500):
                emitter.emit_many("cve", events[i : i + 500])
        except Exception as exc:
            log.warning("KEV event emission failed", extra={"error": str(exc)})
    stats["added_ids"] = added[:50]
    return stats


def _download(url: str) -> dict[str, Any]:
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        if len(r.content) > MAX_BYTES:
            raise ValueError("KEV feed too large")
        return r.json()
