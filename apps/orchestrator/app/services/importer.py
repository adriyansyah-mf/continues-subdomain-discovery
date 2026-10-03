"""bounty-targets-data importer.

domains.txt is a flat list without program attribution, so all entries are
imported into a single aggregate program (slug ``bounty-targets-data``) that is
created **inactive** with the ``passive`` default policy: importing public
bounty scope is not the same as accepting each program's terms, so an operator
must explicitly activate (and ideally split) it before any active scanning.

Each import records source, URL, content hash and timestamps, and is diffed
against the previous import: new values become scope entries, values that
disappeared deactivate their scope entry (never deleted), unchanged values are
touched (last_seen).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy import func, literal_column, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import Asset, ImportRun, ScopeEntry, SourceRecord
from app.models.enums import ScopeMode, ScopeType
from app.scope.normalize import InvalidTarget, classify_target, normalize_domain, normalize_ip, normalize_wildcard
from app.services.assets import asset_type_for, confidence_for
from app.services.audit import Principal, record_audit
from app.services.events import EventContext, EventEmitter, build_event
from app.services.programs import NotFoundError, create_program, get_program
from app.utils.time import utcnow

log = logging.getLogger(__name__)

SOURCE = "bounty-targets-data"
PROGRAM_SLUG = "bounty-targets-data"
MAX_BYTES = 50 * 1024 * 1024


@dataclass
class ParsedList:
    entries: dict[str, ScopeType] = field(default_factory=dict)  # normalized value -> type
    rejected: list[tuple[str, str]] = field(default_factory=list)


def parse_domains(text: str) -> ParsedList:
    """Validate, normalize and deduplicate. Unsupported/ambiguous lines are rejected, not guessed."""
    out = ParsedList()
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            if raw.startswith("*."):
                out.entries[normalize_wildcard(raw)] = ScopeType.WILDCARD
                continue
            try:
                ip = normalize_ip(raw)
                out.entries[str(ip)] = ScopeType.IPV4 if ip.version == 4 else ScopeType.IPV6
                continue
            except InvalidTarget:
                pass
            out.entries[normalize_domain(raw)] = ScopeType.DOMAIN
        except InvalidTarget as exc:
            out.rejected.append((raw, str(exc)))
    return out


def _chunks(items: Sequence[str], size: int) -> Iterator[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def download(url: str) -> bytes:
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        if len(resp.content) > MAX_BYTES:
            raise ValueError("bounty-targets file too large")
        return resp.content


def import_bounty_targets(
    session: Session,
    principal: Principal,
    *,
    url: str,
    content: bytes | None = None,
    emitter: EventEmitter | None = None,
    create_assets: bool = True,
) -> dict:
    data = content if content is not None else download(url)
    source_hash = hashlib.sha256(data).hexdigest()
    parsed = parse_domains(data.decode("utf-8", errors="replace"))

    try:
        program = get_program(session, PROGRAM_SLUG)
    except NotFoundError:
        program = create_program(
            session,
            principal,
            name="bounty-targets-data (aggregate)",
            slug=PROGRAM_SLUG,
            platform="bounty-targets-data",
            active=False,
            default_policy="passive",
            description="Aggregate import of arkadiyt/bounty-targets-data. Inactive by default: review the "
            "originating program's rules before activating active scanning.",
            emitter=emitter,
        )

    last = session.execute(
        select(ImportRun).where(ImportRun.source == SOURCE).order_by(ImportRun.imported_at.desc()).limit(1)
    ).scalar_one_or_none()
    run = ImportRun(source=SOURCE, source_url=url, source_hash=source_hash, stats={})
    session.add(run)
    session.flush()
    now = utcnow()

    if last is not None and last.source_hash == source_hash:
        stats: dict[str, Any] = {
            "unchanged_file": True,
            "entries": len(parsed.entries),
            "added": 0,
            "removed": 0,
            "rejected": len(parsed.rejected),
        }
        session.execute(
            update(SourceRecord)
            .where(SourceRecord.source == SOURCE, SourceRecord.removed_at.is_(None))
            .values(last_seen=now, last_import_id=run.id)
        )
        run.stats = stats
        record_audit(
            session,
            principal,
            "import.bounty_targets",
            target_type="import_run",
            target_id=run.id,
            program_id=program.id,
            details=stats,
            emitter=emitter,
        )
        return {"program_id": str(program.id), "import_id": str(run.id), "source_hash": source_hash, **stats}

    existing = {
        r.value: r for r in session.execute(select(SourceRecord).where(SourceRecord.source == SOURCE)).scalars()
    }
    current = set(parsed.entries)
    previous_live = {v for v, r in existing.items() if r.removed_at is None}
    added = current - previous_live
    removed = previous_live - current
    unchanged = current & previous_live

    events = []
    ctx = EventContext(program_id=str(program.id), program_name=program.name, source_name=SOURCE, source_type="import")
    added_sorted = sorted(added)
    entry_ids: dict[str, uuid.UUID] = {}
    rows: list[dict[str, Any]]
    for chunk in _chunks(added_sorted, 1000):
        rows = [
            {
                "id": uuid.uuid4(),
                "program_id": program.id,
                "type": parsed.entries[v].value,
                "value": v,
                "normalized_value": v,
                "mode": ScopeMode.INCLUDE.value,
                "source": SOURCE,
                "active": True,
            }
            for v in chunk
        ]
        scope_stmt = insert(ScopeEntry).values(rows)
        scope_ret = scope_stmt.on_conflict_do_update(
            index_elements=["program_id", "type", "normalized_value", "mode"],
            set_={"active": True, "updated_at": func.now()},
        ).returning(ScopeEntry.id, ScopeEntry.normalized_value)
        entry_ids.update({r.normalized_value: r.id for r in session.execute(scope_ret)})

    for chunk in _chunks(added_sorted, 1000):
        rows = [
            {
                "id": uuid.uuid4(),
                "source": SOURCE,
                "value": v,
                "scope_entry_id": entry_ids.get(v),
                "first_seen": now,
                "last_seen": now,
                "last_import_id": run.id,
                "removed_at": None,
            }
            for v in chunk
        ]
        stmt = insert(SourceRecord).values(rows)
        stmt = stmt.on_conflict_do_update(
            index_elements=["source", "value"],
            set_={
                "removed_at": None,
                "last_seen": now,
                "last_import_id": run.id,
                "scope_entry_id": stmt.excluded.scope_entry_id,
            },
        )
        session.execute(stmt)

    if create_assets:
        conf = confidence_for(SOURCE, "listed in bounty-targets-data domains.txt")
        domains = [v for v in added_sorted if parsed.entries[v] is ScopeType.DOMAIN]
        for chunk in _chunks(domains, 1000):
            rows = []
            for v in chunk:
                t = classify_target(v)
                rows.append(
                    {
                        "id": uuid.uuid4(),
                        "canonical_value": v,
                        "normalized_value": v,
                        "asset_type": asset_type_for(t).value,
                        "status": "discovered",
                        "lifecycle_stage": "DISCOVERED",
                        "first_seen": now,
                        "last_seen": now,
                        "confidence_score": conf.score,
                        "confidence_source": conf.source,
                        "confidence_reason": conf.reason,
                        "tags": [],
                        "paused": False,
                    }
                )
            asset_stmt = insert(Asset).values(rows)
            asset_ret: Any = asset_stmt.on_conflict_do_update(
                index_elements=["asset_type", "normalized_value"], set_={"last_seen": now}
            ).returning(
                Asset.id, Asset.asset_type, Asset.normalized_value, literal_column("(xmax = 0)").label("inserted")
            )
            for r in session.execute(asset_ret):
                if not r.inserted:
                    continue
                events.append(
                    build_event(
                        index="bb-assets",
                        kind="event",
                        category="asset",
                        type_="NEW_DOMAIN" if r.asset_type == "domain" else "NEW_SUBDOMAIN",
                        ctx=ctx.with_asset(str(r.id), r.asset_type, r.normalized_value),
                        body={
                            "asset": {"first_seen": now.isoformat(), "status": "discovered"},
                            "confidence": {"score": conf.score, "source": SOURCE, "reason": conf.reason},
                        },
                        doc_id=str(r.id),
                    )
                )
    for value in removed:
        rec = existing[value]
        rec.removed_at = now
        if rec.scope_entry_id:
            entry = session.get(ScopeEntry, rec.scope_entry_id)
            if entry is not None and entry.source == SOURCE:
                entry.active = False
    if unchanged:
        session.execute(
            update(SourceRecord)
            .where(SourceRecord.source == SOURCE, SourceRecord.value.in_(list(unchanged)))
            .values(last_seen=now, last_import_id=run.id)
        )
    stats = {
        "unchanged_file": False,
        "entries": len(current),
        "added": len(added),
        "removed": len(removed),
        "unchanged": len(unchanged),
        "rejected": len(parsed.rejected),
        "rejected_sample": [f"{v}: {r}" for v, r in parsed.rejected[:20]],
    }
    run.stats = stats
    session.flush()
    record_audit(
        session,
        principal,
        "import.bounty_targets",
        target_type="import_run",
        target_id=run.id,
        program_id=program.id,
        details={k: v for k, v in stats.items() if k != "rejected_sample"},
        emitter=emitter,
    )
    if emitter is not None and events:
        try:
            for i in range(0, len(events), 1000):
                emitter.emit_many("assets", events[i : i + 1000])
        except Exception as exc:
            log.warning("asset event emission failed", extra={"error": str(exc)})
    return {"program_id": str(program.id), "import_id": str(run.id), "source_hash": source_hash, **stats}
