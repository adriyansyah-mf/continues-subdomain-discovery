"""FIRST EPSS scores: bulk import of the daily CSV (kept as an independent signal)."""

from __future__ import annotations

import csv
import gzip
import io
import logging
import re
from datetime import date
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter

log = logging.getLogger(__name__)
_META_RE = re.compile(r"model_version:([^,]+),score_date:(\d{4}-\d{2}-\d{2})")
MAX_BYTES = 100 * 1024 * 1024


def parse_epss(raw: bytes) -> tuple[str | None, date | None, list[tuple[str, float, float]]]:
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    stream = io.StringIO(data.decode("utf-8"))
    first = stream.readline()
    model, score_date = None, None
    m = _META_RE.search(first)
    if m:
        model, score_date = m.group(1), date.fromisoformat(m.group(2))
    else:
        stream.seek(0)
    rows: list[tuple[str, float, float]] = []
    for rec in csv.DictReader(stream):
        cve = (rec.get("cve") or "").strip().upper()
        try:
            score, pct = float(rec["epss"]), float(rec["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        if cve.startswith("CVE-") and 0 <= score <= 1 and 0 <= pct <= 1:
            rows.append((cve, score, pct))
    return model, score_date, rows


def sync_epss(
    session: Session, principal: Principal, *, url: str, emitter: EventEmitter | None = None, fetch=None
) -> dict[str, Any]:
    raw = (fetch or _download)(url)
    model, score_date, rows = parse_epss(raw)
    if not rows:
        raise ValueError("EPSS file contained no scores")
    conn = session.connection().connection.driver_connection  # psycopg connection for COPY
    if conn is None:
        raise RuntimeError("no database connection for EPSS bulk load")
    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE epss_load (cve_id text, score float8, percentile float8) ON COMMIT DROP")
        with cur.copy("COPY epss_load (cve_id, score, percentile) FROM STDIN") as copy:
            for row in rows:
                copy.write_row(row)
    session.execute(
        text(
            "INSERT INTO epss_scores (cve_id, score, percentile, score_date, model_version, updated_at) "
            "SELECT cve_id, score, percentile, :d, :m, now() FROM epss_load "
            "ON CONFLICT (cve_id) DO UPDATE SET score = EXCLUDED.score, percentile = EXCLUDED.percentile, "
            "score_date = EXCLUDED.score_date, model_version = EXCLUDED.model_version, updated_at = now()"
        ),
        {"d": score_date, "m": model},
    )
    stats = {"scores": len(rows), "score_date": str(score_date) if score_date else None, "model_version": model}
    record_audit(session, principal, "sync.epss", target_type="epss", details=stats, emitter=emitter)
    return stats


def _download(url: str) -> bytes:
    with httpx.Client(timeout=120, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        if len(r.content) > MAX_BYTES:
            raise ValueError("EPSS file too large")
        return r.content
