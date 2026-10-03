"""IP -> ASN enrichment from the public iptoasn.com dataset (combined IPv4 + IPv6 TSV).

Stored in PostgreSQL (`asn_ranges`), refreshed daily (ASN_SYNC_INTERVAL) or with
`bbctl sync asn`. Enrichment only: an ASN never authorises scanning an IP.
"""

from __future__ import annotations

import gzip
import ipaddress
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import session_scope
from app.models.enums import RelationshipType
from app.scope.normalize import Target
from app.services.assets import confidence_for, upsert_asset, upsert_relationship
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter

log = logging.getLogger(__name__)
MAX_BYTES = 200 * 1024 * 1024


@dataclass(frozen=True)
class AsnInfo:
    number: int
    organization: str | None
    country: str | None

    def to_event(self) -> dict[str, Any]:
        return {"number": self.number, "organization": self.organization, "country": self.country, "source": "iptoasn"}


def parse_tsv(raw: bytes) -> list[tuple[str, str, int, str | None, str | None]]:
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    rows = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        start, end, asn, country, org = parts[:5]
        try:
            a = int(asn)
            s_ip, e_ip = ipaddress.ip_address(start), ipaddress.ip_address(end)
        except ValueError:
            continue
        if a <= 0 or s_ip.version != e_ip.version or int(e_ip) < int(s_ip):
            continue  # "Not routed" / malformed
        rows.append((str(s_ip), str(e_ip), a, None if country in ("", "None") else country[:8], org[:256] or None))
    return rows


def sync_asn(
    session: Session, principal: Principal, *, url: str, emitter: EventEmitter | None = None, fetch=None
) -> dict[str, Any]:
    raw = (fetch or _download)(url)
    rows = parse_tsv(raw)
    if len(rows) < 1000:
        raise ValueError(f"ASN dataset looks truncated ({len(rows)} rows); keeping the current data")
    conn = session.connection().connection.driver_connection
    if conn is None:
        raise RuntimeError("no database connection for ASN bulk load")
    with conn.cursor() as cur:
        cur.execute(
            "CREATE TEMP TABLE asn_load (start_ip inet, end_ip inet, asn bigint, country text, "
            "organization text) ON COMMIT DROP"
        )
        with cur.copy("COPY asn_load FROM STDIN") as copy:
            for r in rows:
                copy.write_row(r)
    # Atomic swap inside the transaction: readers never see an empty table.
    session.execute(text("DELETE FROM asn_ranges"))
    session.execute(text("INSERT INTO asn_ranges SELECT DISTINCT ON (start_ip) * FROM asn_load ORDER BY start_ip"))
    stats = {"ranges": len(rows), "asns": len({r[2] for r in rows})}
    record_audit(session, principal, "sync.asn", target_type="asn_ranges", details=stats, emitter=emitter)
    AsnLookup.invalidate()
    return stats


def _download(url: str) -> bytes:
    with httpx.Client(timeout=180, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        if len(r.content) > MAX_BYTES:
            raise ValueError("ASN dataset too large")
        return r.content


class AsnLookup:
    """Process-wide cached lookups (each IP answered from PostgreSQL once per TTL)."""

    _cache: dict[str, tuple[float, AsnInfo | None]] = {}
    _lock = threading.Lock()
    TTL = 3600.0
    MAX = 50_000

    @classmethod
    def lookup(cls, ip: str, session: Session | None = None) -> AsnInfo | None:
        try:
            addr = str(ipaddress.ip_address(ip))
        except ValueError:
            return None
        now = time.monotonic()
        with cls._lock:
            hit = cls._cache.get(addr)
            if hit and now - hit[0] < cls.TTL:
                return hit[1]
        try:
            if session is not None:
                info = cls._query(session, addr)
            else:
                with session_scope() as s:
                    info = cls._query(s, addr)
        except Exception as exc:  # enrichment only
            log.warning("ASN lookup failed", extra={"ip": addr, "error": str(exc)})
            return None
        with cls._lock:
            if len(cls._cache) >= cls.MAX:
                cls._cache.clear()
            cls._cache[addr] = (now, info)
        return info

    @staticmethod
    def _query(session: Session, addr: str) -> AsnInfo | None:
        row = session.execute(
            text(
                "SELECT asn, organization, country, end_ip FROM asn_ranges "
                "WHERE start_ip <= CAST(:ip AS inet) AND family(start_ip) = family(CAST(:ip AS inet)) "
                "ORDER BY start_ip DESC LIMIT 1"
            ),
            {"ip": addr},
        ).first()
        if row is None or int(ipaddress.ip_address(addr)) > int(ipaddress.ip_address(str(row.end_ip))):
            return None
        return AsnInfo(int(row.asn), row.organization, row.country)

    @classmethod
    def invalidate(cls) -> None:
        with cls._lock:
            cls._cache.clear()


def enrich_ip_asset(session: Session, ip_asset: Any, ip: str, *, source: str) -> AsnInfo | None:
    """Attach ASN to an IP asset: ASN asset + BELONGS_TO_ASN edge. Returns the info for events."""
    info = AsnLookup.lookup(ip, session)
    if info is None:
        return None
    asn_asset, _ = upsert_asset(
        session,
        Target(kind="asn", value=f"AS{info.number}", asn=info.number),
        confidence=confidence_for("ipranges", "iptoasn.com routing data"),
    )
    upsert_relationship(
        session,
        ip_asset.id,
        asn_asset.id,
        RelationshipType.BELONGS_TO_ASN.value,
        source="iptoasn",
        confidence=0.9,
        metadata={"organization": info.organization, "country": info.country},
    )
    return info
