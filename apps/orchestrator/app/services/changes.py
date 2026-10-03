"""Change detection: pure diff functions over successive observations.

Each diff takes the previous and current *state dict* for one facet of an asset
and returns a list of Change records. Persistence of the latest state happens in
``assets.swap_state``; history lives in Elasticsearch (bb-changes-*, snapshots).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.services.events import EventContext, build_event


@dataclass(frozen=True)
class Change:
    change_type: str
    field: str
    previous: Any
    current: Any


def _as_set(v: Any) -> set:
    return set(v or [])


DNS_RECORD_CHANGE = {
    "A": "A_CHANGED",
    "AAAA": "AAAA_CHANGED",
    "CNAME": "CNAME_CHANGED",
    "MX": "MX_CHANGED",
    "NS": "NS_CHANGED",
    "TXT": "DNS_CHANGED",
}


def diff_dns(prev: dict[str, Any] | None, cur: dict[str, Any]) -> list[Change]:
    """State shape: {"A": [...], "AAAA": [...], "CNAME": [...], ...} (sorted lists)."""
    if prev is None:
        return []
    changes: list[Change] = []
    for rtype, change_type in DNS_RECORD_CHANGE.items():
        p, c = sorted(_as_set(prev.get(rtype))), sorted(_as_set(cur.get(rtype)))
        if p != c:
            changes.append(Change(change_type, f"dns.{rtype.lower()}", p, c))
    if changes:
        changes.insert(0, Change("DNS_CHANGED", "dns", prev, cur))
    if (
        "asn" in prev
        and prev.get("asn")
        and cur.get("asn")
        and sorted(_as_set(prev["asn"])) != sorted(_as_set(cur["asn"]))
    ):
        changes.append(Change("ASN_CHANGED", "asn.number", sorted(_as_set(prev["asn"])), sorted(_as_set(cur["asn"]))))
    if "cloud" in prev and sorted(_as_set(prev.get("cloud"))) != sorted(_as_set(cur.get("cloud"))):
        changes.append(
            Change(
                "CLOUD_PROVIDER_CHANGED",
                "cloud.provider",
                sorted(_as_set(prev.get("cloud"))),
                sorted(_as_set(cur.get("cloud"))),
            )
        )
    ips_prev = _as_set(prev.get("A")) | _as_set(prev.get("AAAA"))
    ips_cur = _as_set(cur.get("A")) | _as_set(cur.get("AAAA"))
    if ips_prev and ips_cur and ips_prev != ips_cur:
        changes.append(Change("IP_CHANGED", "dns.ips", sorted(ips_prev), sorted(ips_cur)))
    return changes


def diff_http(prev: dict[str, Any] | None, cur: dict[str, Any]) -> list[Change]:
    """State shape (per URL/port facet): status_code, title, webserver, technologies, ip, cdn."""
    if prev is None:
        return []
    changes: list[Change] = []
    if prev.get("status_code") != cur.get("status_code"):
        changes.append(
            Change("HTTP_STATUS_CHANGED", "http.status_code", prev.get("status_code"), cur.get("status_code"))
        )
    if (prev.get("title") or "") != (cur.get("title") or ""):
        changes.append(Change("TITLE_CHANGED", "http.title", prev.get("title"), cur.get("title")))
    if (prev.get("webserver") or "") != (cur.get("webserver") or ""):
        changes.append(Change("TECHNOLOGY_CHANGED", "http.webserver", prev.get("webserver"), cur.get("webserver")))
    tp, tc = _as_set(prev.get("technologies")), _as_set(cur.get("technologies"))
    for added in sorted(tc - tp):
        changes.append(Change("TECHNOLOGY_ADDED", "technology.name", None, added))
    for removed in sorted(tp - tc):
        changes.append(Change("TECHNOLOGY_REMOVED", "technology.name", removed, None))
    if prev.get("ip") and cur.get("ip") and prev.get("ip") != cur.get("ip"):
        changes.append(Change("IP_CHANGED", "host.ip", prev.get("ip"), cur.get("ip")))
    if (prev.get("cdn") or None) != (cur.get("cdn") or None):
        changes.append(Change("CLOUD_PROVIDER_CHANGED", "http.cdn", prev.get("cdn"), cur.get("cdn")))
    if "asn" in prev and prev.get("asn") and cur.get("asn") and prev.get("asn") != cur.get("asn"):
        changes.append(Change("ASN_CHANGED", "asn.number", prev.get("asn"), cur.get("asn")))
    if "cloud" in prev and (prev.get("cloud") or None) != (cur.get("cloud") or None):
        changes.append(Change("CLOUD_PROVIDER_CHANGED", "cloud.provider", prev.get("cloud"), cur.get("cloud")))
    return changes


EXPIRY_CHANGE = {"expiring": "CERT_EXPIRING", "expired": "CERTIFICATE_EXPIRED"}


def diff_tls(prev: dict[str, Any] | None, cur: dict[str, Any]) -> list[Change]:
    """State shape: fingerprint, issuer, san, tls_version, not_after, expiry_status.

    Expiry alerts fire when the expiry status changes (including on the first
    observation of an already expiring/expired certificate), not on every scan.
    """
    changes: list[Change] = []
    prev_expiry = (prev or {}).get("expiry_status")
    if cur.get("expiry_status") in EXPIRY_CHANGE and cur.get("expiry_status") != prev_expiry:
        changes.append(Change(EXPIRY_CHANGE[cur["expiry_status"]], "tls.not_after", prev_expiry, cur.get("not_after")))
    if prev is None:
        return changes
    if prev.get("fingerprint") != cur.get("fingerprint"):
        changes.append(Change("CERT_CHANGED", "tls.fingerprint", prev.get("fingerprint"), cur.get("fingerprint")))
        changes.append(
            Change("FINGERPRINT_CHANGED", "tls.fingerprint", prev.get("fingerprint"), cur.get("fingerprint"))
        )
    if prev.get("issuer") != cur.get("issuer"):
        changes.append(Change("ISSUER_CHANGED", "tls.issuer", prev.get("issuer"), cur.get("issuer")))
    if sorted(_as_set(prev.get("san"))) != sorted(_as_set(cur.get("san"))):
        changes.append(
            Change("SAN_CHANGED", "tls.san", sorted(_as_set(prev.get("san"))), sorted(_as_set(cur.get("san"))))
        )
    if prev.get("tls_version") != cur.get("tls_version"):
        changes.append(Change("TLS_VERSION_CHANGED", "tls.version", prev.get("tls_version"), cur.get("tls_version")))
    if any(c.change_type not in EXPIRY_CHANGE.values() for c in changes):
        changes.insert(0, Change("TLS_CHANGED", "tls", None, None))
    return changes


def diff_ports(prev: dict[str, Any] | None, cur: dict[str, Any]) -> list[Change]:
    if prev is None:
        return []
    p, c = _as_set(prev.get("ports")), _as_set(cur.get("ports"))
    out = [Change("NEW_PORT", "network.port", None, port) for port in sorted(c - p)]
    out += [Change("PORT_REMOVED", "network.port", port, None) for port in sorted(p - c)]
    return out


def change_event(
    change: Change,
    ctx: EventContext,
    *,
    confidence: float | None,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    return build_event(
        index="bb-changes",
        kind="event",
        category="change",
        type_=change.change_type,
        ctx=ctx,
        timestamp=timestamp,
        body={
            "change": {
                "type": change.change_type,
                "field": change.field,
                "previous": _jsonable(change.previous),
                "current": _jsonable(change.current),
            },
            "confidence": {"score": confidence, "source": ctx.source_name},
        },
    )


def _jsonable(v: Any) -> Any:
    # Store as text so the ES mapping stays stable regardless of the changed field's type.
    if v is None:
        return None
    if isinstance(v, (list, tuple, set)):
        return [str(x) for x in v]
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True, default=str)
    return str(v)
