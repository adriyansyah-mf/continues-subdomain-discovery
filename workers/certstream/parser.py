"""Pure parsing of CertStream messages (calidog certstream and certstream-server-go formats)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.scope.normalize import InvalidTarget, normalize_domain, normalize_wildcard


@dataclass(frozen=True)
class CertObservation:
    fingerprint: str  # identity used for the certificate asset (sha256 hex, else "sha1:<hex>")
    sha1: str | None
    sha256: str | None
    serial: str | None
    subject_cn: str | None
    subject_dn: str | None
    issuer_cn: str | None
    issuer_o: str | None
    issuer_dn: str | None
    not_before: str | None
    not_after: str | None
    domains: tuple[str, ...]  # normalized, non-wildcard names
    wildcards: tuple[str, ...]  # normalized "*.base" names
    invalid_names: tuple[str, ...] = field(default_factory=tuple)
    seen: str | None = None
    source_url: str | None = None
    source_name: str | None = None
    cert_index: int | None = None
    update_type: str | None = None


def _hex(v: Any) -> str | None:
    if not isinstance(v, str) or not v:
        return None
    return v.replace(":", "").lower()


def _epoch(v: Any) -> str | None:
    if isinstance(v, (int, float)) and v > 0:
        return datetime.fromtimestamp(v, UTC).isoformat().replace("+00:00", "Z")
    return None


def _names(leaf: dict[str, Any]) -> list[str]:
    names = list(leaf.get("all_domains") or [])
    cn = (leaf.get("subject") or {}).get("CN")
    if cn:
        names.append(cn)
    san = (leaf.get("extensions") or {}).get("subjectAltName") or ""
    for part in san.split(","):
        part = part.strip()
        if part.startswith("DNS:"):
            names.append(part[4:])
    return names


def parse_message(msg: Any) -> CertObservation | None:
    """Return an observation for certificate_update messages, None for anything else."""
    if not isinstance(msg, dict) or msg.get("message_type") != "certificate_update":
        return None
    data = msg.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    sha1 = _hex(leaf.get("sha1")) or _hex(leaf.get("fingerprint"))
    sha256 = _hex(leaf.get("sha256"))
    if not (sha1 or sha256):
        return None
    domains: set[str] = set()
    wildcards: set[str] = set()
    invalid: set[str] = set()
    for name in _names(leaf):
        if not isinstance(name, str):
            continue
        try:
            if name.startswith("*."):
                wildcards.add(normalize_wildcard(name))
            else:
                domains.add(normalize_domain(name))
        except InvalidTarget:
            invalid.add(name[:255])
    subject = leaf.get("subject") or {}
    issuer = leaf.get("issuer") or {}
    source = data.get("source") or {}
    return CertObservation(
        fingerprint=sha256 or f"sha1:{sha1}",
        sha1=sha1,
        sha256=sha256,
        serial=leaf.get("serial_number"),
        subject_cn=subject.get("CN"),
        subject_dn=subject.get("aggregated"),
        issuer_cn=issuer.get("CN"),
        issuer_o=issuer.get("O"),
        issuer_dn=issuer.get("aggregated"),
        not_before=_epoch(leaf.get("not_before")),
        not_after=_epoch(leaf.get("not_after")),
        domains=tuple(sorted(domains)),
        wildcards=tuple(sorted(wildcards)),
        invalid_names=tuple(sorted(invalid)),
        seen=_epoch(data.get("seen")),
        source_url=source.get("url"),
        source_name=source.get("name"),
        cert_index=data.get("cert_index") if isinstance(data.get("cert_index"), int) else None,
        update_type=data.get("update_type"),
    )
