"""Provider IP-range attribution from lord-alfred/ipranges.

Ranges are stored in PostgreSQL (`cloud_ranges`) with first/last seen and are used
only to *enrich* IP observations (``cloud.provider``) - they never become scope
and are never scanned unless an operator adds them to a program's CDB explicitly.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.database import session_scope
from app.models import CloudRange
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.utils.time import utcnow

log = logging.getLogger(__name__)

# provider directory -> (organization, category)
PROVIDERS: dict[str, tuple[str, str]] = {
    "amazon": ("Amazon Web Services", "cloud"),
    "google": ("Google Cloud", "cloud"),
    "microsoft": ("Microsoft Azure", "cloud"),
    "oracle": ("Oracle Cloud", "cloud"),
    "digitalocean": ("DigitalOcean", "cloud"),
    "linode": ("Akamai Linode", "cloud"),
    "vultr": ("Vultr", "cloud"),
    "cloudflare": ("Cloudflare", "cdn"),
    "github": ("GitHub", "service"),
    "facebook": ("Meta", "service"),
    "twitter": ("X / Twitter", "service"),
    "telegram": ("Telegram", "service"),
    "openai": ("OpenAI", "service"),
    "perplexity": ("Perplexity", "service"),
    "apple-proxy": ("Apple iCloud Private Relay", "service"),
    "protonvpn": ("Proton VPN", "service"),
    "bing": ("Microsoft Bingbot", "crawler"),
    "googlebot": ("Googlebot", "crawler"),
    "duckduckbot": ("DuckDuckBot", "crawler"),
    "duckassistbot": ("DuckAssistBot", "crawler"),
    "pingdom": ("Pingdom", "monitoring"),
    "statuscake": ("StatusCake", "monitoring"),
}
MAX_FILE_BYTES = 20 * 1024 * 1024


def raw_base(repo_url: str, branch: str = "main") -> str:
    """https://github.com/lord-alfred/ipranges -> raw.githubusercontent.com base URL."""
    parts = urlparse(repo_url)
    if parts.netloc != "github.com":
        return repo_url.rstrip("/")
    owner_repo = parts.path.strip("/").removesuffix(".git")
    return f"https://raw.githubusercontent.com/{owner_repo}/{branch}"


def parse_ranges(text: str) -> tuple[set[str], int]:
    """Strictly parse a CIDR list; returns (networks, rejected_count)."""
    nets: set[str] = set()
    rejected = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            nets.add(str(ipaddress.ip_network(line, strict=False)))
        except ValueError:
            rejected += 1
    return nets, rejected


def sync_ipranges(
    session: Session,
    principal: Principal,
    *,
    repo_url: str,
    providers: list[str] | None = None,
    emitter: EventEmitter | None = None,
    fetch=None,
) -> dict[str, Any]:
    base = raw_base(repo_url)
    now = utcnow()
    stats: dict[str, Any] = {"providers": {}, "added": 0, "removed": 0, "unchanged": 0, "rejected": 0}
    get = fetch or _download
    for provider in providers or list(PROVIDERS):
        if provider not in PROVIDERS:
            raise ValueError(f"unknown provider {provider!r}")
        organization, category = PROVIDERS[provider]
        nets: set[str] = set()
        for fname in ("ipv4_merged.txt", "ipv6_merged.txt"):
            url = f"{base}/{provider}/{fname}"
            try:
                parsed, rejected = parse_ranges(get(url))
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    continue  # some providers publish only one address family
                raise
            nets |= parsed
            stats["rejected"] += rejected
        current = {
            r.cidr: r for r in session.execute(select(CloudRange).where(CloudRange.provider == provider)).scalars()
        }
        live = {c for c, r in current.items() if r.removed_at is None}
        added, removed, unchanged = nets - live, live - nets, nets & live
        rows = [
            {
                "provider": provider,
                "organization": organization,
                "category": category,
                "cidr": c,
                "ip_version": ipaddress.ip_network(c).version,
                "source": f"{base}/{provider}",
                "first_seen": now,
                "last_seen": now,
                "removed_at": None,
            }
            for c in sorted(added)
        ]
        for i in range(0, len(rows), 2000):
            stmt = insert(CloudRange).values(rows[i : i + 2000])
            session.execute(
                stmt.on_conflict_do_update(
                    index_elements=["provider", "cidr"], set_={"removed_at": None, "last_seen": now}
                )
            )
        if removed:
            session.execute(
                update(CloudRange)
                .where(CloudRange.provider == provider, CloudRange.cidr.in_(list(removed)))
                .values(removed_at=now)
            )
        if unchanged:
            session.execute(
                update(CloudRange)
                .where(CloudRange.provider == provider, CloudRange.removed_at.is_(None))
                .values(last_seen=now)
            )
        stats["providers"][provider] = {"ranges": len(nets), "added": len(added), "removed": len(removed)}
        stats["added"] += len(added)
        stats["removed"] += len(removed)
        stats["unchanged"] += len(unchanged)
    record_audit(
        session,
        principal,
        "sync.ipranges",
        target_type="cloud_ranges",
        details={k: v for k, v in stats.items() if k != "providers"},
        emitter=emitter,
    )
    CloudRangeIndex.invalidate()
    return stats


def _download(url: str) -> str:
    with httpx.Client(timeout=60, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        if len(r.content) > MAX_FILE_BYTES:
            raise ValueError(f"{url} is too large")
        return r.text


@dataclass(frozen=True)
class Attribution:
    provider: str
    organization: str
    category: str
    cidr: str

    def to_event(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "organization": self.organization,
            "category": self.category,
            "cidr": self.cidr,
            "source": "lord-alfred/ipranges",
        }


class CloudRangeIndex:
    """Longest-prefix lookup: one dict per prefix length keyed by the network integer."""

    _cache: CloudRangeIndex | None = None
    _loaded_at = 0.0
    _lock = threading.Lock()
    TTL = 600.0

    def __init__(self, ranges: list[tuple[str, str, str, str]]):
        self._tables: dict[tuple[int, int], dict[int, Attribution]] = {}
        for provider, organization, category, cidr in ranges:
            net = ipaddress.ip_network(cidr)
            key = (net.version, net.prefixlen)
            self._tables.setdefault(key, {})[int(net.network_address)] = Attribution(
                provider, organization, category, cidr
            )
        # most specific first
        self._order = sorted(self._tables, key=lambda k: -k[1])

    def lookup(self, ip: str) -> Attribution | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        bits = addr.max_prefixlen
        value = int(addr)
        for version, prefixlen in self._order:
            if version != addr.version:
                continue
            masked = value >> (bits - prefixlen) << (bits - prefixlen) if prefixlen else 0
            hit = self._tables[(version, prefixlen)].get(masked)
            if hit is not None:
                return hit
        return None

    @classmethod
    def load(cls, session: Session) -> CloudRangeIndex:
        rows = session.execute(
            select(CloudRange.provider, CloudRange.organization, CloudRange.category, CloudRange.cidr).where(
                CloudRange.removed_at.is_(None)
            )
        ).all()
        return cls([(r[0], r[1], r[2], r[3]) for r in rows])

    @classmethod
    def cached(cls) -> CloudRangeIndex:
        """Process-wide cached index, loaded in its own session (never the caller's transaction)."""
        with cls._lock:
            if cls._cache is None or time.monotonic() - cls._loaded_at > cls.TTL:
                try:
                    with session_scope() as session:
                        cls._cache = cls.load(session)
                except Exception as exc:  # enrichment only: degrade to "unknown provider"
                    log.warning("cloud range index unavailable", extra={"error": str(exc)})
                    cls._cache = cls([])
                cls._loaded_at = time.monotonic()
            return cls._cache

    @classmethod
    def invalidate(cls) -> None:
        with cls._lock:
            cls._cache = None


def tag_cloud(asset: Any, attribution: Attribution | None) -> None:
    """Tag an IP asset with its provider (enrichment; never affects scope)."""
    if attribution is None:
        return
    tag = f"cloud:{attribution.provider}"
    if tag not in (asset.tags or []):
        asset.tags = [*(asset.tags or []), tag]
