"""Scan policy configuration schema.

Policies are stored as JSON in PostgreSQL and validated here. Values are bounded
twice: by the schema (hard sanity limits) and by ``enforce_global_limits`` against
the deployment's configured maxima (HTTPX_RATE_LIMIT, MAX_CRAWL_DEPTH, ...).
Policies can never carry arbitrary command-line flags.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config import Settings

_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_TEMPLATE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,200}$")


class ScannerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    rate_limit: int = Field(default=10, ge=1, le=1000, description="requests per second")
    concurrency: int = Field(default=2, ge=1, le=100)
    timeout: int = Field(default=10, ge=1, le=120, description="per-request timeout (s)")
    retries: int = Field(default=1, ge=0, le=5)
    max_duration: int = Field(default=600, ge=10, le=86400, description="wall-clock limit per job (s)")
    time_bucket_seconds: int = Field(default=3600, ge=60, le=30 * 86400, description="idempotency window")


def _ports(v: list[int]) -> list[int]:
    if len(v) > 32:
        raise ValueError("at most 32 ports")
    for p in v:
        if not 0 < p < 65536:
            raise ValueError(f"invalid port {p}")
    return sorted(set(v))


class HttpxSettings(ScannerSettings):
    ports: list[int] = Field(default_factory=list, description="empty = httpx defaults (80/443)")
    follow_host_redirects: bool = False
    tech_detect: bool = True
    favicon: bool = True

    _v_ports = field_validator("ports")(classmethod(lambda cls, v: _ports(v)))


class TlsxSettings(ScannerSettings):
    ports: list[int] = Field(default_factory=lambda: [443])

    _v_ports = field_validator("ports")(classmethod(lambda cls, v: _ports(v)))


DnsRecord = Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT"]
_DNS_RECORDS: tuple[DnsRecord, ...] = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


class DnsSettings(ScannerSettings):
    record_types: list[DnsRecord] = Field(default_factory=lambda: list(_DNS_RECORDS))
    resolvers: list[str] = Field(default_factory=list, description="empty = system resolver")

    @field_validator("resolvers")
    @classmethod
    def _resolvers(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(x)) for x in v]


KnownFile = Literal["robotstxt", "sitemapxml"]
_KNOWN_FILES: tuple[KnownFile, ...] = ("robotstxt", "sitemapxml")


# Scanners a discovery worker may queue for what it found (always scope-checked again).
FollowupScanner = Literal["dns", "httpx", "tlsx"]


class MapcidrSettings(ScannerSettings):
    skip_base_broadcast: bool = True
    followup_scanners: list[FollowupScanner] = Field(default_factory=list)


UncoverEngine = Literal[
    "shodan", "censys", "fofa", "netlas", "zoomeye", "quake", "hunter", "criminalip", "onyphe", "driftnet", "odin"
]


class UncoverSettings(ScannerSettings):
    engines: list[UncoverEngine] = Field(default_factory=lambda: ["shodan"])  # type: ignore[arg-type]
    limit: int = Field(default=100, ge=1, le=1000, description="max results per engine query")
    followup_scanners: list[FollowupScanner] = Field(default_factory=list)


_MODULE_RE = re.compile(r"^[a-z0-9_]{1,64}$")


class BbotSettings(ScannerSettings):
    """BBOT runs the subdomain-enum preset. passive_only=True (default) requires the
    `passive` and `safe` module flags, so nothing is sent to the target itself."""

    preset: Literal["subdomain-enum"] = "subdomain-enum"
    passive_only: bool = True
    # crt_db needs a database driver not shipped in the image
    exclude_modules: list[str] = Field(default_factory=lambda: ["crt_db"])

    @field_validator("exclude_modules")
    @classmethod
    def _modules(cls, v: list[str]) -> list[str]:
        for m in v:
            if not _MODULE_RE.match(m):
                raise ValueError(f"invalid module name {m!r}")
        return v


class KatanaSettings(ScannerSettings):
    follow_redirects: bool = False
    depth: int = Field(default=2, ge=1, le=10)
    js_crawl: bool = True
    jsluice: bool = False
    max_urls: int = Field(default=500, ge=1, le=100_000)
    known_files: list[KnownFile] = Field(default_factory=lambda: list(_KNOWN_FILES))


Severity = Literal["info", "low", "medium", "high", "critical"]


_DEFAULT_SEVERITY: tuple[Severity, ...] = ("medium", "high", "critical")
# Destructive and credential-guessing templates are never allowed: the worker always passes
# these to -etags (which overrides -tags/-id/-t selection) and policies cannot select them.
FORBIDDEN_NUCLEI_TAGS: tuple[str, ...] = ("dos", "bruteforce", "default-login")
# Baseline selection: the whole bundle is never run by default (thousands of templates).
BASELINE_NUCLEI_TAGS: tuple[str, ...] = ("exposure", "misconfig", "takeover")


class NucleiSettings(ScannerSettings):
    severity: list[Severity] = Field(default_factory=lambda: list(_DEFAULT_SEVERITY))
    tags: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=lambda: ["dos", "fuzz", "intrusive", "bruteforce", "default-login"])
    templates: list[str] = Field(default_factory=list, description="template ids / relative paths")

    @field_validator("tags", "exclude_tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        for t in v:
            if not _TAG_RE.match(t):
                raise ValueError(f"invalid tag {t!r}")
        return v

    @field_validator("tags")
    @classmethod
    def _no_forbidden_tags(cls, v: list[str]) -> list[str]:
        bad = sorted(set(v) & set(FORBIDDEN_NUCLEI_TAGS))
        if bad:
            raise ValueError(f"tags {bad} are never allowed (destructive or credential attacks)")
        return v

    @field_validator("templates")
    @classmethod
    def _templates(cls, v: list[str]) -> list[str]:
        style = None
        for t in v:
            if not _TEMPLATE_RE.match(t) or ".." in t:
                raise ValueError(f"invalid template reference {t!r}")
            # nuclei selects ids (-id, within the bundle) and paths (-t) by different
            # mechanisms that cannot be combined in one run
            is_path = "/" in t or t.endswith((".yaml", ".yml"))
            if style is None:
                style = "path" if is_path else "id"
            elif style != ("path" if is_path else "id"):
                raise ValueError("templates must be all ids or all relative paths (cannot be mixed)")
        return v


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dns: DnsSettings = Field(default_factory=DnsSettings)
    httpx: HttpxSettings = Field(default_factory=HttpxSettings)
    tlsx: TlsxSettings = Field(default_factory=TlsxSettings)
    katana: KatanaSettings = Field(default_factory=KatanaSettings)
    nuclei: NucleiSettings = Field(default_factory=NucleiSettings)
    uncover: UncoverSettings = Field(default_factory=UncoverSettings)
    mapcidr: MapcidrSettings = Field(default_factory=MapcidrSettings)
    bbot: BbotSettings = Field(default_factory=BbotSettings)

    def for_scanner(self, scanner: str) -> ScannerSettings:
        return getattr(self, scanner)


def enforce_global_limits(cfg: PolicyConfig, s: Settings) -> list[str]:
    """Return a list of violations of deployment-wide limits (empty = OK)."""
    errors = []
    caps = {
        "httpx": s.httpx_rate_limit,
        "tlsx": s.tlsx_rate_limit,
        "nuclei": s.nuclei_rate_limit,
        "katana": s.katana_rate_limit,
        "bbot": s.bbot_rate_limit,
    }
    for scanner, cap in caps.items():
        sc = cfg.for_scanner(scanner)
        if sc.rate_limit > cap:
            errors.append(f"{scanner}.rate_limit {sc.rate_limit} exceeds global cap {cap}")
    for scanner in PolicyConfig.model_fields:
        sc = cfg.for_scanner(scanner)
        if sc.concurrency > s.max_concurrency:
            errors.append(f"{scanner}.concurrency {sc.concurrency} exceeds MAX_CONCURRENCY {s.max_concurrency}")
        if sc.max_duration > s.max_scan_duration:
            errors.append(f"{scanner}.max_duration exceeds MAX_SCAN_DURATION {s.max_scan_duration}")
    if cfg.katana.depth > s.max_crawl_depth:
        errors.append(f"katana.depth {cfg.katana.depth} exceeds MAX_CRAWL_DEPTH {s.max_crawl_depth}")
    if cfg.katana.max_urls > s.max_urls_per_crawl:
        errors.append(f"katana.max_urls exceeds MAX_URLS_PER_CRAWL {s.max_urls_per_crawl}")
    return errors


def _on(**kw) -> dict:
    return {"enabled": True, **kw}


_BASELINE = list(BASELINE_NUCLEI_TAGS)


# Seeded on first start; editable afterwards through the API.
DEFAULT_POLICIES: dict[str, tuple[str, dict]] = {
    "passive": ("DNS resolution only. No traffic is sent to targets.", {"dns": _on()}),
    "discovery": (
        "DNS + conservative HTTP/TLS probing.",
        {"dns": _on(), "httpx": _on(rate_limit=10, concurrency=2), "tlsx": _on(rate_limit=10, concurrency=2)},
    ),
    "conservative-web": (
        "HTTP fingerprinting, TLS and shallow crawling.",
        {
            "dns": _on(),
            "httpx": _on(rate_limit=20, concurrency=4),
            "tlsx": _on(rate_limit=10, concurrency=2),
            "katana": _on(rate_limit=5, concurrency=2, depth=3),
        },
    ),
    "recon": (
        "Discovery and recon: DNS, HTTP/TLS probing, CIDR expansion -> TLS, uncover -> TLS/HTTP, shallow crawl.",
        {
            "dns": _on(),
            "httpx": _on(rate_limit=10, concurrency=2),
            "tlsx": _on(rate_limit=10, concurrency=2),
            "mapcidr": _on(followup_scanners=["tlsx"]),
            "uncover": _on(
                engines=["shodan"], limit=100, followup_scanners=["tlsx", "httpx"], time_bucket_seconds=86400
            ),
            "katana": _on(rate_limit=5, concurrency=2, depth=2, time_bucket_seconds=86400),
            "bbot": _on(time_bucket_seconds=86400, max_duration=900),
        },
    ),
    "crawl": ("Crawling of approved URLs.", {"katana": _on(rate_limit=5, concurrency=2, depth=3)}),
    "vulnerability": (
        "Nuclei baseline: exposure/misconfig/takeover templates, medium/high/critical, intrusive tags excluded.",
        {"nuclei": _on(rate_limit=10, concurrency=2, max_duration=900, time_bucket_seconds=86400, tags=_BASELINE)},
    ),
    "full": (
        "All implemented scanners with conservative limits.",
        {
            "dns": _on(),
            "httpx": _on(rate_limit=20, concurrency=4),
            "tlsx": _on(rate_limit=10, concurrency=2),
            "katana": _on(rate_limit=5, concurrency=2, depth=3),
            "nuclei": _on(rate_limit=10, concurrency=2, max_duration=900, time_bucket_seconds=86400, tags=_BASELINE),
        },
    ),
}
