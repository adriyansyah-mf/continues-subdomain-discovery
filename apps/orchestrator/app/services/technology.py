"""Technology normalization.

Scanner fingerprints ("Nginx", "nginx web server", "Nginx:1.24.0") are mapped to
a canonical technology record. Rules:

* versions are only ever taken from the scanner output, never inferred;
* ``confidence`` (is this technology present?) and ``version_confidence``
  (is the version right?) are separate values;
* both come from a fixed per-source table below, documented in
  docs/data-model.md, because the upstream tools do not expose calibrated scores.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any

# alias (lowercase) -> canonical name
ALIASES: dict[str, str] = {
    "nginx": "nginx",
    "nginx web server": "nginx",
    "openresty": "openresty",
    "apache": "apache-httpd",
    "apache http server": "apache-httpd",
    "apache httpd": "apache-httpd",
    "httpd": "apache-httpd",
    "microsoft-iis": "iis",
    "iis": "iis",
    "microsoft iis": "iis",
    "lighttpd": "lighttpd",
    "caddy": "caddy",
    "envoy": "envoy",
    "tomcat": "tomcat",
    "apache tomcat": "tomcat",
    "jetty": "jetty",
    "php": "php",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "jquery": "jquery",
    "react": "react",
    "vue.js": "vue",
    "vue": "vue",
    "angular": "angular",
    "angularjs": "angularjs",
    "bootstrap": "bootstrap",
    "grafana": "grafana",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "kibana": "kibana",
    "elasticsearch": "elasticsearch",
    "cloudflare": "cloudflare",
    "amazon cloudfront": "cloudfront",
    "cloudfront": "cloudfront",
    "akamai": "akamai",
    "fastly": "fastly",
    "varnish": "varnish",
    "express": "express",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "hsts": "hsts",
}

# canonical -> (vendor, product) where the mapping is well established (used later for CPE work).
VENDOR_PRODUCT: dict[str, tuple[str, str]] = {
    "nginx": ("f5", "nginx"),
    "apache-httpd": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "php": ("php", "php"),
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla\\!"),
    "jquery": ("jquery", "jquery"),
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "kibana": ("elastic", "kibana"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "openresty": ("openresty", "openresty"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "varnish": ("varnish-software", "varnish_cache"),
    "nodejs": ("nodejs", "node.js"),
}

# Fixed confidence per source (see docs/data-model.md#confidence).
SOURCE_TECH_CONFIDENCE: dict[str, tuple[float, float]] = {
    "bbot-cpe": (0.6, 0.5),  # passive third-party data (e.g. Shodan InternetDB via BBOT)
    "bbot": (0.6, 0.5),
    # source: (technology_confidence, version_confidence)
    "httpx-wappalyzer": (0.8, 0.7),
    "httpx-server-header": (0.9, 0.8),
}

_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+){0,3}[a-z0-9.+-]*)$", re.IGNORECASE)
_SERVER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 ._-]*?)(?:/([0-9][A-Za-z0-9.+-]*))?(?:\s.*)?$")


@dataclass(frozen=True)
class Technology:
    name: str
    vendor: str | None
    product: str | None
    version: str | None
    confidence: float
    version_confidence: float | None
    source: str
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonical_name(name: str) -> str:
    key = re.sub(r"\s+", " ", name.strip().lower())
    if key in ALIASES:
        return ALIASES[key]
    return re.sub(r"[^a-z0-9.+_-]+", "-", key).strip("-") or key


def _clean_version(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    m = _VERSION_RE.match(v)
    return m.group(1) if m else None


def _build(name: str, version: str | None, source: str, raw: str) -> Technology:
    canon = canonical_name(name)
    vendor, product = VENDOR_PRODUCT.get(canon, (None, None))
    tconf, vconf = SOURCE_TECH_CONFIDENCE[source]
    ver = _clean_version(version)
    return Technology(
        name=canon,
        vendor=vendor,
        product=product or None,
        version=ver,
        confidence=tconf,
        version_confidence=vconf if ver else None,
        source=source,
        raw=raw,
    )


def from_wappalyzer(entry: str) -> Technology:
    """httpx -td output entries look like 'Nginx:1.24.0' or 'HSTS'."""
    name, _, version = entry.partition(":")
    return _build(name, version or None, "httpx-wappalyzer", entry)


def from_server_header(value: str) -> Technology | None:
    """'nginx/1.24.0 (Ubuntu)' -> nginx 1.24.0. Returns None if unparseable."""
    m = _SERVER_RE.match(value.strip())
    if not m:
        return None
    return _build(m.group(1), m.group(2), "httpx-server-header", value)


def merge(techs: list[Technology]) -> list[Technology]:
    """Deduplicate by canonical name; prefer entries carrying a version, then higher confidence."""
    best: dict[str, Technology] = {}
    for t in techs:
        cur = best.get(t.name)
        if (
            cur is None
            or (t.version and not cur.version)
            or (bool(t.version) == bool(cur.version) and t.confidence > cur.confidence)
        ):
            best[t.name] = t
    return sorted(best.values(), key=lambda t: t.name)


def from_cpe(cpe: str, source: str = "bbot-cpe") -> Technology | None:
    """'cpe:/a:vendor:product[:version]' or 'cpe:2.3:a:vendor:product:version:...' -> Technology.

    The version is taken only if the CPE carries one ('*' / '-' mean unknown)."""
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[1] == "2.3":
        vendor, product, version = parts[3], parts[4], parts[5] if len(parts) > 5 else None
    elif len(parts) >= 4 and parts[1].startswith("/"):
        vendor, product, version = parts[2], parts[3], parts[4] if len(parts) > 4 else None
    else:
        return None
    if not product or product in ("*", "-"):
        return None
    if version in ("*", "-", ""):
        version = None
    t = _build(product.replace("_", " "), version, source, cpe)
    return Technology(
        name=t.name,
        vendor=t.vendor or vendor,
        product=t.product or product,
        version=t.version,
        confidence=t.confidence,
        version_confidence=t.version_confidence,
        source=source,
        raw=cpe,
    )


def from_name(name: str, source: str, version: str | None = None) -> Technology:
    """Generic fingerprint (name and optional explicit version) from a known source."""
    return _build(name, version, source, name)
