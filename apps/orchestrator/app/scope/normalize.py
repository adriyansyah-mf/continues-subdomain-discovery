"""Strict normalization of targets and scope values.

Everything that reaches the scope engine or a scanner goes through these
functions. They are deliberately strict: anything ambiguous raises
``InvalidTarget`` so callers fail closed instead of guessing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import idna
import tldextract

from app.models.enums import ScopeType


class InvalidTarget(ValueError):
    """Raised when a value cannot be safely normalized."""


_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)
_FORBIDDEN_CHARS = re.compile(r"[\s\\\x00-\x1f\x7f]")
_ALLOWED_URL_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


@lru_cache(maxsize=1)
def _tld_extractor() -> tldextract.TLDExtract:
    # Bundled public-suffix snapshot only: never fetch the list at runtime.
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def normalize_domain(value: str) -> str:
    """Return the lowercase ASCII (punycode) FQDN without trailing dot."""
    if not isinstance(value, str):
        raise InvalidTarget("domain must be a string")
    raw = value.strip()
    if not raw or _FORBIDDEN_CHARS.search(raw):
        raise InvalidTarget(f"invalid domain: {value!r}")
    if raw.endswith("."):
        raw = raw[:-1]
    if "*" in raw or "/" in raw or ":" in raw or "@" in raw:
        raise InvalidTarget(f"invalid domain characters: {value!r}")
    labels = raw.split(".")
    ascii_labels: list[str] = []
    for label in labels:
        if not label:
            raise InvalidTarget(f"empty label in domain: {value!r}")
        if label.isascii():
            ascii_labels.append(label.lower())
            continue
        try:
            ascii_labels.append(idna.encode(label, uts46=True).decode("ascii").lower())
        except idna.IDNAError as exc:
            raise InvalidTarget(f"invalid IDN label in {value!r}: {exc}") from exc
    if len(ascii_labels) < 2:
        raise InvalidTarget(f"domain must have at least two labels: {value!r}")
    for label in ascii_labels:
        if not _LABEL_RE.match(label):
            raise InvalidTarget(f"invalid label {label!r} in {value!r}")
    # A numeric / hex "TLD" means this is an IP literal in a non-canonical form
    # (e.g. 127.1, 0x7f.0x1) that a resolver might still accept. Never treat it as a name.
    if not _TLD_RE.match(ascii_labels[-1]):
        raise InvalidTarget(f"invalid top-level label in {value!r}")
    result = ".".join(ascii_labels)
    if len(result) > 253:
        raise InvalidTarget("domain longer than 253 characters")
    return result


def registrable_domain(domain: str) -> str | None:
    """eTLD+1 of a normalized domain, or None if the domain is itself a public suffix."""
    ext = _tld_extractor()(domain)
    if not ext.domain:
        return None
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def is_public_suffix(domain: str) -> bool:
    ext = _tld_extractor()(domain)
    return not ext.domain and bool(ext.suffix)


def normalize_wildcard(value: str) -> str:
    """Normalize ``*.example.com``. Returns the base domain prefixed with ``*.``.

    Only a single leading ``*.`` label is supported. Patterns such as
    ``api-*.example.com`` or ``*example.com`` are rejected rather than guessed.
    Wildcards over a public suffix (``*.com``, ``*.co.uk``) are rejected.
    """
    raw = value.strip().lower()
    if not raw.startswith("*."):
        raise InvalidTarget(f"wildcard must start with '*.': {value!r}")
    base = raw[2:]
    if "*" in base:
        raise InvalidTarget(f"only a single leading wildcard label is supported: {value!r}")
    base = normalize_domain(base)
    if is_public_suffix(base):
        raise InvalidTarget(f"wildcard over a public suffix is not allowed: {value!r}")
    return f"*.{base}"


def normalize_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    raw = value.strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if "%" in raw:
        raise InvalidTarget(f"IPv6 zone identifiers are not supported: {value!r}")
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise InvalidTarget(f"invalid IP address: {value!r}") from exc
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def normalize_cidr(value: str, *, strict: bool = True) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    raw = value.strip()
    if "/" not in raw:
        raise InvalidTarget(f"CIDR must contain a prefix length: {value!r}")
    try:
        net = ipaddress.ip_network(raw, strict=strict)
    except ValueError as exc:
        raise InvalidTarget(f"invalid CIDR {value!r}: {exc}") from exc
    if isinstance(net, ipaddress.IPv6Network) and net.network_address.ipv4_mapped is not None:
        raise InvalidTarget("IPv4-mapped IPv6 networks are not supported; use the IPv4 form")
    return net


def normalize_asn(value: str) -> int:
    m = _ASN_RE.match(value.strip())
    if not m:
        raise InvalidTarget(f"invalid ASN: {value!r}")
    asn = int(m.group(1))
    if not 0 < asn < 2**32:
        raise InvalidTarget(f"ASN out of range: {value!r}")
    return asn


@dataclass(frozen=True)
class NormalizedURL:
    raw_url: str
    scheme: str
    host: str
    host_type: str  # "domain" | "ipv4" | "ipv6"
    port: int
    path: str
    query: str
    normalized_url: str
    url_hash: str
    endpoint: str
    endpoint_hash: str
    parameters: tuple[str, ...] = field(default_factory=tuple)

    @property
    def origin(self) -> str:
        host = f"[{self.host}]" if self.host_type == "ipv6" else self.host
        default = _DEFAULT_PORTS[self.scheme]
        return f"{self.scheme}://{host}" + ("" if self.port == default else f":{self.port}")


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    # Decode only to resolve dot-segments safely, then re-encode consistently.
    decoded = unquote(path)
    if "\x00" in decoded:
        raise InvalidTarget("NUL byte in URL path")
    trailing = decoded.endswith("/")
    norm = posixpath.normpath("/" + decoded.lstrip("/"))
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    if trailing and norm != "/":
        norm += "/"
    return quote(norm, safe="/:@!$&'()*+,;=-._~")


def normalize_url(value: str) -> NormalizedURL:
    raw = value.strip()
    if not raw or _FORBIDDEN_CHARS.search(raw):
        raise InvalidTarget(f"URL contains whitespace, backslashes or control characters: {value!r}")
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise InvalidTarget(f"unparseable URL {value!r}: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise InvalidTarget(f"unsupported URL scheme: {value!r}")
    if "@" in parts.netloc:
        # userinfo is a classic host-confusion vector (https://allowed.com@evil.com)
        raise InvalidTarget(f"URLs with userinfo are not allowed: {value!r}")
    hostname = parts.hostname
    if not hostname:
        raise InvalidTarget(f"URL has no host: {value!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidTarget(f"invalid URL port: {value!r}") from exc
    if port is not None and not 0 < port < 65536:
        raise InvalidTarget(f"invalid URL port: {value!r}")
    try:
        ip = normalize_ip(hostname)
        host = str(ip)
        host_type = "ipv4" if ip.version == 4 else "ipv6"
    except InvalidTarget:
        host = normalize_domain(hostname)
        host_type = "domain"
    port = port or _DEFAULT_PORTS[scheme]
    path = _normalize_path(parts.path)
    params = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = urlencode(params, doseq=True)
    netloc_host = f"[{host}]" if host_type == "ipv6" else host
    netloc = netloc_host if port == _DEFAULT_PORTS[scheme] else f"{netloc_host}:{port}"
    normalized = f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")
    param_names = tuple(sorted({k for k, _ in params}))
    endpoint_key = f"{scheme}://{netloc}{path}|" + ",".join(param_names)
    return NormalizedURL(
        raw_url=value,
        scheme=scheme,
        host=host,
        host_type=host_type,
        port=port,
        path=path,
        query=query,
        normalized_url=normalized,
        url_hash=hashlib.sha256(normalized.encode()).hexdigest(),
        endpoint=path,
        endpoint_hash=hashlib.sha256(endpoint_key.encode()).hexdigest(),
        parameters=param_names,
    )


@dataclass(frozen=True)
class Target:
    """A classified, normalized target."""

    kind: str  # domain | wildcard | ipv4 | ipv6 | cidr | url | asn
    value: str  # canonical string form
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    url: NormalizedURL | None = None
    asn: int | None = None


def classify_target(value: str) -> Target:
    """Detect the type of a free-form target and normalize it."""
    if not isinstance(value, str) or not value.strip():
        raise InvalidTarget("empty target")
    raw = value.strip()
    if "://" in raw:
        url = normalize_url(raw)
        return Target(kind="url", value=url.normalized_url, url=url)
    if _ASN_RE.match(raw) and raw.lower().startswith("as"):
        asn = normalize_asn(raw)
        return Target(kind="asn", value=f"AS{asn}", asn=asn)
    if "/" in raw:
        net = normalize_cidr(raw)
        return Target(kind="cidr", value=str(net), network=net)
    try:
        ip = normalize_ip(raw)
        return Target(kind=f"ipv{ip.version}", value=str(ip), ip=ip)
    except InvalidTarget:
        pass
    if raw.startswith("*."):
        return Target(kind="wildcard", value=normalize_wildcard(raw))
    return Target(kind="domain", value=normalize_domain(raw))


def normalize_scope_value(scope_type: ScopeType | str, value: str) -> str:
    """Validate and normalize a scope entry value for its declared type."""
    st = ScopeType(scope_type)
    if st is ScopeType.DOMAIN:
        return normalize_domain(value)
    if st is ScopeType.WILDCARD:
        return normalize_wildcard(value)
    if st is ScopeType.CIDR:
        return str(normalize_cidr(value, strict=True))
    if st is ScopeType.IPV4:
        ip = normalize_ip(value)
        if ip.version != 4:
            raise InvalidTarget(f"not an IPv4 address: {value!r}")
        return str(ip)
    if st is ScopeType.IPV6:
        ip = normalize_ip(value)
        if ip.version != 6:
            raise InvalidTarget(f"not an IPv6 address: {value!r}")
        return str(ip)
    if st is ScopeType.ASN:
        return f"AS{normalize_asn(value)}"
    if st is ScopeType.URL:
        return normalize_url(value).normalized_url
    raise InvalidTarget(f"unsupported scope type: {scope_type!r}")


def infer_scope_type(value: str) -> ScopeType:
    """Best-effort type detection used by importers and the CLI."""
    t = classify_target(value)
    return ScopeType(t.kind)
