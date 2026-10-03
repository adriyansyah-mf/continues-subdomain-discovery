"""ScopeEngine: pure, deterministic scope evaluation.

The engine has no I/O. It is constructed from a snapshot of scope rules and
answers ``is_in_scope(target)``. Loading rules from PostgreSQL (and failing
closed when that is impossible) is the job of ``app.scope.service``.

Precedence (per program):
  1. explicit exclusion            -> blocked
  2. explicit inclusion            -> allowed
  3. inherited wildcard inclusion  -> allowed
  4. otherwise                     -> not in scope

See docs/scope-engine.md for the full matching table.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from app.models.enums import ScopeMode, ScopeType
from app.scope.normalize import (
    InvalidTarget,
    NormalizedURL,
    Target,
    classify_target,
    normalize_asn,
    normalize_cidr,
    normalize_ip,
    normalize_scope_value,
    normalize_url,
)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class ScopeRule:
    id: str
    program_id: str
    type: ScopeType
    mode: ScopeMode
    value: str  # normalized value
    program_name: str | None = None
    # Pre-parsed forms (populated in __post_init__ via object.__setattr__)
    _network: IPNetwork | None = field(default=None, compare=False, repr=False)
    _url: NormalizedURL | None = field(default=None, compare=False, repr=False)
    _asn: int | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        # Coerce plain strings (e.g. straight from the database) into the enums.
        object.__setattr__(self, "type", ScopeType(self.type))
        object.__setattr__(self, "mode", ScopeMode(self.mode))
        if self.type is ScopeType.CIDR:
            object.__setattr__(self, "_network", normalize_cidr(self.value))
        elif self.type in (ScopeType.IPV4, ScopeType.IPV6):
            ip = normalize_ip(self.value)
            object.__setattr__(self, "_network", ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
        elif self.type is ScopeType.URL:
            object.__setattr__(self, "_url", normalize_url(self.value))
        elif self.type is ScopeType.ASN:
            object.__setattr__(self, "_asn", normalize_asn(self.value))

    @classmethod
    def build(
        cls,
        *,
        id: str | uuid.UUID,
        program_id: str | uuid.UUID,
        type: str,
        mode: str,
        value: str,
        program_name: str | None = None,
    ) -> ScopeRule:
        st = ScopeType(type)
        return cls(
            id=str(id),
            program_id=str(program_id),
            type=st,
            mode=ScopeMode(mode),
            value=normalize_scope_value(st, value),
            program_name=program_name,
        )

    def describe(self) -> str:
        return f"{self.mode.value} {self.type.value} {self.value}"


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    program_id: str | None = None
    program_name: str | None = None
    scope_id: str | None = None
    match_kind: str | None = None  # explicit_exclusion | explicit_inclusion | wildcard_inclusion | none
    target: str | None = None
    target_type: str | None = None
    allowed_program_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if not self.allowed:
            # Keep the "blocked" shape minimal as documented, plus diagnostics.
            data["program_id"] = self.program_id
        return data


# ---------------------------------------------------------------------------
# Matching primitives
# ---------------------------------------------------------------------------


def _domain_equal_or_sub(domain: str, base: str) -> bool:
    return domain == base or domain.endswith("." + base)


def _domain_strict_sub(domain: str, base: str) -> bool:
    return domain.endswith("." + base)


def _path_prefix(path: str, prefix: str) -> bool:
    if prefix in ("", "/"):
        return True
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/")


def _url_rule_matches(rule_url: NormalizedURL, url: NormalizedURL) -> bool:
    return (
        rule_url.scheme == url.scheme
        and rule_url.host == url.host
        and rule_url.port == url.port
        and _path_prefix(url.path, rule_url.path)
    )


class _HostTarget:
    """Host-level view of a target: a domain name or an IP network (IP == /32 or /128)."""

    def __init__(self, domain: str | None = None, network: IPNetwork | None = None):
        self.domain = domain
        self.network = network


def _host_of(target: Target) -> _HostTarget | None:
    if target.kind == "domain":
        return _HostTarget(domain=target.value)
    if target.kind in ("ipv4", "ipv6"):
        assert target.ip is not None
        return _HostTarget(network=ipaddress.ip_network(f"{target.ip}/{target.ip.max_prefixlen}"))
    if target.kind == "cidr":
        return _HostTarget(network=target.network)
    if target.kind == "url":
        assert target.url is not None
        u = target.url
        if u.host_type == "domain":
            return _HostTarget(domain=u.host)
        ip = ipaddress.ip_address(u.host)
        return _HostTarget(network=ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
    return None


def _exclusion_matches(rule: ScopeRule, target: Target, host: _HostTarget | None) -> bool:
    """Exclusions are matched conservatively (anything that touches the excluded area)."""
    if rule.type is ScopeType.ASN:
        return target.kind == "asn" and target.asn == rule._asn
    if host is None:
        return False
    if rule.type is ScopeType.DOMAIN and host.domain:
        # Excluding a host also excludes everything beneath it.
        return _domain_equal_or_sub(host.domain, rule.value)
    if rule.type is ScopeType.WILDCARD and host.domain:
        return _domain_strict_sub(host.domain, rule.value[2:])
    if rule.type in (ScopeType.CIDR, ScopeType.IPV4, ScopeType.IPV6) and host.network is not None:
        assert rule._network is not None
        return host.network.version == rule._network.version and host.network.overlaps(rule._network)
    if rule.type is ScopeType.URL:
        assert rule._url is not None
        if target.kind == "url":
            assert target.url is not None
            return _url_rule_matches(rule._url, target.url)
        # Host-level targets are only blocked when the whole origin is excluded (path "/").
        # Narrower URL exclusions are enforced by path-exploring scanners themselves
        # (katana: -cos regexes + output re-validation; see ScopeEngine.url_exclusions).
        if rule._url.path not in ("", "/"):
            return False
        if host.domain and rule._url.host_type == "domain":
            return host.domain == rule._url.host
        if host.network is not None and rule._url.host_type != "domain":
            return host.network.overlaps(
                ipaddress.ip_network(f"{rule._url.host}/{ipaddress.ip_address(rule._url.host).max_prefixlen}")
            )
    return False


def _inclusion_kind(rule: ScopeRule, target: Target, host: _HostTarget | None) -> str | None:
    """Return 'explicit' / 'wildcard' when the inclusion rule covers the target, else None."""
    if rule.type is ScopeType.ASN:
        return "explicit" if target.kind == "asn" and target.asn == rule._asn else None
    if host is None:
        return None
    if rule.type is ScopeType.URL:
        assert rule._url is not None
        if target.kind == "url":
            assert target.url is not None
            return "explicit" if _url_rule_matches(rule._url, target.url) else None
        return None  # a URL rule never authorises host-level scanning
    if rule.type is ScopeType.DOMAIN and host.domain:
        return "explicit" if host.domain == rule.value else None
    if rule.type is ScopeType.WILDCARD and host.domain:
        return "wildcard" if _domain_strict_sub(host.domain, rule.value[2:]) else None
    if rule.type in (ScopeType.CIDR, ScopeType.IPV4, ScopeType.IPV6) and host.network is not None:
        assert rule._network is not None
        if host.network.version != rule._network.version:
            return None
        # The whole target range must sit inside the included range.
        return "explicit" if host.network.subnet_of(rule._network) else None  # type: ignore[arg-type]
    return None


_SPECIFICITY = {
    ScopeType.URL: 6,
    ScopeType.DOMAIN: 5,
    ScopeType.IPV4: 5,
    ScopeType.IPV6: 5,
    ScopeType.ASN: 5,
    ScopeType.CIDR: 4,
    ScopeType.WILDCARD: 3,
}


class _ProgramIndex:
    """Domain/wildcard rules keyed by domain so a lookup only walks the host's suffixes.

    Programs can hold tens of thousands of domain rules (bounty-targets-data); a linear
    scan per evaluation is too slow for high-volume passive sources such as CertStream.
    The index only *selects candidate rules*; matching still uses the same functions.
    """

    def __init__(self) -> None:
        self.by_domain: dict[str, list[ScopeRule]] = defaultdict(list)
        self.other: list[ScopeRule] = []
        self.name: str | None = None

    def add(self, rule: ScopeRule) -> None:
        self.name = self.name or rule.program_name
        if rule.type is ScopeType.DOMAIN:
            self.by_domain[rule.value].append(rule)
        elif rule.type is ScopeType.WILDCARD:
            self.by_domain[rule.value[2:]].append(rule)
        else:
            self.other.append(rule)

    def candidates(self, host: _HostTarget | None) -> list[ScopeRule]:
        out: list[ScopeRule] = []
        if host is not None and host.domain:
            labels = host.domain.split(".")
            for i in range(len(labels)):
                out.extend(self.by_domain.get(".".join(labels[i:]), ()))
        out.extend(self.other)
        return out


class ScopeEngine:
    def __init__(self, rules: Iterable[ScopeRule]):
        self._by_program: dict[str, _ProgramIndex] = defaultdict(_ProgramIndex)
        for rule in rules:
            self._by_program[rule.program_id].add(rule)

    @property
    def program_ids(self) -> list[str]:
        return list(self._by_program)

    def host_exclusions(self, program_id: str, domain: str) -> list[str]:
        """Excluded domains under ``domain`` plus excluded IPs/CIDRs (for tools with their own blacklist).

        Wildcard exclusions are returned as their base domain, which tools such as BBOT treat as
        "this host and everything beneath it" - broader than the rule, i.e. conservative.
        """
        index = self._by_program.get(str(program_id))
        if index is None:
            return []
        out: set[str] = set()
        for value, rules in index.by_domain.items():
            if value == domain or value.endswith("." + domain) or domain.endswith("." + value):
                out.update(value for r in rules if r.mode is ScopeMode.EXCLUDE)
        for r in index.other:
            if r.mode is ScopeMode.EXCLUDE and r.type in (ScopeType.CIDR, ScopeType.IPV4, ScopeType.IPV6):
                out.add(r.value)
        return sorted(out)

    def url_exclusions(self, program_id: str, host: str) -> list[NormalizedURL]:
        """URL exclusion rules for one host (crawlers turn these into out-of-scope regexes)."""
        index = self._by_program.get(str(program_id))
        if index is None:
            return []
        return [
            r._url
            for r in index.other
            if r.type is ScopeType.URL and r.mode is ScopeMode.EXCLUDE and r._url is not None and r._url.host == host
        ]

    def _evaluate_program(self, program_id: str, target: Target) -> ScopeDecision:
        index = self._by_program.get(program_id)
        host = _host_of(target)
        rules = index.candidates(host) if index is not None else []
        name = index.name if index is not None else None

        # 1. explicit exclusion always wins
        for rule in rules:
            if rule.mode is ScopeMode.EXCLUDE and _exclusion_matches(rule, target, host):
                return ScopeDecision(
                    allowed=False,
                    reason=f"excluded by {rule.describe()}",
                    program_id=program_id,
                    program_name=name,
                    scope_id=rule.id,
                    match_kind="explicit_exclusion",
                    target=target.value,
                    target_type=target.kind,
                )

        # 2./3. inclusions, most specific first
        best: tuple[int, ScopeRule, str] | None = None
        for rule in rules:
            if rule.mode is not ScopeMode.INCLUDE:
                continue
            kind = _inclusion_kind(rule, target, host)
            if kind is None:
                continue
            rank = (10 if kind == "explicit" else 0) + _SPECIFICITY[rule.type]
            if best is None or rank > best[0]:
                best = (rank, rule, kind)
        if best is not None:
            _, rule, kind = best
            return ScopeDecision(
                allowed=True,
                reason=f"matched {rule.value}" + (" (wildcard)" if kind == "wildcard" else ""),
                program_id=program_id,
                program_name=name,
                scope_id=rule.id,
                match_kind=f"{kind}_inclusion",
                target=target.value,
                target_type=target.kind,
                allowed_program_ids=[program_id],
            )
        return ScopeDecision(
            allowed=False,
            reason="not in approved scope",
            program_id=program_id,
            program_name=name,
            match_kind="none",
            target=target.value,
            target_type=target.kind,
        )

    def is_in_scope(self, asset: str | Target, program_id: str | uuid.UUID | None = None) -> ScopeDecision:
        """Evaluate a target. With ``program_id`` only that program's rules apply.

        Without ``program_id`` every program is evaluated; the decision is allowed
        if at least one program allows it, and ``allowed_program_ids`` lists them.
        """
        try:
            target = asset if isinstance(asset, Target) else classify_target(asset)
        except InvalidTarget as exc:
            return ScopeDecision(allowed=False, reason=f"invalid target: {exc}", match_kind="none")
        if target.kind == "wildcard":
            return ScopeDecision(
                allowed=False,
                reason="wildcard patterns are not scannable targets",
                target=target.value,
                target_type=target.kind,
                match_kind="none",
            )

        if program_id is not None:
            return self._evaluate_program(str(program_id), target)

        decisions = [self._evaluate_program(pid, target) for pid in self._by_program]
        allowed = [d for d in decisions if d.allowed]
        if allowed:
            first = allowed[0]
            first.allowed_program_ids = [d.program_id for d in allowed if d.program_id]
            return first
        excluded = [d for d in decisions if d.match_kind == "explicit_exclusion"]
        if excluded:
            return excluded[0]
        return ScopeDecision(
            allowed=False,
            reason="not in approved scope",
            target=target.value,
            target_type=target.kind,
            match_kind="none",
        )
