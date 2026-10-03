"""Worker-side scope enforcement (defense-in-depth layers 2 and 3).

Layer 2 - before execution: re-evaluate the job target against *fresh* scope
          from PostgreSQL, and validate DNS resolution (refuse private/reserved
          addresses unless the IP itself is explicitly in scope).
Layer 3 - after execution: every host/URL/IP in scanner output is re-checked;
          results outside scope are dropped and reported as SCOPE_BLOCKED.
Any exception => blocked (fail closed).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app.models.enums import BlockReason
from app.scope.engine import ScopeDecision, ScopeEngine
from app.scope.normalize import Target, classify_target
from app.scope.service import load_rules


class ScopeBlockedError(RuntimeError):
    def __init__(self, reason: BlockReason, detail: str, decision: ScopeDecision | None = None):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.decision = decision


def _is_sensitive(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"))
    )


@dataclass
class ScopeGuard:
    program_id: str
    engine: ScopeEngine
    allow_private: bool = False
    pinned_ips: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, session: Session, program_id: str, *, allow_private: bool) -> ScopeGuard:
        try:
            engine = ScopeEngine(load_rules(session, program_id))
        except Exception as exc:
            raise ScopeBlockedError(BlockReason.SCOPE_UNAVAILABLE, f"scope unavailable: {exc}") from exc
        return cls(program_id=program_id, engine=engine, allow_private=allow_private)

    # --- layer 2 -----------------------------------------------------------
    def check_target(self, target: Target | str) -> ScopeDecision:
        try:
            decision = self.engine.is_in_scope(target, self.program_id)
        except Exception as exc:
            raise ScopeBlockedError(BlockReason.SCOPE_UNAVAILABLE, f"scope evaluation failed: {exc}") from exc
        if not decision.allowed:
            reason = BlockReason.EXCLUDED if decision.match_kind == "explicit_exclusion" else BlockReason.NOT_IN_SCOPE
            raise ScopeBlockedError(reason, decision.reason, decision)
        return decision

    def _ip_allowed(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if not _is_sensitive(ip) or self.allow_private:
            return True
        # Private address is only acceptable when that IP is itself explicitly in scope.
        return self.engine.is_in_scope(str(ip), self.program_id).allowed

    def resolve_and_pin(self, target: Target) -> set[str]:
        """Resolve the target host, validate every address and pin them for the scan."""
        host: str | None = None
        if target.kind == "domain":
            host = target.value
        elif target.kind == "url" and target.url is not None:
            host = target.url.host if target.url.host_type == "domain" else None
            if host is None:
                ip = ipaddress.ip_address(target.url.host)
                if not self._ip_allowed(ip):
                    raise ScopeBlockedError(BlockReason.PRIVATE_ADDRESS, f"{ip} is private/reserved")
                self.pinned_ips = {str(ip)}
                return self.pinned_ips
        elif target.kind in ("ipv4", "ipv6") and target.ip is not None:
            if not self._ip_allowed(target.ip):
                raise ScopeBlockedError(BlockReason.PRIVATE_ADDRESS, f"{target.ip} is private/reserved")
            self.pinned_ips = {str(target.ip)}
            return self.pinned_ips
        if host is None:
            return set()
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return set()  # does not resolve: nothing will be contacted
        ips = {ipaddress.ip_address(str(info[4][0]).split("%")[0]) for info in infos}
        bad = sorted(str(ip) for ip in ips if not self._ip_allowed(ip))
        if bad:
            raise ScopeBlockedError(
                BlockReason.PRIVATE_ADDRESS,
                f"{host} resolves to private/reserved address(es) not in scope: {', '.join(bad)}",
            )
        self.pinned_ips = {
            str(ip.ipv4_mapped or ip) if isinstance(ip, ipaddress.IPv6Address) else str(ip) for ip in ips
        }
        return self.pinned_ips

    # --- layer 3 -----------------------------------------------------------
    def validate_output(self, value: str, *, ip: str | None = None) -> ScopeDecision:
        """Return the decision for a host/URL seen in scanner output (never raises)."""
        try:
            decision = self.engine.is_in_scope(classify_target(value), self.program_id)
        except Exception as exc:
            return ScopeDecision(allowed=False, reason=f"unparseable scanner output target: {exc}", target=value)
        if decision.allowed and ip and self.pinned_ips and ip not in self.pinned_ips:
            return ScopeDecision(allowed=False, reason=f"connected IP {ip} differs from validated IPs", target=value)
        return decision
