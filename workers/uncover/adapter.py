"""uncover adapter: passive discovery through third-party search engines.

Flow: CDB domain -> uncover -> IP/host results -> ScopeEngine -> approved? -> follow-up
(tlsx/httpx per policy). A search-engine result is *never* authorisation: results that
are not in the program's scope are recorded as passive observations only (scope.status
"out") and are never scanned. No traffic goes to the target (``contacts_target=False``).

Engines need API keys (environment, e.g. SHODAN_API_KEY); a job whose engines have no
key fails immediately (non-retryable) instead of retrying.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import shutil
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models.enums import RelationshipType
from app.scope.normalize import InvalidTarget, classify_target, normalize_domain
from app.services.asn import enrich_ip_asset
from app.services.assets import confidence_for, link_program_asset, upsert_asset, upsert_relationship
from app.services.audit import Principal
from app.services.changes import Change, change_event
from app.services.events import build_event
from app.services.ipranges import CloudRangeIndex, tag_cloud
from workers.common.adapter import JobContext, NonRetryableError, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import raw_event
from workers.common.followup import create_followups
from workers.common.process import ToolError, run_tool
from workers.common.tooling import binary_version, parse_jsonl

BINARY = os.environ.get("UNCOVER_BINARY", "uncover")
PRINCIPAL = Principal(name="worker:uncover", role="operator")

# engine -> environment variables uncover reads (any one present = configured)
ENGINE_KEYS: dict[str, tuple[str, ...]] = {
    "shodan": ("SHODAN_API_KEY",),
    "censys": ("CENSYS_API_TOKEN", "CENSYS_API_ID"),
    "fofa": ("FOFA_KEY",),
    "netlas": ("NETLAS_API_KEY",),
    "zoomeye": ("ZOOMEYE_API_KEY",),
    "quake": ("QUAKE_TOKEN",),
    "hunter": ("HUNTER_API_KEY",),
    "criminalip": ("CRIMINALIP_API_KEY",),
    "onyphe": ("ONYPHE_API_KEY",),
    "driftnet": ("DRIFTNET_API_KEY",),
    "odin": ("ODIN_API_KEY",),
}


def query_for(engine: str, domain: str) -> str:
    """Engine-specific query. ``domain`` is a validated FQDN (no quotes/spaces possible)."""
    return {
        "shodan": f'ssl.cert.subject.cn:"{domain}"',
        "fofa": f'domain="{domain}"',
        "censys": domain,
        "netlas": f"host:{domain}",
        "zoomeye": f'hostname:"{domain}"',
    }.get(engine, domain)


def configured_engines(engines: list[str]) -> list[str]:
    return [e for e in engines if any(os.environ.get(k) for k in ENGINE_KEYS.get(e, ()))]


def build_argv(ctx: JobContext, engines: list[str], binary: str = BINARY) -> list[str]:
    s: Any = ctx.settings
    domain = normalize_domain(ctx.target.value)
    argv = [
        binary,
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-l",
        str(s.limit),
        "-timeout",
        str(max(s.timeout, 30)),
        "-rl",
        str(s.rate_limit),
    ]
    for engine in engines:
        argv += ["-e", engine, "-q", query_for(engine, domain)]
    return argv


def result_targets(rec: dict[str, Any]) -> list[str]:
    """Hosts/IPs a result points at (normalized strings; invalid values dropped)."""
    out = []
    ip = rec.get("ip")
    if isinstance(ip, str):
        with contextlib.suppress(ValueError):
            out.append(str(ipaddress.ip_address(ip)))
    host = rec.get("host")
    if isinstance(host, str) and host and host != ip:
        with contextlib.suppress(InvalidTarget):
            out.append(normalize_domain(host))
    return out


class UncoverAdapter(ScannerAdapter):
    name = "uncover"
    queue = "discovery"
    tool = "uncover"
    contacts_target = False

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = binary_version(self.binary, "UNCOVER_VERSION")

    def tool_version(self) -> str:
        return self._version

    def execute(self, ctx: JobContext) -> RawOutput:
        wanted = list(getattr(ctx.settings, "engines", ["shodan"]))
        engines = configured_engines(wanted)
        if not engines:
            raise NonRetryableError(f"no API key configured for uncover engines {wanted} (see docs/scanner-workers.md)")
        result = run_tool(
            build_argv(ctx, engines, self.binary), timeout=ctx.deadline_seconds, is_cancelled=ctx.is_cancelled
        )
        if not result.ok:
            raise ToolError(f"uncover exited {result.returncode}: {result.stderr_tail[-1000:]}")
        raw = parse_jsonl(result.stdout_lines)
        raw.meta = {"duration": round(result.duration, 3), "engines": engines}
        return raw

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        out.add("assets", *(raw_event("bb-uncover-raw", ec, r) for r in raw.records))
        parent_id = uuid.UUID(ctx.asset_id) if ctx.asset_id else None
        index = CloudRangeIndex.cached()
        approved: list[uuid.UUID] = []
        in_scope = out_of_scope = 0
        seen: set[str] = set()
        for rec in raw.records:
            port = rec.get("port")
            for value in result_targets(rec):
                if value in seen:
                    continue
                seen.add(value)
                target = classify_target(value)
                decision = ctx.guard.engine.is_in_scope(target, ctx.program_id)
                body = {
                    "uncover": {
                        "engine": rec.get("source"),
                        "port": port,
                        "host": rec.get("host"),
                        "ip": rec.get("ip"),
                    },
                    "scope_check": {"allowed": decision.allowed, "reason": decision.reason, "layer": "discovery"},
                }
                if not decision.allowed:
                    out_of_scope += 1
                    out.add(
                        "assets",
                        build_event(
                            index="bb-uncover",
                            kind="event",
                            category="discovery",
                            type_="UNCOVER_RESULT",
                            body=body,
                            ctx=ec.with_asset(None, target.kind, value),
                        ),
                    )
                    continue
                in_scope += 1
                asset, created = upsert_asset(
                    session,
                    target,
                    confidence=confidence_for(
                        "uncover", f"returned by {rec.get('source') or 'uncover'} for {ctx.target.value}"
                    ),
                )
                link_program_asset(session, ctx.program_id, asset, decision)
                if parent_id:
                    upsert_relationship(
                        session,
                        asset.id,
                        parent_id,
                        RelationshipType.DISCOVERED_FROM.value,
                        source="uncover",
                        confidence=0.5,
                        metadata={"engine": rec.get("source")},
                    )
                if target.kind in ("ipv4", "ipv6"):
                    tag_cloud(asset, index.lookup(value))
                    asn_info = enrich_ip_asset(session, asset, value, source="uncover")
                    if asn_info:
                        body["asn"] = asn_info.to_event()
                actx = ec.with_asset(str(asset.id), asset.asset_type, value)
                out.add(
                    "assets",
                    build_event(
                        index="bb-uncover",
                        kind="event",
                        category="discovery",
                        type_="UNCOVER_RESULT",
                        ctx=actx,
                        body=body,
                    ),
                )
                if created:
                    kind = {"ipv4": "NEW_IP", "ipv6": "NEW_IP", "domain": "NEW_SUBDOMAIN"}.get(target.kind, "NEW_ASSET")
                    out.add("changes", change_event(Change(kind, "uncover", None, value), actx, confidence=0.5))
                approved.append(asset.id)
        scanners = list(getattr(ctx.settings, "followup_scanners", []))
        out.followup_job_ids = create_followups(
            session, ctx, scanners=scanners, asset_ids=approved, trigger=f"uncover:{ctx.job_id}", principal=PRINCIPAL
        )
        out.summary = {
            "records": len(raw.records),
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
            "malformed": len(raw.malformed),
            "followup_jobs": len(out.followup_job_ids),
            **raw.meta,
        }
        return out
