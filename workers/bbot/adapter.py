"""BBOT adapter: broad discovery/enrichment for an approved domain.

BBOT is treated as one more discovery source - it does not replace httpx/tlsx/katana.
By default only modules flagged ``passive`` and ``safe`` run (third-party data sources and
DNS), so nothing is sent to the target. BBOT's own scope is the job's domain with the
program's exclusions as blacklist, and *every* result is re-evaluated by the platform's
ScopeEngine: only in-scope names/IPs become assets; everything else stays a passive
observation in bb-bbot-*. Speculative events (module ``speculate``) are not treated as
observations.

BBOT lives in its own virtualenv (/opt/bbot) because its dependency pins differ from the
platform's; it is invoked as a subprocess like every other tool.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tempfile
import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.models import Program
from app.models.enums import RelationshipType
from app.scope.normalize import InvalidTarget, Target, classify_target, normalize_asn, normalize_domain
from app.services import technology as tech
from app.services.asn import enrich_ip_asset
from app.services.assets import confidence_for, link_program_asset, swap_state, upsert_asset, upsert_relationship
from app.services.changes import Change, change_event, diff_ports
from app.services.events import build_event
from app.services.ipranges import CloudRangeIndex, tag_cloud
from workers.common.adapter import JobContext, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import raw_event
from workers.common.process import ToolError, run_tool
from workers.common.tooling import parse_jsonl

BINARY = os.environ.get("BBOT_BINARY", "bbot")
SPECULATIVE_MODULES = {"speculate"}


def build_argv(ctx: JobContext, output_dir: str, binary: str = BINARY) -> list[str]:
    s: Any = ctx.settings
    domain = normalize_domain(ctx.target.value)
    argv = [
        binary,
        "-t",
        domain,
        "-p",
        s.preset,
        "-y",
        "--json",
        "--no-deps",
        "-n",
        f"bb_{ctx.job_id.replace('-', '')[:12]}",
        "-o",
        output_dir,
        "-rf",
        *(["passive", "safe"] if s.passive_only else ["safe"]),
    ]
    if s.exclude_modules:
        argv += ["-em", *s.exclude_modules]
    blacklist = ctx.guard.engine.host_exclusions(ctx.program_id, domain)
    if blacklist:
        argv += ["-b", *blacklist]
    return argv


def scan_finished(records: list[dict[str, Any]]) -> bool:
    """BBOT exits 0 even on configuration errors; a final SCAN event proves the scan ran."""
    return any(r.get("type") == "SCAN" and "completed" in str(r.get("discovery_context", "")) for r in records)


def bbot_event_body(rec: dict[str, Any]) -> dict[str, Any]:
    data = rec.get("data")
    return {
        "bbot": {
            "type": rec.get("type"),
            "module": rec.get("module"),
            "scope_distance": rec.get("scope_distance"),
            "tags": rec.get("tags") or [],
            "discovery_context": rec.get("discovery_context"),
            "id": rec.get("id"),
            "parent": rec.get("parent"),
            "host": rec.get("host"),
            "data": data if isinstance(data, str) else None,
            "data_json": rec.get("data_json") if isinstance(rec.get("data_json"), dict) else None,
        }
    }


class BbotAdapter(ScannerAdapter):
    name = "bbot"
    queue = "bbot"
    tool = "bbot"
    contacts_target = False  # passive by default; active modules would need passive_only=false

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = os.environ.get("BBOT_VERSION", "unknown")

    def tool_version(self) -> str:
        return self._version

    def execute(self, ctx: JobContext) -> RawOutput:
        with tempfile.TemporaryDirectory(prefix="bbot-") as outdir:
            result = run_tool(
                build_argv(ctx, outdir, self.binary), timeout=ctx.deadline_seconds, is_cancelled=ctx.is_cancelled
            )
        raw = parse_jsonl(result.stdout_lines)
        if result.returncode != 0 or not scan_finished(raw.records):
            errors = [ln for ln in result.stderr_tail.splitlines() if "ERRR" in ln or "Error" in ln]
            raise ToolError(f"bbot did not complete (exit {result.returncode}): {' | '.join(errors)[-1000:]}")
        raw.meta = {"duration": round(result.duration, 3)}
        return raw

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        program = session.get(Program, uuid.UUID(ctx.program_id))
        assert program is not None
        engine = ctx.guard.engine
        index = CloudRangeIndex.cached()
        parent_asset = uuid.UUID(ctx.asset_id) if ctx.asset_id else None
        id_map: dict[str, uuid.UUID] = {}
        ports: dict[uuid.UUID, set[int]] = defaultdict(set)
        counts: dict[str, int] = defaultdict(int)

        def in_scope_asset(value: str, reason: str) -> tuple[Any, Any, bool] | None:
            try:
                target = classify_target(value)
            except InvalidTarget:
                return None
            decision = engine.is_in_scope(target, ctx.program_id)
            if not decision.allowed:
                return None
            asset, created = upsert_asset(session, target, confidence=confidence_for("bbot", reason[:480]))
            link_program_asset(session, ctx.program_id, asset, decision)
            if target.kind in ("ipv4", "ipv6"):
                tag_cloud(asset, index.lookup(target.value))
                enrich_ip_asset(session, asset, target.value, source="bbot")
            return asset, decision, created

        for rec in raw.records:
            etype, module = rec.get("type"), rec.get("module")
            out.add("bbot", raw_event("bb-bbot-raw", ec, rec))
            if etype == "SCAN" or module in SPECULATIVE_MODULES:
                counts["ignored"] += 1
                continue
            reason = f"bbot {module}: {rec.get('discovery_context') or etype}"
            body = bbot_event_body(rec)
            asset_ctx = ec
            allowed = False
            if etype in ("DNS_NAME", "IP_ADDRESS") and isinstance(rec.get("data"), str):
                value = rec["data"]
                got = in_scope_asset(value if etype == "IP_ADDRESS" else value.lower().rstrip("."), reason)
                if got:
                    asset, _, created = got
                    allowed = True
                    id_map[str(rec.get("id"))] = asset.id
                    asset_ctx = ec.with_asset(str(asset.id), asset.asset_type, asset.normalized_value)
                    if parent_asset and asset.id != parent_asset:
                        upsert_relationship(
                            session,
                            asset.id,
                            parent_asset,
                            RelationshipType.DISCOVERED_FROM.value,
                            source="bbot",
                            confidence=0.7,
                            metadata={"module": module},
                        )
                    if created:
                        kind = (
                            "NEW_IP"
                            if etype == "IP_ADDRESS"
                            else ("NEW_DOMAIN" if asset.asset_type == "domain" else "NEW_SUBDOMAIN")
                        )
                        out.add(
                            "changes",
                            change_event(Change(kind, "bbot", None, asset.normalized_value), asset_ctx, confidence=0.7),
                        )
                    for ip in rec.get("resolved_hosts") or []:
                        got_ip = in_scope_asset(str(ip), f"{asset.normalized_value} resolves to it (bbot)")
                        if got_ip:
                            upsert_relationship(
                                session,
                                asset.id,
                                got_ip[0].id,
                                RelationshipType.RESOLVES_TO.value,
                                source="bbot",
                                confidence=0.7,
                            )
            elif etype == "ASN" and isinstance(rec.get("data_json"), dict):
                with contextlib.suppress(InvalidTarget, TypeError):
                    asn = normalize_asn(str(rec["data_json"].get("asn")))
                    asn_asset, _ = upsert_asset(
                        session,
                        Target(kind="asn", value=f"AS{asn}", asn=asn),
                        confidence=confidence_for("bbot", reason[:480]),
                    )
                    body["asn"] = {"number": asn}
                    parent = id_map.get(str(rec.get("parent")))
                    if parent:
                        upsert_relationship(
                            session,
                            parent,
                            asn_asset.id,
                            RelationshipType.BELONGS_TO_ASN.value,
                            source="bbot",
                            confidence=0.7,
                        )
            elif etype in ("TECHNOLOGY", "OPEN_TCP_PORT") and rec.get("host"):
                got = in_scope_asset(str(rec["host"]).lower(), reason)
                if got:
                    allowed = True
                    host_asset = got[0]
                    asset_ctx = ec.with_asset(str(host_asset.id), host_asset.asset_type, host_asset.normalized_value)
                    if etype == "TECHNOLOGY":
                        raw_t = str((rec.get("data_json") or {}).get("technology") or "")
                        t = (
                            tech.from_cpe(raw_t)
                            if raw_t.startswith("cpe:")
                            else (tech.from_name(raw_t, "bbot") if raw_t else None)
                        )
                        if t is not None:
                            body["technology"] = t.to_dict()
                            tech_asset, _ = upsert_asset(
                                session,
                                Target(kind="technology", value=t.name),
                                confidence=confidence_for("bbot", reason[:480]),
                            )
                            upsert_relationship(
                                session,
                                host_asset.id,
                                tech_asset.id,
                                RelationshipType.USES_TECHNOLOGY.value,
                                source="bbot",
                                confidence=t.confidence,
                                metadata={"version": t.version, "cpe": raw_t or None},
                            )
                    else:
                        with contextlib.suppress(ValueError, AttributeError):
                            port = int(str(rec.get("data")).rsplit(":", 1)[1])
                            ports[host_asset.id].add(port)
                            body["network"] = {"port": port}
            else:
                host = rec.get("host")
                if isinstance(host, str):
                    with contextlib.suppress(InvalidTarget):
                        allowed = engine.is_in_scope(classify_target(host.lower()), ctx.program_id).allowed
            counts[etype or "?"] += 1
            body["scope_check"] = {"allowed": allowed, "layer": "discovery"}
            out.add(
                "bbot",
                build_event(
                    index="bb-bbot", kind="event", category="discovery", type_=f"BBOT_{etype}", ctx=asset_ctx, body=body
                ),
            )
        for asset_id, port_set in ports.items():
            prev = swap_state(session, asset_id, "ports:bbot", {"ports": sorted(port_set)}, source="bbot")
            for c in diff_ports(prev, {"ports": sorted(port_set)}):
                out.add("changes", change_event(c, ec.with_asset(str(asset_id), None, None), confidence=0.5))
        out.summary = {
            "records": len(raw.records),
            "assets": len(id_map),
            "by_type": dict(counts),
            "malformed": len(raw.malformed),
            **raw.meta,
        }
        return out
