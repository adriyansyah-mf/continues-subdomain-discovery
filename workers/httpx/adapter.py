"""httpx adapter: HTTP probing + fingerprinting of one approved target per job."""

from __future__ import annotations

import ipaddress
import os
import shutil
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.models import Program
from app.models.enums import LifecycleStage, RelationshipType
from app.scope.normalize import InvalidTarget, Target, classify_target, normalize_url
from app.services import technology as tech
from app.services.asn import AsnLookup, enrich_ip_asset
from app.services.assets import (
    confidence_for,
    link_program_asset,
    mark_scanned,
    swap_state,
    upsert_asset,
    upsert_relationship,
)
from app.services.changes import Change, change_event, diff_http
from app.services.events import build_event
from app.services.ipranges import CloudRangeIndex, tag_cloud
from app.services.scans import scope_blocked_event
from workers.common.adapter import JobContext, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import error_event, raw_event, snapshot_event
from workers.common.process import ToolError, run_tool
from workers.common.tooling import binary_version, parse_jsonl, request_headers

# Absolute path in the image (see workers/common/Dockerfile); falls back to PATH for local runs.
BINARY = os.environ.get("HTTPX_BINARY", "httpx")


def build_argv(ctx: JobContext, binary: str = BINARY) -> list[str]:
    """Every value comes from validated job/policy fields; there is no free-form flag passthrough."""
    s = ctx.settings
    t = ctx.target
    target = t.url.normalized_url if t.kind == "url" and t.url else (f"[{t.value}]" if t.kind == "ipv6" else t.value)
    argv = [
        binary,
        "-u",
        target,
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-sc",
        "-title",
        "-server",
        "-ip",
        "-cname",
        "-cdn",
        "-rt",
        "-cl",
        "-location",
        "-rl",
        str(s.rate_limit),
        "-t",
        str(s.concurrency),
        "-timeout",
        str(s.timeout),
        "-retries",
        str(s.retries),
    ]
    if getattr(s, "tech_detect", True):
        argv.append("-td")
    if getattr(s, "favicon", True):
        argv.append("-favicon")
    if getattr(s, "follow_host_redirects", False):
        argv.append("-fhr")  # same-host redirects only; cross-host redirects are never followed
    ports = getattr(s, "ports", [])
    if ports and t.kind != "url":
        argv += ["-ports", ",".join(str(p) for p in ports)]
    for header in request_headers():
        argv += ["-H", header]
    if ctx.guard.pinned_ips:
        # Pin connections to the addresses validated by the scope guard (DNS rebinding protection).
        argv += ["-allow", ",".join(sorted(ctx.guard.pinned_ips))]
    return argv


def _ms(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        if value.endswith("ms"):
            return float(value[:-2])
        if value.endswith("µs"):
            return float(value[:-2]) / 1000
        if value.endswith("s"):
            return float(value[:-1]) * 1000
    except ValueError:
        return None
    return None


def normalize_record(rec: dict[str, Any]) -> dict[str, Any]:
    """Map one httpx JSON record to the platform's http observation fields (pure function)."""
    url = normalize_url(rec["url"])
    techs = [tech.from_wappalyzer(x) for x in rec.get("tech") or [] if isinstance(x, str)]
    if rec.get("webserver"):
        server_tech = tech.from_server_header(str(rec["webserver"]))
        if server_tech:
            techs.append(server_tech)
    techs = tech.merge(techs)
    ip = rec.get("host_ip") or rec.get("host")
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:
        ip = None
    return {
        "url": {
            "original": rec.get("url"),
            "full": url.normalized_url,
            "domain": url.host,
            "scheme": url.scheme,
            "port": url.port,
            "path": url.path,
            "hash": url.url_hash,
        },
        "http": {
            "response": {
                "status_code": rec.get("status_code"),
                "content_length": rec.get("content_length"),
                "content_type": rec.get("content_type"),
                "time_ms": _ms(rec.get("time")),
            },
            "title": rec.get("title"),
            "webserver": rec.get("webserver"),
            "location": rec.get("location"),
            "cdn": {"detected": bool(rec.get("cdn")), "name": rec.get("cdn_name"), "type": rec.get("cdn_type")},
            "favicon": {
                "mmh3": rec.get("favicon"),
                "source": "httpx",
                "confidence": 0.5 if rec.get("favicon") else None,
            },
        },
        "host": {"ip": ip, "ips": sorted(set(rec.get("a") or []) | set(rec.get("aaaa") or []))},
        "dns": {"cname": rec.get("cname") or []},
        "network": {"port": url.port},
        "technology": [t.to_dict() for t in techs],
        "_url": url,
    }


class HttpxAdapter(ScannerAdapter):
    name = "httpx"
    queue = "httpx"
    tool = "httpx"

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = binary_version(self.binary, "HTTPX_VERSION")

    def tool_version(self) -> str:
        return self._version

    def execute(self, ctx: JobContext) -> RawOutput:
        result = run_tool(build_argv(ctx, self.binary), timeout=ctx.deadline_seconds, is_cancelled=ctx.is_cancelled)
        if result.returncode != 0:
            raise ToolError(f"httpx exited {result.returncode}: {result.stderr_tail[-1000:]}")
        raw = parse_jsonl(result.stdout_lines)
        raw.meta = {"duration": round(result.duration, 3), "truncated": result.truncated}
        return raw

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        out.add("httpx", *(raw_event("bb-httpx-raw", ec, r) for r in raw.records))
        out.add("httpx", *(raw_event("bb-httpx-raw", ec, line, malformed=True) for line in raw.malformed))
        if raw.malformed:
            out.add("ops", error_event(ec, "MALFORMED_SCANNER_OUTPUT", f"{len(raw.malformed)} malformed httpx lines"))

        accepted = blocked = changes_n = 0
        any_live = False
        program = session.get(Program, ctx.program_id)
        for rec in raw.records:
            if rec.get("failed") or not rec.get("url"):
                continue
            try:
                obs = normalize_record(rec)
            except (InvalidTarget, KeyError) as exc:
                out.add("ops", error_event(ec, "MALFORMED_SCANNER_OUTPUT", f"unusable httpx record: {exc}"))
                continue
            url = obs.pop("_url")
            # Layer 3: the URL actually probed (and the IP connected to) must be in scope.
            decision = ctx.guard.validate_output(url.normalized_url, ip=obs["host"]["ip"])
            if not decision.allowed:
                blocked += 1
                if program is not None:
                    out.add(
                        "changes",
                        scope_blocked_event(
                            decision, program=program, scanner=self.name, layer="scanner_output", job_id=ctx.job_id
                        ),
                    )
                continue
            accepted += 1
            any_live = True
            changes: list[Change] = []
            # --- assets & graph ------------------------------------------------
            url_asset, url_new = upsert_asset(
                session,
                classify_target(url.normalized_url),
                confidence=confidence_for("httpx", "responded to HTTP probe"),
            )
            link_program_asset(session, ctx.program_id, url_asset, decision)
            if url_new:
                changes.append(Change("NEW_URL", "url.full", None, url.normalized_url))
            host_asset_id = None
            if url.host_type == "domain":
                host_asset, _ = upsert_asset(session, url.host, confidence=confidence_for("httpx", "HTTP host"))
                host_asset_id = host_asset.id
                upsert_relationship(
                    session,
                    host_asset.id,
                    url_asset.id,
                    RelationshipType.HAS_URL.value,
                    source="httpx",
                    confidence=0.95,
                )
                ip = obs["host"]["ip"]
                if ip:
                    ip_target = classify_target(ip)
                    ip_asset, ip_new = upsert_asset(
                        session, ip_target, confidence=confidence_for("httpx", f"{url.host} connected to {ip}")
                    )
                    link_program_asset(
                        session, ctx.program_id, ip_asset, ctx.guard.engine.is_in_scope(ip_target, ctx.program_id)
                    )
                    upsert_relationship(
                        session,
                        host_asset.id,
                        ip_asset.id,
                        RelationshipType.RESOLVES_TO.value,
                        source="httpx",
                        confidence=0.95,
                    )
                    if ip_new:
                        changes.append(Change("NEW_IP", "host.ip", None, ip))
                    tag_cloud(ip_asset, CloudRangeIndex.cached().lookup(ip))
                    enrich_ip_asset(session, ip_asset, ip, source="httpx")
            for t in obs["technology"]:
                tech_asset, _ = upsert_asset(
                    session,
                    Target(kind="technology", value=t["name"]),
                    confidence=confidence_for("httpx", f"fingerprinted by {t['source']}"),
                )
                upsert_relationship(
                    session,
                    url_asset.id,
                    tech_asset.id,
                    RelationshipType.USES_TECHNOLOGY.value,
                    source="httpx",
                    confidence=t["confidence"],
                    metadata={"version": t["version"], "version_confidence": t["version_confidence"]},
                )
            # --- state & change detection --------------------------------------
            attribution = CloudRangeIndex.cached().lookup(obs["host"]["ip"]) if obs["host"]["ip"] else None
            if attribution is not None:
                obs["cloud"] = attribution.to_event()
            asn_info = AsnLookup.lookup(obs["host"]["ip"], session) if obs["host"]["ip"] else None
            if asn_info is not None:
                obs["asn"] = asn_info.to_event()
            state = {
                "cloud": attribution.provider if attribution else None,
                "asn": asn_info.number if asn_info else None,
                "status_code": obs["http"]["response"]["status_code"],
                "title": obs["http"]["title"],
                "webserver": obs["http"]["webserver"],
                "technologies": sorted(f"{t['name']}" for t in obs["technology"]),
                "ip": obs["host"]["ip"],
                "cdn": obs["http"]["cdn"]["name"],
            }
            facet_owner = host_asset_id or url_asset.id
            prev = swap_state(session, facet_owner, f"http:{url.origin}", state, source="httpx")
            changes += diff_http(prev, state)
            asset_ctx = ec.with_asset(str(url_asset.id), "url", url.normalized_url)
            out.add(
                "httpx",
                build_event(
                    index="bb-http",
                    kind="event",
                    category="web",
                    type_="HTTP_OBSERVATION",
                    ctx=asset_ctx,
                    body={k: v for k, v in obs.items()},
                ),
            )
            out.add("changes", *(change_event(c, asset_ctx, confidence=0.95) for c in changes))
            changes_n += len(changes)
            stage = LifecycleStage.TECH_IDENTIFIED if obs["technology"] else LifecycleStage.HTTP_PROBED
            mark_scanned(session, url_asset.id, stage=stage.value, changed=bool(changes), active=True)
            if host_asset_id:
                mark_scanned(session, host_asset_id, stage=stage.value, changed=bool(changes), active=True)
            out.add("assets", snapshot_event(asset_ctx, {f"http:{url.origin}": state}))

        if ctx.asset_id and not any_live:
            mark_scanned(session, uuid.UUID(ctx.asset_id), stage=LifecycleStage.VALIDATED.value, active=False)
        out.summary = {
            "records": len(raw.records),
            "accepted": accepted,
            "scope_blocked": blocked,
            "malformed": len(raw.malformed),
            "changes": changes_n,
            **raw.meta,
        }
        return out
