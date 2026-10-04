"""katana adapter: crawl one approved URL/host and build a URL + endpoint inventory.

Safety: crawl scope is the exact host (``-fs fqdn``); the program's URL exclusions for
that host become ``-cos`` regexes so excluded paths are never requested; redirects are
not followed unless the policy allows it; depth, rate, concurrency, wall-clock and the
number of URLs (MAX_URLS_PER_CRAWL) are bounded. Every discovered URL is re-checked
against scope before it is stored (layer 3).

Note: katana cannot pin connections to pre-validated IPs, so DNS-rebinding protection
for crawling relies on the pre-flight resolution check plus output validation.
"""

from __future__ import annotations

import os
import re
import shutil
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Program
from app.models.enums import LifecycleStage
from app.scope.normalize import InvalidTarget, NormalizedURL, normalize_url
from app.services.assets import confidence_for, mark_scanned, swap_state, upsert_asset
from app.services.changes import Change, change_event
from app.services.events import build_event
from app.services.scans import scope_blocked_event
from workers.common.adapter import JobContext, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import error_event, raw_event, snapshot_event
from workers.common.process import ToolError, run_tool
from workers.common.tooling import binary_version, parse_jsonl, request_headers

BINARY = os.environ.get("KATANA_BINARY", "katana")
MAX_ENDPOINTS_IN_STATE = 5000


def start_url(ctx: JobContext) -> NormalizedURL:
    t = ctx.target
    if t.kind == "url" and t.url is not None:
        return t.url
    return normalize_url(f"https://{t.value}/")


def exclusion_regexes(ctx: JobContext, url: NormalizedURL) -> list[str]:
    out = []
    for ex in ctx.guard.engine.url_exclusions(ctx.program_id, url.host):
        if ex.scheme != url.scheme or ex.port != url.port:
            continue
        path = ex.path.rstrip("/") or "/"
        out.append("^" + re.escape(url.origin) + re.escape(path) + r"(/|\?|#|$)")
    return out


def max_urls(ctx: JobContext) -> int:
    return min(int(getattr(ctx.settings, "max_urls", 500)), get_settings().max_urls_per_crawl)


def build_argv(ctx: JobContext, binary: str = BINARY) -> list[str]:
    s: Any = ctx.settings
    url = start_url(ctx)
    depth = min(int(s.depth), get_settings().max_crawl_depth)
    argv = [
        binary,
        "-u",
        url.normalized_url,
        "-jsonl",
        "-silent",
        "-nc",
        "-duc",
        "-or",
        "-ob",
        "-fs",
        "fqdn",
        "-d",
        str(depth),
        "-c",
        str(s.concurrency),
        "-p",
        "1",
        "-rl",
        str(s.rate_limit),
        "-timeout",
        str(s.timeout),
        "-retry",
        str(s.retries),
        "-ct",
        f"{int(ctx.deadline_seconds)}s",
    ]
    if s.js_crawl:
        argv.append("-jc")
    if s.jsluice:
        argv.append("-jsl")
    known = set(s.known_files)
    if known and depth >= 3:  # katana needs depth >= 3 for known files
        argv += ["-kf", "all" if known == {"robotstxt", "sitemapxml"} else known.pop()]
    if not s.follow_redirects:
        argv.append("-dr")
    for header in request_headers():
        argv += ["-H", header]
    for rx in exclusion_regexes(ctx, url):
        argv += ["-cos", rx]
    return argv


def normalize_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    req = rec.get("request") or {}
    endpoint = req.get("endpoint")
    if not isinstance(endpoint, str):
        return None
    url = normalize_url(endpoint)
    source = req.get("source")
    tag = (req.get("tag") or "").lower()
    js = tag in ("js", "jsluice") or (isinstance(source, str) and source.split("?")[0].endswith(".js"))
    return {
        "_url": url,
        "url": {
            "original": endpoint,
            "full": url.normalized_url,
            "domain": url.host,
            "scheme": url.scheme,
            "port": url.port,
            "path": url.path,
            "query": url.query or None,
            "hash": url.url_hash,
            "endpoint_hash": url.endpoint_hash,
            "parameters": list(url.parameters),
            "method": req.get("method"),
            "parent": source,
            "js_discovered": js,
        },
        "katana": {"tag": req.get("tag"), "attribute": req.get("attribute")},
        "http": {"response": {"status_code": (rec.get("response") or {}).get("status_code")}},
    }


class KatanaAdapter(ScannerAdapter):
    name = "katana"
    queue = "katana"
    tool = "katana"

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = binary_version(self.binary, "KATANA_VERSION")

    def tool_version(self) -> str:
        return self._version

    def execute(self, ctx: JobContext) -> RawOutput:
        limit = max_urls(ctx)
        result = run_tool(
            build_argv(ctx, self.binary),
            timeout=ctx.deadline_seconds + 30,
            is_cancelled=ctx.is_cancelled,
            max_lines=limit,
        )
        if not result.ok:
            raise ToolError(f"katana exited {result.returncode}: {result.stderr_tail[-1000:]}")
        raw = parse_jsonl(result.stdout_lines)
        raw.meta = {"duration": round(result.duration, 3), "url_limit_reached": result.limit_reached}
        return raw

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        out.add("katana", *(raw_event("bb-katana-raw", ec, r) for r in raw.records))
        out.add("katana", *(raw_event("bb-katana-raw", ec, ln, malformed=True) for ln in raw.malformed))
        program = session.get(Program, uuid.UUID(ctx.program_id))
        assert program is not None
        root = start_url(ctx)
        host_asset, _ = (
            upsert_asset(session, root.host, confidence=confidence_for("katana", "crawled host responded"))
            if root.host_type == "domain"
            else (None, False)
        )
        endpoints: dict[str, str] = {}
        blocked = js_count = 0
        seen_urls: set[str] = set()
        for rec in raw.records:
            try:
                obs = normalize_record(rec)
            except InvalidTarget:
                obs = None
            if obs is None:
                out.add("ops", error_event(ec, "MALFORMED_SCANNER_OUTPUT", "unusable katana record"))
                continue
            url: NormalizedURL = obs.pop("_url")
            decision = ctx.guard.validate_output(url.normalized_url)
            if not decision.allowed:
                blocked += 1
                if blocked <= 20:  # bounded: crawls can surface many off-scope links
                    out.add(
                        "changes",
                        scope_blocked_event(
                            decision, program=program, scanner=self.name, layer="scanner_output", job_id=ctx.job_id
                        ),
                    )
                continue
            if url.url_hash in seen_urls:
                continue
            seen_urls.add(url.url_hash)
            js_count += int(obs["url"]["js_discovered"])
            endpoints.setdefault(
                url.endpoint_hash, url.endpoint + ("?" + "&".join(url.parameters) if url.parameters else "")
            )
            uctx = ec.with_asset(str(host_asset.id) if host_asset else None, "url", url.normalized_url)
            out.add(
                "katana",
                build_event(index="bb-katana", kind="event", category="web", type_="CRAWLED_URL", ctx=uctx, body=obs),
            )
            out.add(
                "katana",
                build_event(
                    index="bb-urls",
                    kind="state",
                    category="web",
                    type_="URL_INVENTORY",
                    ctx=uctx,
                    body=obs,
                    doc_id=url.url_hash,
                ),
            )
        # endpoint-level change detection per origin (first crawl = baseline, no changes)
        state = {"endpoints": dict(sorted(endpoints.items())[:MAX_ENDPOINTS_IN_STATE])}
        owner = host_asset.id if host_asset else uuid.UUID(ctx.asset_id) if ctx.asset_id else None
        changes: list[Change] = []
        if owner is not None:
            prev = swap_state(session, owner, f"crawl:{root.origin}", state, source="katana")
            if prev is not None:
                prev_eps = prev.get("endpoints", {})
                for h, ep in sorted(endpoints.items()):
                    if h not in prev_eps:
                        changes.append(Change("NEW_ENDPOINT", "url.path", None, f"{root.origin}{ep}"))
            mark_scanned(session, owner, stage=LifecycleStage.CRAWLED.value, changed=bool(changes), active=None)
        actx = ec.with_asset(str(owner) if owner else None, "domain" if host_asset else None, root.host)
        out.add("changes", *(change_event(c, actx, confidence=0.9) for c in changes))
        out.add(
            "assets",
            snapshot_event(actx, {f"crawl:{root.origin}": {"endpoints": len(endpoints), "urls": len(seen_urls)}}),
        )
        out.summary = {
            "records": len(raw.records),
            "urls": len(seen_urls),
            "endpoints": len(endpoints),
            "js_discovered": js_count,
            "scope_blocked": blocked,
            "new_endpoints": len(changes),
            "malformed": len(raw.malformed),
            **raw.meta,
        }
        return out
