"""nuclei adapter: template scanning against one approved host/URL.

Safety: templates are a release pinned in the image (``-duc``, read-only image
layer, release marker cross-checked against ``NUCLEI_TEMPLATES_VERSION``) and are
never fetched at runtime; out-of-band testing is disabled (``-ni``, which also
excludes OAST templates); intrusive tags are excluded by default (policy);
severity/tags/template ids come from the validated policy only. nuclei cannot
restrict its requests to specific URL paths, so a host with any URL exclusion is
refused outright instead of risking requests to excluded paths. Every matched URL
is re-checked against scope before it is stored (layer 3).

Note: like katana, nuclei resolves DNS itself and cannot pin connections to
pre-validated IPs, so rebinding protection relies on the pre-flight resolution
check plus output validation.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import Program
from app.models.enums import BlockReason, LifecycleStage
from app.scope.normalize import InvalidTarget, NormalizedURL, normalize_url
from app.services.assets import confidence_for, mark_scanned, swap_state, upsert_asset
from app.services.changes import Change, change_event
from app.services.events import build_event
from app.services.scans import scope_blocked_event
from app.services.vuln.correlate import record_correlation
from workers.common.adapter import JobContext, NonRetryableError, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import error_event, raw_event, snapshot_event
from workers.common.process import ToolError, run_tool
from workers.common.scope_guard import ScopeBlockedError
from workers.common.tooling import binary_version, identification_header, parse_jsonl

BINARY = os.environ.get("NUCLEI_BINARY", "nuclei")
TEMPLATES_DIR = os.environ.get("NUCLEI_TEMPLATES_DIR", "/opt/pd/nuclei-templates")
RELEASE_FILE = os.environ.get("NUCLEI_TEMPLATES_RELEASE_FILE", "/opt/pd/nuclei-templates-release")
MAX_FINDINGS_IN_STATE = 2000
MAX_CVE_CORRELATIONS = 100  # one template family can reference dozens of CVEs
MAX_SCOPE_BLOCKED_EVENTS = 20


def target_host(ctx: JobContext) -> str:
    t = ctx.target
    if t.kind == "url" and t.url is not None:
        return t.url.host
    return t.value


def start_target(ctx: JobContext) -> str:
    """URL targets are scanned as given; bare hosts let nuclei probe both schemes."""
    t = ctx.target
    if t.kind == "url" and t.url is not None:
        return t.url.normalized_url
    return t.value


def enforce_exclusions(ctx: JobContext) -> None:
    """Refuse hosts with URL exclusions: nuclei requests arbitrary paths and cannot be constrained."""
    host = target_host(ctx)
    exclusions = ctx.guard.engine.url_exclusions(ctx.program_id, host)
    if exclusions:
        raise ScopeBlockedError(
            BlockReason.EXCLUDED,
            f"nuclei cannot avoid excluded URL paths and {host} has {len(exclusions)} "
            "URL exclusion(s); refusing to scan",
        )


def templates_release() -> str:
    """Pinned release from the image build, cross-checked against the env (fail closed on mismatch)."""
    pinned = os.environ.get("NUCLEI_TEMPLATES_VERSION", "").strip().lstrip("v")
    marker = Path(RELEASE_FILE).read_text().strip().lstrip("v") if Path(RELEASE_FILE).is_file() else ""
    if pinned and marker and pinned != marker:
        raise NonRetryableError(f"nuclei templates pin mismatch: env {pinned!r} != image {marker!r}")
    return pinned or marker or "unknown"


def template_args(settings: Any, templates_dir: str) -> list[str]:
    """Allow-list selection; empty = the whole pinned bundle.

    Path entries run as ``-t <bundle>/<rel>``. Id entries resolve *within* the bundle, so the
    bundle is passed with ``-t`` and each id restricts it (``-t <bundle> -id a -id b``); the
    policy schema rejects mixing both styles because nuclei cannot combine them in one run.
    """
    if not settings.templates:
        return ["-t", templates_dir]
    if "/" in settings.templates[0] or settings.templates[0].endswith((".yaml", ".yml")):
        return [x for ref in settings.templates for x in ("-t", f"{templates_dir.rstrip('/')}/{ref}")]
    return ["-t", templates_dir] + [x for ref in settings.templates for x in ("-id", ref)]


def build_argv(ctx: JobContext, binary: str = BINARY, templates_dir: str = TEMPLATES_DIR) -> list[str]:
    enforce_exclusions(ctx)
    s: Any = ctx.settings
    argv = [
        binary,
        "-u",
        start_target(ctx),
        "-j",
        "-silent",
        "-nc",
        "-duc",  # never check for/apply binary or template updates at runtime
        "-ni",  # disable out-of-bound (interactsh) testing; OAST templates are excluded
        "-or",  # omit request/response pairs from the output
        "-ot",  # omit the encoded template from the output
        *template_args(s, templates_dir),
        "-s",
        ",".join(s.severity),
        "-rl",
        str(s.rate_limit),
        "-c",
        str(s.concurrency),
        "-timeout",
        str(s.timeout),
        "-retries",
        str(s.retries),
    ]
    if s.exclude_tags:
        argv += ["-etags", ",".join(s.exclude_tags)]
    if s.tags:
        argv += ["-tags", ",".join(s.tags)]
    header = identification_header()
    if header:
        argv += ["-H", header]
    return argv


def _truncate(v: Any, n: int) -> str | None:
    if not isinstance(v, str) or not v:
        return None
    return v if len(v) <= n else v[: n - 1] + "…"


def _cve_ids(v: Any) -> list[str]:
    out = []
    for c in v or []:
        c = str(c).upper()
        if c.startswith("CVE-"):
            out.append(c)
    return out[:20]


def normalize_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    """One nuclei JSONL finding -> unified schema (None if unusable)."""
    template_id = rec.get("template-id")
    matched_at = rec.get("matched-at")
    info = rec.get("info") or {}
    if not isinstance(template_id, str) or not template_id or not isinstance(matched_at, str):
        return None
    url = normalize_url(matched_at)
    severity = str(info.get("severity") or "unknown").lower()
    classification = info.get("classification") or {}
    cves = _cve_ids(classification.get("cve-id"))
    cwes = [str(c).upper() for c in classification.get("cwe-id") or [] if str(c).upper().startswith("CWE-")][:20]
    return {
        "_url": url,
        "cves": cves,
        "nuclei": {
            "template_id": template_id,
            "template_path": _truncate(rec.get("template-path"), 300),
            "name": _truncate(info.get("name"), 300),
            "severity": severity,
            "matched_at": url.normalized_url,
            "host": _truncate(rec.get("host"), 300),
            "ip": rec.get("ip"),
            "tags": [str(t) for t in (info.get("tags") or [])][:20],
            "description": _truncate(info.get("description"), 2000),
            "reference": [str(r) for r in (info.get("reference") or [])][:10],
            "classification": {
                "cve": cves,
                "cwe": cwes,
                "cvss_metrics": _truncate(classification.get("cvss-metrics"), 100),
                "cvss_score": classification.get("cvss-score"),
            }
            if cves or cwes or classification.get("cvss-score") is not None
            else None,
            "type": rec.get("type"),
            "port": rec.get("port"),
            "matcher_status": bool(rec.get("matcher-status")),
            "extracted_results": [str(r) for r in (rec.get("extracted-results") or [])][:20],
            "curl_command": _truncate(rec.get("curl-command"), 600),
        },
        "url": {
            "original": matched_at,
            "full": url.normalized_url,
            "domain": url.host,
            "scheme": url.scheme,
            "port": url.port,
            "path": url.path,
            "query": url.query or None,
            "hash": url.url_hash,
        },
        "vulnerability": {"severity": severity, "title": info.get("name")},
    }


class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    queue = "nuclei"
    tool = "nuclei"

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = binary_version(self.binary, "NUCLEI_VERSION")

    def tool_version(self) -> str:
        return self._version

    def _check_templates(self, templates_dir: str) -> None:
        root = Path(templates_dir)
        if not root.is_dir() or not any(root.rglob("*.yaml")):
            raise NonRetryableError(f"nuclei templates missing or empty at {templates_dir} (broken image build)")

    def execute(self, ctx: JobContext) -> RawOutput:
        templates_dir = TEMPLATES_DIR
        self._check_templates(templates_dir)
        release = templates_release()
        result = run_tool(
            build_argv(ctx, self.binary, templates_dir),
            timeout=ctx.deadline_seconds + 30,
            is_cancelled=ctx.is_cancelled,
        )
        if not result.ok:
            raise ToolError(f"nuclei exited {result.returncode}: {result.stderr_tail[-1000:]}")
        raw = parse_jsonl(result.stdout_lines)
        raw.meta = {"duration": round(result.duration, 3), "templates_release": release}
        return raw

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        release = templates_release()
        ec = dataclasses.replace(ctx.event_ctx, template_version=release)
        out.add("nuclei", *(raw_event("bb-nuclei-raw", ec, r) for r in raw.records))
        out.add("nuclei", *(raw_event("bb-nuclei-raw", ec, ln, malformed=True) for ln in raw.malformed))
        program = session.get(Program, uuid.UUID(ctx.program_id))
        assert program is not None
        host = target_host(ctx)
        host_asset, _ = upsert_asset(session, host, confidence=confidence_for("nuclei", "vulnerability scan target"))

        findings: dict[str, tuple[str, str, str]] = {}  # hash -> (severity, template_id, url)
        by_severity: dict[str, int] = {}
        blocked = cve_correlations = 0
        for rec in raw.records:
            try:
                obs = normalize_record(rec)
            except InvalidTarget:
                obs = None
            if obs is None:
                out.add("ops", error_event(ec, "MALFORMED_SCANNER_OUTPUT", "unusable nuclei record"))
                continue
            url: NormalizedURL = obs.pop("_url")
            cves = obs.pop("cves")
            decision = ctx.guard.validate_output(url.normalized_url)
            if not decision.allowed:
                blocked += 1
                if blocked <= MAX_SCOPE_BLOCKED_EVENTS:
                    out.add(
                        "changes",
                        scope_blocked_event(
                            decision, program=program, scanner=self.name, layer="scanner_output", job_id=ctx.job_id
                        ),
                    )
                continue
            obs["nuclei"]["template_version"] = release
            sev = obs["nuclei"]["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            fh = hashlib.sha256(f"{obs['nuclei']['template_id']}|{url.normalized_url}".encode()).hexdigest()[:16]
            findings[fh] = (sev, obs["nuclei"]["template_id"], url.normalized_url)
            uctx = ec.with_asset(str(host_asset.id), "url", url.normalized_url)
            out.add(
                "nuclei",
                build_event(
                    index="bb-nuclei",
                    kind="event",
                    category="vulnerability",
                    type_="VULNERABILITY_DETECTED",
                    ctx=uctx,
                    body=obs,
                ),
            )
            for cve in cves:
                if cve_correlations >= MAX_CVE_CORRELATIONS:
                    break
                cve_correlations += 1
                events = record_correlation(
                    session,
                    asset=host_asset,
                    cve_id=cve,
                    source="nuclei",
                    status="detected",
                    evidence={
                        "template_id": obs["nuclei"]["template_id"],
                        "matched_at": url.normalized_url,
                        "finding_hash": fh,
                    },
                    ctx=uctx,
                )
                out.add("cve", *(e for e in events if e["bb"]["index"] == "bb-cve"))
                out.add("changes", *(e for e in events if e["bb"]["index"] == "bb-changes"))

        # finding-level change detection per host (first scan = baseline, no changes)
        state = {"findings": {h: list(v) for h, v in sorted(findings.items())[:MAX_FINDINGS_IN_STATE]}}
        prev = swap_state(session, host_asset.id, f"vulnscan:{host}", state, source="nuclei")
        changes: list[Change] = []
        if prev is not None:
            prev_findings = {h: tuple(v) for h, v in (prev.get("findings") or {}).items()}
            for h, (sev, tid, u) in sorted(findings.items()):
                if h not in prev_findings:
                    label = f"{tid} @ {u} ({sev})"
                    changes.append(Change("NEW_FINDING", "vuln.finding", None, label))
                    if sev == "critical":
                        changes.append(Change("NEW_CRITICAL_FINDING", "vuln.finding", None, label))
            for h, (sev, tid, u) in sorted(prev_findings.items()):
                if h not in findings:
                    changes.append(Change("FINDING_RESOLVED", "vuln.finding", f"{tid} @ {u} ({sev})", None))
        mark_scanned(
            session, host_asset.id, stage=LifecycleStage.VULN_SCANNED.value, changed=bool(changes), active=None
        )
        actx = ec.with_asset(str(host_asset.id), None, host)
        out.add("changes", *(change_event(c, actx, confidence=0.9) for c in changes))
        out.add(
            "assets",
            snapshot_event(actx, {f"vulnscan:{host}": {"findings": len(findings), "by_severity": by_severity}}),
        )
        out.summary = {
            "records": len(raw.records),
            "findings": len(findings),
            "by_severity": dict(sorted(by_severity.items())),
            "new_findings": sum(1 for c in changes if c.change_type == "NEW_FINDING"),
            "resolved_findings": sum(1 for c in changes if c.change_type == "FINDING_RESOLVED"),
            "cve_correlations": cve_correlations,
            "scope_blocked": blocked,
            "malformed": len(raw.malformed),
            "templates_release": release,
            **raw.meta,
        }
        return out
