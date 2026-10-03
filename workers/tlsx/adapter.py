"""tlsx adapter: TLS/certificate observation for an approved host.

Domain targets are pinned: tlsx connects to the IPs validated by the scope
guard and sends the domain as SNI, so DNS changes between check and scan
cannot redirect the connection.
"""

from __future__ import annotations

import os
import shutil
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import Program
from app.models.enums import LifecycleStage, RelationshipType
from app.scope.normalize import InvalidTarget, Target, classify_target, normalize_domain
from app.services.assets import (
    confidence_for,
    link_program_asset,
    mark_scanned,
    swap_state,
    upsert_asset,
    upsert_relationship,
)
from app.services.changes import Change, change_event, diff_tls
from app.services.events import build_event
from app.services.scans import scope_blocked_event
from workers.common.adapter import JobContext, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import error_event, raw_event, snapshot_event
from workers.common.process import ToolError, run_tool
from workers.common.tooling import binary_version, parse_jsonl

# Absolute path in the image (see workers/common/Dockerfile); falls back to PATH for local runs.
BINARY = os.environ.get("TLSX_BINARY", "tlsx")
EXPIRING_DAYS = 30


def build_argv(ctx: JobContext, binary: str = BINARY) -> list[str] | None:
    s = ctx.settings
    t = ctx.target
    if t.kind == "domain":
        if not ctx.guard.pinned_ips:
            return None  # does not resolve: nothing to connect to
        hosts = sorted(ctx.guard.pinned_ips)
        sni = t.value
    else:
        hosts = [t.value]
        sni = None
    argv = [
        binary,
        "-u",
        ",".join(hosts),
        "-p",
        ",".join(str(p) for p in getattr(s, "ports", [443])),
        "-json",
        "-silent",
        "-nc",
        "-duc",
        "-tv",
        "-cipher",
        "-hash",
        "sha256",
        "-serial",
        "-c",
        str(s.concurrency),
        "-timeout",
        str(s.timeout),
        "-retry",
        str(s.retries),
    ]
    if sni:
        argv += ["-sni", sni]
    return argv


def _parse_time(v: Any) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def expiry_status(not_after: datetime | None, now: datetime | None = None) -> str | None:
    if not_after is None:
        return None
    now = now or datetime.now(UTC)
    days = (not_after - now).total_seconds() / 86400
    if days < 0:
        return "expired"
    if days <= EXPIRING_DAYS:
        return "expiring"
    return "valid"


def normalize_record(rec: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    fp = (rec.get("fingerprint_hash") or {}).get("sha256")
    not_after = _parse_time(rec.get("not_after"))
    sans = sorted({str(x).lower() for x in rec.get("subject_an") or []})
    return {
        "tls": {
            "version": rec.get("tls_version"),
            "cipher": rec.get("cipher"),
            "sni": rec.get("sni"),
            "fingerprint": fp,
            "cn": rec.get("subject_cn"),
            "san": sans,
            "serial": rec.get("serial"),
            "subject": rec.get("subject_dn"),
            "issuer": rec.get("issuer_dn"),
            "issuer_cn": rec.get("issuer_cn"),
            "issuer_org": rec.get("issuer_org") or [],
            "not_before": rec.get("not_before"),
            "not_after": rec.get("not_after"),
            "self_signed": rec.get("self_signed", False),
            "mismatched": rec.get("mismatched", False),
            "expired": rec.get("expired", False),
            "expiry_status": expiry_status(not_after, now),
            "days_until_expiry": round((not_after - (now or datetime.now(UTC))).total_seconds() / 86400, 1)
            if not_after
            else None,
        },
        "host": {"ip": rec.get("ip")},
        "network": {"port": int(rec["port"]) if str(rec.get("port", "")).isdigit() else None},
    }


class TlsxAdapter(ScannerAdapter):
    name = "tlsx"
    queue = "tlsx"
    tool = "tlsx"

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = binary_version(self.binary, "TLSX_VERSION")

    def tool_version(self) -> str:
        return self._version

    def execute(self, ctx: JobContext) -> RawOutput:
        argv = build_argv(ctx, self.binary)
        if argv is None:
            return RawOutput(meta={"skipped": "target does not resolve"})
        result = run_tool(argv, timeout=ctx.deadline_seconds, is_cancelled=ctx.is_cancelled)
        if result.returncode != 0:
            raise ToolError(f"tlsx exited {result.returncode}: {result.stderr_tail[-1000:]}")
        raw = parse_jsonl(result.stdout_lines)
        raw.meta = {"duration": round(result.duration, 3), "truncated": result.truncated}
        return raw

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        out.add("tlsx", *(raw_event("bb-tlsx-raw", ec, r) for r in raw.records))
        out.add("tlsx", *(raw_event("bb-tlsx-raw", ec, line, malformed=True) for line in raw.malformed))
        if raw.malformed:
            out.add("ops", error_event(ec, "MALFORMED_SCANNER_OUTPUT", f"{len(raw.malformed)} malformed tlsx lines"))
        program = session.get(Program, ctx.program_id)
        assert program is not None
        host_value = ctx.target.value
        host_asset, _ = upsert_asset(session, ctx.target, confidence=confidence_for("tlsx", "TLS endpoint"))
        accepted = blocked = changes_n = sans_in_scope = 0
        for rec in raw.records:
            if not rec.get("probe_status", True) or not (rec.get("fingerprint_hash") or {}).get("sha256"):
                continue
            ip = rec.get("ip")
            # Layer 3: the connected IP must be one we validated; the host must be in scope.
            decision = ctx.guard.validate_output(host_value, ip=ip)
            if not decision.allowed:
                blocked += 1
                out.add(
                    "changes",
                    scope_blocked_event(
                        decision, program=program, scanner=self.name, layer="scanner_output", job_id=ctx.job_id
                    ),
                )
                continue
            accepted += 1
            obs = normalize_record(rec)
            tls = obs["tls"]
            port = obs["network"]["port"]
            changes: list[Change] = []
            cert_asset, cert_new = upsert_asset(
                session,
                Target(kind="certificate", value=tls["fingerprint"]),
                confidence=confidence_for("tlsx", "certificate presented by approved host"),
            )
            if cert_new:
                changes.append(Change("NEW_CERTIFICATE", "tls.fingerprint", None, tls["fingerprint"]))
            upsert_relationship(
                session,
                host_asset.id,
                cert_asset.id,
                RelationshipType.USES_CERTIFICATE.value,
                source="tlsx",
                confidence=0.95,
                metadata={"port": port, "ip": ip},
            )
            for san in tls["san"]:
                if san.startswith("*."):
                    continue
                try:
                    st = classify_target(normalize_domain(san))
                except InvalidTarget:
                    continue
                d = ctx.guard.engine.is_in_scope(st, ctx.program_id)
                if not d.allowed:
                    continue  # out-of-scope SANs stay in the passive observation only
                sans_in_scope += 1
                san_asset, san_new = upsert_asset(
                    session, st, confidence=confidence_for("tlsx", f"certificate SAN matched {d.reason}")
                )
                link_program_asset(session, ctx.program_id, san_asset, d)
                upsert_relationship(
                    session,
                    san_asset.id,
                    cert_asset.id,
                    RelationshipType.DISCOVERED_FROM.value,
                    source="tlsx",
                    confidence=0.7,
                )
                if san_new:
                    changes.append(Change("NEW_SUBDOMAIN", "tls.san", None, san))
            state = {k: tls[k] for k in ("fingerprint", "issuer", "san", "not_after", "expiry_status")}
            state["tls_version"] = tls["version"]
            prev = swap_state(session, host_asset.id, f"tls:{port}", state, source="tlsx")
            changes += diff_tls(prev, state)
            actx = ec.with_asset(str(host_asset.id), host_asset.asset_type, host_value)
            out.add(
                "tlsx",
                build_event(
                    index="bb-tls",
                    kind="event",
                    category="network",
                    type_="TLS_OBSERVATION",
                    ctx=actx,
                    body={**obs, "certificate": {"asset_id": str(cert_asset.id)}},
                ),
            )
            out.add("changes", *(change_event(c, actx, confidence=0.95) for c in changes))
            out.add("assets", snapshot_event(actx, {f"tls:{port}": state}))
            changes_n += len(changes)
            mark_scanned(
                session, host_asset.id, stage=LifecycleStage.TLS_IDENTIFIED.value, changed=bool(changes), active=True
            )
        if accepted == 0 and ctx.asset_id:
            mark_scanned(session, uuid.UUID(ctx.asset_id))
        out.summary = {
            "records": len(raw.records),
            "accepted": accepted,
            "scope_blocked": blocked,
            "malformed": len(raw.malformed),
            "sans_in_scope": sans_in_scope,
            "changes": changes_n,
            **raw.meta,
        }
        return out
