"""mapcidr adapter: bounded expansion of an in-scope CIDR into an IP inventory.

No traffic is sent to targets (``contacts_target=False``). Expansion size is
bounded twice: the orchestrator/runner block CIDRs above MAX_CIDR_SIZE /
MAX_IPS_PER_JOB (``BLOCKED / CIDR_LIMIT_EXCEEDED``) and the tool output is
capped at the same limit. Every produced IP is re-validated (inside the job's
CIDR and in scope). Optional follow-up scanners (policy ``followup_scanners``,
e.g. tlsx) are queued for the expanded IPs through the normal scan path.
"""

from __future__ import annotations

import ipaddress
import os
import shutil

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import LifecycleStage, RelationshipType
from app.scope.normalize import classify_target
from app.services.asn import enrich_ip_asset
from app.services.assets import confidence_for, link_program_asset, mark_scanned, upsert_asset, upsert_relationship
from app.services.audit import Principal
from app.services.events import build_event
from app.services.ipranges import CloudRangeIndex, tag_cloud
from workers.common.adapter import JobContext, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import error_event
from workers.common.followup import create_followups
from workers.common.process import ToolError, run_tool
from workers.common.tooling import binary_version

BINARY = os.environ.get("MAPCIDR_BINARY", "mapcidr")
PRINCIPAL = Principal(name="worker:mapcidr", role="operator")


def build_argv(ctx: JobContext, binary: str = BINARY) -> list[str]:
    argv = [binary, "-cl", ctx.target.value, "-silent", "-duc"]
    if getattr(ctx.settings, "skip_base_broadcast", True) and ctx.target.network and ctx.target.network.version == 4:
        argv += ["-skip-base", "-skip-broadcast"]
    return argv


class MapcidrAdapter(ScannerAdapter):
    name = "mapcidr"
    queue = "mapcidr"
    tool = "mapcidr"
    contacts_target = False

    def __init__(self, binary: str = BINARY):
        self.binary = shutil.which(binary) or binary
        self._version = binary_version(self.binary, "MAPCIDR_VERSION")

    def tool_version(self) -> str:
        return self._version

    def execute(self, ctx: JobContext) -> RawOutput:
        s = get_settings()
        limit = min(s.max_cidr_size, s.max_ips_per_job)
        result = run_tool(
            build_argv(ctx, self.binary),
            timeout=ctx.deadline_seconds,
            is_cancelled=ctx.is_cancelled,
            max_lines=limit + 1,
        )
        if not result.ok:
            raise ToolError(f"mapcidr exited {result.returncode}: {result.stderr_tail[-1000:]}")
        lines = [ln.strip() for ln in result.stdout_lines if ln.strip()]
        if len(lines) > limit:
            # Defense in depth: the runner already blocks oversized CIDRs before execution.
            raise ToolError(f"mapcidr produced more than {limit} IPs (MAX_IPS_PER_JOB)")
        return RawOutput(records=lines, meta={"duration": round(result.duration, 3)})

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        network = ctx.target.network
        assert network is not None
        cidr_asset, _ = upsert_asset(session, ctx.target, confidence=confidence_for("manual", "in-scope CIDR"))
        index = CloudRangeIndex.cached()
        accepted, rejected = [], 0
        for line in raw.records:
            try:
                ip = ipaddress.ip_address(line)
            except ValueError:
                rejected += 1
                continue
            # Layer 3: inside the job's CIDR and still in scope (exclusions inside the range are blocked).
            decision = ctx.guard.engine.is_in_scope(str(ip), ctx.program_id)
            if ip not in network or not decision.allowed:
                rejected += 1
                continue
            target = classify_target(str(ip))
            asset, _ = upsert_asset(session, target, confidence=confidence_for("mapcidr", f"member of {network}"))
            link_program_asset(session, ctx.program_id, asset, decision)
            upsert_relationship(
                session,
                asset.id,
                cidr_asset.id,
                RelationshipType.BELONGS_TO_CIDR.value,
                source="mapcidr",
                confidence=1.0,
            )
            attribution = index.lookup(str(ip))
            tag_cloud(asset, attribution)
            asn_info = enrich_ip_asset(session, asset, str(ip), source="mapcidr")
            accepted.append(asset.id)
            out.add(
                "assets",
                build_event(
                    index="bb-ips",
                    kind="state",
                    category="asset",
                    type_="IP_INVENTORY",
                    ctx=ec.with_asset(str(asset.id), asset.asset_type, str(ip)),
                    body={
                        "host": {"ip": str(ip)},
                        "network": {"cidr": str(network)},
                        **({"cloud": attribution.to_event()} if attribution else {}),
                        **({"asn": asn_info.to_event()} if asn_info else {}),
                    },
                    doc_id=str(asset.id),
                ),
            )
        if rejected:
            out.add("ops", error_event(ec, "SCANNER_OUTPUT_REJECTED", f"{rejected} mapcidr lines rejected"))
        mark_scanned(session, cidr_asset.id, stage=LifecycleStage.VALIDATED.value)
        scanners = list(getattr(ctx.settings, "followup_scanners", []))
        out.followup_job_ids = create_followups(
            session, ctx, scanners=scanners, asset_ids=accepted, trigger=f"mapcidr:{ctx.job_id}", principal=PRINCIPAL
        )
        out.summary = {
            "ips": len(accepted),
            "rejected": rejected,
            "followup_jobs": len(out.followup_job_ids),
            **raw.meta,
        }
        return out
