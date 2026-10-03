"""DNS adapter: resolves A/AAAA/CNAME/MX/NS/TXT for an approved domain and maps the graph.

DNS lookups go to resolvers, not to the target's infrastructure, but the job is
still scope-checked like every other job. IPs, CNAME targets, name servers and
mail servers discovered here become assets (linked to the program with their
own scope status) - discovery never implies authorization to scan them.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import dns.exception
import dns.resolver
import dns.version
from sqlalchemy.orm import Session

from app.models import Program
from app.models.enums import LifecycleStage, RelationshipType
from app.scope.normalize import InvalidTarget, classify_target, normalize_domain
from app.services.asn import enrich_ip_asset
from app.services.assets import (
    confidence_for,
    link_program_asset,
    mark_scanned,
    swap_state,
    upsert_asset,
    upsert_relationship,
)
from app.services.changes import Change, change_event, diff_dns
from app.services.events import build_event
from app.services.ipranges import CloudRangeIndex, tag_cloud
from workers.common.adapter import JobContext, RawOutput, ScannerAdapter, ScanOutcome
from workers.common.event import snapshot_event

RECORD_REL = {
    "A": RelationshipType.RESOLVES_TO,
    "AAAA": RelationshipType.RESOLVES_TO,
    "CNAME": RelationshipType.CNAME_TO,
    "NS": RelationshipType.USES_NAMESERVER,
    "MX": RelationshipType.USES_MAIL_SERVER,
}


def _rdata_value(rtype: str, rdata: Any) -> str | None:
    if rtype in ("A", "AAAA"):
        return rdata.address
    if rtype == "CNAME":
        return str(rdata.target).rstrip(".").lower()
    if rtype == "NS":
        return str(rdata.target).rstrip(".").lower()
    if rtype == "MX":
        return str(rdata.exchange).rstrip(".").lower()
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", errors="replace")[:2048]
    return None


class DnsAdapter(ScannerAdapter):
    name = "dns"
    queue = "dns"
    tool = "dnspython"
    contacts_target = False

    def tool_version(self) -> str:
        return dns.version.version

    def execute(self, ctx: JobContext) -> RawOutput:
        resolver = dns.resolver.Resolver()
        s = ctx.settings
        if getattr(s, "resolvers", None):
            resolver.nameservers = list(s.resolvers)  # type: ignore[attr-defined]
        resolver.lifetime = float(s.timeout)
        records: dict[str, list[str]] = {}
        nxdomain: set[str] = set()
        start = time.monotonic()
        rtypes = list(getattr(s, "record_types", ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]))
        for rtype in rtypes:
            for attempt in range(s.retries + 1):
                try:
                    answer = resolver.resolve(ctx.target.value, rtype, raise_on_no_answer=False)
                    records[rtype] = sorted({v for r in answer if (v := _rdata_value(rtype, r))})
                    break
                except dns.resolver.NXDOMAIN:
                    # Some resolvers (e.g. Docker's embedded DNS) answer NXDOMAIN per record type,
                    # so one NXDOMAIN does not mean the name does not exist.
                    nxdomain.add(rtype)
                    records[rtype] = []
                    break
                except (dns.resolver.NoNameservers, dns.exception.Timeout):
                    if attempt == s.retries:
                        raise
                    time.sleep(1)
            if time.monotonic() - start > ctx.deadline_seconds:
                raise TimeoutError("DNS job exceeded its deadline")
        has_records = any(records.values())
        status = "NXDOMAIN" if nxdomain == set(rtypes) and not has_records else "NOERROR"
        return RawOutput(
            records=[{"domain": ctx.target.value, "status": status, "records": records}],
            meta={"duration": round(time.monotonic() - start, 3)},
        )

    def process(self, session: Session, ctx: JobContext, raw: RawOutput) -> ScanOutcome:
        out = ScanOutcome()
        ec = ctx.event_ctx
        result = raw.records[0]
        records: dict[str, list[str]] = result["records"]
        domain = ctx.target.value
        program = session.get(Program, ctx.program_id)
        assert program is not None
        asset, _ = upsert_asset(session, domain, confidence=confidence_for("dns", "resolved by DNS worker"))
        changes: list[Change] = []
        clouds: dict[str, dict] = {}
        asns: dict[int, Any] = {}
        new_edges = 0
        for rtype, rel in RECORD_REL.items():
            for value in records.get(rtype, []):
                try:
                    t = classify_target(value) if rtype in ("A", "AAAA") else classify_target(normalize_domain(value))
                except InvalidTarget:
                    continue
                other, created = upsert_asset(
                    session, t, confidence=confidence_for("dns", f"{rtype} record of {domain}")
                )
                link_program_asset(session, program.id, other, ctx.guard.engine.is_in_scope(t, program.id))
                if upsert_relationship(
                    session,
                    asset.id,
                    other.id,
                    rel.value,
                    source="dns",
                    confidence=0.95,
                    metadata={"record_type": rtype},
                ):
                    new_edges += 1
                if rtype in ("A", "AAAA"):
                    attribution = CloudRangeIndex.cached().lookup(value)
                    tag_cloud(other, attribution)
                    asn_info = enrich_ip_asset(session, other, value, source="dns")
                    if asn_info is not None:
                        asns[asn_info.number] = asn_info
                    if attribution is not None:
                        clouds[attribution.provider] = attribution.to_event()
                if created and rtype in ("A", "AAAA"):
                    changes.append(Change("NEW_IP", "dns.ip", None, value))
        state: dict[str, Any] = {rt: records.get(rt, []) for rt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT")}
        state["status"] = result["status"]
        state["cloud"] = sorted(clouds)
        state["asn"] = sorted(asns)
        prev = swap_state(session, asset.id, "dns", state, source="dns")
        changes += diff_dns(prev, state)
        actx = ec.with_asset(str(asset.id), asset.asset_type, domain)
        out.add(
            "dns",
            build_event(
                index="bb-dns",
                kind="event",
                category="network",
                type_="DNS_OBSERVATION",
                ctx=actx,
                body={
                    "dns": {
                        "question": {"name": domain},
                        "response_code": result["status"],
                        "a": state["A"],
                        "aaaa": state["AAAA"],
                        "cname": state["CNAME"],
                        "mx": state["MX"],
                        "ns": state["NS"],
                        "txt": state["TXT"],
                    },
                    "asn": {
                        "number": sorted(asns),
                        "organization": [a.organization for a in asns.values()],
                        "country": sorted({a.country for a in asns.values() if a.country}),
                        "source": "iptoasn",
                    }
                    if asns
                    else None,
                    "cloud": {
                        "provider": sorted(clouds),
                        "organization": [c["organization"] for c in clouds.values()],
                        "category": sorted({c["category"] for c in clouds.values()}),
                        "source": "lord-alfred/ipranges",
                    }
                    if clouds
                    else None,
                },
            ),
        )
        out.add("changes", *(change_event(c, actx, confidence=0.95) for c in changes))
        out.add("assets", snapshot_event(actx, {"dns": state}))
        resolved = bool(state["A"] or state["AAAA"] or state["CNAME"])
        mark_scanned(
            session,
            asset.id,
            stage=LifecycleStage.VALIDATED.value if resolved else None,
            changed=bool(changes),
            active=resolved,
        )
        if ctx.asset_id and uuid.UUID(ctx.asset_id) != asset.id:
            mark_scanned(session, uuid.UUID(ctx.asset_id))
        out.summary = {
            "status": result["status"],
            "records": {k: len(v) for k, v in state.items() if k != "status"},
            "new_edges": new_edges,
            "changes": len(changes),
            **raw.meta,
        }
        return out
