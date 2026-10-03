"""Asset -> technology -> version -> CPE -> CVE -> KEV/EPSS correlation.

* Observations come from USES_TECHNOLOGY edges that carry a fingerprinted version
  (httpx, BBOT). Version-less observations are never correlated.
* CVE candidates come from NVD CPE match lookups, cached in ``cpe_lookups``.
* A correlation is stored as status ``potential`` with separate technology / version /
  cpe confidences - a fingerprint is *not* proof of a vulnerable version. Nuclei
  detections use the same table with status ``detected``.
* CVSS, EPSS and KEV are attached side by side; no composite risk score is computed.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetRelationship,
    CpeLookup,
    CveRecord,
    EpssScore,
    KevEntry,
    Program,
    ProgramAsset,
    VulnCorrelation,
)
from app.models.enums import RelationshipType
from app.scope.normalize import Target
from app.services.assets import confidence_for, upsert_asset, upsert_relationship
from app.services.changes import Change, change_event
from app.services.events import EventContext, EventEmitter, build_event
from app.services.vuln.cpe import CpeCandidate, candidate_for, confidence_level
from app.services.vuln.nvd import NvdClient, parse_cve
from app.utils.time import utcnow

log = logging.getLogger(__name__)
LOOKUP_TTL = timedelta(days=7)


@dataclass(frozen=True)
class TechObservation:
    asset_id: uuid.UUID
    technology: str
    version: str
    technology_confidence: float | None
    version_confidence: float | None
    candidate: CpeCandidate


def collect_observations(session: Session) -> list[TechObservation]:
    rows = session.execute(
        select(AssetRelationship, Asset.normalized_value)
        .join(Asset, Asset.id == AssetRelationship.target_asset_id)
        .where(AssetRelationship.relationship_type == RelationshipType.USES_TECHNOLOGY.value)
    ).all()
    out = []
    for rel, tech_name in rows:
        meta = rel.meta or {}
        version = meta.get("version")
        cand = candidate_for(tech_name, version, meta.get("cpe"))
        if cand is None:
            continue
        out.append(
            TechObservation(
                rel.source_asset_id, tech_name, str(version), rel.confidence, meta.get("version_confidence"), cand
            )
        )
    return out


def upsert_cve(session: Session, parsed: dict[str, Any]) -> None:
    values = {**parsed, "source": "nvd", "fetched_at": utcnow()}
    stmt = insert(CveRecord).values(**values)
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=["cve_id"], set_={k: stmt.excluded[k] for k in values if k != "cve_id"}
        )
    )


def lookup_cpe(session_factory: Callable, nvd: NvdClient, cpe: str, *, force: bool = False) -> list[str]:
    """CVE ids for a CPE, from cache or NVD (network call happens outside any transaction)."""
    with session_factory() as s:
        cached = s.get(CpeLookup, cpe)
        if cached is not None and not force and utcnow() - cached.fetched_at < LOOKUP_TTL:
            return list(cached.cve_ids)
    cves = nvd.cves_for_cpe(cpe)
    ids = []
    with session_factory() as s:
        for c in cves:
            parsed = parse_cve(c)
            if parsed["cve_id"]:
                upsert_cve(s, parsed)
                ids.append(parsed["cve_id"])
        stmt = insert(CpeLookup).values(cpe=cpe, cve_ids=ids, total=len(ids), fetched_at=utcnow())
        s.execute(
            stmt.on_conflict_do_update(
                index_elements=["cpe"], set_={"cve_ids": ids, "total": len(ids), "fetched_at": utcnow()}
            )
        )
    return ids


def asset_programs(session: Session, asset_id: uuid.UUID) -> list[tuple[str, str]]:
    return [
        (str(pid), name)
        for pid, name in session.execute(
            select(ProgramAsset.program_id, Program.name)
            .join(Program, Program.id == ProgramAsset.program_id)
            .where(ProgramAsset.asset_id == asset_id, ProgramAsset.status == "in_scope", Program.deleted_at.is_(None))
        ).all()
    ]


def record_correlation(
    session: Session,
    *,
    asset: Asset,
    cve_id: str,
    source: str,
    status: str,
    technology: str | None = None,
    version: str | None = None,
    cpe: str | None = None,
    technology_confidence: float | None = None,
    version_confidence: float | None = None,
    cpe_confidence: float | None = None,
    evidence: dict[str, Any] | None = None,
    ctx: EventContext | None = None,
) -> list[dict]:
    """Upsert one asset<->CVE correlation; returns the events to emit (bb-cve doc + changes)."""
    now = utcnow()
    kev = session.get(KevEntry, cve_id)
    in_kev = kev is not None and kev.removed_at is None
    stmt = insert(VulnCorrelation).values(
        id=uuid.uuid4(),
        asset_id=asset.id,
        cve_id=cve_id,
        source=source,
        status=status,
        technology=technology,
        version=version,
        cpe=cpe,
        technology_confidence=technology_confidence,
        version_confidence=version_confidence,
        cpe_confidence=cpe_confidence,
        evidence={**(evidence or {}), "kev": in_kev},
        first_seen=now,
        last_seen=now,
    )
    existing = session.execute(
        select(VulnCorrelation).where(
            VulnCorrelation.asset_id == asset.id, VulnCorrelation.cve_id == cve_id, VulnCorrelation.source == source
        )
    ).scalar_one_or_none()
    was_kev = bool(existing and (existing.evidence or {}).get("kev"))
    session.execute(
        stmt.on_conflict_do_update(
            index_elements=["asset_id", "cve_id", "source"],
            set_={
                "last_seen": now,
                "status": status,
                "evidence": {**(evidence or {}), "kev": in_kev},
                "version": version,
                "cpe": cpe,
            },
        )
    )
    cve_asset, _ = upsert_asset(
        session, Target(kind="cve", value=cve_id), confidence=confidence_for(source, f"{source} correlation")
    )
    upsert_relationship(
        session,
        asset.id,
        cve_asset.id,
        RelationshipType.AFFECTED_BY_CVE.value,
        source=source,
        confidence=cpe_confidence if status == "potential" else 0.9,
        metadata={"status": status, "technology": technology, "version": version, "cpe": cpe},
    )
    rec = session.get(CveRecord, cve_id)
    epss = session.get(EpssScore, cve_id)
    programs: list[tuple[str | None, str | None]] = list(asset_programs(session, asset.id)) or [(None, None)]
    base = ctx or EventContext(source_name=source, source_type="correlation")
    events: list[dict] = []
    for pid, pname in programs:
        pctx = EventContext(
            **{
                **base.__dict__,
                "program_id": pid,
                "program_name": pname,
                "asset_id": str(asset.id),
                "asset_type": asset.asset_type,
                "asset_value": asset.normalized_value,
            }
        )
        doc_id = hashlib.sha256(f"{asset.id}|{cve_id}|{source}|{pid}".encode()).hexdigest()
        events.append(
            build_event(
                index="bb-cve",
                kind="state",
                category="vulnerability",
                type_="CVE_CORRELATION",
                ctx=pctx,
                doc_id=doc_id,
                body={
                    "cve": {
                        "id": cve_id,
                        "description": rec.description if rec else None,
                        "published": rec.published.isoformat() if rec and rec.published else None,
                        "cpe": cpe,
                        "cpe_confidence": cpe_confidence,
                        "cpe_confidence_level": confidence_level(cpe_confidence) if cpe else None,
                        "status": status,
                        "source": source,
                    },
                    "cvss": {
                        "score": rec.cvss_score,
                        "version": rec.cvss_version,
                        "vector": rec.cvss_vector,
                        "severity": rec.cvss_severity,
                    }
                    if rec
                    else None,
                    "epss": {
                        "score": epss.score,
                        "percentile": epss.percentile,
                        "date": epss.score_date.isoformat() if epss.score_date else None,
                    }
                    if epss
                    else None,
                    "kev": {
                        "in_catalog": in_kev,
                        "vendor": kev.vendor,
                        "product": kev.product,
                        "name": kev.vulnerability_name,
                        "date_added": kev.date_added.isoformat() if kev.date_added else None,
                        "due_date": kev.due_date.isoformat() if kev.due_date else None,
                        "known_ransomware_use": kev.known_ransomware_use,
                    }
                    if in_kev and kev
                    else {"in_catalog": False},
                    "technology": {
                        "name": technology,
                        "version": version,
                        "confidence": technology_confidence,
                        "version_confidence": version_confidence,
                    }
                    if technology
                    else None,
                    "vulnerability": {"status": status, "source": source},
                },
            )
        )
        if existing is None:
            events.append(
                change_event(
                    Change("NEW_CVE", "cve.id", None, cve_id),
                    pctx,
                    confidence=cpe_confidence if status == "potential" else 0.9,
                )
            )
        if in_kev and not was_kev:
            events.append(
                change_event(
                    Change("KEV_ADDED", "kev", None, cve_id),
                    pctx,
                    confidence=cpe_confidence if status == "potential" else 0.9,
                )
            )
    return events


def run_correlation(
    session_factory: Callable, nvd: NvdClient, emitter: EventEmitter | None, *, max_cpes: int = 500, force: bool = False
) -> dict[str, Any]:
    with session_factory() as s:
        observations = collect_observations(s)
    cpes = sorted({o.candidate.cpe for o in observations})[:max_cpes]
    cve_map: dict[str, list[str]] = {}
    errors = 0
    for cpe in cpes:
        try:
            cve_map[cpe] = lookup_cpe(session_factory, nvd, cpe, force=force)
        except Exception as exc:
            errors += 1
            log.warning("NVD lookup failed", extra={"cpe": cpe, "error": str(exc)})
    correlations = 0
    events: list[dict] = []
    with session_factory() as s:
        for o in observations:
            asset = s.get(Asset, o.asset_id)
            if asset is None:
                continue
            for cve_id in cve_map.get(o.candidate.cpe, []):
                events += record_correlation(
                    s,
                    asset=asset,
                    cve_id=cve_id,
                    source="cpe-correlation",
                    status="potential",
                    technology=o.technology,
                    version=o.version,
                    cpe=o.candidate.cpe,
                    technology_confidence=o.technology_confidence,
                    version_confidence=o.version_confidence,
                    cpe_confidence=o.candidate.confidence,
                )
                correlations += 1
        if emitter is not None and events:
            for pipeline, idx in (("cve", "bb-cve"), ("changes", "bb-changes")):
                batch = [e for e in events if e["bb"]["index"] == idx]
                for i in range(0, len(batch), 500):
                    emitter.emit_many(pipeline, batch[i : i + 500])
    return {
        "observations": len(observations),
        "cpes": len(cpes),
        "nvd_errors": errors,
        "correlations": correlations,
        "events": len(events),
    }
