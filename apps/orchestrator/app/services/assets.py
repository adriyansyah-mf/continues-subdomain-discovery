"""Asset identity, program membership, graph edges and last-known state."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, literal_column, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import Asset, AssetRelationship, AssetState, ProgramAsset
from app.models.enums import AssetType, ProgramAssetStatus
from app.scope.engine import ScopeDecision
from app.scope.normalize import Target, classify_target, registrable_domain
from app.utils.hashing import stable_hash
from app.utils.time import utcnow


@dataclass(frozen=True)
class Confidence:
    """Source-based confidence. Scores are a static table (docs/data-model.md), not ML output."""

    score: float
    source: str
    reason: str


# Static, documented confidence per discovery source.
SOURCE_CONFIDENCE: dict[str, float] = {
    "manual": 1.0,
    "scope_import": 1.0,
    "bounty-targets-data": 0.9,
    "dns": 0.95,
    "httpx": 0.95,
    "tlsx": 0.9,
    "certstream": 0.7,
    "uncover": 0.5,
    "katana": 0.9,
    "nuclei": 0.9,
    "cpe-correlation": 0.5,
    "mapcidr": 1.0,
    "bbot": 0.7,
}


def confidence_for(source: str, reason: str) -> Confidence:
    return Confidence(score=SOURCE_CONFIDENCE.get(source, 0.5), source=source, reason=reason)


def asset_type_for(target: Target) -> AssetType:
    if target.kind == "domain":
        reg = registrable_domain(target.value)
        return AssetType.DOMAIN if reg == target.value else AssetType.SUBDOMAIN
    return AssetType(target.kind)


def upsert_asset(
    session: Session,
    target: Target | str,
    *,
    confidence: Confidence,
    seen_at: datetime | None = None,
    asset_type: AssetType | None = None,
) -> tuple[Asset, bool]:
    """Create or touch an asset by canonical identity. Returns (asset, created)."""
    t = classify_target(target) if isinstance(target, str) else target
    atype = asset_type or asset_type_for(t)
    now = seen_at or utcnow()
    stmt: Any = (
        insert(Asset)
        .values(
            id=uuid.uuid4(),
            canonical_value=t.value,
            normalized_value=t.value,
            asset_type=atype.value,
            status="discovered",
            lifecycle_stage="DISCOVERED",
            first_seen=now,
            last_seen=now,
            confidence_score=confidence.score,
            confidence_source=confidence.source,
            confidence_reason=confidence.reason,
            tags=[],
            paused=False,
        )
        .on_conflict_do_update(
            index_elements=["asset_type", "normalized_value"],
            set_={"last_seen": func.greatest(Asset.last_seen, now), "updated_at": func.now()},
        )
        .returning(Asset.id, literal_column("(xmax = 0)").label("inserted"))
    )
    row = session.execute(stmt).one()
    asset = session.get(Asset, row.id, populate_existing=True)
    assert asset is not None
    # Keep the highest-confidence explanation we have seen.
    if not row.inserted and (asset.confidence_score or 0) < confidence.score:
        asset.confidence_score = confidence.score
        asset.confidence_source = confidence.source
        asset.confidence_reason = confidence.reason
    return asset, bool(row.inserted)


def link_program_asset(
    session: Session, program_id: uuid.UUID | str, asset: Asset, decision: ScopeDecision
) -> tuple[ProgramAsset, bool]:
    if decision.allowed:
        status = ProgramAssetStatus.IN_SCOPE
    elif decision.match_kind == "explicit_exclusion":
        status = ProgramAssetStatus.EXCLUDED
    else:
        status = ProgramAssetStatus.OUT_OF_SCOPE
    now = utcnow()
    stmt: Any = (
        insert(ProgramAsset)
        .values(
            id=uuid.uuid4(),
            program_id=uuid.UUID(str(program_id)),
            asset_id=asset.id,
            scope_id=uuid.UUID(decision.scope_id) if decision.scope_id else None,
            status=status.value,
            scope_reason=decision.reason[:512],
            tags=[],
            first_seen=now,
            last_seen=now,
        )
        .on_conflict_do_update(
            index_elements=["program_id", "asset_id"],
            set_={
                "last_seen": now,
                "status": status.value,
                "scope_id": uuid.UUID(decision.scope_id) if decision.scope_id else None,
                "scope_reason": decision.reason[:512],
                "updated_at": func.now(),
            },
        )
        .returning(ProgramAsset.id, literal_column("(xmax = 0)").label("inserted"))
    )
    row = session.execute(stmt).one()
    pa = session.get(ProgramAsset, row.id, populate_existing=True)
    assert pa is not None
    return pa, bool(row.inserted)


def upsert_relationship(
    session: Session,
    source_asset_id: uuid.UUID,
    target_asset_id: uuid.UUID,
    relationship_type: str,
    *,
    source: str,
    confidence: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> bool:
    """Create or refresh an edge. Returns True when the edge is new."""
    now = utcnow()
    stmt: Any = (
        insert(AssetRelationship)
        .values(
            id=uuid.uuid4(),
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            relationship_type=relationship_type,
            source=source,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
            meta=metadata or {},
        )
        .on_conflict_do_update(
            index_elements=["source_asset_id", "target_asset_id", "relationship_type"],
            set_={"last_seen": now},
        )
        .returning(literal_column("(xmax = 0)").label("inserted"))
    )
    return bool(session.execute(stmt).scalar_one())


def swap_state(
    session: Session, asset_id: uuid.UUID, facet: str, state: dict[str, Any], *, source: str
) -> dict[str, Any] | None:
    """Store the latest state for (asset, facet); return the previous state (None if first)."""
    now = utcnow()
    existing = session.get(AssetState, (asset_id, facet), with_for_update=True)
    h = stable_hash(state)
    if existing is None:
        session.add(
            AssetState(asset_id=asset_id, facet=facet, state=state, state_hash=h, observed_at=now, source=source)
        )
        return None
    previous = dict(existing.state)
    existing.state = state
    existing.state_hash = h
    existing.observed_at = now
    existing.source = source
    return previous


def mark_scanned(
    session: Session,
    asset_id: uuid.UUID,
    *,
    stage: str | None = None,
    changed: bool = False,
    active: bool | None = None,
) -> None:
    asset = session.get(Asset, asset_id)
    if asset is None:
        return
    now = utcnow()
    asset.last_scanned = now
    asset.last_seen = now
    if changed:
        asset.last_changed = now
    if stage:
        asset.lifecycle_stage = stage
    if active is True:
        asset.status = "active"
    elif active is False and asset.status in ("discovered", "active"):
        asset.status = "inactive"


def relationships_for(session: Session, asset_id: uuid.UUID) -> list[tuple[AssetRelationship, Asset, str]]:
    """Edges touching the asset, with the asset on the other end and the direction."""
    out: list[tuple[AssetRelationship, Asset, str]] = []
    q_out = (
        select(AssetRelationship, Asset)
        .join(Asset, Asset.id == AssetRelationship.target_asset_id)
        .where(AssetRelationship.source_asset_id == asset_id)
    )
    q_in = (
        select(AssetRelationship, Asset)
        .join(Asset, Asset.id == AssetRelationship.source_asset_id)
        .where(AssetRelationship.target_asset_id == asset_id)
    )
    out += [(r, a, "outgoing") for r, a in session.execute(q_out).all()]
    out += [(r, a, "incoming") for r, a in session.execute(q_in).all()]
    return out
