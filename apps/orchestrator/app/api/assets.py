from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_emitter, operator, viewer
from app.database import get_session
from app.models import Asset, AssetState, ProgramAsset
from app.schemas.api import AssetDetailOut, AssetOut, AssetPatch, ProgramAssetOut, RelationshipOut
from app.services import programs as program_svc
from app.services.assets import relationships_for
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter

router = APIRouter(tags=["assets"])


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    session: Session = Depends(get_session),
    _: Principal = Depends(viewer),
    program: str | None = None,
    asset_type: str | None = Query(None, alias="type"),
    status: str | None = None,
    q: str | None = Query(None, description="substring match on the normalized value"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[Asset]:
    stmt = select(Asset)
    if program:
        try:
            p = program_svc.get_program(session, program)
        except program_svc.NotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        stmt = stmt.join(ProgramAsset, ProgramAsset.asset_id == Asset.id).where(ProgramAsset.program_id == p.id)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if status:
        stmt = stmt.where(Asset.status == status)
    if q:
        stmt = stmt.where(Asset.normalized_value.contains(q.lower()))
    stmt = stmt.order_by(Asset.last_seen.desc()).limit(limit).offset(offset)
    return list(session.execute(stmt).scalars())


def _asset(session: Session, asset_id: uuid.UUID) -> Asset:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "asset not found")
    return asset


@router.get("/assets/{asset_id}", response_model=AssetDetailOut)
def get_asset(
    asset_id: uuid.UUID, session: Session = Depends(get_session), _: Principal = Depends(viewer)
) -> AssetDetailOut:
    asset = _asset(session, asset_id)
    links = session.execute(select(ProgramAsset).where(ProgramAsset.asset_id == asset.id)).scalars()
    states = session.execute(select(AssetState).where(AssetState.asset_id == asset.id)).scalars()
    out = AssetDetailOut.model_validate(asset)
    out.programs = [ProgramAssetOut.model_validate(pa) for pa in links]
    out.states = {
        st.facet: {"observed_at": st.observed_at.isoformat(), "source": st.source, **st.state} for st in states
    }
    return out


@router.patch("/assets/{asset_id}", response_model=AssetOut)
def patch_asset(
    asset_id: uuid.UUID,
    body: AssetPatch,
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> Asset:
    asset = _asset(session, asset_id)
    changes = body.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in (
        "discovered",
        "active",
        "inactive",
        "retired",
        "blocked",
        "unknown",
    ):
        raise HTTPException(422, "invalid status")
    for k, v in changes.items():
        setattr(asset, k, v.value if hasattr(v, "value") else v)
    record_audit(
        session,
        principal,
        "asset.updated",
        target_type="asset",
        target_id=asset.id,
        details={k: str(v) for k, v in changes.items()},
        emitter=emitter,
    )
    return asset


@router.get("/assets/{asset_id}/relationships", response_model=list[RelationshipOut])
def asset_relationships(
    asset_id: uuid.UUID, session: Session = Depends(get_session), _: Principal = Depends(viewer)
) -> list[RelationshipOut]:
    _asset(session, asset_id)
    return [
        RelationshipOut(
            id=rel.id,
            relationship_type=rel.relationship_type,
            direction=direction,
            other_asset_id=other.id,
            other_asset_value=other.normalized_value,
            other_asset_type=other.asset_type,
            confidence=rel.confidence,
            source=rel.source,
            first_seen=rel.first_seen,
            last_seen=rel.last_seen,
            metadata=rel.meta,
        )
        for rel, other, direction in relationships_for(session, asset_id)
    ]
