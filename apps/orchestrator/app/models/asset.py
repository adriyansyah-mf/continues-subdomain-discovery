from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.program import TimestampMixin


class Asset(TimestampMixin, Base):
    """Canonical asset identity. Identity is (asset_type, normalized_value)."""

    __tablename__ = "assets"
    __table_args__ = (Index("uq_asset_identity", "asset_type", "normalized_value", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    canonical_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    normalized_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="discovered")
    lifecycle_stage: Mapped[str] = mapped_column(String(32), nullable=False, default="DISCOVERED")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_scanned: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_changed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Manually configured only; never inferred.
    criticality: Mapped[str | None] = mapped_column(String(16))
    confidence_score: Mapped[float | None] = mapped_column(Float)
    confidence_source: Mapped[str | None] = mapped_column(String(64))
    confidence_reason: Mapped[str | None] = mapped_column(String(512))
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    paused: Mapped[bool] = mapped_column(nullable=False, default=False)


class ProgramAsset(TimestampMixin, Base):
    """Many-to-many link: the same asset can belong to several programs."""

    __tablename__ = "program_assets"
    __table_args__ = (Index("uq_program_asset", "program_id", "asset_id", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_entries.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="in_scope")
    scope_reason: Mapped[str | None] = mapped_column(String(512))
    criticality: Mapped[str | None] = mapped_column(String(16))
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AssetState(Base):
    """Latest observed state per (asset, facet) used for change detection.

    The full history lives in Elasticsearch (snapshots + change events); this
    table only keeps the last value so diffs can be computed deterministically.
    """

    __tablename__ = "asset_states"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    facet: Mapped[str] = mapped_column(String(64), primary_key=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
