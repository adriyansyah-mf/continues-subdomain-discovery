"""Request/response models for the HTTP API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import Criticality, ScopeMode, ScopeType


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ProgramIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str | None = Field(default=None, max_length=128)
    platform: str = Field(default="custom", max_length=64)
    description: str | None = None
    active: bool = True
    default_policy: str | None = Field(default=None, description="scan policy name")


class ProgramPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    platform: str | None = None
    description: str | None = None
    active: bool | None = None
    default_policy: str | None = None


class ProgramOut(ORM):
    id: uuid.UUID
    name: str
    slug: str
    platform: str
    description: str | None
    active: bool
    default_scan_policy_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class ScopeIn(BaseModel):
    type: ScopeType | None = Field(default=None, description="inferred from value when omitted")
    value: str = Field(min_length=1, max_length=2048)
    mode: ScopeMode = ScopeMode.INCLUDE
    description: str | None = None
    source: str = "manual"


class ScopePatch(BaseModel):
    value: str | None = None
    mode: ScopeMode | None = None
    active: bool | None = None
    description: str | None = None


class ScopeOut(ORM):
    id: uuid.UUID
    program_id: uuid.UUID
    type: str
    value: str
    normalized_value: str
    mode: str
    source: str
    active: bool
    description: str | None
    created_at: datetime
    updated_at: datetime


class ScopeCheckIn(BaseModel):
    target: str
    program_id: uuid.UUID | None = None


class AssetOut(ORM):
    id: uuid.UUID
    canonical_value: str
    asset_type: str
    normalized_value: str
    status: str
    lifecycle_stage: str
    first_seen: datetime
    last_seen: datetime
    last_scanned: datetime | None
    last_changed: datetime | None
    criticality: str | None
    confidence_score: float | None
    confidence_source: str | None
    confidence_reason: str | None
    tags: list[str]
    paused: bool


class ProgramAssetOut(ORM):
    program_id: uuid.UUID
    scope_id: uuid.UUID | None
    status: str
    scope_reason: str | None
    criticality: str | None
    tags: list[str]
    first_seen: datetime
    last_seen: datetime


class AssetDetailOut(AssetOut):
    programs: list[ProgramAssetOut] = []
    states: dict[str, Any] = {}


class AssetPatch(BaseModel):
    criticality: Criticality | None = None
    tags: list[str] | None = None
    paused: bool | None = None
    status: str | None = None


class RelationshipOut(BaseModel):
    id: uuid.UUID
    relationship_type: str
    direction: str
    other_asset_id: uuid.UUID
    other_asset_value: str
    other_asset_type: str
    confidence: float | None
    source: str
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any]


class ScanIn(BaseModel):
    program: str = Field(description="program id or slug")
    scanners: list[str] = Field(min_length=1)
    targets: list[str] = Field(default_factory=list)
    asset_ids: list[uuid.UUID] = Field(default_factory=list)
    policy: str | None = Field(default=None, description="policy name; defaults to the program default")
    priority: int = Field(default=5, ge=0, le=9)
    force: bool = Field(default=False, description="bypass idempotency deduplication")


class JobOut(ORM):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    program_id: uuid.UUID
    asset_id: uuid.UUID | None
    scope_id: uuid.UUID | None
    scope_reason: str | None
    target: str
    target_type: str | None
    scanner: str
    policy_id: uuid.UUID | None
    priority: int
    status: str
    block_reason: str | None
    idempotency_key: str
    created_at: datetime
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    next_attempt_at: datetime | None
    error: str | None
    retry_count: int
    max_retries: int
    worker_id: str | None
    tool_version: str | None
    result_summary: dict[str, Any]


class ScanOut(ORM):
    id: uuid.UUID
    program_id: uuid.UUID
    policy_id: uuid.UUID | None
    scanners: list[str]
    trigger: str
    requested_by: str
    status: str
    created_at: datetime
    finished_at: datetime | None


class ScanCreatedOut(BaseModel):
    scan: ScanOut
    summary: dict[str, int]
    jobs: list[JobOut]
    duplicates: list[uuid.UUID]


class ScanDetailOut(ScanOut):
    job_counts: dict[str, int]


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    description: str | None = None
    config: dict[str, Any]


class PolicyOut(ORM):
    id: uuid.UUID
    name: str
    description: str | None
    config: dict[str, Any]
    active: bool
    created_at: datetime
    updated_at: datetime


class ScheduleOut(ORM):
    id: uuid.UUID
    name: str
    scanner: str
    program_id: uuid.UUID | None
    policy_id: uuid.UUID | None
    interval_seconds: int
    enabled: bool
    last_run_at: datetime | None
    next_run_at: datetime | None


class SchedulePatch(BaseModel):
    enabled: bool | None = None
    interval_seconds: int | None = Field(default=None, ge=300)
    program: str | None = None
    policy: str | None = None


class ScannerControlIn(BaseModel):
    paused: bool
    reason: str | None = None


class MaintenanceIn(BaseModel):
    program: str | None = None
    scanner: str | None = None
    asset_id: uuid.UUID | None = None
    start: datetime
    end: datetime
    reason: str = Field(min_length=1, max_length=512)


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: str = Field(pattern="^(viewer|operator|admin)$")


class AuditOut(ORM):
    id: uuid.UUID
    timestamp: datetime
    actor: str
    actor_role: str | None
    action: str
    target_type: str | None
    target_id: str | None
    program_id: uuid.UUID | None
    details: dict[str, Any]
