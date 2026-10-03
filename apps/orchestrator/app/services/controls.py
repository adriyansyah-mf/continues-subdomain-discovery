"""Operational guards evaluated before an active job is created or started:
program pause, scanner pause, asset pause and maintenance windows."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import Asset, MaintenanceWindow, Program, ScannerControl
from app.models.enums import BlockReason
from app.utils.time import utcnow


@dataclass(frozen=True)
class GuardResult:
    ok: bool
    reason: BlockReason | None = None
    detail: str | None = None


OK = GuardResult(ok=True)


def check_operational_guards(
    session: Session,
    *,
    program: Program,
    scanner: str,
    asset_id: uuid.UUID | None,
) -> GuardResult:
    if not program.active or program.deleted_at is not None:
        return GuardResult(False, BlockReason.PROGRAM_INACTIVE, f"program {program.slug} is paused/inactive")
    control = session.get(ScannerControl, scanner)
    if control is not None and control.paused:
        return GuardResult(False, BlockReason.SCANNER_PAUSED, control.reason or f"scanner {scanner} paused")
    if asset_id is not None:
        asset = session.get(Asset, asset_id)
        if asset is not None and (asset.paused or asset.status in ("blocked", "retired")):
            return GuardResult(False, BlockReason.ASSET_PAUSED, f"asset is {asset.status}/paused")
    now = utcnow()
    window = session.execute(
        select(MaintenanceWindow)
        .where(
            MaintenanceWindow.start <= now,
            MaintenanceWindow.end > now,
            or_(MaintenanceWindow.program_id.is_(None), MaintenanceWindow.program_id == program.id),
            or_(MaintenanceWindow.scanner.is_(None), MaintenanceWindow.scanner == scanner),
            or_(
                MaintenanceWindow.asset_id.is_(None),
                and_(MaintenanceWindow.asset_id.is_not(None), MaintenanceWindow.asset_id == asset_id),
            ),
        )
        .limit(1)
    ).scalar_one_or_none()
    if window is not None:
        return GuardResult(False, BlockReason.MAINTENANCE_WINDOW, f"maintenance until {window.end}: {window.reason}")
    return OK
