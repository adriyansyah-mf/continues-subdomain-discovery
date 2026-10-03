"""Follow-up jobs created by discovery workers (mapcidr -> tlsx, uncover -> tlsx/httpx, ...).

Follow-ups go through ScanService exactly like an operator request, so every
scope, pause, policy and limit check applies again; discovery never implies
authorisation. They use the parent job's policy and program, and are enqueued
by the runner only after the parent job's transaction commits.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.enums import JobStatus
from app.services.audit import Principal
from app.services.scans import ScanRequestError, ScanService
from workers.common.adapter import JobContext

log = logging.getLogger(__name__)


def create_followups(
    session: Session,
    ctx: JobContext,
    *,
    scanners: Sequence[str],
    asset_ids: Sequence[uuid.UUID],
    trigger: str,
    principal: Principal,
) -> list[uuid.UUID]:
    if not scanners or not asset_ids:
        return []
    limit = get_settings().max_targets_per_scan
    try:
        plan = ScanService(session).create_scan(
            principal=principal,
            program_id=uuid.UUID(ctx.program_id),
            scanners=list(scanners),
            asset_ids=list(dict.fromkeys(asset_ids))[:limit],
            policy_id=uuid.UUID(ctx.policy_id) if ctx.policy_id else None,
            trigger=trigger,
        )
    except ScanRequestError as exc:
        log.warning("follow-up scan not created", extra={"job_id": ctx.job_id, "error": str(exc)})
        return []
    return [pj.job.id for pj in plan.jobs if not pj.duplicate and pj.job.status == JobStatus.PENDING.value]
