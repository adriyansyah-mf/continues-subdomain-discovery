from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_emitter, get_queue, operator
from app.config import get_settings
from app.database import get_session
from app.queue.redis_queue import RedisQueue
from app.services import asn, ipranges
from app.services.audit import Principal
from app.services.events import EventEmitter
from app.services.importer import import_bounty_targets
from app.services.vuln import kev

router = APIRouter(prefix="/sync", tags=["sync"])


@router.post("/bounty-targets")
def sync_bounty_targets(
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    url = get_settings().bounty_targets_url
    try:
        return import_bounty_targets(session, principal, url=url, emitter=emitter)
    except Exception as exc:
        raise HTTPException(502, f"bounty-targets import failed: {exc}") from exc


@router.post("/ipranges")
def sync_ipranges(
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    try:
        return ipranges.sync_ipranges(session, principal, repo_url=get_settings().ipranges_repo, emitter=emitter)
    except Exception as exc:
        raise HTTPException(502, f"ipranges sync failed: {exc}") from exc


@router.post("/asn")
def sync_asn(
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    """IP -> ASN ranges from iptoasn.com (~700k ranges; enrichment only)."""
    try:
        return asn.sync_asn(session, principal, url=get_settings().asn_feed_url, emitter=emitter)
    except Exception as exc:
        raise HTTPException(502, f"ASN sync failed: {exc}") from exc


@router.post("/kev")
def sync_kev(
    session: Session = Depends(get_session),
    principal: Principal = Depends(operator),
    emitter: EventEmitter = Depends(get_emitter),
    queue: RedisQueue = Depends(get_queue),
) -> dict:
    """Synchronous CISA KEV import + diff; queues a correlation refresh when the catalogue changed."""
    try:
        result = kev.sync_kev(session, principal, url=get_settings().kev_feed_url, emitter=emitter)
    except Exception as exc:
        raise HTTPException(502, f"KEV sync failed: {exc}") from exc
    if result["added"] or result["removed"] or result["baseline"]:
        queue.enqueue("cve", "correlate")
    return result


@router.post("/epss", status_code=202)
def sync_epss(principal: Principal = Depends(operator), queue: RedisQueue = Depends(get_queue)) -> dict:
    """EPSS import (~400k rows) runs in cve-monitor."""
    queue.enqueue("cve", "epss")
    return {"queued": "epss", "requested_by": principal.name}


@router.post("/cve", status_code=202)
def sync_cve(
    principal: Principal = Depends(operator), queue: RedisQueue = Depends(get_queue), force: bool = False
) -> dict:
    """Run asset -> technology -> CPE -> CVE correlation in cve-monitor (NVD is rate limited)."""
    task = "correlate:force" if force else "correlate"
    queue.enqueue("cve", task)
    return {"queued": task, "requested_by": principal.name}
