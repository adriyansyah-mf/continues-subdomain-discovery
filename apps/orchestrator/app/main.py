"""FastAPI application entrypoint for the orchestrator."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from app.api import assets, health, notifications, ops, policies, programs, scans, sync, ui
from app.config import get_settings
from app.database import session_scope
from app.services.programs import ConflictError, NotFoundError
from app.services.seed import seed
from app.utils.logging import configure_logging

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.service_name, settings.log_level)
    with session_scope() as session:
        seed(session, settings)
    log.info("orchestrator started", extra={"environment": settings.environment})
    yield


app = FastAPI(
    title="Bug Bounty Asset Intelligence Platform",
    version="0.1.0",
    description="Orchestrator API: programs, CDB/scope, assets, scans and jobs. Kibana is the UI.",
    lifespan=lifespan,
)


@app.exception_handler(NotFoundError)
async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=404)


@app.middleware("http")
async def _db_unavailable(request: Request, call_next):
    # Fail closed: without the canonical store no scope decision or job can be made.
    # A middleware (not an exception handler) because errors raised inside yield-dependencies
    # (DB session, API-key lookup) surface outside FastAPI's exception-handler layer.
    try:
        return await call_next(request)
    except OperationalError as exc:
        log.error("database unavailable", extra={"error": str(exc.orig)[:300], "path": request.url.path})
        return JSONResponse({"detail": "database unavailable; no action taken"}, status_code=503)


@app.exception_handler(ConflictError)
async def _conflict(_: Request, exc: ConflictError) -> JSONResponse:
    return JSONResponse({"detail": str(exc)}, status_code=409)


for router in (
    health.router,
    programs.router,
    assets.router,
    scans.router,
    policies.router,
    sync.router,
    ops.router,
    notifications.router,
    ui.router,
):
    app.include_router(router)
