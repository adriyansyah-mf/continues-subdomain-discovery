"""CertStream worker: passive Certificate Transparency monitoring.

Flow per certificate:
  websocket message -> parse -> normalize names -> ScopeEngine (cached, all programs)
  -> in scope?  no  -> dropped (or stored as an out-of-scope passive observation if configured)
                yes -> dedup by fingerprint -> certificate + domain assets, program links,
                       DISCOVERED_FROM edges, NEW_* change events, bb-certstream event
                    -> follow-up jobs (default: dns) for NEW assets of ACTIVE programs only,
                       created through ScanService so every normal scope/policy check applies.

CertStream itself is passive: appearing in a CT log never authorises a scan; the
follow-up jobs are scope-checked again by the orchestrator and by the worker.
"""

from __future__ import annotations

import json
import logging
import random
import signal
import socket
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import replace
from pathlib import Path
from typing import Any

from websockets.sync.client import connect

from app.config import Settings, get_settings
from app.database import session_scope
from app.models import Program
from app.models.enums import JobStatus, RelationshipType
from app.queue.redis_queue import RedisQueue, get_redis
from app.scope.normalize import Target, classify_target
from app.scope.service import CachedScopeEngine
from app.services.assets import confidence_for, link_program_asset, upsert_asset, upsert_relationship
from app.services.audit import Principal
from app.services.changes import Change, change_event
from app.services.events import EventContext, EventEmitter, build_event
from app.services.scans import ScanRequestError, ScanService, dispatch_pending
from app.utils.logging import configure_logging
from workers.certstream.parser import CertObservation, parse_message

log = logging.getLogger("worker.certstream")

ALIVE_FILE = Path("/tmp/certstream.alive")  # noqa: S108 - container tmpfs; liveness probe
SEEN_PREFIX = "bb:certstream:seen:"
PRINCIPAL = Principal(name="worker:certstream", role="operator")


def tls_body(obs: CertObservation) -> dict[str, Any]:
    return {
        "tls": {
            "fingerprint": obs.fingerprint,
            "cn": obs.subject_cn,
            "san": list(obs.domains) + list(obs.wildcards),
            "serial": obs.serial,
            "subject": obs.subject_dn,
            "issuer": obs.issuer_dn,
            "issuer_cn": obs.issuer_cn,
            "issuer_org": [obs.issuer_o] if obs.issuer_o else [],
            "not_before": obs.not_before,
            "not_after": obs.not_after,
        },
        "certstream": {
            "source_url": obs.source_url,
            "source_name": obs.source_name,
            "cert_index": obs.cert_index,
            "seen": obs.seen,
            "update_type": obs.update_type,
            "sha1": obs.sha1,
            "sha256": obs.sha256,
            "flags": list(obs.flags),
            "interesting": bool(obs.flags),
        },
    }


class CertstreamService:
    def __init__(self, settings: Settings | None = None, *, url: str | None = None):
        self.settings = settings or get_settings()
        self.url = url or self.settings.certstream_url
        self.redis = get_redis()
        self.queue = RedisQueue(self.redis)
        self.emitter = EventEmitter(self.redis, max_backlog=self.settings.max_event_backlog)
        self.scope = CachedScopeEngine(session_scope, ttl_seconds=30)
        self.followups = [x.strip() for x in self.settings.certstream_followup_scanners.split(",") if x.strip()]
        self.worker_id = f"certstream-{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self.stop = threading.Event()
        self.connected = False
        self.stats: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------ stream
    def run_forever(self) -> None:
        configure_logging("worker-certstream", self.settings.log_level)
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        backoff = 1.0
        while not self.stop.is_set():
            ALIVE_FILE.touch()
            try:
                log.info("connecting", extra={"url": self.url})
                with connect(self.url, open_timeout=20, close_timeout=5, max_size=8 * 2**20) as ws:
                    self.connected = True
                    backoff = 1.0
                    log.info("connected", extra={"url": self.url})
                    last_message = time.monotonic()
                    while not self.stop.is_set():
                        try:
                            raw = ws.recv(timeout=15)
                        except TimeoutError:
                            ALIVE_FILE.touch()
                            idle = time.monotonic() - last_message
                            if idle > self.settings.certstream_idle_timeout:
                                # A silent stream (no certificates, no heartbeats) is treated as dead.
                                self.stats["idle_reconnects"] += 1
                                raise ConnectionError(f"no message for {int(idle)}s") from None
                            continue
                        last_message = time.monotonic()
                        ALIVE_FILE.touch()
                        self.handle_raw(raw)
            except Exception as exc:
                self.stats["disconnects"] += 1
                log.warning("stream disconnected; reconnecting", extra={"error": str(exc)[:300], "backoff": backoff})
            finally:
                self.connected = False
            # exponential backoff with jitter, capped at 5 minutes
            self.stop.wait(backoff + random.uniform(0, backoff / 2))  # noqa: S311 - jitter, not crypto
            backoff = min(backoff * 2, 300.0)
        self.queue.deregister(self.worker_id)

    def _heartbeat_loop(self) -> None:
        interval = self.settings.worker_heartbeat_seconds
        while not self.stop.is_set():
            try:
                self.queue.heartbeat(
                    self.worker_id,
                    "certstream",
                    ttl=interval * 3,
                    tool="certstream",
                    tool_version="websockets",
                    connected=self.connected,
                    **{k: v for k, v in self.stats.items()},
                )
            except Exception as exc:
                log.warning("heartbeat failed", extra={"error": str(exc)})
            self.stop.wait(interval)

    def handle_raw(self, raw: str | bytes) -> None:
        self.stats["messages"] += 1
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            self.stats["malformed"] += 1
            return
        obs = parse_message(msg)
        if obs is None:
            return
        self.stats["certificates"] += 1
        try:
            self.process(obs)
        except Exception:
            self.stats["errors"] += 1
            log.exception("certificate processing failed", extra={"fingerprint": obs.fingerprint})

    # ------------------------------------------------------------------ processing
    def process(self, obs: CertObservation) -> dict[str, Any]:
        """Scope-check a certificate and record in-scope discoveries. Returns a small summary."""
        matches: dict[str, list[tuple[str, Any]]] = defaultdict(list)  # program_id -> [(domain, decision)]
        for domain in obs.domains:
            overall = self.scope.is_in_scope(domain)
            for pid in overall.allowed_program_ids:
                matches[pid].append((domain, self.scope.is_in_scope(domain, pid)))
        base_ctx = EventContext(source_name="certstream", source_type="passive", tool="certstream")
        if not matches:
            if self.settings.certstream_store_out_of_scope:
                self.emitter.emit(
                    "certstream",
                    build_event(
                        index="bb-certstream",
                        kind="event",
                        category="certificate",
                        type_="CT_CERTIFICATE",
                        ctx=replace(base_ctx, scope_status="out"),
                        body=tls_body(obs),
                    ),
                )
            return {"in_scope": False}
        if not self.redis.set(SEEN_PREFIX + obs.fingerprint, "1", nx=True, ex=self.settings.certstream_dedup_ttl):
            self.stats["duplicates"] += 1
            return {"in_scope": True, "duplicate": True}
        self.stats["in_scope"] += 1

        new_assets: dict[str, list[uuid.UUID]] = defaultdict(list)
        with session_scope() as s:
            cert_asset, cert_new = upsert_asset(
                s,
                Target(kind="certificate", value=obs.fingerprint),
                confidence=confidence_for("certstream", "certificate logged in Certificate Transparency"),
            )
            events: list[dict] = []
            program_names: dict[str, str] = {}
            for pid, items in matches.items():
                program = s.get(Program, uuid.UUID(pid))
                if program is None:
                    continue
                program_names[pid] = program.name
                for domain, decision in items:
                    target = classify_target(domain)
                    asset, created = upsert_asset(
                        s,
                        target,
                        confidence=confidence_for("certstream", f"certificate SAN matched {decision.reason}"),
                    )
                    link_program_asset(s, program.id, asset, decision)
                    upsert_relationship(
                        s,
                        asset.id,
                        cert_asset.id,
                        RelationshipType.DISCOVERED_FROM.value,
                        source="certstream",
                        confidence=0.7,
                    )
                    ctx = replace(
                        base_ctx,
                        program_id=pid,
                        program_name=program.name,
                        scope_id=decision.scope_id,
                        scope_status="in",
                        asset_id=str(asset.id),
                        asset_type=asset.asset_type,
                        asset_value=domain,
                    )
                    if created:
                        kind = "NEW_DOMAIN" if asset.asset_type == "domain" else "NEW_SUBDOMAIN"
                        events.append(change_event(Change(kind, "tls.san", None, domain), ctx, confidence=0.7))
                        if program.active:
                            new_assets[pid].append(asset.id)
                    events.append(
                        build_event(
                            index="bb-certstream",
                            kind="event",
                            category="certificate",
                            type_="CT_CERTIFICATE",
                            ctx=ctx,
                            body=tls_body(obs),
                        )
                    )
                if cert_new:
                    events.append(
                        change_event(
                            Change("NEW_CERTIFICATE", "tls.fingerprint", None, obs.fingerprint),
                            replace(
                                base_ctx,
                                program_id=pid,
                                program_name=program.name,
                                asset_id=str(cert_asset.id),
                                asset_type="certificate",
                                asset_value=obs.fingerprint,
                            ),
                            confidence=0.7,
                        )
                    )
            for pipeline in ("certstream", "changes"):
                batch = [e for e in events if (e["bb"]["index"] == "bb-certstream") == (pipeline == "certstream")]
                self.emitter.emit_many(pipeline, batch)
        queued = self._queue_followups(new_assets)
        return {
            "in_scope": True,
            "programs": sorted(program_names.values()),
            "new_assets": sum(len(v) for v in new_assets.values()),
            "jobs": queued,
        }

    def _queue_followups(self, new_assets: dict[str, list[uuid.UUID]]) -> int:
        if not self.followups or not new_assets:
            return 0
        queued = 0
        for pid, asset_ids in new_assets.items():
            try:
                with session_scope() as s:
                    plan = ScanService(s, emitter=self.emitter).create_scan(
                        principal=PRINCIPAL,
                        program_id=uuid.UUID(pid),
                        scanners=self.followups,
                        asset_ids=asset_ids,
                        trigger="certstream",
                    )
                    ids = [pj.job.id for pj in plan.jobs if not pj.duplicate and pj.job.status == JobStatus.PENDING]
                with session_scope() as s:
                    queued += dispatch_pending(s, self.queue, job_ids=ids, emitter=self.emitter)
            except ScanRequestError as exc:
                log.warning("follow-up scan not created", extra={"program_id": pid, "error": str(exc)})
        return queued


def main() -> None:
    CertstreamService().run_forever()
