"""cve-monitor: vulnerability-intelligence service (CISA KEV, EPSS, NVD correlation).

Periodic (leader-locked, intervals configurable):
  * KEV sync          KEV_SYNC_INTERVAL         (default 6 h)   -> KEV_ADDED/UPDATED/REMOVED
  * EPSS import       EPSS_SYNC_INTERVAL        (default 24 h)
  * CVE correlation   CVE_CORRELATION_INTERVAL  (default 24 h; also after KEV changes)
On demand: items on the Redis "cve" queue ("kev", "epss", "correlate", "correlate:force"),
pushed by POST /sync/kev|epss|cve.
"""

from __future__ import annotations

import logging
import signal
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import cast

from app.config import get_settings
from app.database import session_scope
from app.queue.redis_queue import RedisQueue, get_redis
from app.services.audit import Principal
from app.services.events import EventEmitter
from app.services.vuln import correlate, epss, kev
from app.services.vuln.nvd import NvdClient
from app.utils.logging import configure_logging

log = logging.getLogger("worker.cve")
PRINCIPAL = Principal(name="worker:cve-monitor", role="operator")
ALIVE_FILE = Path("/tmp/cve.alive")  # noqa: S108 - container tmpfs; liveness probe
LEADER_KEY = "bb:cve:leader"
TASKS = ("kev", "epss", "correlate")


class CveMonitor:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.redis = get_redis()
        self.queue = RedisQueue(self.redis)
        self.emitter = EventEmitter(self.redis, max_backlog=self.settings.max_event_backlog)
        key = self.settings.nvd_api_key.get_secret_value() if self.settings.nvd_api_key else None
        self.nvd = NvdClient(api_key=key)
        self.worker_id = f"cve-{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self.stop = threading.Event()
        self.intervals = {
            "kev": self.settings.kev_sync_interval,
            "epss": self.settings.epss_sync_interval,
            "correlate": self.settings.cve_correlation_interval,
        }

    def _leader(self) -> bool:
        ttl = 120
        if self.redis.set(LEADER_KEY, self.worker_id, nx=True, ex=ttl):
            return True
        if self.redis.get(LEADER_KEY) == self.worker_id:
            self.redis.expire(LEADER_KEY, ttl)
            return True
        return False

    def run_task(self, task: str) -> dict:
        force = task.endswith(":force")
        name = task.split(":", 1)[0]
        started = time.monotonic()
        if name == "kev":
            with session_scope() as s:
                result = kev.sync_kev(s, PRINCIPAL, url=self.settings.kev_feed_url, emitter=self.emitter)
            if result["added"] or result["removed"] or result["baseline"]:
                self.queue.enqueue("cve", "correlate")  # refresh KEV flags on correlations
        elif name == "epss":
            with session_scope() as s:
                result = epss.sync_epss(s, PRINCIPAL, url=self.settings.epss_feed_url, emitter=self.emitter)
        elif name == "correlate":
            result = correlate.run_correlation(session_scope, self.nvd, self.emitter, force=force)
        else:
            raise ValueError(f"unknown cve task {task!r}")
        self.redis.set(f"bb:cve:last:{name}", time.time())
        log.info(
            "cve task finished",
            extra={
                "task": task,
                "seconds": round(time.monotonic() - started, 1),
                "result": {k: v for k, v in result.items() if k != "added_ids"},
            },
        )
        return result

    def due_tasks(self) -> list[str]:
        due = []
        for name in TASKS:
            interval = self.intervals[name]
            if interval <= 0:
                continue
            last = float(cast(str | None, self.redis.get(f"bb:cve:last:{name}")) or 0)
            if time.time() - last >= interval:
                due.append(name)
        return due

    def run_forever(self) -> None:
        configure_logging("worker-cve", self.settings.log_level)
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        log.info("cve-monitor started", extra={"worker_id": self.worker_id, "nvd_api_key": bool(self.nvd.api_key)})
        while not self.stop.is_set():
            ALIVE_FILE.touch()
            try:
                self.queue.heartbeat(self.worker_id, "cve", ttl=90, tool="cve-monitor", tool_version="1")
                if self._leader():
                    for task in self.due_tasks():
                        self._safe_run(task)
                item = self.queue.reserve("cve", self.worker_id, timeout=30)
                if item:
                    try:
                        self._safe_run(item)
                    finally:
                        self.queue.ack("cve", self.worker_id, item)
            except Exception:
                log.exception("cve-monitor loop error")
                self.stop.wait(10)
        self.queue.deregister(self.worker_id)

    def _safe_run(self, task: str) -> None:
        try:
            self.run_task(task)
        except Exception as exc:
            log.error("cve task failed", extra={"task": task, "error": str(exc)[:500]})


def main() -> None:
    CveMonitor().run_forever()
