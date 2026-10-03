"""Notifier: consumes notifiable events (bb:notify), applies notification policies and delivers.

Event-driven only: it reads compact notification records produced by the event tap and
sends them through provider interfaces (HTTPS webhooks / SMTP). It never executes commands.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import threading
import uuid
from pathlib import Path
from typing import cast

from app.config import get_settings
from app.database import session_scope
from app.queue.redis_queue import RedisQueue, get_redis
from app.services.events import NOTIFY_KEY, EventEmitter
from app.services.notify.catalog import Notification
from app.services.notify.dispatch import Dispatcher
from app.utils.logging import configure_logging

log = logging.getLogger("worker.notifier")
ALIVE_FILE = Path("/tmp/notifier.alive")  # noqa: S108 - container tmpfs; liveness probe


class Notifier:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.redis = get_redis()
        self.queue = RedisQueue(self.redis)
        self.emitter = EventEmitter(self.redis, max_backlog=self.settings.max_event_backlog)
        self.dispatcher = Dispatcher(
            self.redis, self.emitter, rate_per_minute=int(os.environ.get("NOTIFY_RATE_PER_MINUTE", "20"))
        )
        self.worker_id = f"notifier-{socket.gethostname()}-{uuid.uuid4().hex[:6]}"
        self.processing = f"{NOTIFY_KEY}:processing:{self.worker_id}"
        self.stop = threading.Event()

    def process_raw(self, raw: str) -> None:
        try:
            n = Notification(**json.loads(raw))
        except (ValueError, TypeError) as exc:
            log.error("discarding malformed notification", extra={"error": str(exc)})
            return
        with session_scope() as s:
            outcomes = self.dispatcher.handle(s, n)
        if outcomes:
            log.info("notification processed", extra={"type": n.type, "outcomes": [o.status for o in outcomes]})

    def recover_orphans(self) -> int:
        """Return in-flight items of notifiers that died (no heartbeat) to the queue."""
        moved = 0
        for key in self.redis.scan_iter(match=f"{NOTIFY_KEY}:processing:*", count=100):
            owner = key.rsplit(":", 1)[-1]
            if owner == self.worker_id or self.redis.exists(f"bb:worker:{owner}"):
                continue
            while self.redis.lmove(key, NOTIFY_KEY, "RIGHT", "RIGHT") is not None:
                moved += 1
        if moved:
            log.warning("recovered orphaned notifications", extra={"count": moved})
        return moved

    def run_forever(self) -> None:
        configure_logging("worker-notifier", self.settings.log_level)
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop.set())
        self.recover_orphans()
        log.info("notifier started", extra={"worker_id": self.worker_id})
        while not self.stop.is_set():
            ALIVE_FILE.touch()
            try:
                self.queue.heartbeat(self.worker_id, "notifications", ttl=60, tool="notifier", tool_version="1")
                for item in self.dispatcher.due_retries():
                    with session_scope() as s:
                        self.dispatcher.retry(s, item)
                raw = cast(str | None, self.redis.blmove(NOTIFY_KEY, self.processing, 5, "RIGHT", "LEFT"))
                if raw is None:
                    continue
                try:
                    self.process_raw(raw)
                finally:
                    self.redis.lrem(self.processing, 1, raw)
            except Exception:
                log.exception("notifier loop error")
                self.stop.wait(5)
        self.queue.deregister(self.worker_id)


def main() -> None:
    Notifier().run_forever()
