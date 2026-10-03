"""Policy matching, deduplication, delivery, retries and rate limiting for notifications."""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, cast

import redis
from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models import NotificationChannel, NotificationDelivery, NotificationPolicy
from app.services.events import EventContext, EventEmitter, build_event
from app.services.notify.catalog import Notification, severity_at_least
from app.services.notify.providers import ConfigError, NotificationError, get_provider, resolve_secret
from app.utils.time import utcnow

log = logging.getLogger(__name__)
RETRY_KEY = "bb:notify:retry"
DLQ_KEY = "bb:dlq:notifications"
BACKOFF = (30, 120, 480)  # seconds before retry 1, 2, 3
MAX_ATTEMPTS = len(BACKOFF) + 1


@dataclass
class Outcome:
    status: str  # sent | failed | duplicate | deferred | retry
    detail: str = ""


def match(session: Session, n: Notification) -> list[tuple[NotificationPolicy, NotificationChannel]]:
    rows = session.execute(
        select(NotificationPolicy, NotificationChannel)
        .join(NotificationChannel, NotificationChannel.id == NotificationPolicy.channel_id)
        .where(NotificationPolicy.enabled.is_(True), NotificationChannel.enabled.is_(True))
        .where(
            or_(
                NotificationPolicy.program_id.is_(None),
                NotificationPolicy.program_id == (uuid.UUID(n.program_id) if n.program_id else None),
            )
        )
    ).all()
    return [
        (p, c)
        for p, c in rows
        if (n.type in p.event_types or "*" in p.event_types) and severity_at_least(n.severity, p.min_severity)
    ]


def dedup_key(policy_id: uuid.UUID, n: Notification) -> str:
    return hashlib.sha256(f"{policy_id}|{n.type}|{n.fact_key}".encode()).hexdigest()


def send_now(channel: NotificationChannel, n: Notification) -> None:
    get_provider(channel.channel_type).send(n, dict(channel.config or {}), resolve_secret(channel.secret_ref))


class Dispatcher:
    def __init__(self, r: redis.Redis, emitter: EventEmitter | None, rate_per_minute: int = 20):
        self.r = r
        self.emitter = emitter
        self.rate = rate_per_minute

    def _rate_ok(self, channel_id: uuid.UUID) -> bool:
        key = f"bb:notify:rate:{channel_id}:{int(time.time() // 60)}"
        n = cast(int, self.r.incr(key))
        if n == 1:
            self.r.expire(key, 120)
        return n <= self.rate

    def _schedule(self, delivery_id: uuid.UUID, n: Notification, delay: float) -> None:
        member = json.dumps({"delivery_id": str(delivery_id), "n": n.to_dict()}, sort_keys=True)
        self.r.zadd(RETRY_KEY, {member: time.time() + delay})

    def _emit(self, status: str, n: Notification, channel: NotificationChannel, detail: str = "") -> None:
        if self.emitter is None:
            return
        try:
            self.emitter.emit(
                "ops",
                build_event(
                    index="bb-notifications",
                    kind="event",
                    category="notification",
                    type_=f"NOTIFICATION_{status.upper()}",
                    ctx=EventContext(
                        program_id=n.program_id,
                        program_name=n.program_name,
                        asset_value=n.asset_value,
                        source_name="notifier",
                        source_type="system",
                    ),
                    body={
                        "notification": {
                            "type": n.type,
                            "severity": n.severity,
                            "event_type": n.event_type,
                            "channel": channel.name,
                            "channel_type": channel.channel_type,
                            "status": status,
                            "detail": detail[:500],
                            "title": n.title[:300],
                        }
                    },
                ),
            )
        except Exception as exc:
            log.warning("notification event emission failed", extra={"error": str(exc)})

    def handle(self, session: Session, n: Notification) -> list[Outcome]:
        outcomes = []
        for policy, channel in match(session, n):
            key = dedup_key(policy.id, n)
            delivery_id = session.execute(
                insert(NotificationDelivery)
                .values(
                    id=uuid.uuid4(),
                    policy_id=policy.id,
                    channel_id=channel.id,
                    event_type=n.type,
                    severity=n.severity,
                    dedup_key=key,
                    status="pending",
                    attempts=0,
                    summary=n.title[:1000],
                )
                .on_conflict_do_nothing(index_elements=["dedup_key"])
                .returning(NotificationDelivery.id)
            ).scalar_one_or_none()
            if delivery_id is None:
                outcomes.append(Outcome("duplicate"))
                continue
            outcomes.append(self.attempt(session, delivery_id, channel, n))
        return outcomes

    def attempt(
        self, session: Session, delivery_id: uuid.UUID, channel: NotificationChannel, n: Notification
    ) -> Outcome:
        delivery = session.get(NotificationDelivery, delivery_id)
        if delivery is None or delivery.status in ("sent", "failed"):
            return Outcome("duplicate")
        if not self._rate_ok(channel.id):
            self._schedule(delivery_id, n, 60)  # does not consume an attempt
            return Outcome("deferred", "channel rate limit")
        delivery.attempts += 1
        try:
            send_now(channel, n)
        except ConfigError as exc:
            delivery.status, delivery.last_error = "failed", str(exc)[:1000]
            self._dead_letter(delivery, channel, n, str(exc))
            return Outcome("failed", str(exc))
        except (NotificationError, Exception) as exc:
            delivery.last_error = str(exc)[:1000]
            if delivery.attempts >= MAX_ATTEMPTS:
                delivery.status = "failed"
                self._dead_letter(delivery, channel, n, str(exc))
                return Outcome("failed", str(exc))
            self._schedule(delivery_id, n, BACKOFF[delivery.attempts - 1])
            return Outcome("retry", str(exc))
        delivery.status, delivery.sent_at, delivery.last_error = "sent", utcnow(), None
        self._emit("sent", n, channel)
        return Outcome("sent")

    def _dead_letter(
        self, delivery: NotificationDelivery, channel: NotificationChannel, n: Notification, error: str
    ) -> None:
        self.r.lpush(
            DLQ_KEY,
            json.dumps(
                {
                    "delivery_id": str(delivery.id),
                    "channel": channel.name,
                    "notification": n.to_dict(),
                    "error": error[:1000],
                    "failed_at": utcnow().isoformat(),
                }
            ),
        )
        self._emit("failed", n, channel, error)

    def due_retries(self, limit: int = 100) -> list[dict[str, Any]]:
        now = time.time()
        members = cast(list[str], self.r.zrangebyscore(RETRY_KEY, "-inf", now, start=0, num=limit))
        out = []
        for m in members:
            if self.r.zrem(RETRY_KEY, m):  # claim (safe with several notifier replicas)
                out.append(json.loads(m))
        return out

    def retry(self, session: Session, item: dict[str, Any]) -> Outcome:
        n = Notification(**item["n"])
        delivery = session.get(NotificationDelivery, uuid.UUID(item["delivery_id"]))
        if delivery is None or delivery.channel_id is None:
            return Outcome("duplicate")
        channel = session.get(NotificationChannel, delivery.channel_id)
        if channel is None or not channel.enabled:
            session.execute(
                update(NotificationDelivery)
                .where(NotificationDelivery.id == delivery.id)
                .values(status="suppressed", last_error="channel disabled or removed")
            )
            return Outcome("failed", "channel disabled")
        return self.attempt(session, delivery.id, channel, n)
