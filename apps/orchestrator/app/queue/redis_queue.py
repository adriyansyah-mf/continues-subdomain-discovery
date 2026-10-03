"""Redis-backed reliable work queue.

Layout:
  bb:q:<queue>                         pending job ids (LPUSH in, BLMOVE out)
  bb:q:<queue>:processing:<worker_id>  jobs a worker has reserved (removed on ack)
  bb:dlq:<queue>                       dead-lettered job payloads
  bb:worker:<worker_id>                heartbeat hash (expires if the worker dies)

The queue only carries job ids. The job's state and parameters live in PostgreSQL,
so a lost Redis message can always be re-dispatched from the database. Retries are
also DB-driven: a failed job goes back to PENDING with ``next_attempt_at`` and the
scheduler's dispatcher re-enqueues it when due.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, cast

import redis

from app.config import get_settings

QUEUE_NAMES = (
    "discovery",
    "mapcidr",
    "certstream",
    "dns",
    "tlsx",
    "httpx",
    "bbot",
    "katana",
    "nuclei",
    "cve",
    "ipranges",
    "notifications",
)

_Q = "bb:q:"
_DLQ = "bb:dlq:"
_HIGH = ":high"
HIGH_PRIORITY = 7  # job priority (0-9) at or above which the high lane is used
_WORKER = "bb:worker:"


@lru_cache(maxsize=1)
def get_redis() -> redis.Redis:
    s = get_settings()
    return redis.Redis.from_url(
        s.redis_url,
        password=s.redis_password_value,
        decode_responses=True,
        socket_timeout=10,
        socket_connect_timeout=5,
        health_check_interval=30,
    )


def _check_queue(name: str) -> str:
    if name not in QUEUE_NAMES:
        raise ValueError(f"unknown queue {name!r}")
    return name


@dataclass
class WorkerInfo:
    worker_id: str
    queue: str
    data: dict[str, Any]


class RedisQueue:
    def __init__(self, client: redis.Redis):
        self.r = client

    # --- producer side ------------------------------------------------
    def enqueue(self, queue: str, job_id: str, priority: int = 5) -> None:
        """Jobs with priority >= HIGH_PRIORITY go to a separate lane that workers drain first."""
        key = _Q + _check_queue(queue)
        if priority >= HIGH_PRIORITY:
            key += _HIGH
        self.r.lpush(key, job_id)

    # --- consumer side --------------------------------------------------
    def processing_key(self, queue: str, worker_id: str) -> str:
        return f"{_Q}{queue}:processing:{worker_id}"

    def reserve(self, queue: str, worker_id: str, timeout: int = 5) -> str | None:
        """Take the oldest high-priority item if any, otherwise block briefly on the normal lane.

        The blocking wait is capped (2 s) so a high-priority job never waits behind a long block.
        """
        base = _Q + _check_queue(queue)
        processing = self.processing_key(queue, worker_id)
        item = self.r.lmove(base + _HIGH, processing, "RIGHT", "LEFT")
        if item is None:
            item = self.r.blmove(base, processing, min(timeout, 2), "RIGHT", "LEFT")
        return cast(str | None, item)

    def ack(self, queue: str, worker_id: str, job_id: str) -> None:
        self.r.lrem(self.processing_key(queue, worker_id), 1, job_id)

    def dead_letter(self, queue: str, payload: dict[str, Any]) -> None:
        self.r.lpush(_DLQ + _check_queue(queue), json.dumps(payload, default=str))

    # --- worker liveness ------------------------------------------------
    def heartbeat(self, worker_id: str, queue: str, ttl: int, **info: Any) -> None:
        key = _WORKER + worker_id
        self.r.hset(key, mapping={"queue": queue, "last_seen": time.time(), **{k: str(v) for k, v in info.items()}})
        self.r.expire(key, ttl)

    def deregister(self, worker_id: str) -> None:
        self.r.delete(_WORKER + worker_id)

    def workers(self) -> list[WorkerInfo]:
        out = []
        for key in self.r.scan_iter(match=_WORKER + "*", count=200):
            data = cast(dict[str, Any], self.r.hgetall(key))
            out.append(WorkerInfo(worker_id=key[len(_WORKER) :], queue=data.get("queue", "?"), data=data))
        return out

    def drop_orphans(self) -> int:
        """Delete processing lists of dead workers (no heartbeat).

        The jobs themselves are recovered from PostgreSQL by the scheduler's
        reaper (stale RUNNING -> retry/FAILED), so nothing is re-run blindly here.
        """
        dropped = 0
        for key in self.r.scan_iter(match=_Q + "*:processing:*", count=200):
            _, _, worker_id = key[len(_Q) :].partition(":processing:")
            if not self.r.exists(_WORKER + worker_id):
                dropped += cast(int, self.r.llen(key))
                self.r.delete(key)
        return dropped

    # --- introspection --------------------------------------------------
    def depths(self) -> dict[str, dict[str, int]]:
        pipe = self.r.pipeline()
        for q in QUEUE_NAMES:
            pipe.llen(_Q + q)
            pipe.llen(_Q + q + _HIGH)
            pipe.llen(_DLQ + q)
        results = cast(list[int], pipe.execute())
        out = {}
        for i, q in enumerate(QUEUE_NAMES):
            normal, high, dlq = (int(x) for x in results[3 * i : 3 * i + 3])
            out[q] = {"pending": normal + high, "high_priority": high, "dlq": dlq}
        return out

    def dlq_items(self, queue: str, limit: int = 50) -> list[dict[str, Any]]:
        items = cast(list[str], self.r.lrange(_DLQ + _check_queue(queue), 0, limit - 1))
        return [json.loads(x) for x in items]


class ConcurrencyLimiter:
    """Cluster-wide semaphore shared by all worker replicas (Redis keys with TTL).

    Used per scanner (MAX_CONCURRENT_SCANS), per program (PROGRAM_MAX_CONCURRENT) and per
    target host (PER_HOST_MAX_CONCURRENT).

    Each slot is a key with a TTL so a crashed worker cannot leak a slot forever.
    """

    def __init__(self, client: redis.Redis, scanner: str, limit: int, ttl: int):
        self.r = client
        self.prefix = f"bb:slots:{scanner}:"
        self.limit = limit
        self.ttl = ttl

    def acquire(self, holder: str) -> bool:
        return any(self.r.set(f"{self.prefix}{slot}", holder, nx=True, ex=self.ttl) for slot in range(self.limit))

    def release(self, holder: str) -> None:
        for slot in range(self.limit):
            key = f"{self.prefix}{slot}"
            if self.r.get(key) == holder:
                self.r.delete(key)
