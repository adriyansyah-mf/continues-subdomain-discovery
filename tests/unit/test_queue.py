import fakeredis
import pytest

from app.queue.redis_queue import ConcurrencyLimiter, RedisQueue


@pytest.fixture
def q():
    return RedisQueue(fakeredis.FakeRedis(decode_responses=True))


def test_reserve_ack_cycle(q):
    q.enqueue("httpx", "job-1")
    q.enqueue("httpx", "job-2")
    assert q.reserve("httpx", "w1", timeout=1) == "job-1"  # FIFO
    assert q.depths()["httpx"]["pending"] == 1
    assert q.r.llen(q.processing_key("httpx", "w1")) == 1
    q.ack("httpx", "w1", "job-1")
    assert q.r.llen(q.processing_key("httpx", "w1")) == 0


def test_unknown_queue_rejected(q):
    with pytest.raises(ValueError):
        q.enqueue("rm -rf", "x")


def test_dlq(q):
    q.dead_letter("httpx", {"job_id": "j", "error": "boom"})
    assert q.depths()["httpx"]["dlq"] == 1
    assert q.dlq_items("httpx")[0]["error"] == "boom"


def test_orphan_processing_lists_dropped_only_for_dead_workers(q):
    q.enqueue("dns", "a")
    q.enqueue("dns", "b")
    q.reserve("dns", "dead", timeout=1)
    q.reserve("dns", "alive", timeout=1)
    q.heartbeat("alive", "dns", ttl=30)
    assert q.drop_orphans() == 1
    assert q.r.llen(q.processing_key("dns", "alive")) == 1


def test_concurrency_limiter():
    r = fakeredis.FakeRedis(decode_responses=True)
    lim = ConcurrencyLimiter(r, "httpx", limit=2, ttl=60)
    assert lim.acquire("a") and lim.acquire("b")
    assert not lim.acquire("c")
    lim.release("a")
    assert lim.acquire("c")
