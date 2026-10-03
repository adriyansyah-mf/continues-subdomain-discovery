import fakeredis

from app.queue.redis_queue import HIGH_PRIORITY, ConcurrencyLimiter, RedisQueue
from app.scope.normalize import classify_target
from workers.common.runner import target_host


def test_high_priority_lane_is_served_first():
    q = RedisQueue(fakeredis.FakeRedis(decode_responses=True))
    q.enqueue("httpx", "normal-1", priority=5)
    q.enqueue("httpx", "normal-2", priority=5)
    q.enqueue("httpx", "urgent", priority=HIGH_PRIORITY)
    d = q.depths()["httpx"]
    assert d["pending"] == 3 and d["high_priority"] == 1
    assert [q.reserve("httpx", "w", timeout=1) for _ in range(3)] == ["urgent", "normal-1", "normal-2"]


def test_target_host_keys():
    assert target_host(classify_target("https://API.example.com:8443/x")) == "api.example.com"
    assert target_host(classify_target("api.example.com")) == "api.example.com"
    assert target_host(classify_target("192.0.2.1")) == "192.0.2.1"
    assert target_host(classify_target("AS13335")) is None


def test_per_host_limit_is_shared_by_replicas():
    r = fakeredis.FakeRedis(decode_responses=True)
    host_a1 = ConcurrencyLimiter(r, "host:api.example.com", 1, ttl=60)
    host_a2 = ConcurrencyLimiter(r, "host:api.example.com", 1, ttl=60)  # another worker process
    host_b = ConcurrencyLimiter(r, "host:other.example.com", 1, ttl=60)
    assert host_a1.acquire("w1:j1")
    assert not host_a2.acquire("w2:j2")  # same host: must wait
    assert host_b.acquire("w2:j3")  # different host: fine
    host_a1.release("w1:j1")
    assert host_a2.acquire("w2:j2")


def test_release_only_frees_own_slot():
    r = fakeredis.FakeRedis(decode_responses=True)
    lim = ConcurrencyLimiter(r, "program:p1", 2, ttl=60)
    assert lim.acquire("a") and lim.acquire("b")
    lim.release("someone-else")
    assert not lim.acquire("c")
