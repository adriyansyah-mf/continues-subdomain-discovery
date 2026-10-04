import importlib.util
import sys
from pathlib import Path

import pytest

from app.services.autoscale import PoolSignal, PoolState, ScaleConfig, decide

CFG = ScaleConfig(min_replicas=1, max_replicas=4, up_wait_seconds=120, down_idle_seconds=600, cooldown_seconds=300)


def sig(queued=0, busy=0, wait=None, cap=4):
    return PoolSignal("httpx", queued=queued, busy_workers=busy, oldest_queued_seconds=wait, concurrency_cap=cap)


def test_scale_up_when_backlog_waits_and_all_busy():
    d = decide(sig(queued=10, busy=2, wait=300), 2, CFG, PoolState(), now=1000, total_headroom=5)
    assert (d.desired, d.changed) == (3, True)


@pytest.mark.parametrize(
    "s,reason",
    [
        (sig(queued=10, busy=1, wait=300), "not busy"),  # a replica is free: no need for more
        (sig(queued=10, busy=2, wait=30), "waited"),  # backlog is young
    ],
)
def test_no_scale_up_without_pressure(s, reason):
    d = decide(s, 2, CFG, PoolState(), now=1000, total_headroom=5)
    assert not d.changed and reason in d.reason


def test_ceiling_is_max_concurrent_scans():
    # replicas beyond MAX_CONCURRENT_SCANS would only wait for cluster-wide slots
    d = decide(sig(queued=10, busy=2, wait=300, cap=2), 2, CFG, PoolState(), now=1000, total_headroom=5)
    assert not d.changed and "ceiling 2" in d.reason
    d = decide(sig(cap=2), 4, CFG, PoolState(), now=1000, total_headroom=5)
    assert d.desired == 2  # clamp down after the cap was lowered


def test_total_budget_blocks_scale_up():
    d = decide(sig(queued=10, busy=2, wait=300), 2, CFG, PoolState(), now=1000, total_headroom=0)
    assert not d.changed and "budget" in d.reason


def test_cooldown_holds():
    st = PoolState(last_action_at=900)
    d = decide(sig(queued=10, busy=2, wait=300), 2, CFG, st, now=1000, total_headroom=5)
    assert not d.changed and d.reason == "cooldown"


def test_scale_down_only_after_sustained_full_idle():
    st = PoolState()
    assert not decide(sig(), 3, CFG, st, now=0, total_headroom=5).changed  # idle timer starts
    assert not decide(sig(), 3, CFG, st, now=599, total_headroom=5).changed
    d = decide(sig(), 3, CFG, st, now=600, total_headroom=5)
    assert d.desired == 2


def test_busy_worker_resets_idle_and_prevents_scale_down():
    # compose stops the highest-numbered container, which may be the busy one
    st = PoolState()
    decide(sig(), 3, CFG, st, now=0, total_headroom=5)
    assert not decide(sig(busy=1), 3, CFG, st, now=700, total_headroom=5).changed
    assert st.idle_since is None
    assert not decide(sig(), 3, CFG, st, now=800, total_headroom=5).changed  # timer restarted


def test_min_replicas_floor():
    st = PoolState(idle_since=0)
    assert not decide(sig(), 1, CFG, st, now=10_000, total_headroom=5).changed
    assert decide(sig(), 0, CFG, PoolState(), now=0, total_headroom=5).desired == 1


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        ScaleConfig(min_replicas=5, max_replicas=2)


# --- applier (scripts/autoscale.py) -------------------------------------------------------------


def _load_script():
    path = Path(__file__).resolve().parents[2] / "scripts" / "autoscale.py"
    spec = importlib.util.spec_from_file_location("autoscale_script", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["autoscale_script"] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeApi:
    def __init__(self, pools, fail_audit=False):
        self.pools, self.fail_audit, self.audits = pools, fail_audit, []

    def call(self, method, path, body=None):
        if method == "GET":
            return {"pools": self.pools, "limits": {"max_concurrent_scans": 4}}
        if self.fail_audit:
            raise OSError("api down")
        self.audits.append(body)
        return {"recorded": True}


class FakeCompose:
    def __init__(self, replicas):
        self.current, self.calls = dict(replicas), []

    def replicas(self, service):
        return self.current[service]

    def scale(self, service, n):
        self.calls.append((service, n))
        self.current[service] = n


def test_applier_audits_before_scaling_and_skips_on_audit_failure():
    mod = _load_script()
    pools = {"httpx": {"pending": 9, "busy_workers": 1, "oldest_queued_seconds": 500}}
    cfgs = {"httpx": CFG}

    api, compose = FakeApi(pools), FakeCompose({"httpx-worker": 1})
    mod.tick(api, compose, cfgs, ["httpx"], 12, {"httpx": PoolState()}, dry_run=False)
    assert api.audits[0]["to_replicas"] == 2 and compose.calls == [("httpx-worker", 2)]

    api, compose = FakeApi(pools, fail_audit=True), FakeCompose({"httpx-worker": 1})
    mod.tick(api, compose, cfgs, ["httpx"], 12, {"httpx": PoolState()}, dry_run=False)
    assert compose.calls == []  # never scale unaudited

    api, compose = FakeApi(pools), FakeCompose({"httpx-worker": 1})
    mod.tick(api, compose, cfgs, ["httpx"], 12, {"httpx": PoolState()}, dry_run=True)
    assert compose.calls == [] and api.audits == []


def test_applier_config_rejects_unscalable_pools():
    mod = _load_script()
    with pytest.raises(SystemExit):
        mod.configs(mod.Env({"AUTOSCALE_SCANNERS": "httpx,certstream"}))
    cfgs, _, total = mod.configs(mod.Env({"AUTOSCALE_MAX_BBOT": "1", "AUTOSCALE_MAX_TOTAL_REPLICAS": "8"}))
    assert cfgs["bbot"].max_replicas == 1 and cfgs["httpx"].max_replicas == 4 and total == 8
