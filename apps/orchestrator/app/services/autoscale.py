"""Worker autoscaling decisions (pure logic; applied by ``scripts/autoscale.py``).

Replicas only add throughput *across* targets. Every replica still has to take the cluster-wide
Redis slots (MAX_CONCURRENT_SCANS per scanner, PROGRAM_MAX_CONCURRENT, PER_HOST_MAX_CONCURRENT)
before a job runs, so scaling never raises the load on one host or one program. Replicas beyond
MAX_CONCURRENT_SCANS would only wait for slots, so that is the ceiling.

Algorithm, per scanner pool, evaluated every interval:

* clamp into ``[min_replicas, ceiling]`` first, where
  ``ceiling = min(max_replicas, MAX_CONCURRENT_SCANS)``;
* **scale up by one** when jobs are waiting in Redis, every replica is busy, the oldest queued job
  has waited at least ``up_wait_seconds``, the pool is out of cooldown, and the total replica
  budget (``max_total_replicas`` across all scaled pools) has room;
* **scale down by one** when nothing is queued and *no* replica is busy, continuously for
  ``down_idle_seconds``, and the pool is out of cooldown. Requiring zero busy workers matters:
  ``docker compose --scale`` stops the highest-numbered container, which may not be the idle one,
  and a job can outlive the stop grace period;
* otherwise hold. One step per decision plus a cooldown gives hysteresis (no flapping).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScaleConfig:
    min_replicas: int = 1
    max_replicas: int = 4
    up_wait_seconds: float = 120
    down_idle_seconds: float = 600
    cooldown_seconds: float = 300

    def __post_init__(self) -> None:
        if not 0 <= self.min_replicas <= self.max_replicas:
            raise ValueError("autoscale: need 0 <= min_replicas <= max_replicas")
        if min(self.up_wait_seconds, self.down_idle_seconds, self.cooldown_seconds) < 0:
            raise ValueError("autoscale: durations must be >= 0")


@dataclass(frozen=True)
class PoolSignal:
    """One queue's live state, from ``GET /workers``."""

    scanner: str
    queued: int  # normal + high-priority lane in Redis
    busy_workers: int
    oldest_queued_seconds: float | None
    concurrency_cap: int  # MAX_CONCURRENT_SCANS


@dataclass
class PoolState:
    """Per-pool memory kept by the applier between decisions."""

    last_action_at: float | None = None
    idle_since: float | None = None


@dataclass(frozen=True)
class Decision:
    scanner: str
    current: int
    desired: int
    reason: str

    @property
    def changed(self) -> bool:
        return self.desired != self.current


def ceiling(cfg: ScaleConfig, sig: PoolSignal) -> int:
    return max(cfg.min_replicas, min(cfg.max_replicas, sig.concurrency_cap))


def decide(
    sig: PoolSignal, current: int, cfg: ScaleConfig, state: PoolState, now: float, total_headroom: int
) -> Decision:
    """Desired replica count for one pool. Updates ``state.idle_since``; the caller sets
    ``state.last_action_at`` only once a change has actually been applied."""

    def hold(reason: str) -> Decision:
        return Decision(sig.scanner, current, current, reason)

    top = ceiling(cfg, sig)
    idle = sig.queued == 0 and sig.busy_workers == 0
    if not idle:
        state.idle_since = None
    elif state.idle_since is None:
        state.idle_since = now

    if current < cfg.min_replicas:
        return Decision(sig.scanner, current, cfg.min_replicas, f"below min_replicas {cfg.min_replicas}")
    if current > top:
        return Decision(sig.scanner, current, top, f"above ceiling {top} (max_replicas / MAX_CONCURRENT_SCANS)")
    if state.last_action_at is not None and now - state.last_action_at < cfg.cooldown_seconds:
        return hold("cooldown")

    if sig.queued > 0:
        if sig.busy_workers < current:
            return hold(f"{sig.queued} queued but {current - sig.busy_workers} replica(s) not busy")
        waited = sig.oldest_queued_seconds or 0.0
        if waited < cfg.up_wait_seconds:
            return hold(f"oldest queued job waited {waited:.0f}s < {cfg.up_wait_seconds:.0f}s")
        if current >= top:
            return hold(f"at ceiling {top} (max_replicas / MAX_CONCURRENT_SCANS)")
        if total_headroom <= 0:
            return hold("total replica budget exhausted (max_total_replicas)")
        return Decision(
            sig.scanner, current, current + 1, f"{sig.queued} queued, all busy, oldest waited {waited:.0f}s"
        )

    if idle and state.idle_since is not None:
        idle_for = now - state.idle_since
        if current <= cfg.min_replicas:
            return hold("idle at min_replicas")
        if idle_for < cfg.down_idle_seconds:
            return hold(f"idle {idle_for:.0f}s < {cfg.down_idle_seconds:.0f}s")
        return Decision(sig.scanner, current, current - 1, f"idle for {idle_for:.0f}s")
    return hold("steady")
