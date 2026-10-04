#!/usr/bin/env python3
"""Worker autoscaler for the Docker Compose deployment (runs on the Docker host).

Every interval it reads ``GET /workers``, decides per scanner pool with
``app.services.autoscale.decide`` (algorithm documented there and in docs/deployment.md), audits
each change through ``POST /workers/scale-events`` and only then applies it with
``docker compose up -d --no-deps --no-recreate --scale <scanner>-worker=N``. If the audit call
fails, the change is skipped. Containers get no Docker-socket access; the host applies changes.

Usage (from the repository root; `make autoscale` / `make autoscale-dry`):
    .venv/bin/python scripts/autoscale.py [--dry-run] [--once] [--interval 60]
        [--compose-file compose.yaml --compose-file compose.dev.yaml]

Configuration: AUTOSCALE_* in the environment or .env (see .env.example); API key from
BB_API_KEY (an operator key; scale events are operator actions), else BB_BOOTSTRAP_ADMIN_KEY.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "apps" / "orchestrator"))

from app.services.autoscale import Decision, PoolSignal, PoolState, ScaleConfig, decide  # noqa: E402

# Queue-consuming scanner pools. certstream-worker holds one websocket and is never scaled.
SCALABLE = ("dns", "httpx", "tlsx", "katana", "nuclei", "mapcidr", "uncover", "bbot")


def log(message: str, **fields: object) -> None:
    rec = {"@timestamp": datetime.now(UTC).isoformat(), "service.name": "autoscaler", "message": message, **fields}
    print(json.dumps(rec, default=str), flush=True)


def read_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key.strip()] = value
    return out


class Env:
    def __init__(self, file_values: dict[str, str]):
        self.file_values = file_values

    def get(self, key: str, default: str | None = None) -> str | None:
        return os.environ.get(key) or self.file_values.get(key) or default

    def num(self, key: str, default: float) -> float:
        raw = self.get(key)
        return float(raw) if raw else default


def configs(env: Env) -> tuple[dict[str, ScaleConfig], list[str], int]:
    enabled = [s.strip() for s in (env.get("AUTOSCALE_SCANNERS", ",".join(SCALABLE)) or "").split(",") if s.strip()]
    unknown = sorted(set(enabled) - set(SCALABLE))
    if unknown:
        raise SystemExit(f"AUTOSCALE_SCANNERS: not scalable: {unknown} (allowed: {', '.join(SCALABLE)})")
    out = {}
    for scanner in enabled:
        up = scanner.upper()
        out[scanner] = ScaleConfig(
            min_replicas=int(env.num(f"AUTOSCALE_MIN_{up}", env.num("AUTOSCALE_MIN_REPLICAS", 1))),
            max_replicas=int(env.num(f"AUTOSCALE_MAX_{up}", env.num("AUTOSCALE_MAX_REPLICAS", 4))),
            up_wait_seconds=env.num("AUTOSCALE_UP_WAIT_SECONDS", 120),
            down_idle_seconds=env.num("AUTOSCALE_DOWN_IDLE_SECONDS", 600),
            cooldown_seconds=env.num("AUTOSCALE_COOLDOWN_SECONDS", 300),
        )
    return out, enabled, int(env.num("AUTOSCALE_MAX_TOTAL_REPLICAS", 12))


class Api:
    def __init__(self, base: str, key: str):
        if not base.startswith(("http://", "https://")):
            raise SystemExit("BB_API_URL must be an http(s) URL")
        self.base, self.key = base.rstrip("/"), key

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310 - http(s) checked
        req.add_header("X-API-Key", self.key)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - http(s) checked
            return json.loads(resp.read() or b"{}")


class Compose:
    def __init__(self, files: list[str]):
        self.base = ["docker", "compose"] + [x for f in files for x in ("-f", f)]

    def replicas(self, service: str) -> int:
        out = subprocess.run(
            [*self.base, "ps", "-q", "--status", "running", service],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        return sum(1 for ln in out.stdout.splitlines() if ln.strip())

    def scale(self, service: str, n: int) -> None:
        subprocess.run(
            [*self.base, "up", "-d", "--no-deps", "--no-recreate", "--scale", f"{service}={n}", service],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=900,  # scale-down waits for the stop grace period
        )


def tick(
    api: Api,
    compose: Compose,
    cfgs: dict[str, ScaleConfig],
    order: list[str],
    max_total: int,
    states: dict[str, PoolState],
    dry_run: bool,
) -> list[Decision]:
    snapshot = api.call("GET", "/workers")
    pools, cap = snapshot["pools"], int(snapshot["limits"]["max_concurrent_scans"])
    current = {s: compose.replicas(f"{s}-worker") for s in order}
    total = sum(current.values())
    now = time.monotonic()
    decisions = []
    for scanner in order:
        pool = pools.get(scanner) or {}
        sig = PoolSignal(
            scanner=scanner,
            queued=int(pool.get("pending", 0)),
            busy_workers=int(pool.get("busy_workers", 0)),
            oldest_queued_seconds=pool.get("oldest_queued_seconds"),
            concurrency_cap=cap,
        )
        d = decide(sig, current[scanner], cfgs[scanner], states[scanner], now, max_total - total)
        decisions.append(d)
        if not d.changed:
            continue
        log("scale decision", scanner=scanner, current=d.current, desired=d.desired, reason=d.reason, dry_run=dry_run)
        if dry_run:
            continue
        try:
            api.call(
                "POST",
                "/workers/scale-events",
                {
                    "scanner": scanner,
                    "from_replicas": d.current,
                    "to_replicas": d.desired,
                    "reason": d.reason,
                },
            )
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log("audit failed; change skipped", scanner=scanner, error=str(exc))
            continue
        try:
            compose.scale(f"{scanner}-worker", d.desired)
        except subprocess.SubprocessError as exc:
            err = getattr(exc, "stderr", "") or str(exc)
            log("scale failed", scanner=scanner, error=str(err)[-500:])
            continue
        states[scanner].last_action_at = time.monotonic()
        total += d.desired - d.current
        log("scaled", scanner=scanner, replicas=d.desired)
    return decisions


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="log decisions, change nothing")
    ap.add_argument("--once", action="store_true", help="evaluate once and exit")
    ap.add_argument("--interval", type=float, default=None, help="seconds between evaluations (default 60)")
    ap.add_argument("--compose-file", action="append", default=None, help="repeatable; default compose.yaml")
    args = ap.parse_args()

    env = Env(read_env_file(ROOT / ".env"))
    key = env.get("BB_API_KEY") or env.get("BB_BOOTSTRAP_ADMIN_KEY")
    if not key:
        raise SystemExit("set BB_API_KEY (operator key) or BB_BOOTSTRAP_ADMIN_KEY")
    api = Api(env.get("BB_API_URL") or f"http://127.0.0.1:{env.get('API_PORT', '18000')}", key)
    compose = Compose(args.compose_file or ["compose.yaml"])
    cfgs, order, max_total = configs(env)
    interval = args.interval if args.interval is not None else env.num("AUTOSCALE_INTERVAL_SECONDS", 60)
    states = {s: PoolState() for s in order}
    log(
        "autoscaler started",
        scanners=order,
        max_total_replicas=max_total,
        interval=interval,
        dry_run=args.dry_run,
        config={s: vars(c) for s, c in cfgs.items()},
    )

    stop = False

    def _stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    while not stop:
        try:
            decisions = tick(api, compose, cfgs, order, max_total, states, args.dry_run)
            if args.once:
                for d in decisions:
                    log("pool", scanner=d.scanner, current=d.current, desired=d.desired, reason=d.reason)
                return 0
        except (urllib.error.URLError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            # API/Docker unavailable: change nothing this round (fail closed), try again later.
            log("evaluation failed; no changes", error=str(exc))
            if args.once:
                return 1
        deadline = time.monotonic() + interval
        while not stop and time.monotonic() < deadline:
            time.sleep(1)
    log("autoscaler stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
