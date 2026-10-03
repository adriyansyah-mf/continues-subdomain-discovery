import socket
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.models.enums import BlockReason
from app.schemas.policy import HttpxSettings, TlsxSettings
from app.scope.engine import ScopeEngine, ScopeRule
from app.scope.normalize import classify_target
from app.services.events import EventContext
from workers.common.adapter import JobContext
from workers.common.process import ToolTimeoutError, run_tool
from workers.common.scope_guard import ScopeBlockedError, ScopeGuard
from workers.common.tooling import parse_jsonl
from workers.httpx.adapter import build_argv as httpx_argv
from workers.httpx.adapter import normalize_record as httpx_normalize
from workers.tlsx.adapter import build_argv as tlsx_argv
from workers.tlsx.adapter import expiry_status
from workers.tlsx.adapter import normalize_record as tlsx_normalize

FIX = Path(__file__).parent.parent / "fixtures"
P = "11111111-1111-1111-1111-111111111111"


def guard(*rules, allow_private=False):
    built = [ScopeRule.build(id=f"r{i}", program_id=P, type=t, mode=m, value=v) for i, (t, v, m) in enumerate(rules)]
    return ScopeGuard(program_id=P, engine=ScopeEngine(built), allow_private=allow_private)


def ctx_for(target, g, settings):
    return JobContext(
        job_id="j",
        scan_id=None,
        program_id=P,
        program_name="p",
        asset_id=None,
        scope_id=None,
        target=classify_target(target),
        settings=settings,
        guard=g,
        event_ctx=EventContext(),
        deadline_seconds=60,
        is_cancelled=lambda: False,
    )


def test_parse_jsonl_separates_malformed():
    raw = parse_jsonl((FIX / "httpx_output.jsonl").read_text().splitlines())
    assert len(raw.records) == 2 and len(raw.malformed) == 2


def test_httpx_normalize_record():
    rec = parse_jsonl((FIX / "httpx_output.jsonl").read_text().splitlines()).records[0]
    obs = httpx_normalize(rec)
    assert obs["url"]["full"] == "https://api.example.com/"
    assert obs["http"]["response"]["status_code"] == 200 and obs["http"]["response"]["time_ms"] == 12.5
    assert obs["host"]["ip"] == "192.0.2.10"
    assert obs["http"]["cdn"] == {"detected": True, "name": "cloudflare", "type": "waf"}
    names = {t["name"]: t["version"] for t in obs["technology"]}
    assert names["nginx"] == "1.24.0" and names["ubuntu"] is None


def test_layer3_blocks_out_of_scope_output_and_unpinned_ip():
    g = guard(("wildcard", "*.example.com", "include"))
    g.pinned_ips = {"192.0.2.10"}
    assert g.validate_output("https://api.example.com/", ip="192.0.2.10").allowed
    assert not g.validate_output("https://evil.example.org/", ip="203.0.113.9").allowed
    assert not g.validate_output("https://api.example.com/", ip="203.0.113.9").allowed  # rebinding


def test_resolution_guard_blocks_private_unless_explicitly_in_scope(monkeypatch):
    def fake_getaddrinfo(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    g = guard(("wildcard", "*.example.com", "include"))
    with pytest.raises(ScopeBlockedError) as exc:
        g.resolve_and_pin(classify_target("internal.example.com"))
    assert exc.value.reason is BlockReason.PRIVATE_ADDRESS
    g2 = guard(("wildcard", "*.example.com", "include"), ("cidr", "10.0.0.0/24", "include"))
    assert g2.resolve_and_pin(classify_target("internal.example.com")) == {"10.0.0.5"}


@pytest.mark.parametrize("ip", ["127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "0.0.0.0"])
def test_sensitive_ip_targets_blocked(ip):
    g = guard(("cidr", "0.0.0.0/0", "include"), ("cidr", "::/0", "include"))
    # broad include still does not authorise sensitive space: only an explicit /32 does
    g.engine = ScopeEngine([])
    with pytest.raises(ScopeBlockedError):
        g.resolve_and_pin(classify_target(ip))


def test_check_target_raises_on_exclusion():
    g = guard(("wildcard", "*.example.com", "include"), ("domain", "admin.example.com", "exclude"))
    with pytest.raises(ScopeBlockedError) as exc:
        g.check_target(classify_target("admin.example.com"))
    assert exc.value.reason is BlockReason.EXCLUDED


def test_httpx_argv_is_list_and_pinned():
    g = guard(("wildcard", "*.example.com", "include"))
    g.pinned_ips = {"192.0.2.10"}
    argv = httpx_argv(ctx_for("api.example.com", g, HttpxSettings(enabled=True, rate_limit=7)), "httpx")
    assert argv[:3] == ["httpx", "-u", "api.example.com"]
    assert argv[argv.index("-rl") + 1] == "7"
    assert argv[argv.index("-allow") + 1] == "192.0.2.10"
    assert "-fr" not in argv  # never follow cross-host redirects


def test_tlsx_argv_connects_to_pinned_ip_with_sni():
    g = guard(("wildcard", "*.example.com", "include"))
    g.pinned_ips = {"192.0.2.10"}
    argv = tlsx_argv(ctx_for("api.example.com", g, TlsxSettings(enabled=True)), "tlsx")
    assert argv[argv.index("-u") + 1] == "192.0.2.10" and argv[argv.index("-sni") + 1] == "api.example.com"
    g.pinned_ips = set()
    assert tlsx_argv(ctx_for("api.example.com", g, TlsxSettings(enabled=True)), "tlsx") is None


def test_tlsx_normalize_and_expiry():
    rec = parse_jsonl((FIX / "tlsx_output.jsonl").read_text().splitlines()).records[0]
    now = datetime(2026, 10, 2, tzinfo=UTC)
    obs = tlsx_normalize(rec, now=now)
    assert obs["tls"]["fingerprint"] == "53fe7f77" and obs["tls"]["expiry_status"] == "expiring"
    assert obs["network"]["port"] == 443 and "other.example.net" in obs["tls"]["san"]
    assert expiry_status(datetime(2026, 9, 1, tzinfo=UTC), now) == "expired"
    assert expiry_status(datetime(2027, 1, 1, tzinfo=UTC), now) == "valid"


def test_run_tool_timeout_kills_process():
    with pytest.raises(ToolTimeoutError):
        run_tool([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1, poll_interval=0.2)


def test_run_tool_captures_lines():
    res = run_tool([sys.executable, "-c", "print('{\"a\":1}'); print('x')"], timeout=10)
    assert res.returncode == 0 and res.stdout_lines == ['{"a":1}', "x"]


def test_run_tool_line_limit_stops_tool():
    import time as _t

    start = _t.monotonic()
    res = run_tool(
        [sys.executable, "-c", "import time\nfor i in range(1000):\n print(i, flush=True); time.sleep(0.01)"],
        timeout=30,
        max_lines=5,
        poll_interval=0.2,
    )
    assert res.limit_reached and res.ok and len(res.stdout_lines) == 5
    assert _t.monotonic() - start < 8
