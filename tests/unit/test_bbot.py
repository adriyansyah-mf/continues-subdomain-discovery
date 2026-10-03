from pathlib import Path

from app.schemas.policy import BbotSettings
from app.scope.engine import ScopeEngine, ScopeRule
from app.scope.normalize import classify_target
from app.services.events import EventContext
from app.services.technology import from_cpe
from workers.bbot.adapter import bbot_event_body, build_argv, scan_finished
from workers.common.adapter import JobContext
from workers.common.scope_guard import ScopeGuard
from workers.common.tooling import parse_jsonl

FIX = Path(__file__).parent.parent / "fixtures" / "bbot_output.jsonl"
P = "11111111-1111-1111-1111-111111111111"


def ctx(settings, *rules):
    built = [ScopeRule.build(id=f"r{i}", program_id=P, type=t, mode=m, value=v) for i, (t, v, m) in enumerate(rules)]
    return JobContext(
        job_id="0f0e0d0c-0000-0000-0000-000000000000",
        scan_id=None,
        program_id=P,
        program_name="p",
        asset_id=None,
        scope_id=None,
        target=classify_target("example.com"),
        settings=settings,
        guard=ScopeGuard(program_id=P, engine=ScopeEngine(built)),
        event_ctx=EventContext(),
        deadline_seconds=600,
        is_cancelled=lambda: False,
    )


def test_argv_passive_by_default_with_blacklist():
    c = ctx(
        BbotSettings(enabled=True),
        ("wildcard", "*.example.com", "include"),
        ("domain", "example.com", "include"),
        ("domain", "admin.example.com", "exclude"),
        ("wildcard", "*.internal.example.com", "exclude"),
        ("domain", "other.org", "exclude"),
        ("cidr", "192.0.2.0/24", "exclude"),
    )
    argv = build_argv(c, "/tmp/x", "bbot")
    rf = argv[argv.index("-rf") + 1 : argv.index("-rf") + 3]
    assert rf == ["passive", "safe"]
    assert argv[argv.index("-em") + 1] == "crt_db"
    bl = argv[argv.index("-b") + 1 :]
    assert bl == ["192.0.2.0/24", "admin.example.com", "internal.example.com"]  # other.org not relevant
    assert "--allow-deadly" not in argv


def test_active_mode_still_requires_safe():
    argv = build_argv(
        ctx(BbotSettings(enabled=True, passive_only=False), ("domain", "example.com", "include")), "/tmp/x", "bbot"
    )
    assert argv[argv.index("-rf") + 1] == "safe" and "passive" not in argv


def test_fixture_parses_and_finishes():
    raw = parse_jsonl(FIX.read_text().splitlines())
    assert scan_finished(raw.records)
    assert not scan_finished([r for r in raw.records if r.get("type") != "SCAN"])
    body = bbot_event_body(next(r for r in raw.records if r["type"] == "DNS_NAME"))
    assert body["bbot"]["module"] and body["bbot"]["type"] == "DNS_NAME"


def test_cpe_parsing_never_invents_versions():
    t = from_cpe("cpe:/a:cloudflare:cloudflare")
    assert t is not None and t.vendor == "cloudflare" and t.version is None and t.version_confidence is None
    t = from_cpe("cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*")
    assert t is not None and t.name == "nginx" and t.version == "1.25.3"
    assert from_cpe("cpe:2.3:a:x:*:*") is None and from_cpe("garbage") is None
