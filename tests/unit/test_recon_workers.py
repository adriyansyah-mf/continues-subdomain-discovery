import re
from pathlib import Path

import pytest

from app.schemas.policy import KatanaSettings, MapcidrSettings, UncoverSettings
from app.scope.engine import ScopeEngine, ScopeRule
from app.scope.normalize import classify_target
from app.services.events import EventContext
from workers.common.adapter import JobContext
from workers.common.scope_guard import ScopeGuard
from workers.common.tooling import parse_jsonl
from workers.katana import adapter as katana
from workers.mapcidr.adapter import build_argv as mapcidr_argv
from workers.uncover import adapter as uncover

FIX = Path(__file__).parent.parent / "fixtures"
P = "11111111-1111-1111-1111-111111111111"


def ctx(target, settings, *rules):
    built = [ScopeRule.build(id=f"r{i}", program_id=P, type=t, mode=m, value=v) for i, (t, v, m) in enumerate(rules)]
    guard = ScopeGuard(program_id=P, engine=ScopeEngine(built))
    return JobContext(
        job_id="j",
        scan_id=None,
        program_id=P,
        program_name="p",
        asset_id=None,
        scope_id=None,
        target=classify_target(target),
        settings=settings,
        guard=guard,
        event_ctx=EventContext(),
        deadline_seconds=120,
        is_cancelled=lambda: False,
    )


def test_mapcidr_argv():
    c = ctx("10.0.0.0/28", MapcidrSettings(enabled=True), ("cidr", "10.0.0.0/24", "include"))
    assert mapcidr_argv(c, "mapcidr") == [
        "mapcidr",
        "-cl",
        "10.0.0.0/28",
        "-silent",
        "-duc",
        "-skip-base",
        "-skip-broadcast",
    ]


def test_katana_argv_scope_and_limits(monkeypatch):
    c = ctx(
        "lab.example.com",
        KatanaSettings(enabled=True, depth=9, rate_limit=3),
        ("domain", "lab.example.com", "include"),
        ("url", "https://lab.example.com/admin", "exclude"),
        ("url", "https://other.example.com/x", "exclude"),
    )
    argv = katana.build_argv(c, "katana")
    assert argv[argv.index("-u") + 1] == "https://lab.example.com/"
    assert argv[argv.index("-fs") + 1] == "fqdn"
    assert argv[argv.index("-d") + 1] == "3"  # clamped to MAX_CRAWL_DEPTH
    assert argv[argv.index("-rl") + 1] == "3" and "-dr" in argv
    cos = [argv[i + 1] for i, a in enumerate(argv) if a == "-cos"]
    assert len(cos) == 1  # only exclusions for this host
    rx = re.compile(cos[0])
    assert rx.search("https://lab.example.com/admin") and rx.search("https://lab.example.com/admin/x?y=1")
    assert not rx.search("https://lab.example.com/administrator")


def test_katana_records_normalised_and_js_flag():
    raw = parse_jsonl((FIX / "katana_output.jsonl").read_text().splitlines())
    recs = [katana.normalize_record(r) for r in raw.records]
    js = [r for r in recs if r["url"]["js_discovered"]]
    assert {r["url"]["full"] for r in js} == {
        "https://lab.example.com/api/v2/items?page=2",
        "https://lab.example.com/api/v2/items?page=3",
    }
    # same endpoint, different parameter values
    assert js[0]["_url"].endpoint_hash == js[1]["_url"].endpoint_hash
    assert js[0]["url"]["parameters"] == ["page"] and js[0]["url"]["parent"].endswith("app.js")


def test_uncover_queries_and_targets(monkeypatch):
    assert uncover.query_for("shodan", "example.com") == 'ssl.cert.subject.cn:"example.com"'
    assert uncover.result_targets({"ip": "192.0.2.1", "host": "API.Example.com", "port": 443}) == [
        "192.0.2.1",
        "api.example.com",
    ]
    assert uncover.result_targets({"ip": "not-ip", "host": "bad..host"}) == []
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert uncover.configured_engines(["shodan"]) == []
    monkeypatch.setenv("SHODAN_API_KEY", "x")
    assert uncover.configured_engines(["shodan", "fofa"]) == ["shodan"]
    c = ctx("example.com", UncoverSettings(enabled=True, limit=50), ("domain", "example.com", "include"))
    argv = uncover.build_argv(c, ["shodan"], "uncover")
    assert argv[argv.index("-q") + 1] == 'ssl.cert.subject.cn:"example.com"' and argv[argv.index("-l") + 1] == "50"


def test_uncover_missing_key_is_non_retryable(monkeypatch):
    from workers.common.adapter import NonRetryableError

    for keys in uncover.ENGINE_KEYS.values():
        for k in keys:
            monkeypatch.delenv(k, raising=False)
    adapter = uncover.UncoverAdapter.__new__(uncover.UncoverAdapter)
    c = ctx("example.com", UncoverSettings(enabled=True), ("domain", "example.com", "include"))
    with pytest.raises(NonRetryableError):
        adapter.execute(c)


@pytest.mark.parametrize(
    "value,ok",
    [
        ("X-Bug-Bounty: handle", True),
        ("", True),
        ("X-Bug-Bounty: a\r\nInjected: 1", False),
        ("Bad Header: x", False),
        ("X-A:nospace", False),
    ],
)
def test_identification_header_validation(monkeypatch, value, ok):
    from app.config import get_settings
    from workers.common.tooling import identification_header

    monkeypatch.setenv("BB_REQUEST_HEADER", value)
    get_settings.cache_clear()
    try:
        if ok:
            assert identification_header() == (value or None)
        else:
            with pytest.raises(ValueError):
                identification_header()
    finally:
        get_settings.cache_clear()
