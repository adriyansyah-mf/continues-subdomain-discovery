import re
from pathlib import Path

import pytest

from app.schemas.policy import KatanaSettings, MapcidrSettings, NucleiSettings, UncoverSettings
from app.scope.engine import ScopeEngine, ScopeRule
from app.scope.normalize import classify_target
from app.services.events import EventContext
from workers.common.adapter import JobContext
from workers.common.scope_guard import ScopeGuard
from workers.common.tooling import parse_jsonl
from workers.katana import adapter as katana
from workers.mapcidr.adapter import build_argv as mapcidr_argv
from workers.nuclei import adapter as nuclei
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


def test_nuclei_argv_pinned_and_safe(monkeypatch):
    from app.config import get_settings

    monkeypatch.delenv("BB_REQUEST_HEADER", raising=False)
    get_settings.cache_clear()
    c = ctx("lab.example.com", NucleiSettings(enabled=True, rate_limit=5), ("domain", "lab.example.com", "include"))
    argv = nuclei.build_argv(c, "nuclei", "/opt/pd/nuclei-templates")
    assert argv[argv.index("-u") + 1] == "lab.example.com"  # bare host: nuclei probes both schemes
    for flag in ("-ni", "-duc", "-j", "-silent", "-nc", "-or", "-ot"):  # no OOB, no runtime updates
        assert flag in argv
    assert argv[argv.index("-t") + 1] == "/opt/pd/nuclei-templates"
    assert argv[argv.index("-s") + 1] == "medium,high,critical"
    assert argv[argv.index("-etags") + 1] == "dos,fuzz,intrusive,bruteforce"
    assert argv[argv.index("-rl") + 1] == "5" and argv[argv.index("-c") + 1] == "2"
    assert "-headless" not in argv and "-tags" not in argv


def test_nuclei_argv_url_target_and_allowlist():
    c = ctx(
        "https://lab.example.com/app",
        NucleiSettings(enabled=True, tags=["cve"], exclude_tags=["dos"], templates=["tech-detect", "cve-2023-44487"]),
        ("url", "https://lab.example.com/app", "include"),
    )
    argv = nuclei.build_argv(c, "nuclei", "/tpl")
    assert argv[argv.index("-u") + 1] == "https://lab.example.com/app"
    # id entries resolve within the pinned bundle (-t + -id restrictions)
    assert argv[argv.index("-t") + 1] == "/tpl"
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "-id"] == ["tech-detect", "cve-2023-44487"]
    assert argv[argv.index("-tags") + 1] == "cve" and argv[argv.index("-etags") + 1] == "dos"

    c2 = ctx(
        "https://lab.example.com/app",
        NucleiSettings(enabled=True, templates=["http/files/backup.yaml"]),
        ("url", "https://lab.example.com/app", "include"),
    )
    argv2 = nuclei.build_argv(c2, "nuclei", "/tpl")
    assert [argv2[i + 1] for i, a in enumerate(argv2) if a == "-t"] == ["/tpl/http/files/backup.yaml"]
    assert "-id" not in argv2


def test_nuclei_template_styles_cannot_be_mixed():
    with pytest.raises(ValueError, match="cannot be mixed"):
        NucleiSettings(enabled=True, templates=["tech-detect", "http/files/backup.yaml"])


def test_nuclei_refuses_host_with_url_exclusions():
    from workers.common.scope_guard import ScopeBlockedError

    c = ctx(
        "lab.example.com",
        NucleiSettings(enabled=True),
        ("domain", "lab.example.com", "include"),
        ("url", "https://lab.example.com/admin", "exclude"),
    )
    with pytest.raises(ScopeBlockedError):
        nuclei.build_argv(c, "nuclei", "/tpl")


def test_nuclei_normalize_record():
    raw = parse_jsonl((FIX / "nuclei_output.jsonl").read_text().splitlines())
    recs = {r["template-id"]: nuclei.normalize_record(r) for r in raw.records}
    classified = recs["demo-classified-finding"]
    assert classified["nuclei"]["severity"] == "high"
    assert classified["nuclei"]["matched_at"] == "http://lab.example.com/admin.html"
    assert classified["cves"] == ["CVE-2023-44487", "CVE-2025-23419"]  # nuclei lowercases CVE ids
    assert classified["nuclei"]["classification"]["cvss_score"] == 7.5
    assert classified["nuclei"]["extracted_results"] == ["1.2.3"]
    assert classified["url"]["full"] == "http://lab.example.com/admin.html" and classified["url"]["hash"]
    assert classified["_url"].url_hash == classified["url"]["hash"]
    assert recs["demo-exposure-finding"]["cves"] == []
    assert nuclei.normalize_record({"info": {"severity": "high"}}) is None  # no template-id/matched-at


def test_nuclei_execute_missing_templates(monkeypatch):
    from workers.common.adapter import NonRetryableError

    adapter = nuclei.NucleiAdapter.__new__(nuclei.NucleiAdapter)
    monkeypatch.setattr(nuclei, "TEMPLATES_DIR", "/nonexistent-nuclei-templates")
    c = ctx("lab.example.com", NucleiSettings(enabled=True), ("domain", "lab.example.com", "include"))
    with pytest.raises(NonRetryableError):
        adapter.execute(c)


def test_nuclei_templates_release_pin_checked(tmp_path, monkeypatch):
    from workers.common.adapter import NonRetryableError

    marker = tmp_path / "release"
    marker.write_text("v10.4.9\n")
    monkeypatch.setattr(nuclei, "RELEASE_FILE", str(marker))
    monkeypatch.setenv("NUCLEI_TEMPLATES_VERSION", "10.4.9")
    assert nuclei.templates_release() == "10.4.9"
    monkeypatch.setenv("NUCLEI_TEMPLATES_VERSION", "9.9.9")
    with pytest.raises(NonRetryableError):
        nuclei.templates_release()
