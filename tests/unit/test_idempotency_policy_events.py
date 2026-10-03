import uuid
from datetime import UTC, datetime

import fakeredis
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.schemas.policy import DEFAULT_POLICIES, NucleiSettings, PolicyConfig, enforce_global_limits
from app.services.events import EventContext, EventEmitter, build_event
from app.services.scans import idempotency_key

PID = uuid.uuid4()
POL = uuid.uuid4()


def key(t="a.example.com", scanner="httpx", now=datetime(2026, 10, 2, 10, 5, tzinfo=UTC), nonce=None, bucket=3600):
    return idempotency_key(
        target=t, scanner=scanner, policy_id=POL, bucket_seconds=bucket, now=now, program_id=PID, nonce=nonce
    )


def test_idempotency_same_bucket_same_key():
    assert key() == key(now=datetime(2026, 10, 2, 10, 59, tzinfo=UTC))


def test_idempotency_differs_by_bucket_scanner_target_nonce():
    base = key()
    assert base != key(now=datetime(2026, 10, 2, 11, 0, tzinfo=UTC))
    assert base != key(scanner="tlsx")
    assert base != key(t="b.example.com")
    assert base != key(nonce="force")


def test_default_policies_valid_and_within_limits():
    for name, (_, raw) in DEFAULT_POLICIES.items():
        assert enforce_global_limits(PolicyConfig.model_validate(raw), Settings()) == [], name


def test_policy_rejects_unknown_fields_and_flags():
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"httpx": {"enabled": True, "extra_args": "-o /etc/passwd"}})
    with pytest.raises(ValidationError):
        PolicyConfig.model_validate({"bogus": {}})


def test_policy_global_caps():
    cfg = PolicyConfig.model_validate({"httpx": {"enabled": True, "rate_limit": 500}, "katana": {"depth": 9}})
    errors = enforce_global_limits(cfg, Settings())
    assert any("httpx.rate_limit" in e for e in errors) and any("MAX_CRAWL_DEPTH" in e for e in errors)


def test_nuclei_template_paths_restricted():
    with pytest.raises(ValidationError):
        NucleiSettings(templates=["../../etc/passwd"])
    with pytest.raises(ValidationError):
        NucleiSettings(templates=["/abs/path.yaml"])
    with pytest.raises(ValidationError):
        NucleiSettings(tags=["cve;rm -rf"])
    assert NucleiSettings(templates=["http/cves/2024/CVE-2024-0001.yaml"]).templates


def test_event_schema_and_pipeline_allowlist():
    r = fakeredis.FakeRedis(decode_responses=True)
    em = EventEmitter(r, max_backlog=2)
    ctx = EventContext(
        program_id="p",
        scan_id="s",
        job_id="j",
        tool="httpx",
        tool_version="1.12.0",
        source_name="httpx",
        source_type="active",
        asset_id="a",
        asset_type="url",
        asset_value="u",
    )
    ev = build_event(
        index="bb-http",
        kind="event",
        category="web",
        type_="HTTP_OBSERVATION",
        ctx=ctx,
        body={"http": {"response": {"status_code": 200}}},
    )
    for field in ("@timestamp", "event", "program", "asset", "scan", "source"):
        assert field in ev
    assert ev["scan"] == {"id": "s", "job_id": "j", "tool": "httpx", "tool_version": "1.12.0"}
    em.emit("httpx", ev)
    assert r.llen("bb:events:httpx") == 1
    with pytest.raises(ValueError):
        em.emit("dns", ev)  # bb-http is not routed by the dns pipeline
    with pytest.raises(ValueError):
        em.emit("nope", ev)


def test_event_backlog_limit():
    from app.services.events import EventBacklogFullError

    r = fakeredis.FakeRedis(decode_responses=True)
    em = EventEmitter(r, max_backlog=1)
    ev = build_event(index="bb-dns", kind="event", category="network", type_="X", ctx=EventContext())
    em.emit("dns", ev)
    with pytest.raises(EventBacklogFullError):
        em.emit("dns", ev)
