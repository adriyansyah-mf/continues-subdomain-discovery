import hashlib
import hmac
import json
import socket

import pytest

from app.services.notify import providers
from app.services.notify.catalog import EVENT_MAP, from_event, render_text, severity_at_least
from app.services.notify.dispatch import dedup_key
from app.services.notify.providers import ConfigError, check_destination, get_provider, resolve_secret


def change(etype, current="1.2.3.4", previous=None, asset_id="a1"):
    return {
        "@timestamp": "2026-10-04T00:00:00Z",
        "event": {"type": etype},
        "program": {"id": None, "name": "Lab"},
        "asset": {"id": asset_id, "value": "api.example.com"},
        "change": {"current": current, "previous": previous},
    }


def test_only_mapped_events_notify():
    assert from_event(change("HTTP_STATUS_CHANGED")) is None
    n = from_event(change("KEV_ADDED", current="CVE-2023-44487"))
    assert n.type == "NEW_KEV" and n.severity == "critical" and "CVE-2023-44487" in n.detail
    assert set(EVENT_MAP[k][0] for k in EVENT_MAP) >= {
        "NEW_KEV",
        "NEW_CVE",
        "TLS_EXPIRING",
        "SCAN_FAILURE",
        "DLQ_EVENT",
    }


def test_same_fact_same_dedup_key_different_fact_different_key():
    import uuid

    pid = uuid.uuid4()
    a, b = from_event(change("NEW_IP")), from_event(change("NEW_IP"))
    c = from_event(change("NEW_IP", current="5.6.7.8"))
    assert dedup_key(pid, a) == dedup_key(pid, b) != dedup_key(pid, c)
    assert dedup_key(pid, a) != dedup_key(uuid.uuid4(), a)  # per policy


def test_severity_filter_and_render():
    assert severity_at_least("critical", "high") and not severity_at_least("low", "medium")
    assert severity_at_least("info", None)
    text = render_text(from_event(change("TLS_CHANGED", current="new", previous="old")))
    assert text.startswith("[Lab] LOW") and "old -> new" in text


def test_scan_failure_notification():
    ev = {
        "event": {"type": "DLQ_EVENT"},
        "asset": {"value": "x.example.com"},
        "scan": {"tool": "httpx", "job_id": "j1"},
        "error": {"message": "boom", "retry_count": 3},
    }
    n = from_event(ev)
    assert n.type == "DLQ_EVENT" and "httpx" in n.title and n.detail == "boom"


@pytest.mark.parametrize("ref", ["lowercase", "BAD-NAME", "A", "X" * 65, "$(id)"])
def test_secret_ref_validation(ref):
    with pytest.raises(ConfigError):
        resolve_secret(ref)


def test_secret_ref_resolves_env(monkeypatch):
    monkeypatch.setenv("NOTIFY_TEST_SECRET", "s3cret")
    assert resolve_secret("NOTIFY_TEST_SECRET") == "s3cret"
    monkeypatch.delenv("NOTIFY_TEST_SECRET")
    with pytest.raises(ConfigError):
        resolve_secret("NOTIFY_TEST_SECRET")


def _fake_dns(ip):
    return lambda host, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


def test_destination_requires_https_and_public_address(monkeypatch):
    monkeypatch.delenv("NOTIFY_ALLOW_PRIVATE_DESTINATIONS", raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns("93.184.216.34"))
    check_destination("https://hooks.example.com/x")
    with pytest.raises(ConfigError):
        check_destination("http://hooks.example.com/x")
    with pytest.raises(ConfigError):
        check_destination("https://user:pw@hooks.example.com/x")
    for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254"):
        monkeypatch.setattr(socket, "getaddrinfo", _fake_dns(ip))
        with pytest.raises(ConfigError):
            check_destination("https://hooks.example.com/x")
    monkeypatch.setenv("NOTIFY_ALLOW_PRIVATE_DESTINATIONS", "true")
    check_destination("http://hooks.example.com/x")  # lab override


def test_provider_config_validation():
    with pytest.raises(ConfigError):
        get_provider("sms")
    with pytest.raises(ConfigError):
        get_provider("webhook").validate_config({"url": "https://x", "command": "rm"}, None)
    with pytest.raises(ConfigError):
        get_provider("telegram").validate_config({}, "NOTIFY_TELEGRAM_TOKEN")
    with pytest.raises(ConfigError):
        get_provider("email").validate_config({"host": "smtp.example.com"}, None)
    get_provider("email").validate_config({"host": "smtp.example.com", "from": "a@x", "to": ["b@x"]}, None)


def test_webhook_signature(monkeypatch):
    sent = {}
    monkeypatch.setattr(
        providers,
        "_post_json",
        lambda url, payload, headers=None: sent.update(url=url, payload=payload, headers=headers),
    )
    n = from_event(change("NEW_IP"))
    get_provider("webhook").send(n, {"url": "https://hooks.example.com/x", "sign": True}, "k3y")
    expected = hmac.new(b"k3y", json.dumps(n.to_dict()).encode(), hashlib.sha256).hexdigest()
    assert sent["headers"]["X-BB-Signature"] == "sha256=" + expected
    with pytest.raises(ConfigError):
        get_provider("webhook").send(n, {"url": "https://hooks.example.com/x", "sign": True}, None)


def test_emitter_tap_is_bounded_and_filtered():
    import fakeredis

    from app.services.events import NOTIFY_KEY, EventContext, EventEmitter, build_event

    r = fakeredis.FakeRedis(decode_responses=True)
    em = EventEmitter(r)
    ev = build_event(
        index="bb-changes",
        kind="event",
        category="change",
        type_="NEW_IP",
        ctx=EventContext(),
        body={"change": {"current": "1.2.3.4"}},
    )
    other = build_event(index="bb-changes", kind="event", category="change", type_="TITLE_CHANGED", ctx=EventContext())
    em.emit_many("changes", [ev, other])
    assert r.llen("bb:events:changes") == 2 and r.llen(NOTIFY_KEY) == 1
    assert json.loads(r.lindex(NOTIFY_KEY, 0))["type"] == "NEW_IP"
