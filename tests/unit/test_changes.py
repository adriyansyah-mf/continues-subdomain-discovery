from app.services.changes import change_event, diff_dns, diff_http, diff_ports, diff_tls
from app.services.events import EventContext


def types(changes):
    return [c.change_type for c in changes]


def test_first_observation_produces_no_diff():
    assert diff_dns(None, {"A": ["1.2.3.4"]}) == []
    assert diff_http(None, {"status_code": 200}) == []


def test_dns_ip_change():
    prev = {"A": ["1.2.3.4"], "CNAME": [], "NS": ["ns1.x.com"]}
    cur = {"A": ["1.2.3.5"], "CNAME": [], "NS": ["ns1.x.com"]}
    t = types(diff_dns(prev, cur))
    assert t[0] == "DNS_CHANGED" and "A_CHANGED" in t and "IP_CHANGED" in t and "NS_CHANGED" not in t


def test_dns_unchanged_order_insensitive():
    assert diff_dns({"A": ["2.2.2.2", "1.1.1.1"]}, {"A": ["1.1.1.1", "2.2.2.2"]}) == []


def test_snapshot_example_from_spec():
    # 2026-10-01: IP=1.2.3.4 TLS=AAA tech=nginx ; 2026-10-02: IP=1.2.3.5 TLS=BBB tech=nginx,Grafana
    http = diff_http(
        {"ip": "1.2.3.4", "technologies": ["nginx"], "status_code": 200},
        {"ip": "1.2.3.5", "technologies": ["grafana", "nginx"], "status_code": 200},
    )
    tls = diff_tls({"fingerprint": "AAA"}, {"fingerprint": "BBB"})
    assert "IP_CHANGED" in types(http) and "TECHNOLOGY_ADDED" in types(http)
    assert "TLS_CHANGED" in types(tls) and "CERT_CHANGED" in types(tls)
    added = [c for c in http if c.change_type == "TECHNOLOGY_ADDED"]
    assert added[0].current == "grafana"


def test_http_status_title_and_tech_removed():
    t = types(
        diff_http(
            {"status_code": 200, "title": "a", "technologies": ["php"]},
            {"status_code": 500, "title": "b", "technologies": []},
        )
    )
    assert t == ["HTTP_STATUS_CHANGED", "TITLE_CHANGED", "TECHNOLOGY_REMOVED"]


def test_tls_expiry_alerts_once():
    cur = {"fingerprint": "A", "expiry_status": "expiring", "not_after": "2026-10-20"}
    assert types(diff_tls(None, cur)) == ["CERT_EXPIRING"]  # first sight of an expiring cert alerts
    assert diff_tls(cur, dict(cur)) == []  # no repeat while unchanged
    expired = {**cur, "expiry_status": "expired"}
    assert types(diff_tls(cur, expired)) == ["CERTIFICATE_EXPIRED"]


def test_tls_san_issuer_version():
    t = types(
        diff_tls(
            {"fingerprint": "A", "issuer": "X", "san": ["a"], "tls_version": "tls12"},
            {"fingerprint": "A", "issuer": "Y", "san": ["a", "b"], "tls_version": "tls13"},
        )
    )
    assert t == ["TLS_CHANGED", "ISSUER_CHANGED", "SAN_CHANGED", "TLS_VERSION_CHANGED"]


def test_ports():
    assert types(diff_ports({"ports": [80, 443]}, {"ports": [443, 8443]})) == ["NEW_PORT", "PORT_REMOVED"]


def test_change_event_has_required_fields():
    from app.services.changes import Change

    ctx = EventContext(
        program_id="p", program_name="P", asset_id="a", asset_type="domain", asset_value="x.com", source_name="dns"
    )
    ev = change_event(Change("IP_CHANGED", "dns.ips", ["1.1.1.1"], ["2.2.2.2"]), ctx, confidence=0.95)
    assert ev["bb"]["index"] == "bb-changes"
    assert ev["event"]["type"] == "IP_CHANGED"
    assert ev["asset"]["value"] == "x.com" and ev["program"]["id"] == "p"
    assert ev["change"]["previous"] == ["1.1.1.1"] and ev["change"]["current"] == ["2.2.2.2"]
    assert ev["confidence"]["score"] == 0.95 and ev["source"]["name"] == "dns"
    assert ev["@timestamp"].endswith("Z")
