import time
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration


def test_ready(api):
    body = api.get("/ready").json()
    assert body["status"] == "ready", body
    assert all(c["ok"] for c in body["checks"].values())


def test_auth_required_and_rbac(api):
    assert httpx.get(f"{api.base_url}/programs").status_code == 401
    assert httpx.get(f"{api.base_url}/programs", headers={"X-API-Key": "wrong"}).status_code == 401
    r = api.post("/api-keys", json={"name": f"viewer-{uuid.uuid4().hex[:6]}", "role": "viewer"})
    viewer = httpx.Client(base_url=api.base_url, headers={"X-API-Key": r.json()["api_key"]})
    assert viewer.get("/programs").status_code == 200
    assert viewer.post("/programs", json={"name": "nope"}).status_code == 403
    assert (
        viewer.post("/scans", json={"program": "x", "scanners": ["httpx"], "targets": ["a.b.com"]}).status_code == 403
    )


@pytest.mark.parametrize(
    "value,type_",
    [("*.com", "wildcard"), ("api-*.example.com", "wildcard"), ("10.0.0.5/24", "cidr"), ("127.1", "domain")],
)
def test_malformed_scope_rejected(api, program, value, type_):
    r = api.post(f"/programs/{program['slug']}/scope", json={"type": type_, "value": value})
    assert r.status_code == 422, r.text


def test_scope_check_explains_decision(api, program):
    d = api.post("/scope/check", json={"target": "x.admin.example.com", "program_id": program["id"]}).json()
    assert d["allowed"] is False and "excluded" in d["reason"]
    d = api.post("/scope/check", json={"target": "https://api.example.com/x", "program_id": program["id"]}).json()
    assert d["allowed"] is True and d["reason"] == "matched *.example.com (wildcard)"


def test_scope_bypass_attempts_never_queue(api, program):
    targets = [
        "admin.example.com",
        "https://api.example.com@evil.net/",
        "https://evil.net\\@api.example.com/",
        "evilexample.com",
        "127.1",
        "8.8.8.8",
        "10.89.0.0/16",
    ]
    r = api.post("/scans", json={"program": program["slug"], "scanners": ["httpx"], "targets": targets})
    assert r.status_code == 201, r.text
    statuses = {j["target"]: j["status"] for j in r.json()["jobs"]}
    assert "QUEUED" not in statuses.values() and "PENDING" not in statuses.values(), statuses
    audit = api.get("/audit", params={"action": "SCOPE_BLOCKED", "limit": 50}).json()
    assert any(a["details"].get("target") == "admin.example.com" for a in audit)


def test_unimplemented_scanner_is_explicit(api, program):
    r = api.post("/scans", json={"program": program["slug"], "scanners": ["nuclei"], "targets": ["a.example.com"]})
    assert r.status_code == 422 and "not implemented" in r.text


def test_policy_limits_enforced(api):
    r = api.post(
        "/policies",
        json={"name": f"too-fast-{uuid.uuid4().hex[:6]}", "config": {"httpx": {"enabled": True, "rate_limit": 999}}},
    )
    assert r.status_code == 422


def test_end_to_end_lab_scan_reaches_elasticsearch(api, es, program):
    """worker -> event -> Logstash -> Elasticsearch, plus idempotency on resubmit."""
    body = {"program": program["slug"], "scanners": ["httpx"], "targets": ["lab-target.bb.test"]}
    r = api.post("/scans", json=body)
    assert r.status_code == 201, r.text
    job = r.json()["jobs"][0]
    if job["status"] == "OUT_OF_SCOPE":
        pytest.fail(job)
    dup = api.post("/scans", json=body).json()
    assert dup["summary"] == {"DUPLICATE": 1} and dup["duplicates"] == [job["id"]]

    deadline = time.time() + 120
    while time.time() < deadline:
        j = api.get(f"/jobs/{job['id']}").json()
        if j["status"] in ("SUCCESS", "FAILED", "BLOCKED"):
            break
        time.sleep(2)
    if j["status"] == "BLOCKED" and "resolves" in (j["error"] or ""):
        pytest.skip("lab network not attached (start with compose.dev.yaml)")
    assert j["status"] == "SUCCESS", j
    query = {"query": {"term": {"scan.job_id": job["id"]}}}
    hits = 0
    while time.time() < deadline:
        es.post("/bb-http-*/_refresh")
        hits = es.post("/bb-http-*/_count", json=query).json().get("count", 0)
        if hits:
            break
        time.sleep(2)
    assert hits >= 1
    doc = es.post("/bb-http-*/_search", json=query).json()["hits"]["hits"][0]["_source"]
    assert doc["program"]["id"] == program["id"] and doc["scope"]["id"]
    assert doc["scan"]["tool"] == "httpx" and doc["scan"]["tool_version"]


def test_kev_sync_and_queued_feeds(api):
    """KEV sync is synchronous and idempotent; EPSS/CVE correlation are queued for cve-monitor."""
    first = api.post("/sync/kev").json()
    assert first["entries"] > 1000
    again = api.post("/sync/kev").json()
    assert again["added"] == 0 and again["removed"] == 0 and again["baseline"] is False
    assert api.post("/sync/epss").status_code == 202
    r = api.post("/sync/cve")
    assert r.status_code == 202 and r.json()["queued"] == "correlate"


def test_correlation_is_explained(api, es):
    """Correlations carry separate technology / version / CPE confidences and are never 'detected' by CPE."""
    hits = (
        es.post("/bb-cve-*/_search", json={"size": 50, "query": {"term": {"cve.source": "cpe-correlation"}}})
        .json()
        .get("hits", {})
        .get("hits", [])
    )
    if not hits:
        pytest.skip("no CPE correlations yet (needs a versioned technology observation)")
    for h in hits:
        s = h["_source"]
        assert s["vulnerability"]["status"] == "potential"
        assert s["technology"]["version"] and s["cve"]["cpe"].startswith("cpe:2.3:a:")
        assert s["cve"]["cpe_confidence_level"] in ("low", "medium", "high")
