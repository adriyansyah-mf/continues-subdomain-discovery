"""CertStream worker against a local fake CT stream and the dev stack's PostgreSQL/Redis.

Needs compose.dev.yaml (PostgreSQL on 127.0.0.1:15432, Redis on 127.0.0.1:16379).
"""

import json
import os
import socket
import threading
import time
import uuid
from pathlib import Path

import pytest

from tests.integration.conftest import ENV

pytestmark = pytest.mark.integration
FIX = Path(__file__).parent.parent / "fixtures" / "certstream_messages.jsonl"


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


@pytest.fixture(scope="module")
def service_env():
    pg, rd = int(ENV.get("POSTGRES_DEV_PORT", 15432)), int(ENV.get("REDIS_DEV_PORT", 16379))
    if not (_port_open(pg) and _port_open(rd)):
        pytest.skip("dev overlay ports not exposed (make up-dev)")
    os.environ.update(
        {
            "POSTGRES_HOST": "127.0.0.1",
            "POSTGRES_PORT": str(pg),
            "POSTGRES_PASSWORD": ENV["POSTGRES_PASSWORD"],
            "POSTGRES_DB": ENV["POSTGRES_DB"],
            "POSTGRES_USER": ENV["POSTGRES_USER"],
            "REDIS_URL": f"redis://127.0.0.1:{rd}/0",
            "REDIS_PASSWORD": ENV["REDIS_PASSWORD"],
        }
    )
    os.environ.pop("DATABASE_URL", None)
    from app.config import get_settings
    from app.database import get_engine
    from app.queue.redis_queue import get_redis

    for f in (get_settings, get_engine, get_redis):
        f.cache_clear()
    yield
    for f in (get_settings, get_engine, get_redis):
        f.cache_clear()


def _unique_cert(domain: str) -> dict:
    msg = json.loads(FIX.read_text().splitlines()[1])
    leaf = msg["data"]["leaf_cert"]
    leaf["fingerprint"] = uuid.uuid4().hex
    leaf["all_domains"] = [domain, "unrelated.example.net"]
    leaf["subject"]["CN"] = domain
    leaf["extensions"]["subjectAltName"] = f"DNS:{domain}"
    return msg


def test_in_scope_discovery_creates_asset_and_followup(api, program, service_env):
    from workers.certstream.service import CertstreamService

    svc = CertstreamService()
    domain = f"ct-{uuid.uuid4().hex[:8]}.example.com"  # inside *.example.com of the test program
    res = svc.process(__import__("workers.certstream.parser", fromlist=["x"]).parse_message(_unique_cert(domain)))
    assert res["in_scope"] and res["new_assets"] == 1 and res["jobs"] == 1, res
    assets = api.get("/assets", params={"q": domain}).json()
    assert len(assets) == 1 and assets[0]["confidence_source"] == "certstream"
    assert "certificate SAN matched" in assets[0]["confidence_reason"]
    rels = api.get(f"/assets/{assets[0]['id']}/relationships").json()
    assert any(r["relationship_type"] == "DISCOVERED_FROM" and r["other_asset_type"] == "certificate" for r in rels)
    jobs = api.get("/jobs", params={"program": program["slug"], "scanner": "dns"}).json()
    assert any(j["target"] == domain for j in jobs)


def test_excluded_and_out_of_scope_names_are_not_recorded(api, program, service_env):
    from workers.certstream.parser import parse_message
    from workers.certstream.service import CertstreamService

    svc = CertstreamService()
    sub = f"x{uuid.uuid4().hex[:6]}.admin.example.com"  # excluded subtree in the test program
    res = svc.process(parse_message(_unique_cert(sub)))
    if res["in_scope"]:  # another program on this platform may legitimately include it
        assert program["name"] not in res.get("programs", [])
    assert not api.get("/assets", params={"q": "unrelated.example.net", "program": program["slug"]}).json()


def test_websocket_stream_with_reconnect(service_env):
    """Messages are consumed over a real websocket; the client reconnects after the server drops it."""
    from websockets.sync.server import serve

    from workers.certstream.service import CertstreamService

    lines = FIX.read_text().splitlines()
    connections = []

    def handler(ws):
        connections.append(1)
        for line in lines:
            ws.send(line)
        ws.close()  # force a reconnect

    server = serve(handler, "127.0.0.1", 0)
    port = server.socket.getsockname()[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    svc = CertstreamService(url=f"ws://127.0.0.1:{port}")
    t = threading.Thread(target=svc.run_forever, daemon=True)
    import signal

    orig = signal.signal
    signal.signal = lambda *a, **k: None  # run_forever installs handlers; not allowed off the main thread
    try:
        t.start()
        deadline = time.time() + 20
        while time.time() < deadline and len(connections) < 2:
            time.sleep(0.2)
    finally:
        svc.stop.set()
        server.shutdown()
        signal.signal = orig
    assert len(connections) >= 2, "client did not reconnect"
    assert svc.stats["messages"] >= len(lines) and svc.stats["certificates"] >= 2
