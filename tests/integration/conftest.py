"""Integration tests run against the live compose stack (make up-dev).

They read credentials from .env and are skipped when the API is not reachable.
"""

import os
import uuid
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]


def _env() -> dict[str, str]:
    out = {}
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip()
    return {**out, **os.environ}


ENV = _env()
API = f"http://127.0.0.1:{ENV.get('API_PORT', '18000')}"
ES = f"http://127.0.0.1:{ENV.get('ES_PORT', '19200')}"


@pytest.fixture(scope="session")
def api() -> httpx.Client:
    try:
        httpx.get(f"{API}/health", timeout=3).raise_for_status()
    except httpx.HTTPError:
        pytest.skip("platform API not reachable; start it with `make up-dev`")
    return httpx.Client(base_url=API, headers={"X-API-Key": ENV["BB_BOOTSTRAP_ADMIN_KEY"]}, timeout=120)


@pytest.fixture(scope="session")
def es() -> httpx.Client:
    return httpx.Client(base_url=ES, auth=("elastic", ENV["ELASTIC_PASSWORD"]), timeout=30)


@pytest.fixture(scope="session")
def program(api: httpx.Client) -> dict:
    slug = f"it-{uuid.uuid4().hex[:8]}"
    r = api.post("/programs", json={"name": f"Integration {slug}", "slug": slug, "default_policy": "discovery"})
    r.raise_for_status()
    p = r.json()
    for body in (
        {"type": "wildcard", "value": "*.example.com"},
        {"type": "domain", "value": "admin.example.com", "mode": "exclude"},
        {"type": "domain", "value": "lab-target.bb.test"},
        {"type": "cidr", "value": "10.89.250.0/24"},
    ):
        api.post(f"/programs/{slug}/scope", json=body).raise_for_status()
    yield p
    api.delete(f"/programs/{slug}")
