"""Minimal NVD CVE API 2.0 client (CPE match lookups) with rate limiting and retries.

Without an API key NVD allows 5 requests / 30 s; with NVD_API_KEY 50 / 30 s.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Any

import httpx

log = logging.getLogger(__name__)
API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdError(RuntimeError):
    pass


class NvdClient:
    def __init__(self, api_key: str | None = None, base_url: str = API, timeout: float = 60):
        self.api_key = api_key
        self.base_url = base_url
        self.interval = 0.7 if api_key else 6.5
        self._last = 0.0
        self._lock = threading.Lock()
        self._client = httpx.Client(timeout=timeout, headers={"apiKey": api_key} if api_key else {})

    def _throttle(self) -> None:
        with self._lock:
            wait = self.interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(5):
            self._throttle()
            try:
                r = self._client.get(self.base_url, params=params)
            except httpx.HTTPError as exc:
                log.warning("NVD request failed", extra={"error": str(exc), "attempt": attempt})
                time.sleep(2**attempt * 5)
                continue
            if r.status_code in (403, 429, 503):
                time.sleep(2**attempt * 10)
                continue
            if r.status_code == 404:
                return {"totalResults": 0, "vulnerabilities": []}
            r.raise_for_status()
            return r.json()
        raise NvdError(f"NVD unavailable after retries for {params}")

    def cves_for_cpe(self, cpe: str, limit: int = 2000) -> list[dict[str, Any]]:
        """CVEs whose configurations match the (versioned) CPE."""
        out: list[dict[str, Any]] = []
        start = 0
        while True:
            page = self._get({"virtualMatchString": cpe, "resultsPerPage": 2000, "startIndex": start})
            vulns = page.get("vulnerabilities") or []
            out += [v["cve"] for v in vulns if isinstance(v, dict) and "cve" in v]
            start += len(vulns)
            if not vulns or start >= int(page.get("totalResults", 0)) or len(out) >= limit:
                return out[:limit]


def parse_cve(cve: dict[str, Any]) -> dict[str, Any]:
    """Normalize an NVD CVE object. Preference: CVSS v4.0 > v3.1 > v3.0 > v2."""
    desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None)
    metrics = cve.get("metrics") or {}
    score = version = vector = severity = None
    for key, ver in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        items = metrics.get(key) or []
        primary = next((m for m in items if m.get("type") == "Primary"), items[0] if items else None)
        if primary:
            data = primary.get("cvssData") or {}
            score, version, vector = data.get("baseScore"), ver, data.get("vectorString")
            severity = data.get("baseSeverity") or primary.get("baseSeverity")
            break
    cwes = sorted(
        {
            d.get("value")
            for w in cve.get("weaknesses") or []
            for d in w.get("description") or []
            if str(d.get("value", "")).startswith("CWE-")
        }
    )

    def _ts(v: Any) -> datetime | None:
        try:
            return datetime.fromisoformat(str(v)) if v else None
        except ValueError:
            return None

    return {
        "cve_id": cve.get("id"),
        "description": desc,
        "published": _ts(cve.get("published")),
        "last_modified": _ts(cve.get("lastModified")),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_score": float(score) if score is not None else None,
        "cvss_version": version,
        "cvss_vector": vector,
        "cvss_severity": severity,
        "cwes": cwes,
    }
