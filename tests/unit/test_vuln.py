import gzip

import pytest

from app.services.vuln.cpe import (
    CURATED_CPE_CONFIDENCE,
    SOURCE_CPE_CONFIDENCE,
    build_cpe,
    candidate_for,
    confidence_level,
)
from app.services.vuln.epss import parse_epss
from app.services.vuln.kev import parse_catalog
from app.services.vuln.nvd import parse_cve

KEV_DOC = {
    "catalogVersion": "2026.10.02",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-0001",
            "vendorProject": "F5",
            "product": "NGINX",
            "vulnerabilityName": "x",
            "dateAdded": "2026-01-02",
            "dueDate": "2026-01-23",
            "knownRansomwareCampaignUse": "Unknown",
            "requiredAction": "patch",
            "shortDescription": "d",
            "notes": "",
            "cwes": ["CWE-79"],
        },
        {"cveID": "not-a-cve"},
    ],
}


def test_kev_parse():
    version, entries = parse_catalog(KEV_DOC)
    assert version == "2026.10.02" and list(entries) == ["CVE-2024-0001"]
    assert entries["CVE-2024-0001"]["vendor"] == "F5" and entries["CVE-2024-0001"]["cwes"] == ["CWE-79"]


def test_epss_parse_gzip_with_metadata():
    raw = gzip.compress(
        b"#model_version:v2026.06.15,score_date:2026-10-03T12:00:21Z\n"
        b"cve,epss,percentile\nCVE-2024-0001,0.5,0.99\nCVE-X,2,3\nbad,line\n"
    )
    model, score_date, rows = parse_epss(raw)
    assert model == "v2026.06.15" and str(score_date) == "2026-10-03"
    assert rows == [("CVE-2024-0001", 0.5, 0.99)]


def test_nvd_parse_prefers_newest_cvss():
    cve = {
        "id": "CVE-2024-0001",
        "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "english"}],
        "published": "2024-01-01T00:00:00.000",
        "metrics": {
            "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}],
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"baseScore": 9.1, "vectorString": "s", "baseSeverity": "CRITICAL"}},
                {"type": "Primary", "cvssData": {"baseScore": 7.5, "vectorString": "p", "baseSeverity": "HIGH"}},
            ],
        },
        "weaknesses": [{"description": [{"value": "CWE-787"}, {"value": "NVD-CWE-noinfo"}]}],
    }
    p = parse_cve(cve)
    assert p["description"] == "english" and p["cvss_version"] == "3.1"
    assert p["cvss_score"] == 7.5 and p["cvss_severity"] == "HIGH" and p["cwes"] == ["CWE-787"]


@pytest.mark.parametrize(
    "vendor,product,version,ok",
    [
        ("f5", "nginx", "1.24.0", True),
        ("f5", "nginx", "latest", False),  # not a version
        ("f5", "ngi nx", "1.0", False),
        ("f5", "nginx", "1.0:*:*", False),  # cannot smuggle extra CPE fields
    ],
)
def test_build_cpe(vendor, product, version, ok):
    assert (build_cpe(vendor, product, version) is not None) is ok


def test_candidates_never_without_version():
    assert candidate_for("nginx", None) is None
    c = candidate_for("nginx", "1.24.0")
    assert c and c.cpe == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*" and c.confidence == CURATED_CPE_CONFIDENCE
    assert c.level == "high"
    # unknown product: only when a source supplied a CPE, and with lower mapping confidence
    assert candidate_for("someapp", "2.0") is None
    s = candidate_for("someapp", "2.0", "cpe:/a:acme:someapp")
    assert s and s.cpe.startswith("cpe:2.3:a:acme:someapp:2.0:") and s.confidence == SOURCE_CPE_CONFIDENCE
    assert confidence_level(0.3) == "low" and confidence_level(None) == "low"
