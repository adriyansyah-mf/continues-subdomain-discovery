import pytest

from app.services.changes import diff_dns, diff_http
from app.services.ipranges import CloudRangeIndex, parse_ranges, raw_base


def test_raw_base():
    assert (
        raw_base("https://github.com/lord-alfred/ipranges")
        == "https://raw.githubusercontent.com/lord-alfred/ipranges/main"
    )
    assert raw_base("https://mirror.internal/ipranges/") == "https://mirror.internal/ipranges"


def test_parse_ranges_strict_and_counts_rejects():
    nets, rejected = parse_ranges("1.2.3.0/24\n# c\n\nnot-a-cidr\n2001:db8::/32\n10.0.0.5/24\n")
    assert nets == {"1.2.3.0/24", "2001:db8::/32", "10.0.0.0/24"} and rejected == 1


@pytest.fixture
def index():
    return CloudRangeIndex(
        [
            ("amazon", "Amazon Web Services", "cloud", "52.0.0.0/8"),
            ("cloudflare", "Cloudflare", "cdn", "52.10.0.0/16"),  # more specific wins
            ("google", "Google Cloud", "cloud", "2600:1900::/28"),
        ]
    )


@pytest.mark.parametrize(
    "ip,provider",
    [
        ("52.1.2.3", "amazon"),
        ("52.10.9.9", "cloudflare"),
        ("2600:1900::1", "google"),
        ("8.8.8.8", None),
        ("not-an-ip", None),
    ],
)
def test_longest_prefix_lookup(index, ip, provider):
    hit = index.lookup(ip)
    assert (hit.provider if hit else None) == provider


def test_cloud_provider_change_detection():
    assert [c.change_type for c in diff_http({"cloud": "amazon"}, {"cloud": "google"})] == ["CLOUD_PROVIDER_CHANGED"]
    # states recorded before enrichment existed must not produce a spurious change
    assert diff_http({"status_code": 200}, {"status_code": 200, "cloud": "amazon"}) == []
    t = [c.change_type for c in diff_dns({"A": ["1.1.1.1"], "cloud": []}, {"A": ["1.1.1.1"], "cloud": ["amazon"]})]
    assert "CLOUD_PROVIDER_CHANGED" in t
