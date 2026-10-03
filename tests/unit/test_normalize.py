import pytest

from app.models.enums import ScopeType
from app.scope.normalize import (
    InvalidTarget,
    classify_target,
    normalize_cidr,
    normalize_domain,
    normalize_scope_value,
    normalize_url,
    normalize_wildcard,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  sub.example.com ", "sub.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("münchen.de", "xn--mnchen-3ya.de"),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["localhost", "a..b.com", "-a.com", "a-.com", "a.123", "a.0x1f", "x" * 64 + ".com", "a b.com", "a/b.com"],
)
def test_normalize_domain_rejects(raw):
    with pytest.raises(InvalidTarget):
        normalize_domain(raw)


@pytest.mark.parametrize("raw", ["*.com", "*.co.uk", "api-*.example.com", "*example.com", "*.*.example.com"])
def test_wildcard_rejects(raw):
    with pytest.raises(InvalidTarget):
        normalize_wildcard(raw)


def test_wildcard_ok():
    assert normalize_wildcard("*.Example.co.uk") == "*.example.co.uk"


def test_cidr_strict():
    with pytest.raises(InvalidTarget):
        normalize_cidr("10.0.0.5/24")
    assert str(normalize_cidr("10.0.0.0/24")) == "10.0.0.0/24"


def test_url_normalisation():
    u = normalize_url("HTTPS://API.Example.com:443/a/./b/../c?z=1&a=2#frag")
    assert u.normalized_url == "https://api.example.com/a/c?a=2&z=1"
    assert u.port == 443 and u.host == "api.example.com"
    assert u.parameters == ("a", "z")
    assert u.raw_url.startswith("HTTPS://")
    # same endpoint, different parameter values -> same endpoint hash, different url hash
    v = normalize_url("https://api.example.com/a/c?a=9&z=0")
    assert u.endpoint_hash == v.endpoint_hash and u.url_hash != v.url_hash


def test_url_non_default_port_kept():
    assert normalize_url("http://example.com:8080").normalized_url == "http://example.com:8080/"


def test_url_ipv6_host():
    u = normalize_url("http://[2001:DB8::1]:8080/x")
    assert u.host == "2001:db8::1" and u.normalized_url == "http://[2001:db8::1]:8080/x"


@pytest.mark.parametrize(
    "value,kind",
    [
        ("example.com", "domain"),
        ("*.example.com", "wildcard"),
        ("10.0.0.1", "ipv4"),
        ("::1", "ipv6"),
        ("10.0.0.0/8", "cidr"),
        ("AS13335", "asn"),
        ("https://example.com", "url"),
    ],
)
def test_classify(value, kind):
    assert classify_target(value).kind == kind


def test_scope_value_type_mismatch():
    with pytest.raises(InvalidTarget):
        normalize_scope_value(ScopeType.IPV4, "2001:db8::1")
    with pytest.raises(InvalidTarget):
        normalize_scope_value(ScopeType.DOMAIN, "*.example.com")
