import pytest

from app.scope.engine import ScopeEngine, ScopeRule

P1 = "11111111-1111-1111-1111-111111111111"
P2 = "22222222-2222-2222-2222-222222222222"


def rule(i, type_, value, mode="include", program=P1):
    return ScopeRule.build(id=f"r{i}", program_id=program, type=type_, mode=mode, value=value)


@pytest.fixture
def engine():
    return ScopeEngine(
        [
            rule(1, "wildcard", "*.example.com"),
            rule(2, "domain", "admin.example.com", "exclude"),
            rule(3, "domain", "example.com"),
            rule(4, "cidr", "192.0.2.0/24"),
            rule(5, "ipv4", "192.0.2.66", "exclude"),
            rule(6, "ipv6", "2001:db8::1"),
            rule(7, "cidr", "2001:db8:100::/48"),
            rule(8, "asn", "AS64500"),
            rule(9, "url", "https://portal.other.org/app"),
            rule(10, "wildcard", "*.internal.example.com", "exclude"),
            rule(11, "url", "https://www.example.com/private", "exclude"),
            rule(12, "url", "https://app.example.com/", "exclude"),
            rule(20, "domain", "shared.example.net", program=P2),
            rule(21, "wildcard", "*.example.com", program=P2),
        ]
    )


@pytest.mark.parametrize(
    "target,allowed",
    [
        ("example.com", True),  # explicit domain
        ("api.example.com", True),  # wildcard
        ("a.b.c.example.com", True),  # wildcard any depth
        ("API.Example.COM.", True),  # case + trailing dot
        ("admin.example.com", False),  # explicit exclusion
        ("x.admin.example.com", False),  # exclusion covers subtree
        ("internal.example.com", True),  # *.internal excludes only beneath
        ("db.internal.example.com", False),
        ("evilexample.com", False),  # label boundary
        ("example.com.evil.net", False),
        ("example.org", False),
        ("192.0.2.10", True),
        ("192.0.2.66", False),  # excluded IP
        ("192.0.3.1", False),
        ("192.0.2.128/25", True),  # subnet of included range
        ("192.0.2.0/25", False),  # contains the excluded IP
        ("192.0.2.64/26", False),  # overlaps excluded IP
        ("192.0.0.0/16", False),  # wider than included
        ("2001:db8::1", True),
        ("2001:DB8:0:0:0:0:0:1", True),  # IPv6 canonicalisation
        ("2001:db8::2", False),
        ("2001:db8:100:1::5", True),
        ("::ffff:192.0.2.10", True),  # v4-mapped normalised to v4
        ("::ffff:192.0.2.66", False),
        ("AS64500", True),
        ("as64501", False),
        ("https://api.example.com/x", True),
        ("https://admin.example.com/", False),
        ("https://portal.other.org/app", True),
        ("https://portal.other.org/app/sub?x=1", True),
        ("https://portal.other.org/apple", False),  # path segment boundary
        ("https://portal.other.org/", False),
        ("http://portal.other.org/app", False),  # scheme must match
        ("https://portal.other.org:8443/app", False),
        ("portal.other.org", False),  # URL rule never authorises host scans
        ("https://www.example.com/private/x", False),  # URL exclusion
        ("https://www.example.com/private/../private/x", False),
        ("https://www.example.com/public/..%2fprivate", False),
        ("https://www.example.com/public", True),
        ("www.example.com", True),  # narrower URL exclusion: enforced by path-exploring scanners
        ("app.example.com", False),  # whole origin excluded (path "/")
    ],
)
def test_program_decisions(engine, target, allowed):
    d = engine.is_in_scope(target, P1)
    assert d.allowed is allowed, d.reason


def test_allowed_decision_shape(engine):
    d = engine.is_in_scope("api.example.com", P1)
    assert d.allowed and d.scope_id == "r1" and d.program_id == P1
    assert d.reason == "matched *.example.com (wildcard)"
    assert d.match_kind == "wildcard_inclusion"


def test_explicit_beats_wildcard(engine):
    d = engine.is_in_scope("example.com", P1)
    assert d.scope_id == "r3" and d.match_kind == "explicit_inclusion"


def test_blocked_decision_shape(engine):
    d = engine.is_in_scope("nothing.test-domain.org", P1)
    assert d.allowed is False and d.reason == "not in approved scope"


def test_exclusion_reason(engine):
    d = engine.is_in_scope("admin.example.com", P1)
    assert d.match_kind == "explicit_exclusion" and d.scope_id == "r2"


def test_exclusion_is_program_scoped(engine):
    # P2 has no exclusion for admin.example.com
    assert engine.is_in_scope("admin.example.com", P2).allowed


def test_cross_program_evaluation(engine):
    d = engine.is_in_scope("api.example.com")
    assert d.allowed and set(d.allowed_program_ids) == {P1, P2}
    d = engine.is_in_scope("shared.example.net")
    assert d.allowed and d.allowed_program_ids == [P2]


def test_unknown_program_is_out_of_scope(engine):
    assert not engine.is_in_scope("api.example.com", "33333333-3333-3333-3333-333333333333").allowed


def test_empty_engine_blocks_everything():
    assert not ScopeEngine([]).is_in_scope("example.com").allowed


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "127.1",  # shorthand IPv4 literal
        "0x7f.0x0.0x0.0x1",
        "2130706433",  # decimal IP
        "0177.0.0.1",  # octal-looking
        "example.com\x00.evil.net",
        "exa mple.com",
        "https://example.com@evil.net/",  # userinfo confusion
        "https://evil.net\\@api.example.com/",  # backslash confusion
        "javascript://api.example.com/",
        "ftp://api.example.com/",
        "*.example.com",  # pattern, not a target
        "fe80::1%eth0",
        "api.example.com:443",
        "-api.example.com",
    ],
)
def test_bypass_and_malformed_targets_blocked(engine, target):
    assert engine.is_in_scope(target, P1).allowed is False


def test_idn_normalisation():
    e = ScopeEngine([rule(1, "wildcard", "*.bücher.example")])
    assert e.is_in_scope("shop.xn--bcher-kva.example", P1).allowed
    assert e.is_in_scope("shop.BÜCHER.example", P1).allowed


def test_ipv6_exclusion_overlap():
    e = ScopeEngine([rule(1, "cidr", "2001:db8::/32"), rule(2, "cidr", "2001:db8:dead::/48", "exclude")])
    assert e.is_in_scope("2001:db8:beef::1", P1).allowed
    assert not e.is_in_scope("2001:db8:dead::1", P1).allowed
    assert not e.is_in_scope("2001:db8:8000::/33", P1).allowed  # overlaps exclusion


def test_ip_version_mismatch_never_matches():
    e = ScopeEngine([rule(1, "cidr", "0.0.0.0/0")])
    assert not e.is_in_scope("2001:db8::1", P1).allowed
