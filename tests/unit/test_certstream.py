import json
from pathlib import Path

from workers.certstream.parser import parse_message

MSGS = [
    json.loads(x)
    for x in (Path(__file__).parent.parent / "fixtures" / "certstream_messages.jsonl").read_text().splitlines()
]


def test_heartbeat_and_garbage_ignored():
    assert parse_message(MSGS[0]) is None
    assert parse_message({"message_type": "certificate_update", "data": {"leaf_cert": {}}}) is None
    assert parse_message("x") is None


def test_calidog_format():
    obs = parse_message(MSGS[1])
    assert obs is not None
    assert obs.domains == ("api.example.com", "other.example.net")
    assert obs.wildcards == ("*.cdn.example.com",)
    assert obs.invalid_names == ("bad..name",)
    assert obs.fingerprint == "sha1:abcdef01" and obs.sha256 is None
    assert obs.issuer_cn == "R10" and obs.issuer_o == "Let's Encrypt"
    assert obs.not_after.endswith("Z") and obs.cert_index == 12345
    assert obs.source_url.startswith("ct.googleapis.com")


def test_server_go_format_prefers_sha256_and_normalises():
    obs = parse_message(MSGS[2])
    assert obs is not None and obs.fingerprint == "aabbcc" and obs.sha1 == "1122"
    assert obs.domains == ("www.example.com",)


def test_classify_interesting_domains():
    from workers.certstream.parser import classify_name, classify_names

    assert classify_name("shop.example.tk") == ["suspicious_tld"]
    assert classify_name("1secure.example.com") == ["numeric"]
    assert classify_name("*.123.example.com") == ["numeric"]
    assert classify_name("xn--bcher-kva.example") == ["punycode"]
    assert classify_name("api.example.com") == []
    # union over a certificate's names, deduplicated and sorted
    assert classify_names(["api.example.com", "9to5.example.tk", "xn--d1a.example.com"]) == [
        "numeric",
        "punycode",
        "suspicious_tld",
    ]


def test_parse_message_sets_flags():
    from workers.certstream.parser import parse_message

    obs = parse_message(
        {
            "message_type": "certificate_update",
            "data": {
                "leaf_cert": {
                    "sha256": "AA",
                    "all_domains": ["7abc.example.tk"],
                    "subject": {},
                    "issuer": {},
                    "extensions": {},
                }
            },
        }
    )
    assert obs is not None and set(obs.flags) == {"numeric", "suspicious_tld"}
