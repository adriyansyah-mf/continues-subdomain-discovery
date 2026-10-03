import gzip

from app.services.asn import parse_tsv
from app.services.changes import diff_dns, diff_http

TSV = (
    b"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"
    b"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n"
    b"2606:4700::\t2606:4700:ffff:ffff:ffff:ffff:ffff:ffff\t13335\tUS\tCLOUDFLARENET\n"
    b"9.9.9.9\t1.1.1.1\t1\tUS\tbackwards range\n"
    b"bad\tline\n"
    b"8.8.8.0\t8.8.8.255\t15169\tNone\tGOOGLE\n"
)


def test_parse_skips_unrouted_and_malformed():
    rows = parse_tsv(gzip.compress(TSV))
    assert [(r[0], r[2], r[3]) for r in rows] == [
        ("1.0.0.0", 13335, "US"),
        ("2606:4700::", 13335, "US"),
        ("8.8.8.0", 15169, None),
    ]


def test_asn_change_detection():
    assert [c.change_type for c in diff_http({"asn": 13335}, {"asn": 15169})] == ["ASN_CHANGED"]
    assert diff_http({"status_code": 200}, {"status_code": 200, "asn": 13335}) == []  # pre-enrichment state
    assert diff_http({"asn": 13335}, {"asn": None}) == []  # lookup gap is not a change
    t = [c.change_type for c in diff_dns({"A": ["1.1.1.1"], "asn": [13335]}, {"A": ["1.1.1.1"], "asn": [15169]})]
    assert "ASN_CHANGED" in t
