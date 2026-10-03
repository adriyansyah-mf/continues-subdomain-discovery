from app.services.technology import canonical_name, from_server_header, from_wappalyzer, merge


def test_aliases_normalise_to_one_name():
    assert {canonical_name(x) for x in ("Nginx", "nginx", "nginx web server", " NGINX ")} == {"nginx"}


def test_wappalyzer_version_and_confidences_are_separate():
    t = from_wappalyzer("Nginx:1.24.0")
    assert (t.name, t.version, t.vendor, t.product) == ("nginx", "1.24.0", "f5", "nginx")
    assert t.confidence == 0.8 and t.version_confidence == 0.7


def test_never_invent_version():
    t = from_wappalyzer("HSTS")
    assert t.version is None and t.version_confidence is None


def test_garbage_version_dropped():
    assert from_wappalyzer("Foo:not a version").version is None


def test_server_header():
    t = from_server_header("nginx/1.24.0 (Ubuntu)")
    assert t is not None and t.name == "nginx" and t.version == "1.24.0"
    assert from_server_header("Apache").version is None


def test_merge_prefers_versioned():
    merged = merge([from_wappalyzer("Nginx"), from_server_header("nginx/1.25.1")])
    assert len(merged) == 1 and merged[0].version == "1.25.1"
