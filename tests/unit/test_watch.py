"""Pure checks for the watch/full-auto wiring (DB-backed behaviour is covered in integration)."""

from app.schemas.policy import AUTO_POLICY_NAME, DEFAULT_POLICIES, PolicyConfig
from app.services.watch import AUTO_SCANNERS


def test_full_auto_policy_enables_the_whole_pipeline():
    assert AUTO_POLICY_NAME in DEFAULT_POLICIES
    cfg = PolicyConfig.model_validate(DEFAULT_POLICIES[AUTO_POLICY_NAME][1])
    enabled = {name for name in ("bbot", "dns", "httpx", "tlsx", "katana", "nuclei") if getattr(cfg, name).enabled}
    assert enabled == {"bbot", "dns", "httpx", "tlsx", "katana", "nuclei"}


def test_auto_scanners_cover_scope_kinds_and_only_known_scanners():
    from app.schemas.policy import DEFAULT_POLICIES as _DP

    auto_cfg = PolicyConfig.model_validate(_DP[AUTO_POLICY_NAME][1])
    for kind in ("domain", "wildcard", "url", "ipv4", "ipv6", "cidr", "asn"):
        assert kind in AUTO_SCANNERS
    # wildcard/domain drive discovery, so BBOT must be in the set
    assert "bbot" in AUTO_SCANNERS["wildcard"] and "bbot" in AUTO_SCANNERS["domain"]
    # a URL has no host to enumerate, so no BBOT there
    assert "bbot" not in AUTO_SCANNERS["url"]
    # every scanner named for any kind must be enabled in the full-auto policy
    for scanners in AUTO_SCANNERS.values():
        for s in scanners:
            assert getattr(auto_cfg, s).enabled, s
