"""Scanner registry: the orchestrator's view of which scanners exist.

The orchestrator never runs scanners itself; it only needs to know which queue
a scanner consumes from, which target types it accepts and whether a worker
implementation exists yet. Swapping a tool (e.g. httpx -> another prober) only
requires a new worker adapter with the same name/queue.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    queue: str
    active: bool  # sends traffic to the target
    implemented: bool
    target_types: frozenset[str]
    description: str


SCANNERS: dict[str, ScannerSpec] = {
    s.name: s
    for s in (
        # name, queue (one scanner per queue: workers drop jobs for other scanners), active, implemented
        ScannerSpec(
            "dns", "dns", False, True, frozenset({"domain"}), "DNS resolution (A/AAAA/CNAME/MX/NS/TXT) via dnspython"
        ),
        ScannerSpec(
            "httpx",
            "httpx",
            True,
            True,
            frozenset({"domain", "ipv4", "ipv6", "url"}),
            "HTTP probing and fingerprinting (ProjectDiscovery httpx)",
        ),
        ScannerSpec(
            "tlsx",
            "tlsx",
            True,
            True,
            frozenset({"domain", "ipv4", "ipv6"}),
            "TLS/certificate grabbing (ProjectDiscovery tlsx)",
        ),
        ScannerSpec(
            "uncover",
            "discovery",
            False,
            True,
            frozenset({"domain"}),
            "search-engine discovery (ProjectDiscovery uncover); results are never authorisation",
        ),
        ScannerSpec(
            "mapcidr",
            "mapcidr",
            False,
            True,
            frozenset({"cidr"}),
            "bounded CIDR expansion into IP inventory (ProjectDiscovery mapcidr)",
        ),
        ScannerSpec(
            "katana",
            "katana",
            True,
            True,
            frozenset({"url", "domain"}),
            "crawling / URL and endpoint inventory (ProjectDiscovery katana)",
        ),
        ScannerSpec(
            "bbot",
            "bbot",
            False,
            True,
            frozenset({"domain"}),
            "BBOT subdomain-enum (passive+safe modules by default) as a discovery/enrichment source",
        ),
        ScannerSpec(
            "nuclei",
            "nuclei",
            True,
            True,
            frozenset({"url", "domain", "ipv4", "ipv6"}),
            "template scanning (ProjectDiscovery nuclei); templates pinned in the image, OOB disabled",
        ),
    )
}


def get_scanner(name: str) -> ScannerSpec:
    try:
        return SCANNERS[name]
    except KeyError as exc:
        raise ValueError(f"unknown scanner {name!r}") from exc
