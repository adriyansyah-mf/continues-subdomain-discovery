"""CPE 2.3 construction for observed technologies. Never invents a CPE or a version."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.technology import VENDOR_PRODUCT

_TOKEN_RE = re.compile(r"^[a-z0-9._\-\\!]{1,128}$")
_VERSION_RE = re.compile(r"^[0-9][0-9a-z._\-]{0,63}$")

# Documented confidence of the *mapping* (technology -> CPE), separate from technology/version confidence.
CURATED_CPE_CONFIDENCE = 0.8  # vendor/product from the curated table, version from the fingerprint
SOURCE_CPE_CONFIDENCE = 0.5  # CPE reported verbatim by a third-party source (e.g. Shodan via BBOT)


@dataclass(frozen=True)
class CpeCandidate:
    cpe: str
    vendor: str
    product: str
    version: str
    confidence: float

    @property
    def level(self) -> str:
        return confidence_level(self.confidence)


def confidence_level(value: float | None) -> str:
    if value is None:
        return "low"
    return "high" if value >= 0.75 else "medium" if value >= 0.5 else "low"


def build_cpe(vendor: str, product: str, version: str) -> str | None:
    vendor, product, version = vendor.lower(), product.lower(), version.lower()
    if not (_TOKEN_RE.match(vendor) and _TOKEN_RE.match(product) and _VERSION_RE.match(version)):
        return None
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def candidate_for(technology: str, version: str | None, source_cpe: str | None = None) -> CpeCandidate | None:
    """CPE for a technology observation, or None when it cannot be determined reliably."""
    if not version:
        return None  # a product without a version says nothing about which CVEs apply
    if technology in VENDOR_PRODUCT:
        vendor, product = VENDOR_PRODUCT[technology]
        cpe = build_cpe(vendor, product, version)
        return CpeCandidate(cpe, vendor, product, version, CURATED_CPE_CONFIDENCE) if cpe else None
    if source_cpe:
        parts = source_cpe.split(":")
        if source_cpe.startswith("cpe:2.3:") and len(parts) >= 6:
            vendor, product = parts[3], parts[4]
        elif source_cpe.startswith("cpe:/") and len(parts) >= 4:
            vendor, product = parts[2], parts[3]
        else:
            return None
        cpe = build_cpe(vendor, product, version)
        return CpeCandidate(cpe, vendor, product, version, SOURCE_CPE_CONFIDENCE) if cpe else None
    return None
