"""Vulnerability intelligence state (CISA KEV, EPSS, NVD CVEs, correlations).

PostgreSQL keeps what is needed to diff and correlate (previous KEV catalogue, latest
EPSS score per CVE, fetched CVE records, NVD lookup cache, asset<->CVE correlations);
Elasticsearch holds the searchable documents and change events.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class KevEntry(Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(256))
    product: Mapped[str | None] = mapped_column(String(256))
    vulnerability_name: Mapped[str | None] = mapped_column(String(512))
    short_description: Mapped[str | None] = mapped_column(Text)
    date_added: Mapped[date | None] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date)
    known_ransomware_use: Mapped[str | None] = mapped_column(String(32))
    required_action: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    cwes: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False, default=list)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    catalog_version: Mapped[str | None] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class EpssScore(Base):
    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    score_date: Mapped[date | None] = mapped_column(Date)
    model_version: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CveRecord(Base):
    """CVEs fetched from NVD because they were relevant to an observed technology."""

    __tablename__ = "cves"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    published: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_modified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vuln_status: Mapped[str | None] = mapped_column(String(64))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_severity: Mapped[str | None] = mapped_column(String(16))
    cwes: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False, default=list)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="nvd")
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class CpeLookup(Base):
    """Cache of NVD 'which CVEs match this CPE' answers."""

    __tablename__ = "cpe_lookups"

    cpe: Mapped[str] = mapped_column(String(512), primary_key=True)
    cve_ids: Mapped[list[str]] = mapped_column(ARRAY(String(32)), nullable=False, default=list)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VulnCorrelation(Base):
    """An asset potentially affected by (cpe-correlation) or detected with (nuclei) a CVE."""

    __tablename__ = "vuln_correlations"
    __table_args__ = (Index("uq_vuln_correlation", "asset_id", "cve_id", "source", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)  # cpe-correlation | nuclei
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # potential | detected
    technology: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    cpe: Mapped[str | None] = mapped_column(String(512))
    technology_confidence: Mapped[float | None] = mapped_column(Float)
    version_confidence: Mapped[float | None] = mapped_column(Float)
    cpe_confidence: Mapped[float | None] = mapped_column(Float)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
