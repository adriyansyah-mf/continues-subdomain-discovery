"""Provider IP ranges (lord-alfred/ipranges). Enrichment only - never scope authorization."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, func
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class CloudRange(Base):
    __tablename__ = "cloud_ranges"
    __table_args__ = (Index("uq_cloud_range", "provider", "cidr", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    organization: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)  # cloud | cdn | service | crawler | monitoring
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    ip_version: Mapped[int] = mapped_column(Integer, nullable=False)
    region: Mapped[str | None] = mapped_column(String(64))  # not provided by the merged lists
    source: Mapped[str] = mapped_column(String(256), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AsnRange(Base):
    """IP range -> ASN (iptoasn.com). Enrichment only - an ASN never authorises scanning an IP."""

    __tablename__ = "asn_ranges"

    start_ip: Mapped[str] = mapped_column(INET, primary_key=True)
    end_ip: Mapped[str] = mapped_column(INET, nullable=False)
    asn: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    country: Mapped[str | None] = mapped_column(String(8))
    organization: Mapped[str | None] = mapped_column(String(256))
