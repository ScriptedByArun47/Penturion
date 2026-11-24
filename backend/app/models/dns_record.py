"""Database model for DNS records collected by PENTURION."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DNSRecord(Base):
    __tablename__ = "dns_records"

    __table_args__ = (
        CheckConstraint(
            "record_type IN ('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA')",
            name="ck_dns_record_type",
        ),
        UniqueConstraint(
            "discovered_asset_id",
            "record_type",
            "value",
            name="uq_dns_record_asset_type_value",
        ),
        Index(
            "ix_dns_records_discovered_asset_id",
            "discovered_asset_id",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    discovered_asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("discovered_assets.id", ondelete="CASCADE"),
        nullable=False,
    )

    record_name: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    record_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )

    value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    ttl: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    priority: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    discovered_asset: Mapped["DiscoveredAsset"] = relationship(
        "DiscoveredAsset",
        back_populates="dns_records",
    )