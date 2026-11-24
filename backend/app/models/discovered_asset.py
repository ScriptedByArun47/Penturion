import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class DiscoveredAsset(Base):
    __tablename__ = "discovered_assets"

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "value",
            name="uq_discovered_asset_scan_value",
        ),
        CheckConstraint(
            "scope_status IN ('pending', 'in_scope', 'out_of_scope')",
            name="ck_discovered_asset_scope_status",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    value: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
    )

    asset_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="subdomain",
    )

    source_agent: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )

    scope_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    metadata_json: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        nullable=False,
        default=dict,
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="discovered_assets",
    )
    
    dns_records: Mapped[list["DNSRecord"]] = relationship(
        "DNSRecord",
        back_populates="discovered_asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
