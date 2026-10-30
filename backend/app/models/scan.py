
"""Database model for PENTURION scans."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.authorization import AuthorizationRequest
from app.core.database import Base


def utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    authorization_request_id: Mapped[str | None] = mapped_column(
    String(36),
    ForeignKey("authorization_requests.id", ondelete="RESTRICT"),
    nullable=True,
    index=True,
    )
    
    requested_by: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="queued",
        index=True,
    )

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="web",
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
    DateTime(timezone=True),
    nullable=True,
    )
    
    worker_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        index=True,
    )

    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    target: Mapped["Target"] = relationship()
    requester: Mapped["User"] = relationship()
    authorization_request: Mapped["AuthorizationRequest | None"] = relationship()
