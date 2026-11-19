import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class AgentExecution(Base):
    __tablename__ = "agent_executions"

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "agent_id",
            "attempt_number",
            name="uq_agent_execution_attempt",
        ),
        CheckConstraint(
            "attempt_number >= 1",
            name="ck_agent_execution_attempt_positive",
        ),
        CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name="ck_agent_execution_duration_nonnegative",
        ),
        CheckConstraint(
            "findings_count >= 0",
            name="ck_agent_execution_findings_nonnegative",
        ),
        CheckConstraint(
            "assets_discovered >= 0",
            name="ck_agent_execution_assets_nonnegative",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'skipped')",
            name="ck_agent_execution_status",
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

    agent_id: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
    )

    agent_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )

    attempt_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    findings_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    assets_discovered: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    metadata_json: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        nullable=False,
        default=dict,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    
    scan: Mapped["Scan"] = relationship(
        "Scan",
        back_populates="agent_executions",
    )