"""Lifecycle management for PENTURION agent executions."""

from datetime import datetime, timezone

from sqlalchemy import select, update, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.agent_execution import AgentExecution


AGENT_STATUSES = {
    "pending",
    "running",
    "completed",
    "failed",
    "skipped",
}


class AgentExecutionLifecycleError(Exception):
    """Raised when an agent execution transition is invalid."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _get_execution(
    db: Session,
    execution_id: str,
) -> AgentExecution | None:
    return db.get(AgentExecution, execution_id)


def _commit_execution(
    db: Session,
    execution_id: str,
) -> AgentExecution:
    db.commit()
    db.expire_all()

    execution = _get_execution(db, execution_id)

    if execution is None:
        raise AgentExecutionLifecycleError(
            "Agent execution could not be retrieved"
        )

    return execution


def _duration_ms(
    started_at: datetime,
    completed_at: datetime,
) -> int:
    # SQLite may return naive datetimes.
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)

    if completed_at.tzinfo is None:
        completed_at = completed_at.replace(tzinfo=timezone.utc)

    return max(
        0,
        int((completed_at - started_at).total_seconds() * 1000),
    )


def create_agent_execution(
    db: Session,
    scan_id: str,
    agent_id: str,
    agent_name: str,
    metadata_json: dict | None = None,
) -> AgentExecution:
    """Create the first pending execution for an agent."""

    if not agent_id or not agent_id.startswith("A"):
        raise ValueError("Invalid agent ID")

    if not agent_name.strip():
        raise ValueError("Agent name is required")

    if metadata_json is not None and not isinstance(
        metadata_json, dict
    ):
        raise ValueError("Execution metadata must be a dictionary")

    try:
        existing = db.scalar(
            select(AgentExecution.id).where(
                AgentExecution.scan_id == scan_id,
                AgentExecution.agent_id == agent_id,
            ).limit(1)
        )

        if existing is not None:
            raise AgentExecutionLifecycleError(
                "An execution already exists for this agent and scan"
            )

        execution = AgentExecution(
            scan_id=scan_id,
            agent_id=agent_id,
            agent_name=agent_name.strip(),
            attempt_number=1,
            status="pending",
            metadata_json=metadata_json or {},
        )

        db.add(execution)
        db.flush()

        return _commit_execution(db, execution.id)

    except Exception:
        db.rollback()
        raise


def start_agent_execution(
    db: Session,
    execution_id: str,
) -> AgentExecution:
    """Start a pending agent execution."""

    now = utc_now()

    try:
        result = db.execute(
            update(AgentExecution)
            .where(
                AgentExecution.id == execution_id,
                AgentExecution.status == "pending",
            )
            .values(
                status="running",
                started_at=now,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            raise AgentExecutionLifecycleError(
                "Only pending executions can be started"
            )

        return _commit_execution(db, execution_id)

    except Exception:
        db.rollback()
        raise


def complete_agent_execution(
    db: Session,
    execution_id: str,
    findings_count: int = 0,
    assets_discovered: int = 0,
) -> AgentExecution:
    """Complete a running execution and save its metrics."""

    if findings_count < 0 or assets_discovered < 0:
        raise ValueError("Execution metrics cannot be negative")

    now = utc_now()

    try:
        execution = _get_execution(db, execution_id)

        if execution is None:
            raise AgentExecutionLifecycleError(
                "Agent execution not found"
            )

        if execution.status != "running":
            raise AgentExecutionLifecycleError(
                "Only running executions can be completed"
            )

        if execution.started_at is None:
            raise AgentExecutionLifecycleError(
                "Running execution has no start timestamp"
            )

        result = db.execute(
            update(AgentExecution)
            .where(
                AgentExecution.id == execution_id,
                AgentExecution.status == "running",
            )
            .values(
                status="completed",
                completed_at=now,
                duration_ms=_duration_ms(
                    execution.started_at,
                    now,
                ),
                findings_count=findings_count,
                assets_discovered=assets_discovered,
                error_message=None,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            raise AgentExecutionLifecycleError(
                "Execution status changed concurrently"
            )

        return _commit_execution(db, execution_id)

    except Exception:
        db.rollback()
        raise


def fail_agent_execution(
    db: Session,
    execution_id: str,
    error_message: str,
) -> AgentExecution:
    """Fail a running execution while preserving its history."""

    if not error_message or not error_message.strip():
        raise AgentExecutionLifecycleError(
            "An error message is required"
        )

    now = utc_now()

    try:
        execution = _get_execution(db, execution_id)

        if execution is None:
            raise AgentExecutionLifecycleError(
                "Agent execution not found"
            )

        if execution.status != "running":
            raise AgentExecutionLifecycleError(
                "Only running executions can be failed"
            )

        duration = (
            _duration_ms(execution.started_at, now)
            if execution.started_at is not None
            else None
        )

        result = db.execute(
            update(AgentExecution)
            .where(
                AgentExecution.id == execution_id,
                AgentExecution.status == "running",
            )
            .values(
                status="failed",
                completed_at=now,
                duration_ms=duration,
                error_message=error_message.strip()[:2000],
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            raise AgentExecutionLifecycleError(
                "Execution status changed concurrently"
            )

        return _commit_execution(db, execution_id)

    except Exception:
        db.rollback()
        raise


def skip_agent_execution(
    db: Session,
    execution_id: str,
    reason: str,
) -> AgentExecution:
    """Mark a pending execution as skipped."""

    if not reason or not reason.strip():
        raise AgentExecutionLifecycleError(
            "A skip reason is required"
        )

    now = utc_now()

    try:
        result = db.execute(
            update(AgentExecution)
            .where(
                AgentExecution.id == execution_id,
                AgentExecution.status == "pending",
            )
            .values(
                status="skipped",
                completed_at=now,
                error_message=reason.strip()[:2000],
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            raise AgentExecutionLifecycleError(
                "Only pending executions can be skipped"
            )

        return _commit_execution(db, execution_id)

    except Exception:
        db.rollback()
        raise


def retry_agent_execution(
    db: Session,
    scan_id: str,
    agent_id: str,
    max_attempts: int = 2,
) -> AgentExecution:
    """Create a new attempt after a failed execution."""

    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    try:
        previous = db.scalars(
            select(AgentExecution)
            .where(
                AgentExecution.scan_id == scan_id,
                AgentExecution.agent_id == agent_id,
            )
            .order_by(
                AgentExecution.attempt_number.desc()
            )
            .limit(1)
        ).first()

        if previous is None:
            raise AgentExecutionLifecycleError(
                "No previous execution exists"
            )

        if previous.status != "failed":
            raise AgentExecutionLifecycleError(
                "Only failed executions can be retried"
            )

        if previous.attempt_number >= max_attempts:
            raise AgentExecutionLifecycleError(
                "Maximum retry attempts reached"
            )

        execution = AgentExecution(
            scan_id=scan_id,
            agent_id=agent_id,
            agent_name=previous.agent_name,
            attempt_number=previous.attempt_number + 1,
            status="pending",
            metadata_json=dict(previous.metadata_json or {}),
        )

        db.add(execution)
        db.flush()

        return _commit_execution(db, execution.id)

    except IntegrityError as exc:
        db.rollback()
        raise AgentExecutionLifecycleError(
            "Duplicate agent execution attempt"
        ) from exc

    except Exception:
        db.rollback()
        raise