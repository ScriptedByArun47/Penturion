
"""Business logic for authorized scan management."""


from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target


ALLOWED_SCAN_TRANSITIONS = {
    "queued": {"running", "failed"},
    "running": {"completed", "failed"},
    "completed": set(),
    "failed": set(),
}

class ScanLifecycleError(Exception):
    """Raised when a scan lifecycle transition is invalid."""
    
class ScanAuthorizationError(Exception):
    """Raised when a scan request is not authorized."""


def validate_scan_authorization(
    db: Session,
    target_id: str,
    owner_id: str,
) -> Target:
    """Verify target ownership and authorization before scanning."""

    statement = (
        select(Target)
        .join(Project, Target.project_id == Project.id)
        .where(
            Target.id == target_id,
            Project.owner_id == owner_id,
        )
    )

    target = db.scalars(statement).first()

    if target is None:
        raise ScanAuthorizationError(
            "Target not found or access denied"
        )

    if target.authorization_status != "approved":
        raise ScanAuthorizationError(
            "Target authorization must be approved before scanning"
        )

    return target


def validate_scan_for_execution(
    db: Session,
    scan_id: str,
) -> Scan | None:
    """Revalidate authorization before a claimed scan can execute.

    Returns None if the scan does not exist.
    Raises ScanAuthorizationError if authorization is no longer valid.
    """

    statement = (
        select(Scan)
        .join(Target, Scan.target_id == Target.id)
        .join(Project, Target.project_id == Project.id)
        .where(Scan.id == scan_id)
    )

    scan = db.scalars(statement).first()

    if scan is None:
        return None

    if scan.status != "running":
        raise ScanLifecycleError(
            "Only running scans can be validated for execution"
        )

    if scan.requested_by != scan.requester.id:
        raise ScanAuthorizationError(
            "Scan requester does not match the scan owner"
        )

    if scan.target.project.owner_id != scan.requested_by:
        raise ScanAuthorizationError(
            "Target ownership has changed; execution denied"
        )

    if scan.target.authorization_status != "approved":
        raise ScanAuthorizationError(
            "Target authorization is no longer approved"
        )

    return scan



def create_scan(
    db: Session,
    target_id: str,
    owner_id: str,
    scan_type: str = "web",
) -> Scan:
    """Create a queued scan only for an authorized target."""

    # Enforce an allowlist rather than accepting arbitrary scan types.
    allowed_scan_types = {"web"}

    if scan_type not in allowed_scan_types:
        raise ValueError("Unsupported scan type")

    target = validate_scan_authorization(
        db=db,
        target_id=target_id,
        owner_id=owner_id,
    )

    scan = Scan(
        target_id=target.id,
        requested_by=owner_id,
        scan_type=scan_type,
        status="queued",
    )

    try:
        db.add(scan)
        db.commit()
        db.refresh(scan)
    except Exception:
        db.rollback()
        raise

    return scan

def list_scans(
    db: Session,
    owner_id: str,
) -> list[Scan]:
    """Return scans requested by the specified user."""

    statement = (
        select(Scan)
        .where(Scan.requested_by == owner_id)
        .order_by(Scan.created_at.desc())
    )

    return list(db.scalars(statement).all())


def get_scan(
    db: Session,
    scan_id: str,
    owner_id: str,
) -> Scan | None:
    """Return a scan only if it belongs to the specified user."""

    statement = select(Scan).where(
        Scan.id == scan_id,
        Scan.requested_by == owner_id,
    )

    return db.scalars(statement).first()

def claim_next_scan(
    db: Session,
    worker_id: str | None = None,
    lease_seconds: int = 60,
) -> Scan | None:
    """Atomically claim one queued scan and assign a worker lease.

    Scanner execution remains disabled.
    """

    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be greater than zero")

    worker_id = worker_id or str(uuid4())

    if not worker_id.strip() or len(worker_id) > 100:
        raise ValueError("worker_id must contain 1-100 characters")

    now = datetime.now(timezone.utc)
    lease_expiry = now + timedelta(seconds=lease_seconds)

    try:
        candidate = db.scalars(
            select(Scan)
            .where(Scan.status == "queued")
            .order_by(Scan.created_at.asc(), Scan.id.asc())
            .limit(1)
        ).first()

        if candidate is None:
            return None

        result = db.execute(
            update(Scan)
            .where(
                Scan.id == candidate.id,
                Scan.status == "queued",
            )
            .values(
                status="running",
                started_at=now,
                last_heartbeat_at=now,
                worker_id=worker_id,
                lease_expires_at=lease_expiry,
                error_message=None,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            db.rollback()
            return None

        scan_id = candidate.id
        db.commit()
        db.expire_all()

        return db.get(Scan, scan_id)

    except Exception:
        db.rollback()
        raise
    

def transition_scan(
    db: Session,
    scan_id: str,
    owner_id: str,
    new_status: str,
    error_message: str | None = None,
) -> Scan | None:
    """Atomically transition an owned scan to a valid lifecycle status.

    Returns None if the scan does not exist or is not owned by the user.
    Raises ScanLifecycleError for invalid or concurrent transitions.
    """

    if new_status not in ALLOWED_SCAN_TRANSITIONS:
        raise ScanLifecycleError("Unsupported scan status")

    if new_status == "failed":
        if not error_message or not error_message.strip():
            raise ScanLifecycleError(
                "An error message is required for failed scans"
            )
        error_message = error_message.strip()
    else:
        error_message = None

    scan = get_scan(
        db=db,
        scan_id=scan_id,
        owner_id=owner_id,
    )

    if scan is None:
        return None

    current_status = scan.status

    if new_status not in ALLOWED_SCAN_TRANSITIONS.get(
        current_status, set()
    ):
        raise ScanLifecycleError(
            f"Cannot transition scan from '{current_status}' "
            f"to '{new_status}'"
        )

    now = datetime.now(timezone.utc)

    values = {
        "status": new_status,
        "error_message": error_message,
    }

    if new_status == "running":
        values["started_at"] = now

    if new_status in {"completed", "failed"}:
        values["completed_at"] = now

    # Only update if the owner and original status still match.
    # This prevents two workers from successfully claiming the same
    # queued scan.
    from sqlalchemy import update

    statement = (
        update(Scan)
        .where(
            Scan.id == scan_id,
            Scan.requested_by == owner_id,
            Scan.status == current_status,
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )

    try:
        result = db.execute(statement)

        if result.rowcount != 1:
            db.rollback()
            raise ScanLifecycleError(
                "Scan status changed concurrently; reload and retry"
            )

        db.commit()

        # Clear stale ORM objects and fetch the updated database state.
        db.expire_all()

        return get_scan(
            db=db,
            scan_id=scan_id,
            owner_id=owner_id,
        )

    except Exception:
        db.rollback()
        raise


def process_next_scan(db: Session) -> Scan | None:
    """Claim a scan and validate authorization without executing it."""

    scan = claim_next_scan(db)

    if scan is None:
        return None

    try:
        validated_scan = validate_scan_for_execution(
            db=db,
            scan_id=scan.id,
        )

        if validated_scan is None:
            raise ScanAuthorizationError(
                "Scan disappeared during authorization validation"
            )

        # Actual scanner execution remains intentionally disabled.
        return validated_scan

    except ScanAuthorizationError as exc:
        return fail_running_scan(
            db=db,
            scan_id=scan.id,
            error_message=str(exc),
            worker_id=scan.worker_id,
        )

    except Exception:
        # Do not expose internal exception details in the scan record.
        try:
            return fail_running_scan(
                db=db,
                scan_id=scan.id,
                error_message="Unexpected worker error during scan validation",
                worker_id=scan.worker_id,
            )
        except ScanLifecycleError:
            raise



def fail_running_scan(
    db: Session,
    scan_id: str,
    error_message: str,
    worker_id: str,
) -> Scan:
    """Fail a running scan only if the worker owns a valid lease."""

    message = error_message.strip() or "Unexpected worker error"
    now = datetime.now(timezone.utc)

    if not worker_id.strip() or len(worker_id) > 100:
        raise ValueError("worker_id must contain 1-100 characters")

    try:
        result = db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
            )
            .values(
                status="failed",
                error_message=message[:2000],
                completed_at=now,
                worker_id=None,
                lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            raise ScanLifecycleError(
                "Could not fail scan: worker ownership or lease is invalid"
            )

        db.commit()
        db.expire_all()

        scan = db.get(Scan, scan_id)

        if scan is None:
            raise ScanLifecycleError(
                "Scan could not be retrieved after failure update"
            )

        return scan

    except Exception:
        db.rollback()
        raise


def recover_abandoned_scans(
    db: Session,
    timeout_minutes: int = 30,
) -> int:
    """Fail scans with expired worker leases.

    The lease expiry is authoritative; timeout_minutes is retained
    for backward compatibility and validated as a positive value.
    Returns the number of scans marked as failed.
    """

    if timeout_minutes <= 0:
        raise ValueError("timeout_minutes must be greater than zero")

    now = datetime.now(timezone.utc)

    try:
        result = db.execute(
            update(Scan)
            .where(
                Scan.status == "running",
                Scan.lease_expires_at.is_not(None),
                Scan.lease_expires_at < now,
            )
            .values(
                status="failed",
                error_message=(
                    "Scan timed out and was recovered as abandoned"
                ),
                completed_at=now,
                worker_id=None,
                lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )

        db.commit()
        db.expire_all()

        return result.rowcount or 0

    except Exception:
        db.rollback()
        raise

def run_worker_cycle(
    db: Session,
    timeout_minutes: int = 30,
) -> Scan | None:
    """Recover abandoned scans, then process one queued scan.

    Scanner execution remains disabled.
    """

    recover_abandoned_scans(
        db=db,
        timeout_minutes=timeout_minutes,
    )

    return process_next_scan(db)


def update_scan_heartbeat(
    db: Session,
    scan_id: str,
    worker_id: str,
    lease_seconds: int = 60,
) -> bool:
    """Renew a scan lease only for its current, unexpired owner."""

    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be greater than zero")

    if not worker_id.strip() or len(worker_id) > 100:
        raise ValueError("worker_id must contain 1-100 characters")

    now = datetime.now(timezone.utc)
    new_expiry = now + timedelta(seconds=lease_seconds)

    try:
        result = db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
            )
            .values(
                last_heartbeat_at=now,
                lease_expires_at=new_expiry,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            db.rollback()
            return False

        db.commit()
        db.expire_all()
        return True

    except Exception:
        db.rollback()
        raise