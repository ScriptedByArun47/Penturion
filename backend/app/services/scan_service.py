
"""Business logic for authorized scan management."""


from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target

import ipaddress
import json
import logging
logger = logging.getLogger(__name__)

from collections.abc import Callable

from app.core.database import SessionLocal
from app.scanners.heartbeat import ScanHeartbeatKeeper

from app.models.finding import Finding
from app.scanners.adapters.http_scanner import HTTPScanner

from app.models.authorization import AuthorizationRequest
from app.scanners.scope import (
    ScopeValidationError,
    host_matches_domain,
    normalize_hostname,
    validate_target_in_scope,
)
from app.services.authorization_scope import (
    AuthorizationScopeError,
    validate_authorization_scope,
)


ALLOWED_SCAN_TRANSITIONS = {
    "queued": {"running", "failed", "cancelled"},
    "running": {"completed", "failed", "cancelled"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}

class ScanLifecycleError(Exception):
    """Raised when a scan lifecycle transition is invalid."""

class ScanCancellationRequested(ScanLifecycleError):
    """Raised when cancellation wins the scan completion race."""

class ScanAuthorizationError(Exception):
    """Raised when a scan request is not authorized."""
def validate_approved_scope(
    request: AuthorizationRequest,
    target: Target,
) -> None:
    """Verify that an approved request is valid, unexpired, and covers the target."""

    # 1. Verify approval status.
    if request.status != "approved":
        raise ScanAuthorizationError(
            "The authorization request is not approved"
        )

    # 2. Reject expired authorization.
    if request.expires_at is not None:
        expires_at = request.expires_at

        # SQLite may return naive datetimes even when timezone=True.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc):
            raise ScanAuthorizationError(
                "Authorization has expired; scan execution denied"
            )

    # 3. Verify that authorization belongs to this target.
    if request.target_id != target.id:
        raise ScanAuthorizationError(
            "Authorization request does not belong to this target"
        )

    # 4. Validate the approved scope.
    try:
        canonical_scope = validate_authorization_scope(
            requested_scope=request.requested_scope,
            target_value=target.value,
            target_type=target.target_type,
        )

        entries = json.loads(canonical_scope)

        if target.target_type == "domain":
            target_hostname = normalize_hostname(target.value)

            covered = any(
                host_matches_domain(target_hostname, entry)
                for entry in entries
            )

        elif target.target_type == "ip":
            target_ip = ipaddress.ip_address(target.value)

            covered = any(
                ipaddress.ip_address(entry) == target_ip
                for entry in entries
            )

        elif target.target_type == "url":
            covered = False

            for entry in entries:
                try:
                    validate_target_in_scope(
                        target.value,
                        entry,
                        "url",
                    )
                    covered = True
                    break
                except ScopeValidationError:
                    continue

        else:
            raise ScanAuthorizationError(
                "Unsupported target type"
            )

    except (
        AuthorizationScopeError,
        ScopeValidationError,
        ValueError,
    ) as exc:
        raise ScanAuthorizationError(
            "Authorization scope validation failed"
        ) from exc

    # 5. Reject targets outside the approved scope.
    if not covered:
        raise ScanAuthorizationError(
            "The approved scope does not cover the scan target"
        )


def validate_scan_authorization(
    db: Session,
    target_id: str,
    owner_id: str,
    authorization_request_id: str,
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

    authorization_request = db.scalars(
        select(AuthorizationRequest).where(
            AuthorizationRequest.id == authorization_request_id,
            AuthorizationRequest.target_id == target.id,
        )
    ).first()

    if authorization_request is None:
        raise ScanAuthorizationError(
            "Authorization request not found for this target"
        )

    validate_approved_scope(
        request=authorization_request,
        target=target,
    )

    return target

def validate_scan_for_execution(
    db: Session,
    scan_id: str,
) -> Scan | None:
    """Revalidate authorization before a claimed scan can execute.

    Returns None if the scan does not exist.
    Raises ScanAuthorizationError if authorization is no longer valid.
    Scanner network execution remains disabled.
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

    # Verify that the requester matches the scan's recorded requester.
    if scan.requested_by != scan.requester.id:
        raise ScanAuthorizationError(
            "Scan requester does not match the scan owner"
        )

    # Verify that the target still belongs to the requesting user.
    if scan.target.project.owner_id != scan.requested_by:
        raise ScanAuthorizationError(
            "Target ownership has changed; execution denied"
        )

    # Require a specific authorization request for this scan.
    if scan.authorization_request_id is None:
        raise ScanAuthorizationError(
            "Scan has no associated authorization request"
        )

    authorization_request = db.scalars(
        select(AuthorizationRequest).where(
            AuthorizationRequest.id == scan.authorization_request_id,
            AuthorizationRequest.target_id == scan.target_id,
        )
    ).first()

    if authorization_request is None:
        raise ScanAuthorizationError(
            "Authorization request is no longer valid"
        )

    # Both the request and target must remain approved.
    if authorization_request.status != "approved":
        raise ScanAuthorizationError(
            "Target authorization is no longer approved"
        )

    if scan.target.authorization_status != "approved":
        raise ScanAuthorizationError(
            "Target authorization is no longer approved"
        )

    # Revalidate the approved scope against the current target.
    try:
        validate_approved_scope(
            request=authorization_request,
            target=scan.target,
        )
    except ScanAuthorizationError:
        raise

    return scan



def create_scan(
    db: Session,
    target_id: str,
    owner_id: str,
    authorization_request_id: str,
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
        authorization_request_id=authorization_request_id,
    )

    scan = Scan(
        target_id=target.id,
        authorization_request_id=authorization_request_id,
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

def request_scan_cancellation(
    db: Session,
    scan_id: str,
    owner_id: str,
) -> Scan | None:
    """Request cancellation of an owned scan."""

    scan = get_scan(
        db=db,
        scan_id=scan_id,
        owner_id=owner_id,
    )

    if scan is None:
        return None

    if scan.status == "cancelled":
        return scan

    if (scan.status == "running" and scan.cancel_requested_at is not None):
        return scan

    if scan.status in {"completed", "failed"}:
        raise ScanLifecycleError( f"Cannot cancel a scan with status '{scan.status}'")

    now = datetime.now(timezone.utc)

    try:
        if scan.status == "queued":
            statement = (
                update(Scan)
                .where(
                    Scan.id == scan_id,
                    Scan.requested_by == owner_id,
                    Scan.status == "queued",
                )
                .values(
                    status="cancelled",
                    cancel_requested_at=now,
                    completed_at=now,
                    error_message=None,
                )
            )
        elif scan.status == "running":
            statement = (
                update(Scan)
                .where(
                    Scan.id == scan_id,
                    Scan.requested_by == owner_id,
                    Scan.status == "running",
                    Scan.cancel_requested_at.is_(None),
                )
                .values(cancel_requested_at=now)
            )
        else:
            raise ScanLifecycleError(
                f"Cannot cancel a scan with status '{scan.status}'"
            )

        result = db.execute(
            statement.execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            db.rollback()

            # Another request may have cancelled it concurrently.
            current_scan = get_scan(
                db=db,
                scan_id=scan_id,
                owner_id=owner_id,
            )

            if current_scan is not None:
                if current_scan.status == "cancelled":
                    return current_scan

                if (
                    current_scan.status == "running"
                    and current_scan.cancel_requested_at is not None
                ):
                    return current_scan



            raise ScanLifecycleError(
                "Scan state changed while cancellation was requested"
            )

        db.commit()
        db.expire_all()

        updated_scan = get_scan(
            db=db,
            scan_id=scan_id,
            owner_id=owner_id,
        )

        return updated_scan

    except Exception:
        db.rollback()
        raise

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

def process_next_scan(
    db: Session,
    heartbeat_session_factory: Callable[[], Session] | None = None,
) -> Scan | None:
    """Claim, authorize, execute and persist one HTTP scan."""

    scan = claim_next_scan(db)

    if scan is None:
        return None

    worker_id = scan.worker_id

    if not worker_id:
        raise ScanLifecycleError(
            "Claimed scan has no assigned worker"
        )

    scan_id = scan.id
    keeper = None

    try:
        # 1. Revalidate authorization and target scope.
        validated_scan = validate_scan_for_execution(
            db=db,
            scan_id=scan_id,
        )

        if validated_scan is None:
            raise ScanAuthorizationError(
                "Scan disappeared during authorization validation"
            )

        target = validated_scan.target

        # Capture target information before ending the read transaction.
        target_type = target.target_type
        target_value = target.value

        # 2. Build the scanner input.
        if target_type == "url":
            scan_url = target_value

        elif target_type == "domain":
            hostname = normalize_hostname(target_value)
            scan_url = f"https://{hostname}/"

        else:
            raise ScanLifecycleError(
                "HTTP scanning does not support IP targets yet"
            )

        # 3. Verify that this worker owns a valid lease.
        now = datetime.now(timezone.utc)

        lease_valid = db.scalar(
            select(Scan.id).where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
            )
        )

        if lease_valid is None:
            raise ScanLifecycleError(
                "Worker lease expired before scanner execution"
            )

        # End the main session's read transaction before heartbeat writes.
        db.rollback()

        session_factory = heartbeat_session_factory or SessionLocal

        # 4. Start independent background heartbeat management.
        keeper = ScanHeartbeatKeeper(
            session_factory=session_factory,
            heartbeat_callback=update_scan_heartbeat,
            cancellation_callback=check_scan_cancellation,
            scan_id=scan_id,
            worker_id=worker_id,
            lease_seconds=60,
            heartbeat_interval=20,
        )

        keeper.start()

        # 5. Execute the HTTP scanner and stop heartbeat management.
        scanner_error = None
        result = None

        try:
            result = HTTPScanner(
                    cancel_event=keeper.cancel_event
                ).execute(scan_url)

        except Exception as exc:
            scanner_error = exc

        finally:
            stopped = keeper.stop(timeout=5)

        if not stopped:
            raise ScanLifecycleError(
                "Heartbeat thread did not stop within the allowed time"
            )

    # 6. Refuse to continue if lease ownership was lost.
        if keeper.lease_lost:
            raise ScanLifecycleError(
                keeper.failure_reason or "Worker lease was lost"
            )

        if keeper.cancellation_requested:
            return cancel_running_scan(
                db=db,
                scan_id=scan_id,
                worker_id=worker_id,
            )

        if scanner_error is not None:
            raise scanner_error




        # Check the current lease again. This also protects short scans
        # that finish before the first periodic heartbeat.
        now = datetime.now(timezone.utc)

        lease_valid = db.scalar(
            select(Scan.id).where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
            )
        )

        if lease_valid is None:
            raise ScanLifecycleError(
                "Worker lease expired during scanner execution"
            )

        # 7. Handle scanner failure.
        if not result.success:
            return fail_running_scan(
                db=db,
                scan_id=scan_id,
                error_message=result.error or "HTTP scanner failed",
                worker_id=worker_id,
            )

        # 8. Validate and persist findings.
        allowed_severities = {
            "informational",
            "low",
            "medium",
            "high",
            "critical",
        }

        for item in result.findings:
            severity = item.severity.lower()

            if severity not in allowed_severities:
                raise ValueError(
                    "Scanner returned an unsupported severity"
                )

            db.add(
                Finding(
                    scan_id=scan_id,
                    scanner_name=result.scanner_name,
                    title=item.title,
                    severity=severity,
                    description=item.description,
                    evidence=item.evidence,
                    remediation=item.remediation,
                )
            )

        # 9. Complete the scan.
        # Findings and completion remain in one transaction.
        return complete_running_scan(
            db=db,
            scan_id=scan_id,
            worker_id=worker_id,
        )

    except ScanAuthorizationError as exc:
        return fail_running_scan(
            db=db,
            scan_id=scan_id,
            error_message=str(exc),
            worker_id=worker_id,
        )

    except ScanCancellationRequested:
        db.rollback()

        return cancel_running_scan(
            db=db,
            scan_id=scan_id,
            worker_id=worker_id,
        )
    except ScanLifecycleError:
        db.rollback()
        raise

    except Exception:
        db.rollback()

        return fail_running_scan(
            db=db,
            scan_id=scan_id,
            error_message=(
                "Unexpected worker error during HTTP scanning"
            ),
            worker_id=worker_id,
        )

    finally:
       if keeper is not None:
            if not keeper.stop(timeout=5):
                logger.error(
                    "Heartbeat thread did not stop: scan_id=%s",
                    scan_id,
                )


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

def complete_running_scan(
    db: Session,
    scan_id: str,
    worker_id: str,
) -> Scan:
    """Complete a running scan only if the worker owns a valid lease."""

    if not worker_id.strip() or len(worker_id) > 100:
        raise ValueError("worker_id must contain 1-100 characters")

    now = datetime.now(timezone.utc)

    try:
        result = db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
                Scan.cancel_requested_at.is_(None),
            )
            .values(
                status="completed",
                completed_at=now,
                error_message=None,
                worker_id=None,
                lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            cancellation_requested = db.scalar(
                select(Scan.cancel_requested_at).where(
                    Scan.id == scan_id,
                    Scan.status == "running",
                    Scan.worker_id == worker_id,
                    Scan.lease_expires_at > now,
                )
            )

            if cancellation_requested is not None:
                raise ScanCancellationRequested(
                    "Scan cancellation was requested before completion"
                )

            raise ScanLifecycleError(
                "Could not complete scan: worker ownership or lease is invalid"
            )

        db.commit()
        db.expire_all()

        scan = db.get(Scan, scan_id)

        if scan is None:
            raise ScanLifecycleError(
                "Scan could not be retrieved after completion"
            )

        return scan

    except Exception:
        db.rollback()
        raise
def cancel_running_scan(
    db: Session,
    scan_id: str,
    worker_id: str,
) -> Scan:
    """Finalize cancellation when the current worker owns a valid lease."""

    if not worker_id.strip() or len(worker_id) > 100:
        raise ValueError("worker_id must contain 1-100 characters")

    now = datetime.now(timezone.utc)

    try:
        result = db.execute(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
                Scan.cancel_requested_at.is_not(None),
            )
            .values(
                status="cancelled",
                completed_at=now,
                error_message=None,
                worker_id=None,
                lease_expires_at=None,
            )
            .execution_options(synchronize_session=False)
        )

        if result.rowcount != 1:
            raise ScanLifecycleError(
                "Could not cancel scan: worker ownership, lease, "
                "or cancellation request is invalid"
            )

        db.commit()
        db.expire_all()

        scan = db.get(Scan, scan_id)

        if scan is None:
            raise ScanLifecycleError(
                "Scan could not be retrieved after cancellation"
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
    """Recover abandoned scans, then execute one queued HTTP scan."""

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

def check_scan_cancellation(
    db: Session,
    scan_id: str,
    worker_id: str,
) -> bool:
    """Check cancellation for the current worker with a valid lease."""

    if not worker_id.strip() or len(worker_id) > 100:
        raise ValueError("worker_id must contain 1-100 characters")

    now = datetime.now(timezone.utc)

    try:
        cancel_requested_at = db.scalar(
            select(Scan.cancel_requested_at).where(
                Scan.id == scan_id,
                Scan.status == "running",
                Scan.worker_id == worker_id,
                Scan.lease_expires_at > now,
            )
        )

        return cancel_requested_at is not None

    except Exception:
        db.rollback()
        raise
