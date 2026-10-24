
"""Business logic for authorized scan management."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target


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