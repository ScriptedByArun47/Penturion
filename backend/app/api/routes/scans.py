"""API routes for authorized scan management."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user
from app.core.database import get_db
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanResponse
from app.services.scan_service import (
    ScanAuthorizationError,
    create_scan,
    get_scan,
    list_scans,
)


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
    dependencies=[Depends(get_current_user)],
)


@router.get("", response_model=list[ScanResponse])
def get_scans(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List scans requested by the authenticated user."""

    return list_scans(db=db, owner_id=current_user.id)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_details(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a scan belonging to the authenticated user."""

    scan = get_scan(
        db=db,
        scan_id=scan_id,
        owner_id=current_user.id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return scan

@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_new_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a queued scan for an approved target."""

    try:
        scan = create_scan(
            db=db,
            target_id=scan_data.target_id,
            owner_id=current_user.id,
            scan_type=scan_data.scan_type,
        )
        return scan

    except ScanAuthorizationError as exc:
        message = str(exc)

        if message == "Target authorization must be approved before scanning":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=message,
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found",
        ) from exc