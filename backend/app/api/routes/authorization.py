"""API endpoints for authorization requests."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_reviewer
from app.core.database import get_db
from app.models.user import User
from app.schemas.authorization import (
    AuthorizationRequestCreate,
    AuthorizationRequestResponse,
    AuthorizationReview,
)
from app.services.authorization_scope import AuthorizationScopeError
from app.services import authorization_service

router = APIRouter(
    prefix="/authorization-requests",
    tags=["Authorization"],
    dependencies=[Depends(get_current_user)],
)


@router.post(
    "",
    response_model=AuthorizationRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_request(
    request_data: AuthorizationRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        return authorization_service.create_authorization_request(
            db=db,
            request_data=request_data,
            requester_email=current_user.email,
            owner_id=current_user.id,
        )
    except AuthorizationScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=list[AuthorizationRequestResponse],
)
def list_requests(
    target_id: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return authorization_service.list_authorization_requests(
        db=db,
        owner_id=current_user.id,
        target_id=target_id,
    )


@router.get(
    "/{request_id}",
    response_model=AuthorizationRequestResponse,
)
def get_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    request = authorization_service.get_authorization_request(
        db=db,
        request_id=request_id,
        owner_id=current_user.id,
    )

    if request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authorization request not found",
        )

    return request


@router.patch(
    "/{request_id}/review",
    response_model=AuthorizationRequestResponse,
)
def review_request(
    request_id: str,
    review_data: AuthorizationReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_reviewer),
):
    try:
        request = authorization_service.review_authorization_request(
            db=db,
            request_id=request_id,
            review_data=review_data,
            reviewed_by=current_user.id,
        )
    except ValueError as exc:
        message = str(exc)

        code = (
            status.HTTP_404_NOT_FOUND
            if message == "Target not found"
            else status.HTTP_409_CONFLICT
        )

        raise HTTPException(
            status_code=code,
            detail=message,
        ) from exc

    if request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Authorization request not found",
        )

    return request