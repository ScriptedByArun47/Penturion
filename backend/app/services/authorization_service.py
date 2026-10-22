"""Business logic for authorization requests."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.authorization import AuthorizationRequest
from app.models.target import Target
from app.schemas.authorization import (
    AuthorizationRequestCreate,
    AuthorizationReview,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def create_authorization_request(
    db: Session,
    request_data: AuthorizationRequestCreate,
) -> AuthorizationRequest:
    target = db.get(Target, request_data.target_id)

    if target is None:
        raise ValueError("Target not found")

    request = AuthorizationRequest(
        target_id=target.id,
        evidence_reference=request_data.evidence_reference,
        requested_scope=request_data.requested_scope,
        requested_by=request_data.requested_by,
        status="pending",
    )

    try:
        db.add(request)
        db.commit()
        db.refresh(request)
    except Exception:
        db.rollback()
        raise

    return request


def get_authorization_request(
    db: Session,
    request_id: str,
) -> AuthorizationRequest | None:
    return db.get(AuthorizationRequest, request_id)


def list_authorization_requests(
    db: Session,
    target_id: str | None = None,
) -> list[AuthorizationRequest]:
    statement = select(AuthorizationRequest)

    if target_id is not None:
        statement = statement.where(
            AuthorizationRequest.target_id == target_id
        )

    statement = statement.order_by(
        AuthorizationRequest.created_at.desc()
    )

    return list(db.scalars(statement).all())


def review_authorization_request(
    db: Session,
    request_id: str,
    review_data: AuthorizationReview,
    reviewed_by: str,
) -> AuthorizationRequest | None:
    request = db.get(AuthorizationRequest, request_id)

    if request is None:
        return None

    if request.status != "pending":
        raise ValueError(
            "Only pending authorization requests can be reviewed"
        )

    target = db.get(Target, request.target_id)

    if target is None:
        raise ValueError("Target not found")

    try:
        request.status = review_data.status
        request.reviewed_by = reviewed_by
        request.review_reason = review_data.review_reason
        request.reviewed_at = utc_now()

        target.authorization_status = review_data.status

        db.commit()
        db.refresh(request)
    except Exception:
        db.rollback()
        raise

    return request
