"""Business logic for authorization requests."""

from datetime import datetime,timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.authorization import AuthorizationRequest
from app.models.project import Project
from app.models.target import Target
from app.schemas.authorization import (
    AuthorizationRequestCreate,
    AuthorizationReview,
)
from app.services.authorization_scope import (
    validate_authorization_scope,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def recalculate_target_authorization_status(
    db: Session,
    target: Target,
) -> None:
    """Recalculate target status from all its authorization requests."""

    requests = list(
        db.scalars(
            select(AuthorizationRequest).where(
                AuthorizationRequest.target_id == target.id
            )
        ).all()
    )

    now = utc_now()

    def is_valid_approval(request: AuthorizationRequest) -> bool:
        if request.status != "approved":
            return False

        if request.expires_at is None:
            return True

        expires_at = request.expires_at

        # SQLite may return a naive datetime.
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return expires_at > now

    # Any currently valid approval keeps the target approved.
    if any(is_valid_approval(request) for request in requests):
        target.authorization_status = "approved"
        return

    # Pending requests take priority over historical decisions.
    if any(request.status == "pending" for request in requests):
        target.authorization_status = "pending"
        return

    if not requests:
        target.authorization_status = "pending"
        return

    # Determine the status from the most recently created request.
    latest_request = max(
        requests,
        key=lambda request: request.created_at,
    )

    if latest_request.status == "approved":
        target.authorization_status = "expired"
    elif latest_request.status in {"rejected", "revoked"}:
        target.authorization_status = latest_request.status
    else:
        target.authorization_status = "pending"
        
        

def create_authorization_request(
    db: Session,
    request_data: AuthorizationRequestCreate,
    requester_email: str,
    owner_id: str,
) -> AuthorizationRequest:
    # Only the owner of the target's project may request authorization.
    target = db.scalars(
        select(Target)
        .join(Project, Target.project_id == Project.id)
        .where(
            Target.id == request_data.target_id,
            Project.owner_id == owner_id,
        )
    ).first()

    if target is None:
        raise ValueError("Target not found")

    validated_scope = validate_authorization_scope(
        requested_scope=request_data.requested_scope,
        target_value=target.value,
        target_type=target.target_type,
    )
     
    request = AuthorizationRequest(
        target_id=target.id,
        evidence_reference=request_data.evidence_reference,
        requested_scope=validated_scope,
        requested_by=requester_email,
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
    owner_id: str,
) -> AuthorizationRequest | None:
    statement = (
        select(AuthorizationRequest)
        .join(Target, AuthorizationRequest.target_id == Target.id)
        .join(Project, Target.project_id == Project.id)
        .where(
            AuthorizationRequest.id == request_id,
            Project.owner_id == owner_id,
        )
    )

    return db.scalars(statement).first()


def list_authorization_requests(
    db: Session,
    owner_id: str,
    target_id: str | None = None,
) -> list[AuthorizationRequest]:
    statement = (
        select(AuthorizationRequest)
        .join(Target, AuthorizationRequest.target_id == Target.id)
        .join(Project, Target.project_id == Project.id)
        .where(Project.owner_id == owner_id)
    )

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
        if review_data.status == "approved":
            request.expires_at = (
                request.reviewed_at
                + timedelta(days=review_data.validity_days)
            )
        else:
            request.expires_at = None

        recalculate_target_authorization_status(
            db=db,
            target=target,
        )

        db.commit()
        db.refresh(request)
    except Exception:
        db.rollback()
        raise

    return request

def revoke_authorization_request(
    db: Session,
    request_id: str,
    revoked_by: str,
) -> AuthorizationRequest | None:
    """Revoke an approved authorization request."""

    request = db.get(AuthorizationRequest, request_id)

    if request is None:
        return None

    if request.status != "approved":
        raise ValueError(
            "Only approved authorization requests can be revoked"
        )

    target = db.get(Target, request.target_id)

    if target is None:
        raise ValueError("Target not found")

    try:
        request.status = "revoked"
        request.revoked_by = revoked_by
        request.revoked_at = utc_now()

        recalculate_target_authorization_status(
            db=db,
            target=target,
        )

        db.commit()
        db.refresh(request)

    except Exception:
        db.rollback()
        raise

    return request