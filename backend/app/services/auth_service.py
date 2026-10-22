"""Business logic for user registration and login."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User
from app.schemas.auth import UserRegister


class EmailAlreadyRegisteredError(Exception):
    """Raised when an email is already registered."""


class InvalidCredentialsError(Exception):
    """Raised when login credentials are invalid."""


def register_user(db: Session, data: UserRegister) -> User:
    """Register a new user with a securely hashed password."""
    email = str(data.email).strip().lower()

    existing_user = db.scalar(
        select(User).where(User.email == email)
    )
    if existing_user:
        raise EmailAlreadyRegisteredError

    user = User(
        email=email,
        password_hash=hash_password(data.password),
        role="user",
        is_active=True,
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        # Handles a concurrent registration racing on the unique email.
        raise

    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> tuple[User, str]:
    """Verify credentials and return the user and access token."""
    normalized_email = email.strip().lower()

    user = db.scalar(
        select(User).where(User.email == normalized_email)
    )

    if (
        user is None
        or not user.is_active
        or not verify_password(password, user.password_hash)
    ):
        raise InvalidCredentialsError

    token = create_access_token(user.id)
    return user, token