"""Import model modules here so Alembic can discover their metadata."""

from app.core.database import Base
from app.models.project import Project
from app.models.target import Target
from app.models.authorization import AuthorizationRequest

__all__ = [
    "Base",
    "Project",
    "Target",
    "AuthorizationRequest",
]