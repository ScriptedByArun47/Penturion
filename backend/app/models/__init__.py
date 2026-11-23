"""Import model modules here so Alembic can discover their metadata."""

from app.core.database import Base
from app.models.project import Project
from app.models.target import Target
from app.models.scan import Scan
from app.models.authorization import AuthorizationRequest
from app.models.user import User
from app.models.finding import Finding
from app.models.agent_execution import AgentExecution
from app.models.discovered_asset import DiscoveredAsset

__all__ = [
    "Base",
    "Project",
    "Target",
    "AuthorizationRequest",
    "User",
    "Scan",
    "Finding",
    "AgentExecution",
    "DiscoveredAsset",
]