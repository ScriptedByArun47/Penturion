"""Standard result structure returned by PENTURION agents."""

from dataclasses import dataclass, field
from typing import Any

from app.scanners.base import ScanFinding
from app.scanners.agent_context import AssetCandidate


@dataclass(frozen=True)
class AgentResult:
    """Normalized result returned by a security agent."""

    agent_id: str
    success: bool

    findings: tuple[ScanFinding, ...] = ()

    asset_candidates: tuple[AssetCandidate, ...] = ()

    metadata: dict[str, Any] = field(default_factory=dict)

    error: str | None = None

    def __post_init__(self) -> None:
        if not self.agent_id.strip():
            raise ValueError("agent_id must not be empty")

        if self.success and self.error is not None:
            raise ValueError(
                "Successful execution cannot contain an error"
            )

        if not self.success and (
            self.error is None or not self.error.strip()
        ):
            raise ValueError(
                "Failed execution must contain an error message"
            )