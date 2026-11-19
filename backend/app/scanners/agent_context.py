"""Execution context and asset models for PENTURION agents."""

from dataclasses import dataclass, field
from datetime import datetime
from threading import Event
from typing import Any, Protocol


class RequestLimiter(Protocol):
    """Interface for controlling concurrent requests per host."""

    def acquire(self, host: str, timeout: float | None = None) -> bool:
        ...

    def release(self, host: str) -> None:
        ...


@dataclass(frozen=True)
class AssetCandidate:
    """An asset discovered by an agent but not yet scope-validated."""

    value: str
    asset_type: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DiscoveredAsset:
    """An asset accepted by the orchestrator after scope validation."""

    value: str
    asset_type: str
    source_agent: str
    discovered_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentExecutionContext:
    """Shared execution information provided to an agent."""

    scan_id: str
    target: str
    target_type: str
    authorized_value: str

    timeout_seconds: int

    cancel_event: Event
    request_limiter: RequestLimiter

    discovered_assets: tuple[DiscoveredAsset, ...] = ()

    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.scan_id.strip():
            raise ValueError("scan_id must not be empty")

        if not self.target.strip():
            raise ValueError("target must not be empty")

        if self.target_type not in {"domain", "ip", "url"}:
            raise ValueError("Unsupported target_type")

        if not self.authorized_value.strip():
            raise ValueError("authorized_value must not be empty")

        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")