"""Common interface and result types for PENTURION scanners."""

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ScanFinding:
    """A normalized security finding."""

    title: str
    severity: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""


@dataclass(frozen=True)
class ScannerResult:
    """Result returned by a scanner module."""

    scanner_name: str
    target: str
    success: bool
    findings: tuple[ScanFinding, ...] = ()
    error: str | None = None


class ScannerAdapter(Protocol):
    """Interface implemented by each scanner module."""

    def execute(self, target: str) -> ScannerResult:
        """Run the scanner against a validated target."""
        ...