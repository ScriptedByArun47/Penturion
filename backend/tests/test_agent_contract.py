from datetime import datetime, timezone
from threading import Event

import pytest

from app.scanners.agent_context import (
    AgentExecutionContext,
    AssetCandidate,
    DiscoveredAsset,
)
from app.scanners.agent_result import AgentResult
from app.scanners.base import ScanFinding


class DummyRequestLimiter:
    def acquire(self, host, timeout=None):
        return True

    def release(self, host):
        pass


@pytest.fixture
def valid_context():
    return AgentExecutionContext(
        scan_id="scan-123",
        target="https://example.com",
        target_type="domain",
        authorized_value="example.com",
        timeout_seconds=120,
        cancel_event=Event(),
        request_limiter=DummyRequestLimiter(),
    )


def test_asset_candidate_creation():
    candidate = AssetCandidate(
        value="api.example.com",
        asset_type="subdomain",
    )

    assert candidate.value == "api.example.com"
    assert candidate.asset_type == "subdomain"


def test_discovered_asset_creation():
    asset = DiscoveredAsset(
        value="api.example.com",
        asset_type="subdomain",
        source_agent="A01",
        discovered_at=datetime.now(timezone.utc),
    )

    assert asset.source_agent == "A01"


def test_valid_execution_context(valid_context):
    assert valid_context.scan_id == "scan-123"
    assert valid_context.timeout_seconds == 120


def test_execution_context_rejects_invalid_target_type(valid_context):
    with pytest.raises(ValueError):
        AgentExecutionContext(
            scan_id="scan-123",
            target="https://example.com",
            target_type="invalid",
            authorized_value="example.com",
            timeout_seconds=120,
            cancel_event=Event(),
            request_limiter=DummyRequestLimiter(),
        )


def test_execution_context_rejects_nonpositive_timeout():
    with pytest.raises(ValueError):
        AgentExecutionContext(
            scan_id="scan-123",
            target="https://example.com",
            target_type="domain",
            authorized_value="example.com",
            timeout_seconds=0,
            cancel_event=Event(),
            request_limiter=DummyRequestLimiter(),
        )


def test_successful_agent_result():
    result = AgentResult(
        agent_id="A01",
        success=True,
    )

    assert result.success is True
    assert result.error is None


def test_agent_result_reuses_scan_finding():
    finding = ScanFinding(
        title="Missing CSP",
        severity="low",
        description="CSP header is missing.",
    )

    result = AgentResult(
        agent_id="A11",
        success=True,
        findings=(finding,),
    )

    assert result.findings[0] is finding


def test_failed_agent_result():
    result = AgentResult(
        agent_id="A01",
        success=False,
        error="Discovery operation failed",
    )

    assert result.success is False
    assert result.error == "Discovery operation failed"


def test_failed_result_requires_error():
    with pytest.raises(ValueError):
        AgentResult(
            agent_id="A01",
            success=False,
        )


def test_successful_result_rejects_error():
    with pytest.raises(ValueError):
        AgentResult(
            agent_id="A01",
            success=True,
            error="Unexpected error",
        )