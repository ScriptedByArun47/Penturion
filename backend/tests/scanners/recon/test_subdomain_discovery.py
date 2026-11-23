from threading import Event
from unittest.mock import Mock

import pytest

from app.scanners.agent_context import AgentExecutionContext, AssetCandidate
from app.scanners.agent_result import AgentResult
from app.scanners.recon.subdomain_discovery import SubdomainDiscoveryAgent


class FakeLimiter:
    def acquire(self, host, timeout=None):
        return True

    def release(self, host):
        pass


@pytest.fixture
def context():
    return AgentExecutionContext(
        scan_id="test-scan",
        target="example.com",
        target_type="domain",
        authorized_value="example.com",
        timeout_seconds=30,
        cancel_event=Event(),
        request_limiter=FakeLimiter(),
    )


def test_discovers_and_normalizes_subdomains(context):
    provider = Mock()
    provider.discover.return_value = [
        "api.example.com",
        "API.EXAMPLE.COM.",
        "dev.example.com",
    ]

    agent = SubdomainDiscoveryAgent(provider)
    result = agent.execute(context)

    assert isinstance(result, AgentResult)
    assert result.success is True
    assert result.agent_id == "A01"
    assert result.asset_candidates == (
        AssetCandidate("api.example.com", "subdomain"),
        AssetCandidate("dev.example.com", "subdomain"),
    )


def test_rejects_out_of_scope_and_invalid_candidates(context):
    provider = Mock()
    provider.discover.return_value = [
        "api.example.com",
        "notexample.com",
        "example.com.attacker.test",
        "invalid..example.com",
        "-invalid.example.com",
    ]

    agent = SubdomainDiscoveryAgent(provider)
    result = agent.execute(context)

    assert result.success is True
    assert result.asset_candidates == (
        AssetCandidate("api.example.com", "subdomain"),
    )


def test_passes_authorized_domain_and_timeout_to_provider(context):
    provider = Mock()
    provider.discover.return_value = []

    agent = SubdomainDiscoveryAgent(provider)
    agent.execute(context)

    provider.discover.assert_called_once_with(
        root_domain="example.com",
        timeout_seconds=30,
        cancel_event=context.cancel_event,
    )


def test_rejects_non_domain_target(context):
    provider = Mock()
    agent = SubdomainDiscoveryAgent(provider)

    invalid_context = AgentExecutionContext(
        scan_id="test-scan",
        target="https://example.com/app",
        target_type="url",
        authorized_value="https://example.com/app",
        timeout_seconds=30,
        cancel_event=Event(),
        request_limiter=FakeLimiter(),
    )

    result = agent.execute(invalid_context)

    assert result.success is False
    provider.discover.assert_not_called()



from app.scanners.executor import AgentExecutionCancelled


def test_raises_cancellation_before_provider_execution(context):
    context.cancel_event.set()
    provider = Mock()

    agent = SubdomainDiscoveryAgent(provider)

    with pytest.raises(AgentExecutionCancelled):
        agent.execute(context)

    provider.discover.assert_not_called()


def test_raises_cancellation_after_provider_execution(context):
    provider = Mock()

    def discover(**kwargs):
        context.cancel_event.set()
        return ["api.example.com"]

    provider.discover.side_effect = discover

    agent = SubdomainDiscoveryAgent(provider)

    with pytest.raises(AgentExecutionCancelled):
        agent.execute(context)


def test_provider_failure_returns_failed_result(context):
    provider = Mock()
    provider.discover.side_effect = RuntimeError("Provider unavailable")

    agent = SubdomainDiscoveryAgent(provider)
    result = agent.execute(context)

    assert result.success is False
    assert "Provider unavailable" in result.error
    


def test_rejects_target_outside_authorized_scope():
    provider = Mock()
    agent = SubdomainDiscoveryAgent(provider)

    invalid_context = AgentExecutionContext(
        scan_id="test-scan",
        target="attacker.test",
        target_type="domain",
        authorized_value="example.com",
        timeout_seconds=30,
        cancel_event=Event(),
        request_limiter=FakeLimiter(),
    )

    result = agent.execute(invalid_context)

    assert result.success is False
    provider.discover.assert_not_called()