from datetime import datetime, timezone
from threading import Event
from unittest.mock import Mock

import pytest

from app.scanners.agent_context import (
    AgentExecutionContext,
    DiscoveredAsset,
)
from app.scanners.agent_result import AgentResult, DNSRecordCandidate
from app.scanners.executor import AgentExecutionCancelled
from app.scanners.recon.dns_enumeration import DNSEnumerationAgent
from app.scanners.recon.dns_provider import DNSRecordData


class FakeLimiter:
    def acquire(self, host, timeout=None):
        return True

    def release(self, host):
        pass


@pytest.fixture
def context():
    assets = (
        DiscoveredAsset(
            value="api.example.com",
            asset_type="subdomain",
            source_agent="A01",
            discovered_at=datetime.now(timezone.utc),
            asset_id="asset-001",
            scope_status="in_scope",
        ),
        DiscoveredAsset(
            value="www.example.com",
            asset_type="subdomain",
            source_agent="A01",
            discovered_at=datetime.now(timezone.utc),
            asset_id="asset-002",
            scope_status="in_scope",
        ),
    )

    return AgentExecutionContext(
        scan_id="test-scan",
        target="example.com",
        target_type="domain",
        authorized_value="example.com",
        timeout_seconds=60,
        cancel_event=Event(),
        request_limiter=FakeLimiter(),
        discovered_assets=assets,
    )


def test_collects_dns_records_for_persisted_assets(context):
    provider = Mock()
    provider.collect.side_effect = [
        [
            DNSRecordData(
                record_name="api.example.com",
                record_type="A",
                value="93.184.216.34",
                ttl=300,
            )
        ],
        [
            DNSRecordData(
                record_name="www.example.com",
                record_type="MX",
                value="mail.example.com",
                ttl=600,
                priority=10,
            )
        ],
    ]

    result = DNSEnumerationAgent(provider).execute(context)

    assert isinstance(result, AgentResult)
    assert result.success is True
    assert result.agent_id == "A02"

    assert result.dns_records == (
        DNSRecordCandidate(
            asset_id="asset-001",
            record_name="api.example.com",
            record_type="A",
            value="93.184.216.34",
            ttl=300,
        ),
        DNSRecordCandidate(
            asset_id="asset-002",
            record_name="www.example.com",
            record_type="MX",
            value="mail.example.com",
            ttl=600,
            priority=10,
        ),
    )

    assert provider.collect.call_count == 2


def test_skips_assets_without_database_ids(context):
    provider = Mock()

    asset_without_id = DiscoveredAsset(
        value="missing.example.com",
        asset_type="subdomain",
        source_agent="A01",
        discovered_at=datetime.now(timezone.utc),
    )

    updated_context = AgentExecutionContext(
        scan_id=context.scan_id,
        target=context.target,
        target_type=context.target_type,
        authorized_value=context.authorized_value,
        timeout_seconds=context.timeout_seconds,
        cancel_event=context.cancel_event,
        request_limiter=context.request_limiter,
        discovered_assets=(asset_without_id,),
    )

    result = DNSEnumerationAgent(provider).execute(updated_context)

    assert result.success is True
    assert result.dns_records == ()
    provider.collect.assert_not_called()


def test_skips_out_of_scope_hostname(context):
    provider = Mock()

    outside_asset = DiscoveredAsset(
        value="api.attacker.test",
        asset_type="subdomain",
        source_agent="A01",
        discovered_at=datetime.now(timezone.utc),
        asset_id="asset-outside",
    )

    updated_context = AgentExecutionContext(
        scan_id=context.scan_id,
        target=context.target,
        target_type=context.target_type,
        authorized_value=context.authorized_value,
        timeout_seconds=context.timeout_seconds,
        cancel_event=context.cancel_event,
        request_limiter=context.request_limiter,
        discovered_assets=(outside_asset,),
    )

    result = DNSEnumerationAgent(provider).execute(updated_context)

    assert result.success is True
    assert result.dns_records == ()
    provider.collect.assert_not_called()


def test_rejects_mismatched_authorized_root(context):
    provider = Mock()

    invalid_context = AgentExecutionContext(
        scan_id="test-scan",
        target="attacker.test",
        target_type="domain",
        authorized_value="example.com",
        timeout_seconds=60,
        cancel_event=Event(),
        request_limiter=FakeLimiter(),
        discovered_assets=context.discovered_assets,
    )

    result = DNSEnumerationAgent(provider).execute(invalid_context)

    assert result.success is False
    provider.collect.assert_not_called()


def test_rejects_non_domain_target(context):
    provider = Mock()

    invalid_context = AgentExecutionContext(
        scan_id="test-scan",
        target="https://example.com",
        target_type="url",
        authorized_value="https://example.com",
        timeout_seconds=60,
        cancel_event=Event(),
        request_limiter=FakeLimiter(),
    )

    result = DNSEnumerationAgent(provider).execute(invalid_context)

    assert result.success is False
    provider.collect.assert_not_called()


def test_raises_cancellation_before_dns_query(context):
    context.cancel_event.set()
    provider = Mock()

    with pytest.raises(AgentExecutionCancelled):
        DNSEnumerationAgent(provider).execute(context)

    provider.collect.assert_not_called()


def test_raises_cancellation_after_dns_query(context):
    provider = Mock()

    def collect(**kwargs):
        context.cancel_event.set()
        return []

    provider.collect.side_effect = collect

    with pytest.raises(AgentExecutionCancelled):
        DNSEnumerationAgent(provider).execute(context)


def test_provider_failure_returns_failed_result(context):
    provider = Mock()
    provider.collect.side_effect = RuntimeError("DNS provider unavailable")

    result = DNSEnumerationAgent(provider).execute(context)

    assert result.success is False
    assert "DNS provider unavailable" in result.error