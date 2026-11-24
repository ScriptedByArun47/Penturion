from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from app.scanners.executor import AgentExecutionCancelled
from app.scanners.recon.dns_provider import (
    DNSProviderError,
    DNSRecordProvider,
)


def make_answer(record_type, items, ttl=300):
    return SimpleNamespace(
        rrset=SimpleNamespace(
            ttl=ttl,
            __iter__=lambda self: iter(items),
        )
    )


class FakeRRSet:
    def __init__(self, items, ttl=300):
        self.items = items
        self.ttl = ttl

    def __iter__(self):
        return iter(self.items)


def make_answer(record_type, items, ttl=300):
    return SimpleNamespace(
        rrset=FakeRRSet(items, ttl)
    )


def test_collects_all_seven_record_types():
    responses = {
        "A": [
            SimpleNamespace(address="93.184.216.34")
        ],
        "AAAA": [
            SimpleNamespace(address="2606:2800:220:1:248:1893:25c8:1946")
        ],
        "CNAME": [
            SimpleNamespace(
                target=SimpleNamespace(
                    to_text=lambda: "alias.example.com."
                )
            )
        ],
        "MX": [
            SimpleNamespace(
                preference=10,
                exchange=SimpleNamespace(
                    to_text=lambda: "mail.example.com."
                ),
            )
        ],
        "NS": [
            SimpleNamespace(
                target=SimpleNamespace(
                    to_text=lambda: "ns1.example.com."
                )
            )
        ],
        "TXT": [
            SimpleNamespace(
                to_text=lambda: '"v=spf1 -all"'
            )
        ],
        "SOA": [
            SimpleNamespace(
                to_text=lambda: (
                    "ns1.example.com. hostmaster.example.com. "
                    "2026112401 3600 900 604800 300"
                )
            )
        ],
    }

    resolver = Mock()
    resolver.resolve.side_effect = lambda hostname, record_type, **kwargs: (
        make_answer(record_type, responses[record_type])
    )

    provider = DNSRecordProvider(resolver=resolver)

    records = provider.collect(
        hostname="example.com",
        timeout_seconds=20,
        cancel_event=Event(),
    )

    assert {record.record_type for record in records} == {
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"
    }
    assert len(records) == 7
    assert all(record.record_name == "example.com" for record in records)
    assert all(record.ttl == 300 for record in records)

    mx = next(record for record in records if record.record_type == "MX")
    assert mx.priority == 10
    assert mx.value == "mail.example.com"

    resolver.resolve.assert_has_calls([
        __import__("unittest.mock").mock.call(
            "example.com",
            record_type,
            lifetime=pytest.approx(20, abs=1),
            search=False,
            raise_on_no_answer=False,
        )
        for record_type in DNSRecordProvider.RECORD_TYPES
    ])


def test_normalizes_hostname():
    resolver = Mock()
    resolver.resolve.return_value = SimpleNamespace(rrset=None)

    provider = DNSRecordProvider(resolver=resolver)

    provider.collect(
        hostname="EXAMPLE.COM",
        timeout_seconds=10,
        cancel_event=Event(),
    )

    assert resolver.resolve.call_args_list[0].args == (
        "example.com",
        "A",
    )


def test_missing_records_are_skipped():
    resolver = Mock()
    resolver.resolve.return_value = SimpleNamespace(rrset=None)

    provider = DNSRecordProvider(resolver=resolver)

    records = provider.collect(
        hostname="example.com",
        timeout_seconds=10,
        cancel_event=Event(),
    )

    assert records == []
    assert resolver.resolve.call_count == 7


def test_rejects_private_ip_from_a_record():
    resolver = Mock()
    resolver.resolve.side_effect = lambda hostname, record_type, **kwargs: (
        make_answer(
            record_type,
            [SimpleNamespace(address="127.0.0.1")],
        )
        if record_type == "A"
        else SimpleNamespace(rrset=None)
    )

    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(DNSProviderError, match="prohibited"):
        provider.collect(
            hostname="example.com",
            timeout_seconds=10,
            cancel_event=Event(),
        )


def test_rejects_private_ip_from_aaaa_record():
    resolver = Mock()
    resolver.resolve.side_effect = lambda hostname, record_type, **kwargs: (
        make_answer(
            record_type,
            [SimpleNamespace(address="::1")],
        )
        if record_type == "AAAA"
        else SimpleNamespace(rrset=None)
    )

    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(DNSProviderError, match="prohibited"):
        provider.collect(
            hostname="example.com",
            timeout_seconds=10,
            cancel_event=Event(),
        )


def test_cancellation_before_query():
    resolver = Mock()
    cancel_event = Event()
    cancel_event.set()

    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(AgentExecutionCancelled):
        provider.collect(
            hostname="example.com",
            timeout_seconds=10,
            cancel_event=cancel_event,
        )

    resolver.resolve.assert_not_called()


def test_cancellation_between_queries():
    resolver = Mock()
    cancel_event = Event()

    def resolve(hostname, record_type, **kwargs):
        cancel_event.set()
        return SimpleNamespace(rrset=None)

    resolver.resolve.side_effect = resolve

    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(AgentExecutionCancelled):
        provider.collect(
            hostname="example.com",
            timeout_seconds=10,
            cancel_event=cancel_event,
        )

    assert resolver.resolve.call_count == 1


def test_dns_timeout_raises_provider_error():
    resolver = Mock()
    resolver.resolve.side_effect = dns.exception.Timeout

    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(DNSProviderError, match="timed out"):
        provider.collect(
            hostname="example.com",
            timeout_seconds=10,
            cancel_event=Event(),
        )


def test_rejects_invalid_hostname():
    resolver = Mock()
    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(DNSProviderError, match="Invalid DNS hostname"):
        provider.collect(
            hostname="invalid hostname",
            timeout_seconds=10,
            cancel_event=Event(),
        )

    resolver.resolve.assert_not_called()


def test_rejects_zero_timeout():
    resolver = Mock()
    provider = DNSRecordProvider(resolver=resolver)

    with pytest.raises(ValueError, match="Timeout"):
        provider.collect(
            hostname="example.com",
            timeout_seconds=0,
            cancel_event=Event(),
        )

    resolver.resolve.assert_not_called()
