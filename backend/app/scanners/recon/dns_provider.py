"""DNS record collection provider for PENTURION."""

import ipaddress
import time
from dataclasses import dataclass
from threading import Event

import dns.exception
import dns.resolver

from app.scanners.executor import AgentExecutionCancelled
from app.scanners.scope import (
    ScopeValidationError,
    normalize_hostname,
    validate_destination_ip,
)


@dataclass(frozen=True)
class DNSRecordData:
    """A normalized DNS record returned by the provider."""

    record_name: str
    record_type: str
    value: str
    ttl: int | None = None
    priority: int | None = None


class DNSProviderError(ValueError):
    """Raised when DNS collection cannot be completed safely."""


class DNSRecordProvider:
    RECORD_TYPES = (
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
    )

    def __init__(
        self,
        resolver: dns.resolver.Resolver | None = None,
    ):
        self.resolver = resolver or dns.resolver.Resolver()

    def collect(
        self,
        *,
        hostname: str,
        timeout_seconds: int,
        cancel_event: Event,
    ) -> list[DNSRecordData]:

        if timeout_seconds <= 0:
            raise ValueError("Timeout must be greater than zero")

        try:
            normalized = normalize_hostname(hostname)
        except (ScopeValidationError, ValueError) as exc:
            raise DNSProviderError("Invalid DNS hostname") from exc

        deadline = time.monotonic() + timeout_seconds
        records: list[DNSRecordData] = []
        seen: set[tuple[str, str, str]] = set()

        for record_type in self.RECORD_TYPES:
            if cancel_event.is_set():
                raise AgentExecutionCancelled(
                    "DNS enumeration was cancelled."
                )

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise DNSProviderError(
                    "DNS enumeration exceeded its timeout."
                )

            try:
                answer = self.resolver.resolve(
                    normalized,
                    record_type,
                    lifetime=remaining,
                    search=False,
                    raise_on_no_answer=False,
                )

            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
            ):
                continue

            except dns.exception.Timeout as exc:
                raise DNSProviderError(
                    f"DNS query timed out for {record_type}."
                ) from exc

            except dns.resolver.NoNameservers as exc:
                raise DNSProviderError(
                    f"No usable DNS nameserver for {record_type}."
                ) from exc

            if cancel_event.is_set():
                raise AgentExecutionCancelled(
                    "DNS enumeration was cancelled."
                )

            rrset = answer.rrset

            if rrset is None:
                continue

            ttl = int(rrset.ttl)

            for item in rrset:
                priority = None

                if record_type in ("A", "AAAA"):
                    value = item.address

                    try:
                        validate_destination_ip(
                            ipaddress.ip_address(value)
                        )
                    except (ScopeValidationError, ValueError) as exc:
                        raise DNSProviderError(
                            "DNS returned an IP prohibited by policy."
                        ) from exc

                elif record_type == "MX":
                    priority = int(item.preference)
                    value = item.exchange.to_text().rstrip(".")

                elif record_type == "SOA":
                    value = item.to_text()

                elif record_type in ("CNAME", "NS"):
                    value = item.target.to_text().rstrip(".")

                elif record_type == "TXT":
                    value = item.to_text()

                else:
                    continue

                key = (record_type, value, normalized)

                if key in seen:
                    continue

                seen.add(key)

                records.append(
                    DNSRecordData(
                        record_name=normalized,
                        record_type=record_type,
                        value=value,
                        ttl=ttl,
                        priority=priority,
                    )
                )

        if cancel_event.is_set():
            raise AgentExecutionCancelled(
                "DNS enumeration was cancelled."
            )

        return records