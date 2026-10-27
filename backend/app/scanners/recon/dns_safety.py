"""DNS resolution safety checks for PENTURION.

This module resolves hostnames and validates the returned IP addresses
before a scanner considers connecting to a destination.

IMPORTANT:
- This module does not make HTTP requests.
- DNS preflight validation alone does not prevent DNS rebinding.
- A future HTTP transport must connect to a validated IP address
  while preserving the original hostname for TLS and HTTP validation.
"""

import ipaddress
import socket
from dataclasses import dataclass

from app.scanners.scope import (
    ScopeValidationError,
    is_prohibited_ip,
    normalize_hostname,
)


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class DNSResolutionError(ValueError):
    """Raised when DNS resolution or destination validation fails."""


@dataclass(frozen=True)
class ResolvedDestination:
    """A hostname and its validated destination IP addresses."""

    hostname: str
    addresses: tuple[IPAddress, ...]


def _validate_ip(address: str | IPAddress) -> IPAddress:
    """Parse an IP address and reject prohibited destinations."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise DNSResolutionError(
            "DNS returned an invalid IP address"
        ) from exc

    if is_prohibited_ip(ip):
        raise DNSResolutionError(
            "Destination IP is prohibited by policy"
        )

    return ip


def resolve_public_destination(
    hostname: str,
) -> ResolvedDestination:
    """Resolve a hostname and validate every returned IP address.

    If DNS returns a mixture of public and prohibited IP addresses,
    the entire resolution is rejected.

    Args:
        hostname: A hostname or IP literal to validate.

    Returns:
        A ResolvedDestination containing the normalized hostname and
        validated, unique IP addresses.

    Raises:
        DNSResolutionError: If the hostname is invalid, resolution
            fails, no addresses are returned, or any address is
            prohibited by policy.
    """
    try:
        normalized_hostname = normalize_hostname(hostname)
    except ScopeValidationError as exc:
        raise DNSResolutionError(
            "Invalid destination hostname"
        ) from exc

    # IP literals can be validated directly without DNS.
    try:
        literal_ip = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        validated_ip = _validate_ip(literal_ip)

        return ResolvedDestination(
            hostname=normalized_hostname,
            addresses=(validated_ip,),
        )

    # Resolve both IPv4 and IPv6 records.
    try:
        results = socket.getaddrinfo(
            normalized_hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise DNSResolutionError(
            "DNS resolution failed"
        ) from exc
    except OSError as exc:
        raise DNSResolutionError(
            "DNS lookup encountered a system error"
        ) from exc

    if not results:
        raise DNSResolutionError(
            "DNS returned no usable addresses"
        )

    validated_addresses: set[IPAddress] = set()

    for result in results:
        try:
            sockaddr = result[4]
            raw_address = sockaddr[0]
        except (IndexError, TypeError) as exc:
            raise DNSResolutionError(
                "DNS returned an invalid address record"
            ) from exc

        # Reject the entire response if even one address is prohibited.
        validated_ip = _validate_ip(raw_address)
        validated_addresses.add(validated_ip)

    if not validated_addresses:
        raise DNSResolutionError(
            "DNS returned no usable addresses"
        )

    # Sorting makes the result deterministic for tests and callers.
    ordered_addresses = tuple(
        sorted(
            validated_addresses,
            key=lambda address: (
                address.version,
                int(address),
            ),
        )
    )

    return ResolvedDestination(
        hostname=normalized_hostname,
        addresses=ordered_addresses,
    )