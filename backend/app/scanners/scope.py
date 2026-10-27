"""Scope and destination validation for PENTURION.

These checks do not perform network requests and do not replace
connection-time IP validation or explicit authorization approval.
"""

import ipaddress
from urllib.parse import urlsplit


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeValidationError(ValueError):
    """Raised when a target violates scope or destination policy."""


def _parse_ip(value: str) -> IPAddress | None:
    """Return an IP address if value is a valid IP literal."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _parse_url(value: str):
    """Parse an HTTP(S) URL and validate its basic structure."""
    if not value or value != value.strip():
        raise ScopeValidationError("URL must not be empty or padded")

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ScopeValidationError("Invalid URL") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ScopeValidationError("Only HTTP and HTTPS are allowed")

    if not hostname:
        raise ScopeValidationError("URL must contain a hostname")

    if parsed.username is not None or parsed.password is not None:
        raise ScopeValidationError("Credentials in URLs are not allowed")

    if parsed.fragment:
        raise ScopeValidationError("URL fragments are not allowed")

    if any(character.isspace() for character in value):
        raise ScopeValidationError("Whitespace in URLs is not allowed")

    return parsed


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname for comparisons."""
    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise ScopeValidationError("Hostname cannot be empty")

    # IP literals are handled separately.
    if _parse_ip(hostname) is not None:
        return hostname

    try:
        normalized = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeValidationError("Invalid hostname") from exc

    if len(normalized) > 253:
        raise ScopeValidationError("Hostname is too long")

    labels = normalized.split(".")

    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(
            character.isalnum() or character == "-"
            for character in label
        )
        for label in labels
    ):
        raise ScopeValidationError("Invalid hostname")

    return normalized


def host_matches_domain(hostname: str, authorized_domain: str) -> bool:
    """Match a domain and its subdomains without suffix confusion."""
    hostname = normalize_hostname(hostname)
    authorized_domain = normalize_hostname(authorized_domain)

    if _parse_ip(hostname) is not None:
        return False

    if _parse_ip(authorized_domain) is not None:
        return False

    return (
        hostname == authorized_domain
        or hostname.endswith("." + authorized_domain)
    )


def is_prohibited_ip(address: str | IPAddress) -> bool:
    """Identify IPs prohibited by PENTURION's public-target policy."""
    try:
        ip = (
            ipaddress.ip_address(address)
            if isinstance(address, str)
            else address
        )
    except ValueError as exc:
        raise ScopeValidationError("Invalid IP address") from exc

    # IPv4-mapped IPv6 addresses must be checked as IPv4 too.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_prohibited_ip(ip.ipv4_mapped)

    # Explicitly reject special-purpose destination categories.
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        return True

    return False


def validate_destination_ip(address: str | IPAddress) -> IPAddress:
    """Validate an IP address under the public-target policy."""
    try:
        ip = (
            ipaddress.ip_address(address)
            if isinstance(address, str)
            else address
        )
    except ValueError as exc:
        raise ScopeValidationError("Invalid destination IP") from exc

    if is_prohibited_ip(ip):
        raise ScopeValidationError(
            "Private, local, reserved, or otherwise non-global IPs are prohibited"
        )

    return ip


def validate_target_in_scope(
    target_url: str,
    authorized_value: str,
    target_type: str,
) -> str:
    """Verify that a URL matches the explicitly authorized target.

    Domain targets include the apex domain and its subdomains.
    IP targets require an exact IP match.
    URL targets require an exact scheme, hostname, port, and path match.
    Query strings may vary; URL fragments are prohibited.
    """
    if target_type not in {"domain", "ip", "url"}:
        raise ScopeValidationError("Unsupported target type")

    target = _parse_url(target_url)
    target_host = normalize_hostname(target.hostname or "")

    if target_type == "domain":
        authorized_domain = normalize_hostname(authorized_value)

        if not host_matches_domain(target_host, authorized_domain):
            raise ScopeValidationError(
                "Target hostname is outside the authorized domain"
            )

    elif target_type == "ip":
        authorized_ip = _parse_ip(authorized_value)

        if authorized_ip is None:
            raise ScopeValidationError(
                "Authorized IP target is not a valid IP address"
            )

        target_ip = _parse_ip(target_host)

        if target_ip != authorized_ip:
            raise ScopeValidationError(
                "Target IP does not match the authorized IP"
            )

    else:
        authorized_url = _parse_url(authorized_value)
        authorized_host = normalize_hostname(
            authorized_url.hostname or ""
        )

        if (
            target.scheme.lower() != authorized_url.scheme.lower()
            or target_host != authorized_host
            or target.port != authorized_url.port
            or (target.path or "/") != (authorized_url.path or "/")
        ):
            raise ScopeValidationError(
                "Target URL is outside the authorized URL scope"
            )

    # Reject unsafe IP literals immediately.
    # Domain DNS resolution and connection-time checks are separate.
    target_ip = _parse_ip(target_host)

    if target_ip is not None:
        validate_destination_ip(target_ip)

    return target_url