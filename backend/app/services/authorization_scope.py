"""Validation of machine-readable authorization scopes."""

import ipaddress
import json
from urllib.parse import urlsplit

from app.scanners.scope import (
    ScopeValidationError,
    host_matches_domain,
    normalize_hostname,
    validate_target_in_scope,
)


class AuthorizationScopeError(ValueError):
    """Raised when requested authorization scope is invalid."""


def validate_authorization_scope(
    requested_scope: str,
    target_value: str,
    target_type: str,
) -> str:
    """Validate scope against a registered target and return canonical JSON."""

    try:
        entries = json.loads(requested_scope)
    except (json.JSONDecodeError, TypeError) as exc:
        raise AuthorizationScopeError(
            "Scope must be a JSON array of strings"
        ) from exc

    if not isinstance(entries, list) or not entries:
        raise AuthorizationScopeError(
            "Scope must be a non-empty JSON array"
        )

    if any(not isinstance(entry, str) or not entry.strip() for entry in entries):
        raise AuthorizationScopeError(
            "Every scope entry must be a non-empty string"
        )

    entries = [entry.strip() for entry in entries]

    if len(set(entries)) != len(entries):
        raise AuthorizationScopeError(
            "Duplicate scope entries are not allowed"
        )

    normalized = []

    try:
        for entry in entries:
            if target_type == "domain":
                hostname = normalize_hostname(entry)

                try:
                    ipaddress.ip_address(hostname)
                except ValueError:
                    pass
                else:
                    raise AuthorizationScopeError(
                        "IP addresses cannot be used in a domain scope"
                    )

                if not host_matches_domain(hostname, target_value):
                    raise AuthorizationScopeError(
                        "Scope domain is outside the registered target"
                    )

                normalized.append(hostname)

            elif target_type == "ip":
                requested_ip = ipaddress.ip_address(entry)
                registered_ip = ipaddress.ip_address(target_value)

                if requested_ip != registered_ip:
                    raise AuthorizationScopeError(
                        "Scope IP must match the registered target"
                    )

                normalized.append(str(requested_ip))

            elif target_type == "url":
                validate_target_in_scope(
                    entry,
                    target_value,
                    "url",
                )

                parsed = urlsplit(entry)
                hostname = normalize_hostname(parsed.hostname or "")
                host_display = (
                    f"[{hostname}]"
                    if ":" in hostname
                    else hostname
                )
                port = f":{parsed.port}" if parsed.port is not None else ""
                path = parsed.path or "/"
                query = f"?{parsed.query}" if parsed.query else ""

                normalized.append(
                    f"{parsed.scheme.lower()}://{host_display}{port}"
                    f"{path}{query}"
                )

            else:
                raise AuthorizationScopeError(
                    "Unsupported registered target type"
                )

    except ScopeValidationError as exc:
        raise AuthorizationScopeError(str(exc)) from exc
    except ValueError as exc:
        if isinstance(exc, AuthorizationScopeError):
            raise
        raise AuthorizationScopeError(
            "Invalid scope entry"
        ) from exc

    return json.dumps(normalized, separators=(",", ":"))
