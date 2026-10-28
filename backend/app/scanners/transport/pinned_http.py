"""DNS-pinned synchronous HTTP transport for PENTURION.

Security properties:
- Resolves and validates the destination before each new TCP connection.
- Connects directly to a validated IP literal, avoiding a second DNS lookup.
- Preserves the original hostname for HTTP Host and TLS certificate/SNI checks.
- Disables connection pooling reuse and automatic retries.
- Does not support proxies or Unix-domain sockets.

This transport does not establish authorization or target scope. Callers must
validate authorization and scope separately before issuing HTTP requests.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

import httpcore
import httpx
from httpcore._backends.base import NetworkBackend, NetworkStream, SOCKET_OPTION
from httpcore._backends.sync import SyncBackend
from httpcore._exceptions import ConnectError, ConnectTimeout


from app.scanners.recon.dns_safety import (
    DNSResolutionError,
    resolve_public_destination,
)
from app.scanners.scope import (
    ScopeValidationError,
    is_prohibited_ip,
    normalize_hostname,
)


class PinnedNetworkBackend(NetworkBackend):
    """Connect to validated IPs without resolving the hostname a second time."""

    def __init__(self) -> None:
        self._socket_backend = SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        # HTTPCore supplies the original hostname here. Resolution is performed
        # by our safety module; the socket backend receives only IP literals.
        normalized_host = host.strip()

        if normalized_host.startswith("[") and normalized_host.endswith("]"):
            normalized_host = normalized_host[1:-1]

        try:
            requested_hostname = normalize_hostname(normalized_host)
            destination = resolve_public_destination(requested_hostname)

            resolved_hostname = normalize_hostname(destination.hostname)

            if resolved_hostname != requested_hostname:
                raise ConnectError(
                    "Destination resolver returned a mismatched hostname"
                )

        except ConnectError:
            raise
        except (DNSResolutionError, ScopeValidationError, ValueError) as exc:
            raise ConnectError(
                "Destination failed DNS safety validation"
            ) from exc

        # Reject empty or malformed resolver results before opening a socket.
        if not destination.addresses:
            raise ConnectError("Destination resolver returned no IP addresses")

        validated_addresses = []

        for address in destination.addresses:
            try:
                validated_ip = ipaddress.ip_address(str(address))
            except ValueError as exc:
                raise ConnectError(
                    "Destination resolver returned an invalid IP"
                ) from exc

            # Defense in depth: never trust resolver output without checking
            # the destination policy again at the connection boundary.
            if is_prohibited_ip(validated_ip):
                raise ConnectError(
                    "Destination resolver returned a prohibited IP address"
                )

            validated_addresses.append(validated_ip)

        last_error: Exception | None = None

        for validated_ip in validated_addresses:
            try:
                return self._socket_backend.connect_tcp(
                    host=str(validated_ip),
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except ConnectTimeout as exc:
                last_error = exc
            except ConnectError as exc:
                last_error = exc

        if isinstance(last_error, ConnectTimeout):
            raise ConnectTimeout(
                "Connection to validated destination timed out"
            ) from last_error

        raise ConnectError(
            "Could not connect to any validated destination address"
        ) from last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        # This transport is for TCP HTTP(S) destinations only.
        raise ConnectError("Unix-domain sockets are not supported")


class PinnedHTTPTransport(httpx.HTTPTransport):
    """HTTPX transport using DNS-pinned connections and verified TLS."""

    def __init__(
        self,
        *,
        verify: bool = True,
        cert: str | tuple[str, str] | None = None,
        trust_env: bool = False,
        proxy: httpx.Proxy | None = None,
        limits: httpx.Limits | None = None,
        **kwargs: object,
    ) -> None:
        if proxy is not None:
            raise ValueError("PinnedHTTPTransport does not support proxies")

        if trust_env:
            raise ValueError(
                "PinnedHTTPTransport requires trust_env=False"
            )

        if kwargs.get("http2", False):
            raise ValueError(
                "PinnedHTTPTransport currently supports HTTP/1.1 only"
            )

        # Start with HTTPX's standard SSL configuration and transport setup.
        super().__init__(
            verify=verify,
            cert=cert,
            trust_env=False,
            proxy=None,
            limits=limits
            or httpx.Limits(
                max_connections=10,
                max_keepalive_connections=0,
            ),
            http1=True,
            http2=False,
            **kwargs,
        )

        # Preserve the SSL context created by HTTPX so normal certificate
        # verification and hostname validation remain enabled.
        ssl_context = self._pool._ssl_context

        # Replace the standard pool with one using our pinned backend.
        self._pool.close()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            proxy=None,
            max_connections=10,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(),
        )


def create_pinned_client(
    *,
    timeout: float = 5.0,
) -> httpx.Client:
    """Create a client that does not follow redirects or trust proxy env vars."""

    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    return httpx.Client(
        transport=PinnedHTTPTransport(),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )
