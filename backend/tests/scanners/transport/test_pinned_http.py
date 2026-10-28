import ipaddress
from unittest.mock import Mock

import httpcore
import httpx
import pytest

from app.scanners.recon.dns_safety import (
    DNSResolutionError,
    ResolvedDestination,
)
from app.scanners.transport import pinned_http
from app.scanners.transport.pinned_http import (
    PinnedHTTPTransport,
    PinnedNetworkBackend,
    create_pinned_client,
)


def make_destination(hostname, *addresses):
    return ResolvedDestination(
        hostname=hostname,
        addresses=tuple(ipaddress.ip_address(ip) for ip in addresses),
    )


def test_backend_connects_to_validated_ip_not_hostname(monkeypatch):
    backend = PinnedNetworkBackend()
    fake_stream = object()
    fake_socket_backend = Mock()
    fake_socket_backend.connect_tcp.return_value = fake_stream
    backend._socket_backend = fake_socket_backend

    resolver = Mock(
        return_value=make_destination(
            "example.com",
            "93.184.216.34",
        )
    )
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        resolver,
    )

    result = backend.connect_tcp("example.com", 443, timeout=2.0)

    assert result is fake_stream
    resolver.assert_called_once_with("example.com")

    kwargs = fake_socket_backend.connect_tcp.call_args.kwargs
    assert kwargs["host"] == "93.184.216.34"
    assert kwargs["port"] == 443
    assert kwargs["timeout"] == 2.0


def test_backend_rejects_destination_when_dns_validation_fails(monkeypatch):
    backend = PinnedNetworkBackend()
    fake_socket_backend = Mock()
    backend._socket_backend = fake_socket_backend

    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(side_effect=DNSResolutionError("blocked")),
    )

    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("example.com", 443)

    fake_socket_backend.connect_tcp.assert_not_called()


def test_backend_rejects_invalid_destination(monkeypatch):
    backend = PinnedNetworkBackend()
    fake_socket_backend = Mock()
    backend._socket_backend = fake_socket_backend

    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(side_effect=ValueError("invalid host")),
    )

    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("invalid host", 443)

    fake_socket_backend.connect_tcp.assert_not_called()


def test_backend_tries_next_validated_ip_after_connection_error(monkeypatch):
    backend = PinnedNetworkBackend()
    fake_stream = object()
    fake_socket_backend = Mock()
    fake_socket_backend.connect_tcp.side_effect = [
        httpcore.ConnectError("first IP unavailable"),
        fake_stream,
    ]
    backend._socket_backend = fake_socket_backend

    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(
            return_value=make_destination(
                "example.com",
                "93.184.216.34",
                "93.184.216.35",
            )
        ),
    )

    result = backend.connect_tcp("example.com", 443)

    assert result is fake_stream
    attempted_ips = [
        call.kwargs["host"]
        for call in fake_socket_backend.connect_tcp.call_args_list
    ]
    assert attempted_ips == [
        "93.184.216.34",
        "93.184.216.35",
    ]


def test_backend_fails_when_all_validated_ips_are_unreachable(monkeypatch):
    backend = PinnedNetworkBackend()
    fake_socket_backend = Mock(
        spec=["connect_tcp"],
    )
    fake_socket_backend.connect_tcp.side_effect = httpcore.ConnectError(
        "unreachable"
    )
    backend._socket_backend = fake_socket_backend

    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(
            return_value=make_destination(
                "example.com",
                "93.184.216.34",
            )
        ),
    )

    with pytest.raises(httpcore.ConnectError):
        backend.connect_tcp("example.com", 443)


def test_backend_preserves_connection_timeout_error(monkeypatch):
    backend = PinnedNetworkBackend()
    fake_socket_backend = Mock()
    fake_socket_backend.connect_tcp.side_effect = httpcore.ConnectTimeout(
        "timed out"
    )
    backend._socket_backend = fake_socket_backend

    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(
            return_value=make_destination(
                "example.com",
                "93.184.216.34",
            )
        ),
    )

    with pytest.raises(httpcore.ConnectTimeout):
        backend.connect_tcp("example.com", 443)


def test_backend_does_not_support_unix_sockets():
    backend = PinnedNetworkBackend()

    with pytest.raises(httpcore.ConnectError):
        backend.connect_unix_socket("/tmp/test.sock")


def test_transport_rejects_proxy():
    proxy = httpx.Proxy("http://127.0.0.1:8080")

    with pytest.raises(ValueError, match="does not support proxies"):
        PinnedHTTPTransport(proxy=proxy)


def test_transport_requires_trust_env_disabled():
    with pytest.raises(ValueError, match="trust_env=False"):
        PinnedHTTPTransport(trust_env=True)


def test_transport_rejects_http2():
    with pytest.raises(ValueError, match="HTTP/1.1 only"):
        PinnedHTTPTransport(http2=True)


def test_client_disables_redirects_and_environment_proxies():
    client = create_pinned_client()

    try:
        assert client.follow_redirects is False
        assert client.trust_env is False
        assert isinstance(client._transport, PinnedHTTPTransport)

        pool = client._transport._pool
        assert pool._proxy is None
        assert pool._max_keepalive_connections == 0
        assert pool._retries == 0
        assert isinstance(
            pool._network_backend,
            PinnedNetworkBackend,
        )
    finally:
        client.close()


def test_client_rejects_nonpositive_timeout():
    with pytest.raises(ValueError, match="timeout must be greater than zero"):
        create_pinned_client(timeout=0)
