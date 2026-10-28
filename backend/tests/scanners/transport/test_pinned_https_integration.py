import ipaddress
import socket
import ssl
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import Mock

import httpx
import pytest

import app.scanners.transport.pinned_http as pinned_http
from app.scanners.recon.dns_safety import ResolvedDestination


TEST_HOST = "penturion-test.invalid"


class HTTPSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"secure-test-response"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def create_test_certificate(directory: Path):
    cert_path = directory / "server.crt"
    key_path = directory / "server.key"

    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "1",
            "-nodes",
            "-subj", f"/CN={TEST_HOST}",
            "-addext", f"subjectAltName=DNS:{TEST_HOST}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    return cert_path, key_path


def start_https_server(cert_path: Path, key_path: Path, sni_names: list[str]):
    server = ThreadingHTTPServer(("127.0.0.1", 0), HTTPSHandler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    context.set_servername_callback(
        lambda sock, server_name, ctx: sni_names.append(server_name)
    )

    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def configure_local_test_destination(monkeypatch):
    resolver = Mock(
        return_value=ResolvedDestination(
            hostname=TEST_HOST,
            addresses=("127.0.0.1",),
        )
    )
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        resolver,
    )

    # Test-only exception for the isolated local HTTPS server.
    monkeypatch.setattr(
        pinned_http,
        "is_prohibited_ip",
        lambda address: False,
    )

    return resolver


def test_https_accepts_certificate_when_explicitly_trusted(monkeypatch):
    with TemporaryDirectory() as temp_dir:
        cert_path, key_path = create_test_certificate(Path(temp_dir))
        sni_names = []
        server = start_https_server(cert_path, key_path, sni_names)
        resolver = configure_local_test_destination(monkeypatch)

        try:
            tls_context = ssl.create_default_context(cafile=str(cert_path))
            transport = pinned_http.PinnedHTTPTransport(verify=tls_context)
            with httpx.Client(
                transport=transport,
                follow_redirects=False,
                trust_env=False,
                timeout=5.0,
            ) as client:
                response = client.get(
                    f"https://{TEST_HOST}:{server.server_port}/secure"
                )

            assert response.status_code == 200
            assert response.text == "secure-test-response"
            assert TEST_HOST in sni_names
            assert "127.0.0.1" not in sni_names
            resolver.assert_called_once_with(TEST_HOST)
        finally:
            server.shutdown()
            server.server_close()


def test_https_rejects_untrusted_certificate(monkeypatch):
    with TemporaryDirectory() as temp_dir:
        cert_path, key_path = create_test_certificate(Path(temp_dir))
        server = start_https_server(cert_path, key_path, [])
        configure_local_test_destination(monkeypatch)

        try:
            with pinned_http.create_pinned_client() as client:
                with pytest.raises(httpx.ConnectError):
                    client.get(
                        f"https://{TEST_HOST}:{server.server_port}/secure"
                    )
        finally:
            server.shutdown()
            server.server_close()


def test_backend_rejects_prohibited_ip_even_if_resolver_returns_it(monkeypatch):
    resolver = Mock(
        return_value=ResolvedDestination(
            hostname=TEST_HOST,
            addresses=("127.0.0.1",),
        )
    )
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        resolver,
    )

    # Keep the real prohibited-IP check active in this test.
    backend = pinned_http.PinnedNetworkBackend()
    connect_mock = Mock()
    monkeypatch.setattr(backend._socket_backend, "connect_tcp", connect_mock)

    with pytest.raises(Exception, match="prohibited IP"):
        backend.connect_tcp(TEST_HOST, 443, timeout=1.0)

    connect_mock.assert_not_called()


def test_backend_rejects_empty_resolver_results(monkeypatch):
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(
            return_value=ResolvedDestination(
                hostname=TEST_HOST,
                addresses=(),
            )
        ),
    )

    backend = pinned_http.PinnedNetworkBackend()
    connect_mock = Mock()
    monkeypatch.setattr(backend._socket_backend, "connect_tcp", connect_mock)

    with pytest.raises(Exception, match="no IP addresses"):
        backend.connect_tcp(TEST_HOST, 443, timeout=1.0)

    connect_mock.assert_not_called()


def test_backend_rejects_malformed_resolver_ip(monkeypatch):
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        Mock(
            return_value=ResolvedDestination(
                hostname=TEST_HOST,
                addresses=("not-an-ip-address",),
            )
        ),
    )

    backend = pinned_http.PinnedNetworkBackend()
    connect_mock = Mock()
    monkeypatch.setattr(backend._socket_backend, "connect_tcp", connect_mock)

    with pytest.raises(Exception, match="invalid IP"):
        backend.connect_tcp(TEST_HOST, 443, timeout=1.0)

    connect_mock.assert_not_called()
