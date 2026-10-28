
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import Mock

import httpx
import app.scanners.transport.pinned_http as pinned_http

from app.scanners.recon.dns_safety import ResolvedDestination
from app.scanners.transport.pinned_http import create_pinned_client


class LocalHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return

        body = f"served:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHTTPHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def patch_test_dns(monkeypatch, port):
    resolver = Mock(
        return_value=ResolvedDestination(
            hostname="penturion-test.invalid",
            addresses=("127.0.0.1",),
        )
    )
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        resolver,
    )
    return resolver


def allow_loopback_for_test_only(monkeypatch):
    """Allow the local test server without changing production policy."""
    monkeypatch.setattr(
        pinned_http,
        "is_prohibited_ip",
        lambda address: False,
    )


def test_httpx_request_uses_pinned_backend(monkeypatch):
    server = start_server()
    resolver = patch_test_dns(monkeypatch, server.server_port)
    allow_loopback_for_test_only(monkeypatch)

    try:
        with create_pinned_client() as client:
            response = client.get(
                f"http://penturion-test.invalid:{server.server_port}/hello"
            )

        assert response.status_code == 200
        assert response.text == "served:/hello"
        resolver.assert_called_once_with("penturion-test.invalid")
    finally:
        server.shutdown()
        server.server_close()


def test_httpx_client_does_not_follow_redirects(monkeypatch):
    server = start_server()
    patch_test_dns(monkeypatch, server.server_port)
    allow_loopback_for_test_only(monkeypatch)

    try:
        with create_pinned_client() as client:
            response = client.get(
                f"http://penturion-test.invalid:{server.server_port}/redirect"
            )

        assert response.status_code == 302
        assert response.headers["location"] == "/final"
    finally:
        server.shutdown()
        server.server_close()


def test_request_fails_closed_when_dns_validation_fails(monkeypatch):
    server = start_server()
    resolver = Mock(side_effect=pinned_http.DNSResolutionError("blocked"))
    monkeypatch.setattr(
        pinned_http,
        "resolve_public_destination",
        resolver,
    )

    try:
        with create_pinned_client() as client:
            try:
                client.get(
                    f"http://penturion-test.invalid:{server.server_port}/hello"
                )
            except httpx.RequestError:
                pass
            else:
                raise AssertionError("Request unexpectedly succeeded")

        resolver.assert_called_once_with("penturion-test.invalid")
    finally:
        server.shutdown()
        server.server_close()
