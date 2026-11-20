"""Tests for PENTURION's HTTP scanner."""

import httpx
import pytest
import threading

from app.scanners.adapters.http_scanner import HTTPScanner


def mock_response(
    status_code=200,
    headers=None,
):
    request = httpx.Request(
        "GET",
        "https://example.test",
    )

    return httpx.Response(
        status_code=status_code,
        headers=headers or {},
        request=request,
    )


def test_scanner_detects_missing_security_headers():
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: mock_response()
        )
    )

    try:
        scanner = HTTPScanner(client=client)
        result = scanner.execute("https://example.test")

        assert result.success is True
        assert result.scanner_name == "http"
        assert len(result.findings) == 3

        titles = {
            finding.title for finding in result.findings
        }

        assert "Missing Content-Security-Policy header" in titles
        assert "Missing X-Content-Type-Options header" in titles
        assert "Missing Strict-Transport-Security header" in titles

    finally:
        client.close()


def test_scanner_accepts_present_security_headers():
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
    }

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: mock_response(headers=headers)
        )
    )

    try:
        scanner = HTTPScanner(client=client)
        result = scanner.execute("https://example.test")

        assert result.success is True
        assert result.findings == ()

    finally:
        client.close()


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.test",
        "javascript:alert(1)",
        "https://user:password@example.test",
        "",
        "https://example.test/#fragment",
    ],
)
def test_scanner_rejects_invalid_urls(target):
    scanner = HTTPScanner()

    result = scanner.execute(target)

    assert result.success is False
    assert result.error is not None
    assert result.findings == ()


def test_scanner_handles_timeout():
    def timeout_handler(request):
        raise httpx.ReadTimeout(
            "Simulated timeout",
            request=request,
        )

    client = httpx.Client(
        transport=httpx.MockTransport(timeout_handler)
    )

    try:
        scanner = HTTPScanner(client=client)
        result = scanner.execute("https://example.test")

        assert result.success is False
        assert result.error == "HTTP request timed out"

    finally:
        client.close()



def test_scanner_does_not_follow_redirects():
    requested_urls = []

    def redirect_handler(request):
        requested_urls.append(str(request.url))

        return httpx.Response(
            302,
            headers={
                "Location": "https://other.example.test"
            },
            request=request,
        )

    client = httpx.Client(
        transport=httpx.MockTransport(redirect_handler),
        follow_redirects=False,
    )

    try:
        scanner = HTTPScanner(client=client)
        result = scanner.execute("https://example.test")

        assert result.success is True

        # The scanner made exactly one request.
        assert len(requested_urls) == 1
        assert requested_urls[0] == "https://example.test"

        # The redirect destination was not requested.
        assert "https://other.example.test" not in requested_urls

        # Missing headers on the 302 response may still be reported.
        assert len(result.findings) == 3

    finally:
        client.close()

def test_scanner_uses_pinned_client_by_default(monkeypatch):
    from app.scanners.adapters import http_scanner
    from app.scanners.transport.pinned_http import PinnedHTTPTransport

    created_clients = []

    def tracked_factory(*, timeout):
        client = httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={"content-security-policy": "default-src 'self'"},
                )
            ),
            timeout=timeout,
        )
        created_clients.append(client)
        return client

    monkeypatch.setattr(
        http_scanner,
        "create_pinned_client",
        tracked_factory,
    )

    scanner = HTTPScanner()
    result = scanner.execute("https://example.test")

    assert len(created_clients) == 1
    assert result.success is True
    assert len(result.findings) == 2

    created_clients[0].close()

def test_scanner_stops_before_request_when_cancelled():
    cancel_event = threading.Event()
    cancel_event.set()

    request_count = 0

    def request_handler(request):
        nonlocal request_count
        request_count += 1
        return mock_response()

    client = httpx.Client(
        transport=httpx.MockTransport(request_handler)
    )

    try:
        scanner = HTTPScanner(
            client=client,
            cancel_event=cancel_event,
        )

        result = scanner.execute("https://example.test")

        assert result.success is False
        assert result.error == "Scan cancelled"
        assert request_count == 0

    finally:
        client.close()

def test_scanner_detects_cancellation_after_request():
    cancel_event = threading.Event()

    def request_handler(request):
        cancel_event.set()
        return mock_response()

    client = httpx.Client(
        transport=httpx.MockTransport(request_handler)
    )

    try:
        scanner = HTTPScanner(
            client=client,
            cancel_event=cancel_event,
        )

        result = scanner.execute("https://example.test")

        assert result.success is False
        assert result.error == "Scan cancelled"
        assert result.findings == ()

    finally:
        client.close()
        
import threading


def test_scanner_cancels_during_streaming():
    cancel_event = threading.Event()

    class TrackingStream(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            cancel_event.set()
            yield b"A" * 8192

        def close(self):
            self.closed = True

    stream = TrackingStream()

    def handler(request):
        return httpx.Response(
            200,
            stream=stream,
            request=request,
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler)
    )

    try:
        scanner = HTTPScanner(
            client=client,
            cancel_event=cancel_event,
        )

        result = scanner.execute("https://example.test")

        assert result.success is False
        assert result.error == "Scan cancelled"
        assert stream.closed is True

    finally:
        client.close()

def test_scanner_limits_response_body_reading():
    class TrackingStream(httpx.SyncByteStream):
        def __init__(self):
            self.chunks_yielded = 0
            self.closed = False

        def __iter__(self):
            for _ in range(256):
                self.chunks_yielded += 1
                yield b"A" * 8192

        def close(self):
            self.closed = True

    stream = TrackingStream()

    def handler(request):
        return httpx.Response(
            200,
            stream=stream,
            request=request,
        )

    client = httpx.Client(
        transport=httpx.MockTransport(handler)
    )

    try:
        scanner = HTTPScanner(client=client)
        result = scanner.execute("https://example.test")

        assert result.success is True
        assert stream.chunks_yielded == 128
        assert stream.closed is True

    finally:
        client.close()