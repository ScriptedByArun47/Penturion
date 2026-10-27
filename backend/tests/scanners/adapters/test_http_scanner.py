"""Tests for PENTURION's HTTP scanner."""

import httpx
import pytest

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
