
"""Low-impact HTTP checks for PENTURION."""

from urllib.parse import urlsplit

import httpx

import threading

from app.scanners.base import ScanFinding, ScannerResult

from app.scanners.transport.pinned_http import create_pinned_client


SECURITY_HEADERS = {
    "content-security-policy": (
        "Missing Content-Security-Policy header",
        "A Content Security Policy can help restrict the sources "
        "from which a browser loads resources.",
    ),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header",
        "The nosniff directive helps prevent browsers from "
        "interpreting content as a different media type.",
    ),
    "strict-transport-security": (
        "Missing Strict-Transport-Security header",
        "For HTTPS websites, HSTS can instruct browsers to use "
        "HTTPS for subsequent requests.",
    ),
}


class HTTPScanner:
    """Perform basic, non-intrusive HTTP checks.

    This scanner is not connected to the worker yet.
    Only use it against explicitly authorized targets.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        self.timeout = timeout
        self.client = client
        self.cancel_event = cancel_event

    def _is_cancelled(self) -> bool:
        """Check whether scanner execution has been cancelled."""
        return (
            self.cancel_event is not None
            and self.cancel_event.is_set()
        )
    @staticmethod
    def validate_url(target: str) -> str:
        """Validate basic URL syntax and permitted schemes."""

        if not target or target != target.strip():
            raise ValueError("Target URL must not be empty or padded")

        try:
            parsed = urlsplit(target)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid target URL") from exc

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        if not hostname:
            raise ValueError("Target URL must include a hostname")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials in target URLs are not allowed")

        if parsed.fragment:
            raise ValueError("URL fragments are not supported")

        return target

    def execute(self, target: str) -> ScannerResult:
        """Check response status and selected security headers."""

        try:
            validated_target = self.validate_url(target)
        except ValueError as exc:
            return ScannerResult(
                scanner_name="http",
                target=target,
                success=False,
                error=str(exc),
            )

        owns_client = self.client is None

        client = self.client or create_pinned_client(
             timeout=self.timeout,
            )

        try:
            if self._is_cancelled():
                return ScannerResult(
                    scanner_name="http",
                    target=validated_target,
                    success=False,
                    error="Scan cancelled",
                )
                
            with client.stream("GET", validated_target) as response:
                body_size = 0
                max_body_size = 1024 * 1024

                for chunk in response.iter_bytes(chunk_size=8192):
                    if self._is_cancelled():
                        return ScannerResult(
                            scanner_name="http",
                            target=validated_target,
                            success=False,
                            error="Scan cancelled",
                        )

                    body_size += len(chunk)

                    if body_size >= max_body_size:
                        break

                if self._is_cancelled():
                    return ScannerResult(
                        scanner_name="http",
                        target=validated_target,
                        success=False,
                        error="Scan cancelled",
                    )

            findings = []

            for header, (title, description) in SECURITY_HEADERS.items():
                if header not in response.headers:
                    findings.append(
                        ScanFinding(
                            title=title,
                            severity="low",
                            description=description,
                            evidence={
                                "missing_header": header,
                                "http_status": response.status_code,
                            },
                            remediation=(
                                f"Review whether the {header} header "
                                "should be configured for this application."
                            ),
                        )
                    )

            return ScannerResult(
                scanner_name="http",
                target=validated_target,
                success=True,
                findings=tuple(findings),
            )
            findings = []

            for header, (title, description) in SECURITY_HEADERS.items():
                if header not in response.headers:
                    findings.append(
                        ScanFinding(
                            title=title,
                            severity="low",
                            description=description,
                            evidence={
                                "missing_header": header,
                                "http_status": response.status_code,
                            },
                            remediation=(
                                f"Review whether the {header} header "
                                "should be configured for this application."
                            ),
                        )
                    )

            return ScannerResult(
                scanner_name="http",
                target=validated_target,
                success=True,
                findings=tuple(findings),
            )

        except httpx.TimeoutException:
            return ScannerResult(
                scanner_name="http",
                target=validated_target,
                success=False,
                error="HTTP request timed out",
            )

        except httpx.RequestError:
            return ScannerResult(
                scanner_name="http",
                target=validated_target,
                success=False,
                error="HTTP request failed",
            )

        finally:
            if owns_client:
                client.close()
