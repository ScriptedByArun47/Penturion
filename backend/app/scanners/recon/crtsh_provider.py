"""Passive subdomain discovery using Certificate Transparency records."""

import json
from threading import Event

import httpx

from app.scanners.executor import AgentExecutionCancelled
from app.scanners.transport.pinned_http import create_pinned_client


class CrtShSubdomainProvider:
    ENDPOINT = "https://crt.sh/"
    MAX_RESPONSE_BYTES = 5 * 1024 * 1024
    CHUNK_SIZE = 64 * 1024

    def __init__(self, client: httpx.Client | None = None):
        self.client = client

    def discover(
        self,
        *,
        root_domain: str,
        timeout_seconds: int,
        cancel_event: Event,
    ) -> list[str]:

        if not root_domain:
            raise ValueError("Root domain must not be empty")

        if timeout_seconds <= 0:
            raise ValueError("Timeout must be greater than zero")

        if cancel_event.is_set():
            raise AgentExecutionCancelled(
                "Certificate Transparency lookup cancelled."
            )

        owns_client = self.client is None

        client = self.client or create_pinned_client(
            timeout=float(timeout_seconds)
        )

        try:
            body = bytearray()

            with client.stream(
                "GET",
                self.ENDPOINT,
                params={
                    "q": f"%.{root_domain}",
                    "output": "json",
                },
                timeout=float(timeout_seconds),
            ) as response:

                if cancel_event.is_set():
                    raise AgentExecutionCancelled(
                        "Certificate Transparency lookup cancelled."
                    )

                response.raise_for_status()

                for chunk in response.iter_bytes(
                    chunk_size=self.CHUNK_SIZE
                ):
                    if cancel_event.is_set():
                        raise AgentExecutionCancelled(
                            "Certificate Transparency lookup cancelled."
                        )

                    if len(body) + len(chunk) > self.MAX_RESPONSE_BYTES:
                        raise ValueError(
                            "Certificate Transparency response "
                            "exceeds size limit"
                        )

                    body.extend(chunk)

            if cancel_event.is_set():
                raise AgentExecutionCancelled(
                    "Certificate Transparency lookup cancelled."
                )

            data = json.loads(body)

            if not isinstance(data, list):
                raise ValueError(
                    "Invalid Certificate Transparency response structure"
                )

            results = []
            seen = set()

            for record in data:
                if not isinstance(record, dict):
                    raise ValueError(
                        "Invalid certificate record structure"
                    )

                names = record.get("name_value")

                if not isinstance(names, str):
                    raise ValueError(
                        "Certificate record is missing name_value"
                    )

                for hostname in names.splitlines():
                    hostname = hostname.strip()

                    if hostname and hostname not in seen:
                        seen.add(hostname)
                        results.append(hostname)

            return results

        finally:
            if owns_client:
                client.close()