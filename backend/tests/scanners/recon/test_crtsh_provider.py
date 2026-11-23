from threading import Event
from unittest.mock import MagicMock, Mock

import httpx
import pytest

from app.scanners.executor import AgentExecutionCancelled
from app.scanners.recon.crtsh_provider import CrtShSubdomainProvider


def make_response(data, status_code=200):
    return httpx.Response(
        status_code=status_code,
        json=data,
        request=httpx.Request("GET", "https://crt.sh/"),
    )


def configure_stream(client, response):
    stream_context = MagicMock()
    stream_context.__enter__.return_value = response
    client.stream.return_value = stream_context
    return stream_context


def test_queries_crtsh_for_authorized_domain():
    client = Mock()
    response = make_response([
        {"name_value": "api.example.com"},
        {"name_value": "*.dev.example.com"},
    ])
    configure_stream(client, response)

    provider = CrtShSubdomainProvider(client=client)

    results = provider.discover(
        root_domain="example.com",
        timeout_seconds=20,
        cancel_event=Event(),
    )

    assert results == [
        "api.example.com",
        "*.dev.example.com",
    ]

    client.stream.assert_called_once_with(
        "GET",
        "https://crt.sh/",
        params={
            "q": "%.example.com",
            "output": "json",
        },
        timeout=20.0,
    )

    client.get.assert_not_called()


def test_handles_multiple_names_in_certificate():
    client = Mock()
    response = make_response([
        {
            "name_value": (
                "api.example.com\n"
                "dev.example.com\n"
                "*.stage.example.com"
            )
        }
    ])
    configure_stream(client, response)

    provider = CrtShSubdomainProvider(client=client)

    results = provider.discover(
        root_domain="example.com",
        timeout_seconds=20,
        cancel_event=Event(),
    )

    assert results == [
        "api.example.com",
        "dev.example.com",
        "*.stage.example.com",
    ]


def test_cancellation_before_request():
    client = Mock()
    cancel_event = Event()
    cancel_event.set()

    provider = CrtShSubdomainProvider(client=client)

    with pytest.raises(AgentExecutionCancelled):
        provider.discover(
            root_domain="example.com",
            timeout_seconds=20,
            cancel_event=cancel_event,
        )

    client.stream.assert_not_called()


def test_cancellation_after_response():
    client = Mock()
    cancel_event = Event()

    response = make_response([
        {"name_value": "api.example.com"}
    ])

    stream_context = MagicMock()

    def enter_stream():
        cancel_event.set()
        return response

    stream_context.__enter__.side_effect = enter_stream
    client.stream.return_value = stream_context

    provider = CrtShSubdomainProvider(client=client)

    with pytest.raises(AgentExecutionCancelled):
        provider.discover(
            root_domain="example.com",
            timeout_seconds=20,
            cancel_event=cancel_event,
        )


def test_http_error_is_propagated():
    client = Mock()
    response = make_response([], status_code=503)
    configure_stream(client, response)

    provider = CrtShSubdomainProvider(client=client)

    with pytest.raises(httpx.HTTPStatusError):
        provider.discover(
            root_domain="example.com",
            timeout_seconds=20,
            cancel_event=Event(),
        )


def test_rejects_invalid_json_structure():
    client = Mock()
    response = make_response(
        {"unexpected": "structure"}
    )
    configure_stream(client, response)

    provider = CrtShSubdomainProvider(client=client)

    with pytest.raises(ValueError):
        provider.discover(
            root_domain="example.com",
            timeout_seconds=20,
            cancel_event=Event(),
        )


def test_rejects_response_exceeding_size_limit():
    client = Mock()
    response = Mock()
    response.raise_for_status.return_value = None

    response.iter_bytes.return_value = iter([
        b"x" * (
            CrtShSubdomainProvider.MAX_RESPONSE_BYTES + 1
        )
    ])

    configure_stream(client, response)

    provider = CrtShSubdomainProvider(client=client)

    with pytest.raises(ValueError, match="size limit"):
        provider.discover(
            root_domain="example.com",
            timeout_seconds=20,
            cancel_event=Event(),
        )


def test_uses_streaming_for_response_size_enforcement():
    client = Mock()
    response = Mock()
    response.raise_for_status.return_value = None

    response.iter_bytes.return_value = iter([
        b"x" * (
            CrtShSubdomainProvider.MAX_RESPONSE_BYTES + 1
        )
    ])

    configure_stream(client, response)

    provider = CrtShSubdomainProvider(client=client)

    with pytest.raises(ValueError, match="size limit"):
        provider.discover(
            root_domain="example.com",
            timeout_seconds=20,
            cancel_event=Event(),
        )

    client.stream.assert_called_once()
    client.get.assert_not_called()