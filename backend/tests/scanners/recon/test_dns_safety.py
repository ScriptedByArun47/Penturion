"""Tests for PENTURION DNS destination safety checks."""

import ipaddress
import socket
from unittest.mock import patch

import pytest

from app.scanners.recon.dns_safety import (
    DNSResolutionError,
    resolve_public_destination,
)


DNS_MODULE = "app.scanners.recon.dns_safety.socket.getaddrinfo"


def dns_result(address: str) -> tuple:
    """Build a getaddrinfo-compatible result for an IP address."""
    ip = ipaddress.ip_address(address)

    if ip.version == 4:
        sockaddr = (str(ip), 443)
        family = socket.AF_INET
    else:
        sockaddr = (str(ip), 443, 0, 0)
        family = socket.AF_INET6

    return (
        family,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        sockaddr,
    )


class TestResolvePublicDestination:
    """Test hostname resolution and destination IP validation."""

    @patch(DNS_MODULE)
    def test_resolves_public_ipv4(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            dns_result("93.184.216.34"),
        ]

        result = resolve_public_destination("example.com")

        assert result.hostname == "example.com"
        assert result.addresses == (
            ipaddress.ip_address("93.184.216.34"),
        )
        mock_getaddrinfo.assert_called_once()

    @patch(DNS_MODULE)
    def test_resolves_public_ipv6(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            dns_result("2606:4700:4700::1111"),
        ]

        result = resolve_public_destination("example.com")

        assert result.hostname == "example.com"
        assert result.addresses == (
            ipaddress.ip_address("2606:4700:4700::1111"),
        )

    @patch(DNS_MODULE)
    def test_normalizes_hostname(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            dns_result("93.184.216.34"),
        ]

        result = resolve_public_destination("EXAMPLE.COM.")

        assert result.hostname == "example.com"
        mock_getaddrinfo.assert_called_once_with(
            "example.com",
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )

    @patch(DNS_MODULE)
    def test_rejects_mixed_public_and_private_addresses(
        self,
        mock_getaddrinfo,
    ):
        mock_getaddrinfo.return_value = [
            dns_result("93.184.216.34"),
            dns_result("192.168.1.10"),
        ]

        with pytest.raises(
            DNSResolutionError,
            match="prohibited",
        ):
            resolve_public_destination("example.com")

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ],
    )
    @patch(DNS_MODULE)
    def test_rejects_prohibited_dns_addresses(
        self,
        mock_getaddrinfo,
        address,
    ):
        mock_getaddrinfo.return_value = [
            dns_result(address),
        ]

        with pytest.raises(DNSResolutionError):
            resolve_public_destination("example.com")

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ],
    )
    @patch(DNS_MODULE)
    def test_rejects_prohibited_ip_literals(
        self,
        mock_getaddrinfo,
        address,
    ):
        with pytest.raises(DNSResolutionError):
            resolve_public_destination(address)

        # IP literals should be validated directly without DNS.
        mock_getaddrinfo.assert_not_called()

    @patch(DNS_MODULE)
    def test_ip_literal_does_not_require_dns(self, mock_getaddrinfo):
        result = resolve_public_destination("93.184.216.34")

        assert result.hostname == "93.184.216.34"
        assert result.addresses == (
            ipaddress.ip_address("93.184.216.34"),
        )
        mock_getaddrinfo.assert_not_called()

    @patch(DNS_MODULE)
    def test_rejects_dns_resolution_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror(
            "Name or service not known"
        )

        with pytest.raises(
            DNSResolutionError,
            match="DNS resolution failed",
        ):
            resolve_public_destination("example.com")

    @patch(DNS_MODULE)
    def test_rejects_system_dns_error(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = OSError(
            "Temporary system error"
        )

        with pytest.raises(
            DNSResolutionError,
            match="system error",
        ):
            resolve_public_destination("example.com")

    @patch(DNS_MODULE)
    def test_rejects_empty_dns_results(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = []

        with pytest.raises(
            DNSResolutionError,
            match="no usable addresses",
        ):
            resolve_public_destination("example.com")

    @patch(DNS_MODULE)
    def test_deduplicates_dns_addresses(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            dns_result("93.184.216.34"),
            dns_result("93.184.216.34"),
        ]

        result = resolve_public_destination("example.com")

        assert result.addresses == (
            ipaddress.ip_address("93.184.216.34"),
        )

    @patch(DNS_MODULE)
    def test_sorts_addresses_deterministically(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            dns_result("2606:4700:4700::1111"),
            dns_result("93.184.216.34"),
            dns_result("1.1.1.1"),
        ]

        result = resolve_public_destination("example.com")

        assert result.addresses == (
            ipaddress.ip_address("1.1.1.1"),
            ipaddress.ip_address("93.184.216.34"),
            ipaddress.ip_address("2606:4700:4700::1111"),
        )

    @pytest.mark.parametrize(
        "hostname",
        [
            "",
            " ",
            "invalid..example",
            "-invalid.example",
            "invalid host.example",
        ],
    )
    @patch(DNS_MODULE)
    def test_rejects_invalid_hostnames(
        self,
        mock_getaddrinfo,
        hostname,
    ):
        with pytest.raises(DNSResolutionError):
            resolve_public_destination(hostname)

        mock_getaddrinfo.assert_not_called()

    @patch(DNS_MODULE)
    def test_rejects_malformed_dns_address_record(
        self,
        mock_getaddrinfo,
    ):
        mock_getaddrinfo.return_value = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (),
            ),
        ]

        with pytest.raises(
            DNSResolutionError,
            match="invalid address record",
        ):
            resolve_public_destination("example.com")