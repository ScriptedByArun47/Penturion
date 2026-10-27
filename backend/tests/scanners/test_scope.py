import ipaddress

import pytest

from app.scanners.scope import (
    ScopeValidationError,
    host_matches_domain,
    is_prohibited_ip,
    validate_destination_ip,
    validate_target_in_scope,
)


@pytest.mark.parametrize(
    ("hostname", "domain", "expected"),
    [
        ("example.com", "example.com", True),
        ("api.example.com", "example.com", True),
        ("deep.api.example.com", "example.com", True),
        ("notexample.com", "example.com", False),
        ("example.com.attacker.test", "example.com", False),
        ("attacker.test", "example.com", False),
    ],
)
def test_host_matches_domain(hostname, domain, expected):
    assert host_matches_domain(hostname, domain) is expected


@pytest.mark.parametrize(
    "target",
    [
        "https://example.com",
        "https://api.example.com/v1",
    ],
)
def test_domain_target_accepts_authorized_domain_and_subdomains(target):
    assert (
        validate_target_in_scope(target, "example.com", "domain")
        == target
    )


@pytest.mark.parametrize(
    "target",
    [
        "https://notexample.com",
        "https://example.com.attacker.test",
        "https://attacker.test",
    ],
)
def test_domain_target_rejects_out_of_scope_hosts(target):
    with pytest.raises(ScopeValidationError):
        validate_target_in_scope(target, "example.com", "domain")


def test_ip_target_requires_exact_match():
    assert (
        validate_target_in_scope(
            "https://8.8.8.8/",
            "8.8.8.8",
            "ip",
        )
        == "https://8.8.8.8/"
    )


def test_ip_target_rejects_different_ip():
    with pytest.raises(ScopeValidationError):
        validate_target_in_scope(
            "https://1.1.1.1/",
            "8.8.8.8",
            "ip",
        )


@pytest.mark.parametrize(
    "target",
    [
        "https://user:pass@example.com",
        "ftp://example.com",
        "javascript:alert(1)",
        "https://example.com/#fragment",
        "https://example.com:invalid/",
    ],
)
def test_rejects_invalid_or_unsafe_url_syntax(target):
    with pytest.raises(ScopeValidationError):
        validate_target_in_scope(target, "example.com", "domain")


def test_url_scope_requires_matching_path():
    assert (
        validate_target_in_scope(
            "https://example.com/api",
            "https://example.com/api",
            "url",
        )
        == "https://example.com/api"
    )

    with pytest.raises(ScopeValidationError):
        validate_target_in_scope(
            "https://example.com/admin",
            "https://example.com/api",
            "url",
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "192.0.2.1",
        "224.0.0.1",
        "0.0.0.0",
        "::ffff:127.0.0.1",
    ],
)
def test_prohibits_non_global_ip_addresses(address):
    assert is_prohibited_ip(address) is True

    with pytest.raises(ScopeValidationError):
        validate_destination_ip(address)


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
    ],
)
def test_accepts_global_ip_addresses(address):
    assert is_prohibited_ip(address) is False
    assert validate_destination_ip(address) == ipaddress.ip_address(address)


def test_rejects_malformed_ip():
    with pytest.raises(ScopeValidationError):
        validate_destination_ip("not-an-ip")