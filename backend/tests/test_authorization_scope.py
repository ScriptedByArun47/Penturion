import pytest

from app.services.authorization_scope import (
    AuthorizationScopeError,
    validate_authorization_scope,
)


def test_domain_scope_is_normalized():
    result = validate_authorization_scope(
        '["API.Example.com."]',
        "example.com",
        "domain",
    )

    assert result == '["api.example.com"]'


def test_unrelated_domain_is_rejected():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            '["example.org"]',
            "example.com",
            "domain",
        )


def test_domain_scope_rejects_ip_literals():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            '["127.0.0.1"]',
            "example.com",
            "domain",
        )


def test_invalid_json_is_rejected():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            "example.com",
            "example.com",
            "domain",
        )


def test_empty_scope_is_rejected():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            "[]",
            "example.com",
            "domain",
        )


def test_duplicate_scope_entries_are_rejected():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            '["example.com", "example.com"]',
            "example.com",
            "domain",
        )


def test_ip_scope_must_match_registered_target():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            '["8.8.8.8"]',
            "1.1.1.1",
            "ip",
        )


def test_url_scope_must_match_registered_url():
    with pytest.raises(AuthorizationScopeError):
        validate_authorization_scope(
            '["https://example.com/admin"]',
            "https://example.com/api",
            "url",
        )


def test_url_scope_accepts_exact_registered_url():
    result = validate_authorization_scope(
        '["https://example.com/api"]',
        "https://example.com/api",
        "url",
    )

    assert result == '["https://example.com/api"]'
