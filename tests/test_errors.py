"""Tests for the ErrorsMixin (handle_permyt_error)."""

import pytest

from permyt.exceptions import (
    PermytError,
    UnexpectedError,
    SecurityError,
    InvalidTokenError,
    TokenExpiredError,
    TokenAlreadyUsedError,
    InvalidScopeError,
    InvalidUserError,
    InvalidPublicKeyError,
    InvalidProofError,
    InvalidPayloadError,
    ExpiredRequestError,
    InvalidInputError,
    TransportError,
)

ALL_EXCEPTIONS = [
    PermytError,
    UnexpectedError,
    SecurityError,
    InvalidTokenError,
    TokenExpiredError,
    TokenAlreadyUsedError,
    InvalidScopeError,
    InvalidUserError,
    InvalidPublicKeyError,
    InvalidProofError,
    InvalidPayloadError,
    ExpiredRequestError,
    InvalidInputError,
    TransportError,
]


def test_handle_permyt_error_basic(client):
    exc = PermytError()
    result = client.handle_permyt_error(exc)
    assert result["error"] == "permyt_error"
    assert result["message"] == str(exc)


def test_handle_permyt_error_code_matches(client):
    exc = InvalidTokenError()
    result = client.handle_permyt_error(exc)
    assert result["error"] == exc.code


def test_handle_permyt_error_message_matches(client):
    exc = InvalidTokenError("custom msg")
    result = client.handle_permyt_error(exc)
    assert result["message"] == "custom msg"


def test_handle_permyt_error_extra_info(client):
    exc = PermytError(extra_info="extra detail")
    result = client.handle_permyt_error(exc)
    assert result["extra_info"] == "extra detail"


def test_handle_permyt_error_no_extra_info(client):
    exc = PermytError()
    result = client.handle_permyt_error(exc)
    assert "extra_info" not in result


@pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
def test_handle_permyt_error_all_exceptions(client, exc_cls):
    exc = exc_cls()
    result = client.handle_permyt_error(exc)
    assert result["error"] == exc_cls.code
    assert result["message"] == exc_cls.default_message
