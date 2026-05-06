"""Tests for the exception hierarchy."""

import pytest

from permyt.exceptions import (
    ExpiredRequestError,
    InvalidInputError,
    InvalidPayloadError,
    InvalidProofError,
    InvalidPublicKeyError,
    InvalidScopeError,
    InvalidTokenError,
    InvalidUserError,
    PermytError,
    SecurityError,
    TokenAlreadyUsedError,
    TokenExpiredError,
    UnexpectedError,
)

SECURITY_EXCEPTIONS = [
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
]

ALL_EXCEPTIONS = [PermytError, UnexpectedError, SecurityError] + SECURITY_EXCEPTIONS


@pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
def test_has_code_and_default_message(exc_cls):
    assert isinstance(exc_cls.code, str)
    assert isinstance(exc_cls.default_message, str)


@pytest.mark.parametrize("exc_cls", ALL_EXCEPTIONS)
def test_default_message_used_when_none(exc_cls):
    exc = exc_cls()
    assert str(exc) == exc_cls.default_message


@pytest.mark.parametrize("exc_cls", SECURITY_EXCEPTIONS)
def test_security_exceptions_inherit_from_security_error(exc_cls):
    assert issubclass(exc_cls, SecurityError)
    assert issubclass(exc_cls, PermytError)


def test_unexpected_error_not_security_error():
    assert issubclass(UnexpectedError, PermytError)
    assert not issubclass(UnexpectedError, SecurityError)


def test_custom_message_overrides_default():
    exc = InvalidTokenError("custom message")
    assert str(exc) == "custom message"


def test_extra_info_stored():
    exc = PermytError(extra_info="some detail")
    assert exc.extra_info == "some detail"


def test_extra_info_none_by_default():
    exc = PermytError()
    assert exc.extra_info is None


def test_str_returns_message():
    exc = PermytError("hello")
    assert str(exc) == "hello"
