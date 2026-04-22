"""Smoke tests: verify that public API is importable."""


def test_permyt_client_importable():
    from permyt import PermytClient

    assert PermytClient is not None


def test_exceptions_importable():
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
    )

    assert PermytError is not None
    assert (
        len(
            {
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
            }
        )
        == 12
    )


def test_typing_importable():
    from permyt.typing import (
        AccessRequest,
        AccessPayload,
        AccessStatus,
        AccessResponse,
        ExchangeToken,
        RedeemedToken,
        TokenRequestData,
        TokenMetadata,
        EncryptedPayload,
        EncryptedRequest,
        RequestStatus,
        ServiceCredential,
        ServiceCallPayload,
        ServiceCallRequest,
        ServiceCallEndpoint,
        ConnectPayload,
        ConnectRequest,
    )

    assert AccessRequest is not None
    assert RequestStatus is not None
    assert ConnectRequest is not None


def test_mixins_importable():
    from permyt.mixins.requests import RequesterMixin, ProviderMixin, UserConnectMixin, InboundMixin

    assert RequesterMixin is not None
    assert ProviderMixin is not None
    assert UserConnectMixin is not None
    assert InboundMixin is not None
