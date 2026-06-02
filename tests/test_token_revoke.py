"""Tests for the TokenRevokeMixin and its inbound routing."""

from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

from tests.conftest import StubPermytClient

_FAKE_PUBKEY = "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----"


def _build_signed_envelope(
    sender: StubPermytClient, recipient_public_key: str, inner: dict[str, Any]
) -> dict[str, Any]:
    """Build an EncryptedRequest envelope from one stub client to another."""
    encrypted = sender._encrypt_jwe(inner, recipient_public_key)
    payload = {
        "data": encrypted,
        "nonce": "n" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = sender._create_proof(payload)
    return {"payload": payload, "proof": proof}


def _revoke_inner(reason: str = "user_disconnect") -> dict[str, Any]:
    return {
        "permyt_user_id": "user-7",
        "blocked_service_id": "svc-blocked",
        "blocked_service_public_key": _FAKE_PUBKEY,
        "reason": reason,
    }


def test_handle_token_revoke_user_disconnect(test_keys, permyt_keys):
    """Happy path: valid envelope → process_token_revoke gets the decoded payload."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(permyt, service_public, _revoke_inner())

    result = service.handle_token_revoke(envelope)
    assert result == {"revoked": True}
    assert service._revoked == [
        {
            "permyt_user_id": "user-7",
            "blocked_service_id": "svc-blocked",
            "blocked_service_public_key": _FAKE_PUBKEY,
            "reason": "user_disconnect",
        }
    ]


def test_handle_token_revoke_user_blacklist(test_keys, permyt_keys):
    """Blacklist reason flows through unchanged."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(
        permyt, service_public, _revoke_inner(reason="user_blacklist")
    )

    service.handle_token_revoke(envelope)
    assert service._revoked[0]["reason"] == "user_blacklist"


def test_handle_token_revoke_invalid_proof(test_keys, permyt_keys):
    """Tampered proof rejected before process_token_revoke runs."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(permyt, service_public, _revoke_inner())
    envelope["proof"] = envelope["proof"][:-2] + ("aa" if envelope["proof"][-2:] != "aa" else "bb")

    result = service.handle_token_revoke(envelope)
    assert "error" in result
    assert getattr(service, "_revoked", []) == []


def test_handle_token_revoke_stale_timestamp(test_keys, permyt_keys):
    """A timestamp validator that rejects the request bubbles up as an error."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(permyt, service_public, _revoke_inner())

    from permyt.exceptions import ExpiredRequestError

    def reject(*_args, **_kwargs):
        raise ExpiredRequestError()

    with patch.object(StubPermytClient, "_validate_nonce_and_timestamp", side_effect=reject):
        result = service.handle_token_revoke(envelope)

    assert "error" in result
    assert getattr(service, "_revoked", []) == []


def test_handle_inbound_dispatches_token_revoke(test_keys, permyt_keys):
    """The InboundMixin router maps action=token_revoke to handle_token_revoke."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(permyt, service_public, _revoke_inner())
    envelope["action"] = "token_revoke"

    result = service.handle_inbound(envelope)
    assert result == {"revoked": True}
    assert service._revoked[0]["permyt_user_id"] == "user-7"
