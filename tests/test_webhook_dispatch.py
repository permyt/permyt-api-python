"""Tests for the InboundMixin.handle_inbound dispatcher."""

from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch

from tests.conftest import StubPermytClient


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


def test_handle_inbound_dispatches_token_request(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    inner = {
        "request_id": "req-1",
        "permyt_user_id": "user-42",
        "service_id": "requester",
        "service_public_key": permyt_public,
        "scope": {"identity.basic": {}},
        "ttl_minutes": 5,
    }
    envelope = _build_signed_envelope(permyt, service_public, inner)
    envelope["action"] = "token_request"

    result = service.handle_inbound(envelope)
    assert "encrypted_token" in result
    assert result["request_id"] == "req-1"


def test_handle_inbound_dispatches_user_connect(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(
        permyt, service_public, {"token": "fake-jwt", "permyt_user_id": "permyt-user-1"}
    )
    envelope["action"] = "user_connect"

    result = service.handle_inbound(envelope)
    assert result == {"connected": True}


def test_handle_inbound_dispatches_user_disconnect(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(permyt, service_public, {"permyt_user_id": "permyt-user-9"})
    envelope["action"] = "user_disconnect"

    result = service.handle_inbound(envelope)
    assert result == {"disconnected": True}
    assert service._disconnected_users == ["permyt-user-9"]


def test_handle_inbound_user_disconnect_invalid_proof(test_keys, permyt_keys):
    """Tampered proof must be rejected before reaching process_user_disconnect."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(permyt, service_public, {"permyt_user_id": "permyt-user-9"})
    envelope["action"] = "user_disconnect"
    envelope["proof"] = envelope["proof"][:-2] + ("aa" if envelope["proof"][-2:] != "aa" else "bb")

    result = service.handle_inbound(envelope)
    assert "error" in result


def test_handle_inbound_dispatches_request_status(test_keys, permyt_keys):
    """Default process_request_status returns None → wrapper substitutes {received: True}."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(
        permyt, service_public, {"request_id": "r-1", "status": "completed"}
    )
    envelope["action"] = "request_status"

    result = service.handle_inbound(envelope)
    assert result == {"received": True}


def test_handle_inbound_dispatches_request_status_override(test_keys, permyt_keys):
    """When the subclass overrides process_request_status, its return value wins."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys
    service = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    envelope = _build_signed_envelope(
        permyt, service_public, {"request_id": "r-2", "status": "rejected", "reason": "nope"}
    )
    envelope["action"] = "request_status"

    with patch.object(StubPermytClient, "process_request_status", return_value={"handled": True}):
        result = service.handle_inbound(envelope)
    assert result == {"handled": True}


def test_handle_inbound_unknown_action_returns_error(client):
    result = client.handle_inbound({"action": "nonsense"})
    assert "error" in result


def test_handle_inbound_missing_action_returns_error(client):
    result = client.handle_inbound({})
    assert "error" in result
