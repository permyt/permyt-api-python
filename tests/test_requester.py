"""Tests for RequesterMixin methods."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from permyt.exceptions import (
    TransportError,
)
from tests.conftest import StubPermytClient, _generate_ec_keypair

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_signed_encrypted_response(permyt_client, service_public_key, services_data):
    """Build a signed+encrypted AccessResponse as PERMYT would produce."""
    encrypted = permyt_client._encrypt_jwe(services_data, service_public_key)
    payload = {
        "data": encrypted,
        "nonce": "a" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt_client._create_proof(payload)
    return {"payload": payload, "proof": proof}


def _build_signed_encrypted_request(permyt_client, service_public_key, data):
    """Build a signed+encrypted EncryptedRequest as PERMYT would produce."""
    encrypted = permyt_client._encrypt_jwe(data, service_public_key)
    payload = {
        "data": encrypted,
        "nonce": "b" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt_client._create_proof(payload)
    return {"payload": payload, "proof": proof}


# ---------------------------------------------------------------------------
# request_access
# ---------------------------------------------------------------------------


@patch("permyt.mixins.http.requests.post")
def test_request_access_builds_correct_payload(mock_post, test_keys, permyt_keys):
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    mock_post.return_value = MagicMock(
        ok=True, json=lambda: {"request_id": "req-1", "status": "queued"}
    )

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    result = client.request_access({"user_id": "user-1", "description": "Need data"})

    assert result["request_id"] == "req-1"
    assert mock_post.call_count == 1

    call_args = mock_post.call_args
    body = call_args.kwargs.get("json") or call_args[1]["json"]
    assert body["action"] == "access_request"
    assert "payload" in body
    assert "proof" in body


@patch("permyt.mixins.http.requests.post")
def test_request_access_uses_default_callback_url(mock_post, test_keys, permyt_keys):
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    mock_post.return_value = MagicMock(
        ok=True, json=lambda: {"request_id": "req-2", "status": "queued"}
    )

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    client.DEFAULT_CALLBACK_URL = "https://example.com/callback"
    client.request_access({"user_id": "user-1", "description": "Need data"})

    assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# check_access
# ---------------------------------------------------------------------------


@patch("permyt.mixins.http.requests.post")
def test_check_access_sends_request_id(mock_post, test_keys, permyt_keys):
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    mock_post.return_value = MagicMock(
        ok=True, json=lambda: {"request_id": "req-1", "status": "pending"}
    )

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    result = client.check_access("req-1")

    assert result["status"] == "pending"
    assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# request_token / redeem_token
# ---------------------------------------------------------------------------


@patch("permyt.mixins.http.requests.post")
def test_request_token_sends_user_id(mock_post, test_keys, permyt_keys):
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    mock_post.return_value = MagicMock(
        ok=True, json=lambda: {"user_id": "u-1", "token": "tok", "restricted_to": None}
    )

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    result = client.request_token("u-1", restricted_to="svc-2")

    assert result["token"] == "tok"
    assert mock_post.call_count == 1


@patch("permyt.mixins.http.requests.post")
def test_redeem_token_sends_token_and_user_id(mock_post, test_keys, permyt_keys):
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    mock_post.return_value = MagicMock(ok=True, json=lambda: {"user_id": "u-1"})

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    result = client.redeem_token("u-1", "some-token")

    assert result["user_id"] == "u-1"


# ---------------------------------------------------------------------------
# handle_approved_access
# ---------------------------------------------------------------------------


def test_handle_approved_access_invalid_proof(test_keys, permyt_keys):
    service_private, service_public = test_keys
    _, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)

    # Sign with a rogue key
    rogue_private, _ = _generate_ec_keypair()
    rogue_client = StubPermytClient(private_key=rogue_private, permyt_public_key=permyt_public)

    response = _build_signed_encrypted_response(rogue_client, service_public, [])

    result = service_client.handle_approved_access(response)
    assert "error" in result
    assert result["error"] == "invalid_proof"


@patch("permyt.mixins.http.requests.post")
def test_handle_approved_access_decrypts_and_calls_services(mock_post, test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    # Build a provider credential that the requester would receive
    provider_private, provider_public = _generate_ec_keypair()
    provider_client = StubPermytClient(
        private_key=provider_private, permyt_public_key=permyt_public
    )

    # Issue a token from the provider
    token = provider_client._sign_jwt({"jti": "tok-1", "request_id": "req-1"})
    encrypted_token = provider_client._encrypt_jwe({"token": token}, service_public)

    services = [
        {
            "request_id": "req-1",
            "encrypted_token": encrypted_token,
            "endpoints": [{"url": "https://provider.example.com/api/data", "description": "Test"}],
            "expires_at": "2099-01-01T00:00:00Z",
            "public_key": provider_public,
        }
    ]

    response = _build_signed_encrypted_response(permyt_client, service_public, services)

    mock_post.return_value = MagicMock(ok=True, json=lambda: {"result": "ok"})
    result = service_client.handle_approved_access(response)

    assert isinstance(result, list)
    assert len(result) == 1
    assert mock_post.call_count == 1


# ---------------------------------------------------------------------------
# handle_request_status
# ---------------------------------------------------------------------------


def test_handle_request_status_decrypts_and_dispatches(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    status_data = {"request_id": "req-1", "status": "completed"}
    request = _build_signed_encrypted_request(permyt_client, service_public, status_data)

    result = service_client.handle_request_status(request)
    assert result == {"received": True}


def test_handle_request_status_unexpected_error(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    class ErrorClient(StubPermytClient):
        def process_request_status(self, data):
            raise RuntimeError("boom")

    service_client = ErrorClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    status_data = {"request_id": "req-1", "status": "completed"}
    request = _build_signed_encrypted_request(permyt_client, service_public, status_data)

    result = service_client.handle_request_status(request)
    assert result["error"] == "unexpected_error"


# ---------------------------------------------------------------------------
# call_services
# ---------------------------------------------------------------------------


@patch("permyt.mixins.http.requests.post")
def test_call_services_calls_each_endpoint(mock_post, test_keys, permyt_keys):
    service_private, service_public = test_keys
    _, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)

    provider_private, provider_public = _generate_ec_keypair()
    provider_client = StubPermytClient(
        private_key=provider_private, permyt_public_key=permyt_public
    )

    token = provider_client._sign_jwt({"jti": "t-1", "request_id": "r-1"})
    encrypted_token = provider_client._encrypt_jwe({"token": token}, service_public)

    services = [
        {
            "request_id": "r-1",
            "encrypted_token": encrypted_token,
            "endpoints": [
                {"url": "https://provider.example.com/endpoint1"},
                {"url": "https://provider.example.com/endpoint2"},
            ],
            "expires_at": "2099-01-01T00:00:00Z",
            "public_key": provider_public,
        }
    ]

    mock_post.return_value = MagicMock(ok=True, json=lambda: {"data": "ok"})
    result = service_client.call_services(services)

    assert len(result) == 2
    assert mock_post.call_count == 2


@patch("permyt.mixins.http.requests.post")
def test_call_services_continues_on_failure(mock_post, test_keys, permyt_keys):
    """One endpoint failing should not prevent the other from being called."""
    service_private, service_public = test_keys
    _, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)

    provider_private, provider_public = _generate_ec_keypair()
    provider_client = StubPermytClient(
        private_key=provider_private, permyt_public_key=permyt_public
    )

    token = provider_client._sign_jwt({"jti": "t-2", "request_id": "r-2"})
    encrypted_token = provider_client._encrypt_jwe({"token": token}, service_public)

    services = [
        {
            "request_id": "r-2",
            "encrypted_token": encrypted_token,
            "endpoints": [
                {"url": "https://provider.example.com/fail"},
                {"url": "https://provider.example.com/ok"},
            ],
            "expires_at": "2099-01-01T00:00:00Z",
            "public_key": provider_public,
        }
    ]

    # First call raises, second succeeds
    mock_post.side_effect = [
        TransportError("connection failed"),
        MagicMock(ok=True, json=lambda: {"data": "ok"}),
    ]

    result = service_client.call_services(services)
    assert len(result) == 1
    assert mock_post.call_count == 2
