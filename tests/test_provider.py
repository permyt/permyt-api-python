"""Tests for ProviderMixin methods."""

from datetime import datetime, timezone

from permyt.exceptions import InvalidUserError
from tests.conftest import StubPermytClient, _generate_ec_keypair

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_token_request(permyt_client, service_public, requester_public, scope=None):
    """Build a signed+encrypted token request as PERMYT would send to a provider."""
    inner_data = {
        "request_id": "req-001",
        "permyt_user_id": "user-42",
        "service_id": "requester-service",
        "service_public_key": requester_public,
        "scope": scope or {"professional": {}},
        "ttl_minutes": 5,
    }
    encrypted = permyt_client._encrypt_jwe(inner_data, service_public)
    payload = {
        "data": encrypted,
        "nonce": "d" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt_client._create_proof(payload)
    return {"payload": payload, "proof": proof}


# ---------------------------------------------------------------------------
# handle_token_request
# ---------------------------------------------------------------------------


def test_handle_token_request_success(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()

    request = _build_token_request(permyt_client, service_public, requester_public)
    response = service_client.handle_token_request(request)

    assert "encrypted_token" in response
    assert response["request_id"] == "req-001"
    assert "endpoints" in response
    assert "expires_at" in response


def test_handle_token_request_invalid_user(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    class RejectUserClient(StubPermytClient):
        def resolve_user(self, permyt_user_id=None):
            raise InvalidUserError()

    service_client = RejectUserClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()
    request = _build_token_request(permyt_client, service_public, requester_public)

    result = service_client.handle_token_request(request)
    assert result["error"] == "invalid_user"


def test_handle_token_request_unexpected_error(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    class BrokenClient(StubPermytClient):
        def resolve_user(self, permyt_user_id=None):
            raise RuntimeError("db down")

    service_client = BrokenClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()
    request = _build_token_request(permyt_client, service_public, requester_public)

    result = service_client.handle_token_request(request)
    assert result["error"] == "unexpected_error"


# ---------------------------------------------------------------------------
# handle_service_call — full cycle
# ---------------------------------------------------------------------------


def test_handle_service_call_full_cycle(test_keys, permyt_keys):
    """Issue a token via handle_token_request, then use it in handle_service_call."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()
    requester_client = StubPermytClient(
        private_key=requester_private, permyt_public_key=permyt_public
    )

    # Step 1: Provider issues token
    request = _build_token_request(permyt_client, service_public, requester_public)
    token_response = service_client.handle_token_request(request)

    # Step 2: Requester decrypts the token
    token_data = requester_client._decrypt_data(token_response["encrypted_token"])
    token = token_data["token"]

    # Step 3: Requester calls the provider
    call_data = {"some": "input"}
    encrypted_call = requester_client._encrypt_jwe(call_data, service_public)
    call_payload = {
        "data": encrypted_call,
        "nonce": "e" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof = requester_client._create_proof(call_payload)

    service_call = {
        "token": token,
        "payload": call_payload,
        "proof": call_proof,
    }

    result = service_client.handle_service_call(service_call)
    assert result == {"result": "ok"}


def test_handle_service_call_invalid_proof(test_keys, permyt_keys):
    """Service call with wrong requester key should fail."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()

    # Issue token for the real requester
    request = _build_token_request(permyt_client, service_public, requester_public)
    token_response = service_client.handle_token_request(request)

    requester_client = StubPermytClient(
        private_key=requester_private, permyt_public_key=permyt_public
    )
    token_data = requester_client._decrypt_data(token_response["encrypted_token"])
    token = token_data["token"]

    # Rogue signs the call with a different key
    rogue_private, _ = _generate_ec_keypair()
    rogue_client = StubPermytClient(private_key=rogue_private, permyt_public_key=permyt_public)

    encrypted_call = rogue_client._encrypt_jwe({"data": "test"}, service_public)
    call_payload = {
        "data": encrypted_call,
        "nonce": "f" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof = rogue_client._create_proof(call_payload)

    service_call = {"token": token, "payload": call_payload, "proof": call_proof}

    result = service_client.handle_service_call(service_call)
    assert result["error"] == "invalid_proof"


def test_handle_service_call_token_already_used(test_keys, permyt_keys):
    """Using the same token twice should fail."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()
    requester_client = StubPermytClient(
        private_key=requester_private, permyt_public_key=permyt_public
    )

    # Issue token
    request = _build_token_request(permyt_client, service_public, requester_public)
    token_response = service_client.handle_token_request(request)
    token_data = requester_client._decrypt_data(token_response["encrypted_token"])
    token = token_data["token"]

    # First call — succeeds
    call_data = {"test": "data"}
    encrypted_call = requester_client._encrypt_jwe(call_data, service_public)
    call_payload = {
        "data": encrypted_call,
        "nonce": "g" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof = requester_client._create_proof(call_payload)
    service_call = {"token": token, "payload": call_payload, "proof": call_proof}

    result1 = service_client.handle_service_call(service_call)
    assert result1 == {"result": "ok"}

    # Second call — same token, should fail
    encrypted_call2 = requester_client._encrypt_jwe(call_data, service_public)
    call_payload2 = {
        "data": encrypted_call2,
        "nonce": "h" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof2 = requester_client._create_proof(call_payload2)
    service_call2 = {"token": token, "payload": call_payload2, "proof": call_proof2}

    result2 = service_client.handle_service_call(service_call2)
    assert result2["error"] == "token_already_used"


def test_handle_service_call_unexpected_error(test_keys, permyt_keys):
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    class BrokenProcessClient(StubPermytClient):
        def process_request(self, metadata, data):
            raise RuntimeError("process exploded")

    service_client = BrokenProcessClient(
        private_key=service_private, permyt_public_key=permyt_public
    )
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    requester_private, requester_public = _generate_ec_keypair()
    requester_client = StubPermytClient(
        private_key=requester_private, permyt_public_key=permyt_public
    )

    request = _build_token_request(permyt_client, service_public, requester_public)
    token_response = service_client.handle_token_request(request)
    token_data = requester_client._decrypt_data(token_response["encrypted_token"])
    token = token_data["token"]

    encrypted_call = requester_client._encrypt_jwe({"data": "test"}, service_public)
    call_payload = {
        "data": encrypted_call,
        "nonce": "i" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof = requester_client._create_proof(call_payload)
    service_call = {"token": token, "payload": call_payload, "proof": call_proof}

    result = service_client.handle_service_call(service_call)
    assert result["error"] == "unexpected_error"
