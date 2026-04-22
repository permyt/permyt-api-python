"""
End-to-end integration test: request_access → token_request → service_call.

Uses real cryptographic operations with mocked HTTP to PERMYT.
"""

from datetime import datetime, timezone
from typing import Any
from unittest.mock import patch, MagicMock

from tests.conftest import StubPermytClient, _generate_ec_keypair


def test_full_request_cycle():
    """
    Simulate the full PERMYT request cycle:
    1. Requester requests access (mocked HTTP to PERMYT)
    2. PERMYT sends token_request to provider (real crypto)
    3. Provider issues token
    4. Requester decrypts token and calls provider directly (real crypto)
    5. Provider processes request and returns data
    """
    # Setup keys for all parties
    requester_private, requester_public = _generate_ec_keypair()
    provider_private, provider_public = _generate_ec_keypair()
    permyt_private, permyt_public = _generate_ec_keypair()

    requester = StubPermytClient(private_key=requester_private, permyt_public_key=permyt_public)
    provider = StubPermytClient(private_key=provider_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    # --- Step 1: Requester requests access (mock HTTP) ---
    with patch("permyt.mixins.http.requests.post") as mock_post:
        mock_post.return_value = MagicMock(
            ok=True, json=lambda: {"request_id": "req-integration", "status": "queued"}
        )
        status = requester.request_access(
            {"user_id": "user-1", "description": "Need professional data"}
        )
        assert status["request_id"] == "req-integration"

    # --- Step 2: PERMYT builds and sends token_request to provider ---
    scope = {"professional": {}, "employment": {"company": "Acme"}}
    inner_data = {
        "request_id": "req-integration",
        "permyt_user_id": "user-1",
        "service_id": "requester-service",
        "service_public_key": requester_public,
        "scope": scope,
        "ttl_minutes": 5,
    }
    encrypted = permyt._encrypt_jwe(inner_data, provider_public)
    payload = {
        "data": encrypted,
        "nonce": "x" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt._create_proof(payload)
    token_request = {"payload": payload, "proof": proof}

    # --- Step 3: Provider handles token request ---
    token_response = provider.handle_token_request(token_request)
    assert "encrypted_token" in token_response
    assert token_response["request_id"] == "req-integration"
    assert len(token_response["endpoints"]) > 0

    # --- Step 4: Requester decrypts the token ---
    token_data = requester._decrypt_data(token_response["encrypted_token"])
    token = token_data["token"]

    # --- Step 5: Requester calls provider directly ---
    call_data = {"query": "latest record"}
    encrypted_call = requester._encrypt_jwe(call_data, provider_public)
    call_payload = {
        "data": encrypted_call,
        "nonce": "y" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof = requester._create_proof(call_payload)

    service_call = {
        "token": token,
        "payload": call_payload,
        "proof": call_proof,
    }

    result = provider.handle_service_call(service_call)

    # Provider's StubPermytClient.process_request returns {"result": "ok"}
    assert result == {"result": "ok"}


def test_full_cycle_force_inputs_enforced():
    """
    Verify that force inputs survive the full cycle and are available
    to process_request for enforcement.
    """
    requester_private, requester_public = _generate_ec_keypair()
    provider_private, provider_public = _generate_ec_keypair()
    permyt_private, permyt_public = _generate_ec_keypair()

    captured_metadata = {}

    class EnforcingProvider(StubPermytClient):
        def process_request(self, metadata, data):
            captured_metadata.update(metadata)
            return {"enforced": True}

    provider = EnforcingProvider(private_key=provider_private, permyt_public_key=permyt_public)
    requester = StubPermytClient(private_key=requester_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    locked_scope = {
        "payments.send": {"amount": 500, "currency": "EUR", "receiver": "bob@example.com"},
    }

    inner_data = {
        "request_id": "req-force",
        "permyt_user_id": "user-2",
        "service_id": "requester-svc",
        "service_public_key": requester_public,
        "scope": locked_scope,
        "ttl_minutes": 5,
    }
    encrypted = permyt._encrypt_jwe(inner_data, provider_public)
    payload = {
        "data": encrypted,
        "nonce": "z" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt._create_proof(payload)

    token_response = provider.handle_token_request({"payload": payload, "proof": proof})
    token_data = requester._decrypt_data(token_response["encrypted_token"])

    encrypted_call = requester._encrypt_jwe({"amount": 500}, provider_public)
    call_payload = {
        "data": encrypted_call,
        "nonce": "w" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    call_proof = requester._create_proof(call_payload)

    result = provider.handle_service_call(
        {"token": token_data["token"], "payload": call_payload, "proof": call_proof}
    )

    assert result == {"enforced": True}
    assert captured_metadata["scope"] == locked_scope
    assert captured_metadata["scope"]["payments.send"]["amount"] == 500
