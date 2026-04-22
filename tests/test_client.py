"""Tests for the StubPermytClient exercising mixin logic."""

from datetime import datetime, timedelta, timezone

import pytest

from permyt.exceptions import InvalidProofError
from tests.conftest import StubPermytClient, _generate_ec_keypair


def test_client_instantiates(client):
    assert client is not None


def test_service_id(client):
    assert client.service_id == "test-service"


def test_get_fullpath(client):
    result = client.get_fullpath("request/access/")
    assert result == "https://permyt.io/rest/request/access/"


def test_generate_connect_token(client):
    result = client.generate_connect_token()
    assert "token" in result
    assert "data" in result
    data = result["data"]
    # The QR contents are now a fully-formed signed service-request envelope
    # that PERMYT's ServiceRequestSerializer can consume directly.
    assert data["service_id"] == "test-service"
    assert "payload" in data
    assert "proof" in data
    payload = data["payload"]
    assert "data" in payload  # JWE-encrypted JWT
    assert "timestamp" in payload
    assert "nonce" in payload


def test_generate_connect_token_with_user_id(client):
    result = client.generate_connect_token(system_user_id="user-123")
    assert result["system_user_id"] == "user-123"


def test_extract_request_data_valid(test_keys, permyt_keys):
    """Build a properly signed+encrypted request using permyt keys and verify extraction."""
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    # Create a client acting as the service (provider)
    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)

    # Create a "PERMYT" client to build the request
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    # PERMYT encrypts data for the service using the service's public key
    inner_data = {
        "request_id": "req-001",
        "permyt_user_id": "user-42",
        "service_id": "requester-service",
        "service_public_key": permyt_public,
        "scope": {"professional": {}},
        "ttl_minutes": 5,
    }
    encrypted_data = permyt_client._encrypt_jwe(inner_data, service_public)

    payload = {
        "data": encrypted_data,
        "nonce": "a" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt_client._create_proof(payload)

    request = {"payload": payload, "proof": proof}

    # Service extracts and decrypts the request
    result = service_client._extract_request_data(request)
    assert result["request_id"] == "req-001"
    assert result["permyt_user_id"] == "user-42"


def test_extract_request_data_invalid_proof(test_keys, permyt_keys):
    """Request with a proof signed by the wrong key should fail."""
    service_private, service_public = test_keys
    _, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)

    # Use a random key to sign (not the permyt key)
    rogue_private, _ = _generate_ec_keypair()
    rogue_client = StubPermytClient(private_key=rogue_private, permyt_public_key=permyt_public)

    encrypted_data = rogue_client._encrypt_jwe({"some": "data"}, service_public)
    payload = {
        "data": encrypted_data,
        "nonce": "b" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = rogue_client._create_proof(payload)
    request = {"payload": payload, "proof": proof}

    with pytest.raises(InvalidProofError):
        service_client._extract_request_data(request)


def test_issue_token(test_keys, permyt_keys):
    """_issue_token produces a signed JWT."""
    from joserfc import jwt
    from joserfc.jwk import ECKey

    service_private, service_public = test_keys
    _, permyt_public = permyt_keys

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)

    data = {
        "request_id": "req-100",
        "service_id": "requester-svc",
        "service_public_key": "some-pub-key",
    }
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    token = client._issue_token(data, expires_at)

    claims = jwt.decode(token, ECKey.import_key(service_public)).claims
    assert claims["request_id"] == "req-100"
    assert claims["service_id"] == "requester-svc"
    assert "jti" in claims
    assert "exp" in claims


def test_handle_permyt_error_on_client(client):
    from permyt.exceptions import InvalidScopeError

    exc = InvalidScopeError()
    result = client.handle_permyt_error(exc)
    assert result["error"] == "invalid_scope"


def test_force_inputs_persist_through_token_lifecycle(test_keys, permyt_keys):
    """
    A scope grant carrying locked input values (force inputs) must round-trip
    from the PERMYT token request, through the provider's storage, and back
    out via get_token_metadata so that process_request can enforce the locked
    values against incoming service calls.
    """
    service_private, service_public = test_keys
    permyt_private, permyt_public = permyt_keys

    service_client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt_client = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)

    locked_scope = {
        "payments.send": {
            "amount": 1000,
            "currency": "USD",
            "receiver": "alice@example.com",
        },
        "identity.basic": {},
    }

    inner_data = {
        "request_id": "req-pay-001",
        "permyt_user_id": "user-42",
        "service_id": "requester-service",
        "service_public_key": permyt_public,
        "scope": locked_scope,
        "ttl_minutes": 5,
    }

    encrypted_data = permyt_client._encrypt_jwe(inner_data, service_public)
    payload = {
        "data": encrypted_data,
        "nonce": "c" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    proof = permyt_client._create_proof(payload)
    request = {"payload": payload, "proof": proof}

    # Provider handles the token request — this triggers store_token internally
    response = service_client.handle_token_request(request)
    assert "encrypted_token" in response
    assert response["request_id"] == "req-pay-001"

    # The encrypted token is JWE-encrypted for the requester's public key
    # (here ``permyt_public``), so decrypt with the matching private key.
    decrypted = permyt_client._decrypt_data(response["encrypted_token"])
    metadata = service_client.get_token_metadata(decrypted["token"])

    # The locked force inputs must round-trip identically
    assert metadata["scope"] == locked_scope
    assert metadata["scope"]["payments.send"]["amount"] == 1000
    assert metadata["scope"]["payments.send"]["receiver"] == "alice@example.com"
    assert metadata["scope"]["identity.basic"] == {}
