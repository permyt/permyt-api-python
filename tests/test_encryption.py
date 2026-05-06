"""Tests for the encryption mixin: JWT, JWE, and proof-of-possession."""

import pytest
from joserfc import jwt
from joserfc.jwk import ECKey

from permyt.exceptions import InvalidPayloadError, InvalidProofError, InvalidPublicKeyError
from tests.conftest import StubPermytClient, _generate_ec_keypair


@pytest.fixture
def client_and_keys(test_keys, permyt_keys):
    private_pem, public_pem = test_keys
    _, permyt_public_pem = permyt_keys
    c = StubPermytClient(private_key=private_pem, permyt_public_key=permyt_public_pem)
    return c, private_pem, public_pem


def test_sign_jwt_produces_valid_token(client_and_keys):
    client, _, public_pem = client_and_keys
    token = client._sign_jwt({"sub": "test", "data": "hello"})
    assert isinstance(token, (str, bytes))
    claims = jwt.decode(token, ECKey.import_key(public_pem)).claims
    assert claims["sub"] == "test"
    assert claims["data"] == "hello"


def test_create_and_verify_proof(client_and_keys, test_keys):
    client, _, public_pem = client_and_keys
    payload = {"foo": "bar", "num": 42}
    proof = client._create_proof(payload)
    # Should not raise
    client._verify_proof(proof, payload, public_pem)


def test_verify_proof_tampered_payload(client_and_keys, test_keys):
    client, _, public_pem = client_and_keys
    payload = {"foo": "bar"}
    proof = client._create_proof(payload)
    with pytest.raises(InvalidProofError):
        client._verify_proof(proof, {"foo": "TAMPERED"}, public_pem)


def test_verify_proof_wrong_public_key(client_and_keys):
    client, _, _ = client_and_keys
    payload = {"foo": "bar"}
    proof = client._create_proof(payload)
    _, other_public = _generate_ec_keypair()
    with pytest.raises(InvalidProofError):
        client._verify_proof(proof, payload, other_public)


def test_jwe_encrypt_decrypt_roundtrip(test_keys, permyt_keys):
    private_pem, public_pem = test_keys
    _, permyt_pub = permyt_keys
    client = StubPermytClient(private_key=private_pem, permyt_public_key=permyt_pub)
    original = {"secret": "data", "nested": [1, 2, 3]}

    # Encrypt for ourselves (using our own public key as recipient)
    encrypted = client._encrypt_jwe(original, public_pem)
    assert isinstance(encrypted, (str, bytes))

    # Decrypt with our private key
    decrypted = client._decrypt_data(encrypted)
    assert decrypted == original


def test_encrypt_jwe_without_public_key(client_and_keys):
    client, _, _ = client_and_keys
    with pytest.raises(InvalidPublicKeyError):
        client._encrypt_jwe({"data": "test"})


def test_decrypt_with_wrong_key(test_keys, permyt_keys):
    private_pem, public_pem = test_keys
    _, permyt_pub = permyt_keys
    client = StubPermytClient(private_key=private_pem, permyt_public_key=permyt_pub)

    # Encrypt for our key
    encrypted = client._encrypt_jwe({"secret": "value"}, public_pem)

    # Try to decrypt with a different key
    other_private, _ = _generate_ec_keypair()
    other_client = StubPermytClient(private_key=other_private, permyt_public_key=permyt_pub)
    with pytest.raises(InvalidPayloadError):
        other_client._decrypt_data(encrypted)


def test_load_private_key_invalid_pem(permyt_keys):
    _, permyt_pub = permyt_keys
    with pytest.raises(ValueError):
        StubPermytClient(private_key="not-a-valid-pem", permyt_public_key=permyt_pub)
