from datetime import datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from permyt import PermytClient
from permyt.typing import (
    ConnectRequest,
    DisconnectRequest,
    ScopeGrant,
    ServiceCallEndpoint,
    TokenMetadata,
    TokenRequestData,
)


def _generate_ec_keypair() -> tuple[str, str]:
    """Generate an ECDSA P-256 key pair and return (private_pem, public_pem)."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private_pem, public_pem


@pytest.fixture
def test_keys():
    return _generate_ec_keypair()


@pytest.fixture
def permyt_keys():
    return _generate_ec_keypair()


class StubPermytClient(PermytClient):
    """Concrete stub implementing all abstract methods for testing."""

    def __init__(self, private_key: str, permyt_public_key: str, **kwargs):
        self._private_key = private_key
        self._permyt_public_key = permyt_public_key
        self._token_store: dict[str, dict] = {}
        super().__init__(**kwargs)

    def get_private_key(self) -> str:
        return self._private_key

    def get_service_id(self) -> str:
        return "test-service"

    def get_permyt_public_key(self) -> str:
        return self._permyt_public_key

    def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str) -> None:
        pass  # accept all for testing

    def _prepare_data_for_endpoint(
        self, request_id: str, endpoint: ServiceCallEndpoint
    ) -> dict[str, Any]:
        return {"test": "data"}

    def resolve_user(self, permyt_user_id: str | None = None) -> Any:
        return {"id": "user-1"}

    def store_token(
        self, token: str, user: Any, data: TokenRequestData, expires_at: datetime
    ) -> None:
        # The token is signed by this service, so verify against our own
        # public key (derived from the loaded private key).
        from joserfc import jwt as joserfc_jwt

        claims = joserfc_jwt.decode(token, self.private_key).claims
        self._token_store[claims["jti"]] = {
            "token": token,
            "user": user,
            "scope": data["scope"],
            "service_public_key": data["service_public_key"],
            "expires_at": expires_at.isoformat(),
            "used": False,
        }

    def get_token_metadata(self, token: str) -> TokenMetadata:
        from joserfc import jwt as joserfc_jwt

        claims = joserfc_jwt.decode(token, self.private_key).claims
        record = self._token_store.get(claims["jti"])
        if not record:
            from permyt.exceptions import InvalidTokenError

            raise InvalidTokenError()
        if record["used"]:
            from permyt.exceptions import TokenAlreadyUsedError

            raise TokenAlreadyUsedError()
        record["used"] = True
        return {
            "user": record["user"],
            "scope": record["scope"],
            "service_public_key": record["service_public_key"],
            "expires_at": record["expires_at"],
        }

    def get_endpoints_for_scope(self, scope: ScopeGrant) -> list[ServiceCallEndpoint]:
        return [
            {
                "url": "https://example.com/api/data",
                "description": "Test endpoint",
                "input_fields": None,
            }
        ]

    def process_request(self, metadata: TokenMetadata, data: dict[str, Any]) -> dict[str, Any]:
        return {"result": "ok"}

    def process_user_connect(self, data: ConnectRequest) -> dict[str, Any]:
        return {"connected": True}

    def process_user_disconnect(self, data: DisconnectRequest) -> dict[str, Any]:
        self._disconnected_users = getattr(self, "_disconnected_users", [])
        self._disconnected_users.append(data["permyt_user_id"])
        return {"disconnected": True}


@pytest.fixture
def client(test_keys, permyt_keys):
    private_pem, _ = test_keys
    _, permyt_public_pem = permyt_keys
    return StubPermytClient(private_key=private_pem, permyt_public_key=permyt_public_pem)
