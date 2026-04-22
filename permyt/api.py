from abc import ABC, abstractmethod

from .mixins.encryption import EncryptionMixin
from .mixins.errors import ErrorsMixin
from .mixins.http import HTTPClientMixin
from .mixins.requests import (
    InboundMixin,
    ProviderMixin,
    RequesterMixin,
    ScopeManagementMixin,
    UserConnectMixin,
)

__all__ = ("PermytClient",)


class PermytClient(
    ABC,
    EncryptionMixin,
    ErrorsMixin,
    HTTPClientMixin,
    RequesterMixin,
    ProviderMixin,
    UserConnectMixin,
    ScopeManagementMixin,
    InboundMixin,
):
    """
    Abstract base class for participating in the PERMYT protocol.

    A service may act as a requester (asking for data), a provider (responding
    with data), or both. This class combines all the necessary machinery for
    either role: cryptographic signing and verification (ES256/JWE), HTTP
    transport, and the full PERMYT request lifecycle.

    All subclasses must implement:
        - get_private_key()               — PEM string or file path
        - get_service_id()                — identity registered with PERMYT
        - get_permyt_public_key()         — verify PERMYT's signatures
        - _validate_nonce_and_timestamp() — replay attack prevention

    Requester role (implement if requesting data):
        - _prepare_data_for_endpoint()  — build request payload per endpoint

    Provider role (implement if serving data):
        - resolve_user()                — map PERMYT user to internal user
        - store_token()                 — persist issued token
        - get_token_metadata()          — retrieve and validate token
        - get_endpoints_for_scope()     — map scope to endpoints
        - process_request()             — handle validated request

    Connect capability (implement if supporting user linking):
        - process_user_connect()        — handle user login/linking
    """

    def __init__(self, host: str | None = None):
        """
        Initialize a PermytClient.

        Args:
            host (str, optional): PERMYT server URL. Defaults to "https://permyt.io".
        """
        self.host = host or "https://permyt.io"
        self.private_key = self._load_private_key(self.get_private_key())
        self.service_id = self.get_service_id()

    @abstractmethod
    def get_private_key(self) -> str:
        """
        Return the PEM string or file path of this client's private key for JWE decryption.
        """

    @abstractmethod
    def get_service_id(self) -> str:
        """
        Return the unique identifier registered with PERMYT for this service.
        Obtain this from your PERMYT dashboard and return it here.

        Returns:
            str: The service's unique PERMYT identifier.
        """
