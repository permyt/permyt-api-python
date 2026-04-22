from __future__ import annotations
from typing import Any, Literal, TypeAlias, TypedDict

# -----------------------------------------------------------------------------
# Scope grant — approved scopes plus their locked "force input" values
# -----------------------------------------------------------------------------


ScopeGrant: TypeAlias = dict[str, dict[str, Any]]
"""
Approved scopes for a token, keyed by scope reference.

Each value is a dict of **force inputs** — parameters that the user (or the
PERMYT AI evaluator on their behalf) locked in at approval time and that the
provider must persist with the issued token. The provider then enforces them
inside ``process_request`` so an agent cannot change values between the moment
the user approved the request and the moment the requester actually executes
the call.

For scopes that declare no inputs, the value is an empty dict ``{}``.

Example::

    {
        "payments.send": {
            "amount": 1000,
            "currency": "USD",
            "receiver": "alice@example.com",
        },
        "identity.basic": {},
    }
"""


# -----------------------------------------------------------------------------
# Data structures for requesting access and checking status (requester → PERMYT)
# -----------------------------------------------------------------------------


class AccessRequest(TypedDict):
    """
    Payload a requester sends to PERMYT to ask for access to a user's data.
    """

    user_id: str
    description: str
    callback_url: str | None
    request_id: str | None


class AccessPayload(TypedDict):
    """
    Outer payload PERMYT returns to the requester on an approved access request.
    Contains JWE-encrypted provider credentials plus replay-prevention metadata.
    """

    data: str  # JWE encrypted list[ServiceCredential]
    nonce: str
    timestamp: str  # ISO 8601 format


class AccessStatus(TypedDict):
    """
    PERMYT's response to a request_access or check_access call.
    """

    request_id: str
    status: str  # "pending", "approved", "denied"
    services: list[ServiceCredential] | None


class AccessResponse(TypedDict):
    """
    Signed PERMYT response delivered to the requester when access is approved.
    Contains the encrypted provider list and a proof the requester must verify.
    """

    payload: AccessPayload
    proof: str  # JWT signed by PERMYT's private key, proving payload authenticity


# -----------------------------------------------------------------------------
# Data structures for exchanging tokens between requester and PERMYT
# -----------------------------------------------------------------------------


class ExchangeToken(TypedDict):
    """
    Request payload for obtaining a short-lived token that can be passed to
    another service to prove a user's identity without sharing raw credentials.
    """

    user_id: str
    token: str
    restricted_to: str


class RedeemedToken(TypedDict):
    """
    PERMYT's response when a requester redeems an exchange token.
    """

    user_id: str


# -----------------------------------------------------------------------------
# Data structures for PERMYT requesting tokens from providers (PERMYT → provider)
# -----------------------------------------------------------------------------


class TokenRequestData(TypedDict):
    """
    Decrypted inner data of a token request from PERMYT to a provider.

    PERMYT JWE-encrypts this with the provider's public key so only the
    provider can read it. ``service_public_key`` is the requester's public key
    — the provider uses it to encrypt the issued token so only the requester
    can decrypt it.

    ``scope`` is a :data:`ScopeGrant` mapping scope reference to a dict of
    locked input values (force inputs). The provider must persist these
    alongside the token so they can be enforced when the requester later calls
    a service endpoint.
    """

    request_id: str
    permyt_user_id: str
    service_id: str
    service_public_key: str  # The requester's public key
    scope: ScopeGrant
    ttl_minutes: int


class TokenMetadata(TypedDict):
    """
    Metadata a provider stores when issuing a token and retrieves when the
    requester presents that token to make a call.

    ``service_public_key`` is the requester's public key (as recorded in the
    original token request). The provider uses it to verify the requester's
    proof of possession on incoming calls.

    ``scope`` is the :data:`ScopeGrant` originally received from PERMYT,
    including the locked force-input values. The provider's
    ``process_request`` implementation must validate the incoming request
    against these locked values to prevent agents from tampering with
    parameters between approval and execution.
    """

    user: Any  # Internal user object from resolve_user
    scope: ScopeGrant
    service_public_key: str  # The requester's public key
    expires_at: str  # ISO 8601 format


# -----------------------------------------------------------------------------
# Data structures for encrypted requests
# -----------------------------------------------------------------------------


class EncryptedPayload(TypedDict):
    """
    Outer payload of a token request from PERMYT to a provider.
    Contains JWE-encrypted data plus replay-prevention metadata.
    """

    data: str  # JWE encrypted data
    nonce: str
    timestamp: str  # ISO 8601 format


class EncryptedRequest(TypedDict, total=False):
    """
    Complete signed token request from PERMYT to a provider.

    Carries an outer ``action`` discriminator so a single webhook URL can
    handle every inbound action — see ``handle_webhook`` on ``PermytClient``.
    Older callers that don't set ``action`` still work; the dispatcher only
    uses it when present.
    """

    action: str  # one of: token_request, service_call, user_connect, request_status
    payload: EncryptedPayload
    proof: str  # JWT signed by PERMYT's private key, proving payload authenticity


class RequestStatus(TypedDict, total=False):
    """
    Decrypted inner data of a status callback PERMYT sends to a requester
    when an access request changes state.

    ``services`` is populated only on the COMPLETED status (it carries the
    encrypted token bundle the requester then forwards to the providers).
    ``reason`` is populated only on terminal failure states (rejected,
    incomplete, unavailable).
    """

    request_id: str
    status: str
    services: list[ServiceCredential]
    reason: str


# -----------------------------------------------------------------------------
# Data structures for requester calls to providers (requester → provider)
# -----------------------------------------------------------------------------


class ServiceCredential(TypedDict):
    """
    A single provider access grant returned to the requester by PERMYT.
    Contains the JWE-encrypted token and the endpoints the requester may call.
    """

    request_id: str
    encrypted_token: str  # JWE encrypted for the requester's public key
    endpoints: list[ServiceCallEndpoint]
    expires_at: str
    public_key: str  # Provider's public key, used to encrypt the request payload


class ServiceCallPayload(TypedDict):
    """
    Outer payload of a requester call to a provider endpoint.
    Contains JWE-encrypted request data plus replay-prevention metadata.
    """

    data: str  # JWE encrypted request data
    nonce: str
    timestamp: str  # ISO 8601 format


class ServiceCallRequest(TypedDict):
    """
    Complete signed request from a requester to a provider endpoint.
    """

    token: str  # Single-use JWT issued by the provider
    payload: ServiceCallPayload
    proof: str  # JWT signed by the requester's private key, proving payload authenticity


class ServiceCallEndpoint(TypedDict):
    """
    A provider endpoint exposed to requesters for a given scope.
    """

    url: str
    description: str | None
    input_fields: dict[str, str] | None  # field_name → description


# -----------------------------------------------------------------------------
# Login & Connect user with service account (user → service)
# -----------------------------------------------------------------------------


class ConnectPayload(TypedDict):
    """
    Payload passed to the user for the connect/login flow.
    Can be delivered via QR code, NFC, or an OAuth redirect button.

    This is a fully-formed signed service-request envelope — the same shape
    used by every other service-to-PERMYT call. The inner ``payload.data`` is
    a JWE-encrypted JWT readable only by PERMYT (which holds the private half
    of the key the service used to encrypt). PERMYT's existing
    ``ServiceRequestSerializer`` consumes this envelope unchanged.
    """

    service_id: str
    payload: EncryptedPayload
    proof: str  # JWT signed by the service's private key, proving payload authenticity


class ConnectRequest(TypedDict):
    """
    Request from PERMYT to the service when a user completes a connect/login flow.
    Contains the signed JWT originally issued by the service via generate_connect_token()
    and the PERMYT user_id of the person who completed the connect flow.
    """

    token: str  # Signed JWT issued by the service via generate_connect_token()
    permyt_user_id: str  # The caller's PERMYT identity


# -----------------------------------------------------------------------------
# Consent mode values (mirrors broker's ConsentMode TextChoices)
# -----------------------------------------------------------------------------


ConsentMode: TypeAlias = Literal["auto_grant", "prompt_once", "prompt_always"]
"""
Consent mode for a scope, controlling how requests for that scope are handled.

- ``auto_grant`` — Automatically approve for any requester.
- ``prompt_once`` — Ask on first request per requester, then remember.
- ``prompt_always`` — Always ask, never persist grant.
"""


# -----------------------------------------------------------------------------
# Data structures for scope management (service → PERMYT)
# -----------------------------------------------------------------------------


class ScopeInput(TypedDict):
    """
    A single input field declaration for a scope.

    Inputs are required parameters that the Provider needs to issue a token
    (e.g. a ``payments.send`` scope declaring ``amount``, ``currency``, ``receiver``).
    """

    name: str
    description: str


class ScopeDefinition(TypedDict, total=False):
    """
    A scope definition for programmatic scope management via ``update_scopes()``.

    Only ``reference`` and ``name`` are required. All other fields have defaults
    on the broker side (``description``: null, ``inputs``: [], ``default_consent_mode``:
    ``"prompt_once"``, ``high_sensitivity``: False).
    """

    reference: str  # Required — unique identifier within the service
    name: str  # Required — human-readable display name
    description: str | None
    inputs: list[ScopeInput]
    default_consent_mode: ConsentMode
    high_sensitivity: bool


class UpdateScopesResponse(TypedDict):
    """
    Response from PERMYT after a scope update operation.
    """

    created: int
    updated: int
    deleted: int
