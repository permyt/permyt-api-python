# PERMYT Python SDK

Let users control what data gets shared when AI agents and services act on their behalf.

## Why PERMYT

Today, services exchange data through forms, manual integrations, and shared credentials. Users lose visibility the moment they grant access. As AI agents begin acting on behalf of users — coordinating across services, requesting data, triggering actions — the question becomes: who decides what an agent can access?

PERMYT is the authorization layer that answers this. Users approve each access request explicitly, scoped to exactly what is needed. Data flows directly between services. PERMYT brokers the authorization but never sees, stores, or handles user data.

## How It Works

1. **An agent asks** — A service requests access to user data: "I need your employment history to process your application."
2. **The user decides** — The user receives a notification on their phone showing exactly what is being requested. They approve or deny.
3. **The agent gets access** — Limited to what the user approved. Data flows directly from the source provider to the requester. PERMYT steps aside.

PERMYT is a zero-knowledge broker. It coordinates authorization tokens between services but never touches the data itself. Providers encrypt tokens for the requester's public key — PERMYT cannot decrypt them.

## Where Your Service Fits

A service integrating with PERMYT plays one or more of three roles:

- **Requester** — Your service needs data from other services. Example: a loan application that needs employment history from an HR platform.
- **Provider** — Your service holds user data that other services may request. Example: a bank providing income verification, an HR platform providing employment records.
- **Connect** — Any service can link user accounts with PERMYT via QR code, NFC, or OAuth button, so users can approve requests without re-entering credentials.

A service can be a requester, a provider, or both. Any service can additionally implement Connect.

## Table of Contents

- [Why PERMYT](#why-permyt)
- [How It Works](#how-it-works)
- [Where Your Service Fits](#where-your-service-fits)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Building a Requester](#building-a-requester)
  - [Building a Provider](#building-a-provider)
  - [Connecting Users](#connecting-users)
- [The Full Cycle](#the-full-cycle)
- [Key Concepts](#key-concepts)
  - [Per-Request Scoping](#per-request-scoping)
  - [Force Inputs (Locked Parameters)](#force-inputs-locked-parameters)
  - [Scope Management](#scope-management)
- [Key Generation](#key-generation)
- [Security Best Practices](#security-best-practices)
- [API Reference](#api-reference)
  - [The PermytClient](#the-permytclient)
  - [Required Implementations](#required-implementations)
  - [Error Handling](#error-handling)
  - [Type Definitions](#type-definitions)

## Installation

```bash
pip install permyt
```

**Requirements:**

- Python 3.10+
- Dependencies: `joserfc`, `cryptography`, `requests`

## Quick Start

### Building a Requester

A requester asks PERMYT for access to user data. The user approves via their phone. The requester receives encrypted tokens and calls providers directly — PERMYT is not involved in the data exchange.

**Responsibilities:**

_Security_

- Implement `_validate_nonce_and_timestamp` properly to reject replayed responses from PERMYT — see [Nonce Storage](#nonce-storage).
- If using a `callback_url`, the endpoint must pass the raw request body directly to `handle_approved_access`. The SDK verifies PERMYT's signature internally — never process the payload before this call.
- Do not cache or persist decrypted provider responses beyond the immediate request lifecycle.

_UX and integrity_

- `description` is shown word-for-word to the user when they decide whether to approve. Be honest and specific ("Grant eligibility check — I need your employment history to evaluate loan eligibility") — vague or misleading descriptions erode user trust and may violate PERMYT's terms. Include any concrete values the agent has on hand (amounts, recipients, identifiers) so PERMYT's AI can lock the issued token to those exact parameters.
- In `_prepare_data_for_endpoint`, send only the inputs the endpoint actually needs. Do not forward arbitrary user data.
- Handle a `"denied"` status gracefully. Do not retry automatically or re-prompt the user without a meaningful change in context.

```python
from permyt.api import PermytClient

class MyService(PermytClient):
    def get_service_id(self) -> str:
        return "my-service-id"

    def get_private_key(self) -> str:
        return "./private.pem"

    def get_permyt_public_key(self) -> str:
        return open("permyt_public.pem").read()

    def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str) -> None:
        # See Security Best Practices section
        pass

    def _prepare_data_for_endpoint(self, request_id: str, endpoint: dict) -> dict:
        return {"query": "employment history", "years": 5}

    # --- Provider methods (required, stub if this service only requests data) ---
    def resolve_user(self, permyt_user_id): ...
    def store_token(self, token, user, scope, expires_at): ...
    def get_token_metadata(self, token): ...
    def get_endpoints_for_scope(self, scope): ...
    def process_request(self, metadata, data): ...


service = MyService()

# Request access to user data
status = service.request_access({
    "user_id": "123e4567-e89b-12d3-a456-426614174000",
    "description": "Grant eligibility check — I need employment and income info to evaluate eligibility.",
    "callback_url": "https://my-service.io/permyt/callback",
})

# Poll for approval (or receive via callback_url)
status = service.check_access(request_id=status["request_id"])

# Call approved providers
if status["status"] == "approved":
    responses = service.handle_approved_access(status)
```

### Building a Provider

A provider holds user data. When a user approves an access request, PERMYT asks the provider to issue a single-use encrypted token. The requester then calls the provider directly to redeem it — PERMYT is not involved in the data exchange.

**Responsibilities:**

_Security_

- In `get_token_metadata`, mark the token as used **atomically** (e.g., `select_for_update` in SQL or `SET NX` in Redis) to prevent two concurrent requests from consuming the same single-use token.
- In `process_request`, enforce scope strictly: return **only** the fields covered by `metadata["scope"]`. The scope is the contract the user approved — returning additional fields violates the user's intent regardless of what the requester sends in `data`.
- In `resolve_user`, treat `permyt_user_id` as the sole trusted identifier from PERMYT. Do not use any other field from the decrypted request data to identify the user.

_Data hygiene_

- In `get_endpoints_for_scope`, return only endpoints that correspond to the approved scope labels. Do not expose unscoped endpoints.
- Return structured, stable response shapes from `process_request` so requesters can reliably parse the data across versions.
- Expire and clean up used or expired token records regularly to keep storage lean.

```python
from permyt.api import PermytClient
from permyt.typing import ServiceCallEndpoint, TokenMetadata

class MyService(PermytClient):
    def get_service_id(self) -> str:
        return "my-service-id"

    def get_private_key(self) -> str:
        return "./private.pem"

    def get_permyt_public_key(self) -> str:
        return open("permyt_public.pem").read()

    def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str) -> None:
        # See Security Best Practices section
        pass

    def resolve_user(self, permyt_user_id: str):
        user = User.objects.filter(permyt_id=permyt_user_id).first()
        if not user:
            from permyt.exceptions import InvalidUserError
            raise InvalidUserError()
        return user

    def store_token(self, token: str, user, data: dict, expires_at):
        # ``data`` is a TokenRequestData — persist scope (with locked force
        # inputs) and service_public_key so get_token_metadata and
        # process_request can use them later.
        TokenStorage.objects.create(
            token=token,
            user=user,
            scope=data["scope"],  # e.g. {"payments.send": {"amount": 1000, ...}}
            service_public_key=data["service_public_key"],
            expires_at=expires_at,
            used=False,
        )

    def get_token_metadata(self, token: str) -> TokenMetadata:
        from joserfc import jwt
        from permyt.exceptions import InvalidTokenError, TokenAlreadyUsedError, TokenExpiredError

        try:
            claims = jwt.decode(token, self.private_key).claims
        except Exception:
            raise InvalidTokenError()

        jti = claims["jti"]
        record = TokenStorage.objects.filter(jti=jti).first()
        if not record:
            raise InvalidTokenError()
        if record.used:
            raise TokenAlreadyUsedError()
        if record.is_expired():
            raise TokenExpiredError()

        record.used = True
        record.save()

        return {
            "user": record.user,
            "scope": record.scope,
            "service_public_key": claims["issued_to"],
            "expires_at": record.expires_at.isoformat(),
        }

    def get_endpoints_for_scope(self, scope: dict) -> list:
        # ``scope`` is a ScopeGrant — its keys are the approved scope
        # references. ``in`` membership tests work the same as for a list.
        endpoints = []
        if "professional" in scope:
            endpoints.append({
                "url": "https://my-service.com/api/employment",
                "description": "Employment history",
                "input_fields": {"years": "Years of history"},
            })
        if "payments.send" in scope:
            endpoints.append({
                "url": "https://my-service.com/api/payments",
                "description": "Send a payment",
                "input_fields": {
                    "amount": "Amount in smallest currency unit",
                    "currency": "ISO 4217 code",
                    "receiver": "Recipient identifier",
                },
            })
        return endpoints

    def process_request(self, metadata: TokenMetadata, data: dict) -> dict:
        from permyt.exceptions import InvalidInputError

        scope = metadata["scope"]
        response = {}

        # Plain scope — no force inputs to enforce
        if "professional" in scope:
            response["employment"] = {
                "company": metadata["user"].current_company,
                "title": metadata["user"].job_title,
            }

        # Force-input enforcement: the user approved a payment for an exact
        # amount, currency, and receiver. Reject anything else — this is the
        # security boundary that stops an agent from rewriting the call.
        if "payments.send" in scope:
            locked = scope["payments.send"]
            if (
                data.get("amount") != locked["amount"]
                or data.get("currency") != locked["currency"]
                or data.get("receiver") != locked["receiver"]
            ):
                raise InvalidInputError()
            response["payment"] = self.send_payment(
                user=metadata["user"],
                amount=locked["amount"],
                currency=locked["currency"],
                receiver=locked["receiver"],
            )

        return response

    # --- Requester method (required, stub if this service only provides data) ---
    def _prepare_data_for_endpoint(self, request_id, endpoint): ...


service = MyService()

# Option 1: Single inbound endpoint (recommended)
# Register one URL with PERMYT — handle_inbound routes by action field
def handle_permyt_inbound(request):
    return service.handle_inbound(request.json())

# Option 2: Separate routes per action
def handle_permyt_token_request(request):
    return service.handle_token_request(request.json())

def handle_requester_call(request):
    return service.handle_service_call(request.json())
```

### Connecting Users

Any service — whether it acts as a requester, a provider, or both — can implement the Connect flow to link users' accounts with their PERMYT identity. This lets users approve access requests without re-entering credentials and lets your service resolve a `permyt_user_id` to an internal user.

```python
from permyt.api import PermytClient
from permyt.typing import ConnectRequest

class MyService(PermytClient):
    def get_service_id(self) -> str:
        return "my-service-id"

    def get_private_key(self) -> str:
        return "./private.pem"

    def get_permyt_public_key(self) -> str:
        return open("permyt_public.pem").read()

    def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str) -> None:
        # See Security Best Practices section
        pass

    def process_user_connect(self, data: ConnectRequest) -> dict:
        from joserfc import jwt
        from permyt.exceptions import InvalidTokenError

        # Validate the token the service originally issued
        try:
            claims = jwt.decode(data["token"], self.private_key).claims
        except Exception:
            raise InvalidTokenError()

        jti = claims["jti"]
        system_user_id = claims.get("system_user_id")
        permyt_user_id = data["permyt_user_id"]

        if system_user_id:
            # Account-linking: associate existing account with PERMYT user
            User.objects.filter(id=system_user_id).update(permyt_id=permyt_user_id)
        else:
            user = User.objects.filter(permyt_id=permyt_user_id).first()
            if not user:
                # New user: create account
                user = User.objects.create(permyt_id=permyt_user_id)
            # else: returning user — log them in

        return {"status": "ok"}

    # --- Requester / Provider stubs (implement or leave empty as needed) ---
    def _prepare_data_for_endpoint(self, request_id, endpoint): ...
    def resolve_user(self, permyt_user_id): ...
    def store_token(self, token, user, scope, expires_at): ...
    def get_token_metadata(self, token): ...
    def get_endpoints_for_scope(self, scope): ...
    def process_request(self, metadata, data): ...


service = MyService()

# Anonymous login / sign-up
result = service.generate_connect_token()
# Store result["token"] server-side (keyed by JTI) for signature validation
# result["data"] is a ConnectPayload encrypted for PERMYT — safe to transfer via any channel

payload = result["data"]

# Option 1: QR code (pip install qrcode)
import qrcode
qr = qrcode.make(payload)

# Option 2: NFC tag
import json
nfc_tag.write(json.dumps(payload))

# Option 3: OAuth-style redirect button
import urllib.parse
redirect_url = f"https://permyt.io/connect?payload={urllib.parse.quote(json.dumps(payload))}"

# Account-linking: pass system_user_id for already-authenticated users
result = service.generate_connect_token(system_user_id="user-42")

# Wire into your API route — PERMYT calls this after the user completes the connect flow
# If using handle_inbound (recommended), this is routed automatically via action="user_connect"
def handle_permyt_user_connect(request):
    return service.handle_user_connect(request.json())
```

## The Full Cycle

Here is the complete request-access cycle, showing how requester, user, PERMYT, and provider interact:

```
                          ┌──────────┐
                          │   User   │
                          │(Approves)│
                          └─────┬────┘
                                │
┌───────────┐          ┌────────▼─────┐          ┌──────────┐
│ Requester │          │    PERMYT    │          │ Provider │
│ (Wants    │◄──token──┤   (Broker)   ├─request─►│ (Has     │
│  data)    │          │ never sees   │          │  data)   │
│           ├─request─►│     data     │◄─token───┤          │
└─────┬─────┘          └──────────────┘          └──────────┘
      │                                               ▲
      └──────────────── calls directly ───────────────┘
```

1. **Requester** calls `request_access()` with a natural-language description of what it needs and why.
2. **User** receives a notification on their phone and approves a permission level. PERMYT's AI evaluates the request and determines the minimum scope needed — the requester never gets more than necessary.
3. **PERMYT** sends a token request to each relevant provider, including the approved scope, the requester's public key, and any locked force-input values.
4. **Provider** issues a signed, single-use token encrypted for the requester's public key. PERMYT forwards it to the requester but cannot decrypt it.
5. **Requester** decrypts the token and calls the provider directly. PERMYT is no longer involved.
6. **Provider** validates the token, enforces scope and force inputs, and returns the approved data.

**PERMYT never sees:** user data, decrypted tokens, provider responses, or what data was actually accessed.

## Key Concepts

### Per-Request Scoping

When users approve a permission level, they grant a _maximum_ scope. PERMYT evaluates each request and determines the minimal scope needed for that specific task.

```
User approves: "Financial" level
  ↓
  Maximum scope = ["income", "assets", "debts", "transactions"]

Request 1: "Check if user qualifies for loan"
  ↓
  PERMYT evaluates: Only needs income verification
  ↓
  Issued scope = ["income"]

Request 2: "Generate full financial report"
  ↓
  PERMYT evaluates: Needs comprehensive data
  ↓
  Issued scope = ["income", "assets", "debts", "transactions"]
```

**Key principle**: PERMYT issues the _minimum scope_ needed for each request, never more than the user approved. This limits exposure even within an approved permission level.

**If scope is insufficient**: Requester can make additional requests asking for more data. User is prompted again if the new request requires a higher permission level than previously approved.

### Force Inputs (Locked Parameters)

Some scopes need more than just permission to act — they need the **specific values** the user approved to be locked into the issued token. A scope like `payments.send` is meaningless without an amount, currency, and recipient: if those values were free for the requester (or its underlying agent) to choose at execution time, an agent could redirect a $10 approval into a $10,000 wire transfer to a different account. Force inputs close that gap.

**How it works**: When a user approves a request, PERMYT extracts the relevant input values from the request description and includes them in the token issuance call to the provider. The provider stores those values alongside the token and **must** validate every incoming service call against them inside `process_request`.

`scope` flows through the SDK as a `ScopeGrant` — a dict mapping scope reference to its locked input values:

```python
scope = {
    "payments.send": {
        "amount": 1000,
        "currency": "USD",
        "receiver": "alice@example.com",
    },
    "identity.basic": {},  # no force inputs for this scope
}
```

For scopes that declare no inputs the value is an empty dict, so `if "identity.basic" in scope:` still works exactly like a list membership test.

**Provider responsibilities**:

1. In `store_token`, persist the **full** `scope` dict — not just the keys.
2. In `process_request`, for any scope whose value is non-empty, compare the locked values against `data` and raise `InvalidInputError` on any mismatch.
3. The SDK does **not** auto-enforce force inputs because comparison semantics are scope-specific (exact match for a payment, max cap for a withdrawal, range for a date filter, etc.) and only the provider knows them.

See the `payments.send` example in [Building a Provider](#building-a-provider) for a complete enforcement pattern.

### Scope Management

Services can programmatically update their scopes via `update_scopes()`. The submitted list is the **desired final state** — PERMYT diffs by `reference` to create, update, or delete scopes as needed.

```python
result = service.update_scopes([
    {
        "reference": "payments.send",
        "name": "Send payment",
        "description": "Initiate a payment transfer",
        "inputs": [
            {"name": "amount", "description": "Amount in smallest currency unit"},
            {"name": "currency", "description": "ISO 4217 currency code"},
            {"name": "receiver", "description": "Recipient identifier"},
        ],
        "default_consent_mode": "prompt_always",
        "high_sensitivity": True,
    },
    {
        "reference": "identity.basic",
        "name": "Basic identity",
    },
])

print(result)  # {"created": 2, "updated": 0, "deleted": 0}
```

**Fields per scope:**

| Field | Required | Default | Description |
|---|---|---|---|
| `reference` | Yes | — | Unique machine-readable identifier within the service |
| `name` | Yes | — | Human-readable display name |
| `description` | No | `None` | Longer description of the scope |
| `inputs` | No | `[]` | List of `{name, description}` input fields required for token issuance |
| `default_consent_mode` | No | `"prompt_once"` | One of `"auto_grant"`, `"prompt_once"`, `"prompt_always"` |
| `high_sensitivity` | No | `False` | Flag for scopes requiring additional user attention |

**Notes:**
- When new scopes are created, `ScopeConsent` records are automatically materialized for all existing user connections.
- Deleting a scope (by omitting it from the list) cascades to remove related `ScopeConsent` and `GrantedScope` records.

## Key Generation

All services need ES256 (ECDSA P-256) key pairs.

```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out private.pem

# Extract public key
openssl ec -in private.pem -pubout -out public.pem
```

**Security:**

- Keep `private.pem` secret (never commit to version control)
- Register `public.pem` with PERMYT via your dashboard
- Store private keys in environment variables or secret management systems
- Rotate keys every 90 days

## Security Best Practices

### Nonce Storage

Implement nonce validation to prevent replay attacks:

```python
# Redis example
import redis
from datetime import timedelta

redis_client = redis.Redis(host='localhost', port=6379, db=0)

def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str):
    from datetime import datetime, timezone
    from permyt.exceptions import ExpiredRequestError

    # Validate timestamp (±30 seconds)
    request_time = datetime.fromisoformat(timestamp)
    now = datetime.now(timezone.utc)
    if abs((now - request_time).total_seconds()) > 30:
        raise ExpiredRequestError("Timestamp outside valid window")

    # Check nonce (replay prevention)
    key = f"nonce:{nonce}"
    if redis_client.exists(key):
        raise ExpiredRequestError("Nonce already used")

    # Store nonce with 60 second TTL
    redis_client.setex(key, timedelta(seconds=60), "1")
```

### Token Storage

Use a relational database for token metadata:

```python
# Django example
from django.db import models

class PermytToken(models.Model):
    token = models.TextField(unique=True)  # Store complete JWT
    jti = models.CharField(max_length=64, unique=True, db_index=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scope = models.JSONField()
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Extract JTI once on save for efficient lookup later
        if not self.jti:
            import json, base64
            payload_b64 = self.token.split(".")[1] + "=="
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            self.jti = claims["jti"]
        super().save(*args, **kwargs)

    class Meta:
        indexes = [
            models.Index(fields=['jti', 'used']),
            models.Index(fields=['expires_at']),
        ]
```

### Key Storage

**Never hardcode or commit private keys.** Load from files or environment:

```python
import os

class MyService(PermytClient):
    def get_private_key(self) -> str:
        key_path = os.getenv("PERMYT_PRIVATE_KEY_PATH")
        if not key_path:
            raise ValueError("PERMYT_PRIVATE_KEY_PATH environment variable not set")
        return key_path
```

Or use secret management:

- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Google Secret Manager

## API Reference

### The PermytClient

Both requesters and providers use the same `PermytClient` base class. It handles all the cryptographic complexity of the PERMYT protocol — signing, encryption, proof verification — and provides the entry points for both roles.

```python
from permyt.api import PermytClient

class MyService(PermytClient):
    ...
```

The client provides:

- **Inbound dispatcher** (`handle_inbound`) — single entry point that routes by `action` field to the right handler; lets a service expose one URL instead of one per action
- **Requester methods** (`request_access`, `check_access`, `handle_approved_access`, `call_services`, `handle_request_status`, `process_request_status`, `request_token`, `redeem_token`) for requesting and consuming data
- **Provider methods** (`handle_token_request`, `handle_service_call`) for issuing tokens and processing incoming requests
- **Connect methods** (`generate_connect_token`, `handle_user_connect`) for linking user accounts via QR code, NFC, or OAuth button flows

### Required Implementations

Extend `PermytClient` and implement all abstract methods. The role a service plays (requester, provider, or both) determines which methods are actually exercised at runtime — but all must be defined.

#### Identity

```python
def get_service_id(self) -> str:
    """
    Return the unique identifier registered with PERMYT for this service.
    Get this from your PERMYT dashboard.
    """
```

#### Security (both roles)

```python
@abstractmethod
def get_permyt_public_key(self) -> str:
    """
    Return PERMYT's public key for verifying PERMYT's signatures.
    Get this from your PERMYT dashboard.
    """

@abstractmethod
def _validate_nonce_and_timestamp(self, nonce: str, timestamp: str) -> None:
    """
    Prevent replay attacks by validating request freshness.

    Must implement:
    - Check timestamp is within ±30 seconds of current time
    - Check nonce hasn't been used before
    - Store nonce with 60-second expiry

    Raises:
        ExpiredRequestError: If validation fails
    """
```

#### Requester side

```python
@abstractmethod
def _prepare_data_for_endpoint(
    self, request_id: str, endpoint: ServiceCallEndpoint
) -> dict[str, Any]:
    """
    Prepare input data to send to a specific provider endpoint.

    Args:
        request_id: The PERMYT request ID
        endpoint: Provider endpoint metadata (url, description, input_fields)

    Returns:
        Dictionary of data to send to this endpoint
    """
```

#### Connect side

```python
@abstractmethod
def process_user_connect(self, data: ConnectRequest) -> dict[str, Any] | None:
    """
    Handle user account creation, login, or PERMYT linking after a connect flow.

    Validate data["token"] against your server-side record, then apply one of:
        1. New user       — token not linked + unknown user_id: create account
        2. Returning user — token not linked + known user_id: log in
        3. Account link   — token linked to account + new user_id: link to PERMYT

    Raises:
        InvalidTokenError: If the token is invalid, expired, or already used
        InvalidInputError: If required fields are missing
    """
```

#### Provider side

```python
@abstractmethod
def resolve_user(self, permyt_user_id: str | None = None) -> Any:
    """
    Map PERMYT user ID to your internal user representation.

    Raises:
        InvalidUserError: If user doesn't exist in your service
    """

@abstractmethod
def store_token(
    self, token: str, user: Any, data: TokenRequestData, expires_at: datetime
) -> None:
    """
    Store issued token with its metadata for later validation.

    Args:
        token: The complete signed JWT token string
        user: Internal user object from resolve_user
        data: Full TokenRequestData from PERMYT. Key fields to persist:
            - data["scope"]: ScopeGrant with locked **force inputs**
              (e.g. ``{"payments.send": {"amount": 1000, "currency": "USD",
              "receiver": "alice@example.com"}}``). Must be persisted in full —
              the inner dicts are enforced later in ``process_request``.
            - data["service_public_key"]: Requester's public key, needed by
              ``get_token_metadata`` to verify proof of possession.
            - data["request_id"], data["service_id"]: Useful for auditing.
        expires_at: Token expiration timestamp
    """

@abstractmethod
def get_token_metadata(self, token: str) -> TokenMetadata:
    """
    Validate token and return its metadata.

    Must perform these checks in order:
    1. Verify token signature (proves your service issued it)
    2. Extract JTI from token claims
    3. Look up token in storage by JTI
    4. Verify token exists
    5. Verify token hasn't been used (single-use enforcement)
    6. Verify token hasn't expired
    7. Mark token as used
    8. Return metadata (user, scope, service_public_key, expires_at)

    Raises:
        InvalidTokenError: Token not found or signature invalid
        TokenAlreadyUsedError: Token already used
        TokenExpiredError: Token expired
    """

@abstractmethod
def get_endpoints_for_scope(self, scope: ScopeGrant) -> list[ServiceCallEndpoint]:
    """
    Map PERMYT permission scope to your service's API endpoints.

    Args:
        scope: ScopeGrant whose **keys** are the approved scope references
            (e.g. ``"professional"``, ``"employment"``). The dict values
            carry locked force inputs and can usually be ignored here —
            membership tests like ``"professional" in scope`` work as
            expected against dict keys.

    Returns:
        List of endpoints with url, description, and input_fields
    """

@abstractmethod
def process_request(
    self, metadata: TokenMetadata, data: dict[str, Any]
) -> dict[str, Any] | None:
    """
    Process a validated requester request and return approved data.

    All cryptographic and replay checks have passed at this point.
    Two responsibilities remain on the implementor:

    1. **Scope enforcement**: only return fields covered by the keys of
       ``metadata["scope"]``.
    2. **Force-input enforcement**: for any scope whose ``metadata["scope"]``
       value is non-empty, validate that ``data`` matches the locked values
       and raise ``InvalidInputError`` on mismatch. This is what stops an
       agent from changing parameters between approval and execution.

    Args:
        metadata: Token metadata (user, scope grant with force inputs,
            service_public_key, expires_at)
        data: Input from requester

    Returns:
        Response data to send back to the requester
    """
```

### Error Handling

The handler entry points (`handle_inbound`, `handle_token_request`, `handle_service_call`, `handle_user_connect`, `handle_request_status`) automatically catch and format errors. All PERMYT exceptions inherit from `PermytError`:

```python
from permyt.exceptions import (
    PermytError,           # Base exception
    SecurityError,         # Cryptographic validation failed
    InvalidTokenError,     # Token invalid or malformed
    TokenExpiredError,     # Token past expiry time
    TokenAlreadyUsedError, # Single-use token reused
    InvalidScopeError,     # Endpoint not in approved scope
    InvalidUserError,      # User doesn't exist
    InvalidProofError,     # Proof of possession failed
    InvalidPayloadError,   # Decryption failed
    ExpiredRequestError,   # Nonce/timestamp validation failed
    InvalidInputError,     # Input data invalid
)
```

Raise these in your implementations (e.g., `raise InvalidUserError()` in `resolve_user`). The handlers convert them automatically to properly formatted error responses.

### Type Definitions

The SDK includes full type definitions for all protocol messages:

```python
from permyt.typing import (
    # Access request/response (requester → PERMYT)
    AccessRequest,         # Access request payload
    AccessPayload,         # Outer payload with JWE data + nonce + timestamp
    AccessStatus,          # Pending/approved/denied status
    AccessResponse,        # PERMYT response with approved providers

    # Token exchange
    ExchangeToken,         # Token exchange request
    RedeemedToken,         # Token redemption response

    # Token issuance (PERMYT → provider)
    EncryptedPayload,      # Generic encrypted payload with replay-prevention metadata
    EncryptedRequest,      # Encrypted+signed request with action discriminator
    RequestStatus,         # Status callback data from PERMYT to requester
    TokenRequestData,      # Decrypted token request data
    TokenMetadata,         # Stored token metadata
    ScopeGrant,            # dict[scope_ref, locked_force_inputs]

    # Requester calls (requester → provider)
    ServiceCredential,     # Approved provider access with token
    ServiceCallPayload,    # Requester-to-provider call payload
    ServiceCallRequest,    # Complete requester-to-provider request
    ServiceCallEndpoint,   # Endpoint definition

    # User connect / login flow
    ConnectPayload,        # Connect payload generated by the service (QR code, NFC, or button)
    ConnectRequest,        # Decrypted connect request from PERMYT
)
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.permyt.io
- Issues: https://github.com/LeopardLabsAi/permyt-api-python/issues
- Email: support@permyt.io

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
