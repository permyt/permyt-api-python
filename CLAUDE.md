# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Permyt** is a Python SDK implementing the PERMYT user-controlled authorization protocol — a secure service-to-service data access system where users grant explicit, scoped permissions. The SDK supports two roles: **Requester** (asking for data) and **Provider** (serving data). Any service can additionally implement the **Connect** capability to link user accounts with PERMYT via QR code, NFC, or OAuth button.

## Commands

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
ruff format permyt/ tests/

# Lint
ruff check permyt/ tests/

# Type check
mypy permyt/
```

Code style: **100-character line length** (enforced by ruff).

## Architecture

### Mixin-Based Design

`PermytClient` in [permyt/api.py](permyt/api.py) inherits from multiple mixins rather than being a monolithic class:

- [mixins/encryption.py](permyt/mixins/encryption.py) — ES256 JWT signing, JWE encryption/decryption (ECDH-ES+A256KW + A256GCM), proof-of-possession tokens
- [mixins/http.py](permyt/mixins/http.py) — HTTP client with signed requests, nonce + ISO timestamp for replay attack prevention
- [mixins/errors.py](permyt/mixins/errors.py) — Exception-to-HTTP-response conversion
- [mixins/requests/requester.py](permyt/mixins/requests/requester.py) — Access requests, exchange token redeeming, calling providers
- [mixins/requests/provider.py](permyt/mixins/requests/provider.py) — Token issuance, service call handling, token validation
- [mixins/requests/connect.py](permyt/mixins/requests/connect.py) — connect payload generation (QR code, NFC, or button), user login/account linking flows
- [mixins/requests/webhook.py](permyt/mixins/requests/webhook.py) — `InboundMixin`: single-endpoint dispatcher (`handle_inbound`) that routes by `action` field to the right handler

### Abstract Methods Pattern

All SDK users subclass `PermytClient` and implement abstract methods. The framework calls these methods, catching `PermytError` exceptions and converting them to JSON responses.

**All subclasses must implement:**
```python
get_private_key() -> str                                  # PEM string or file path to private key
get_service_id() -> str
get_permyt_public_key() -> str
_validate_nonce_and_timestamp(nonce, timestamp) -> None  # Must reject replays (±30s window, 60s nonce TTL)
```

**Requester role additionally requires:**
```python
_prepare_data_for_endpoint(request_id, endpoint) -> dict  # Build payload for each provider endpoint call
```

**Provider role additionally requires:**
```python
resolve_user(permyt_user_id) -> Any
store_token(token, user, data: TokenRequestData, expires_at) -> None  # Persist full TokenRequestData (scope, service_public_key, etc.)
get_token_metadata(token) -> TokenMetadata
get_endpoints_for_scope(scope: ScopeGrant) -> list[ServiceCallEndpoint]
process_request(metadata, data) -> dict  # MUST enforce force inputs in metadata["scope"]
```

`ScopeGrant` is `dict[str, dict[str, Any]]` — keys are approved scope references, values are the **locked force-input values** the user approved (empty dict for scopes with no inputs). See the "Force Inputs" section below.

**Connect capability additionally requires:**
```python
process_user_connect(data: ConnectRequest) -> dict
process_user_disconnect(data: DisconnectRequest) -> dict  # idempotent local cleanup
```

### Security Model (SDK-specific)

The SDK implements the security invariants described in the Protocol Reference below. Key implementation details:

- **Force inputs (locked parameters)**: The `ScopeGrant` carried in `TokenRequestData.scope` and `TokenMetadata.scope` is `dict[scope_ref, locked_inputs]`. Providers **must** persist the full `TokenRequestData` in `store_token` (which includes `scope`, `service_public_key`, etc.) and validate incoming `data` against `metadata["scope"][ref]` inside `process_request`, raising `InvalidInputError` on mismatch. The SDK does not auto-enforce this — comparison semantics (exact match vs cap vs range) are scope-specific.
- **Encryption-for-recipient**: The `request()` method in [mixins/http.py](permyt/mixins/http.py) JWE-encrypts `data` when `recipient_public_key` is provided, then attaches a proof-of-possession JWT over the full payload. On the receiving end, `_extract_request_data()` and `_extract_service_call_data()` verify the proof and decrypt. When adding new flows, always pass `recipient_public_key` to `request()`.
- **Replay protection**: Every request includes a unique nonce (64-char hex) + ISO timestamp; implementors must store nonces with 60s TTL.
- **Single-use tokens**: Tokens have a `used` flag; `TokenAlreadyUsedError` is raised on reuse.

### Exception Hierarchy

All exceptions in [permyt/exceptions.py](permyt/exceptions.py) inherit from `PermytError` (has `.code` and `.default_message`). Security exceptions inherit from `SecurityError`: `InvalidTokenError`, `TokenExpiredError`, `TokenAlreadyUsedError`, `InvalidScopeError`, `InvalidUserError`, `InvalidPublicKeyError`, `InvalidProofError`, `InvalidPayloadError`, `ExpiredRequestError`, `InvalidInputError`.

### Type Definitions

[permyt/typing.py](permyt/typing.py) contains all `TypedDict` structures used across the protocol (token metadata, service call endpoints, connect requests, etc.).

<!-- PERMYT Protocol Reference v1 -->
## PERMYT Protocol Reference

### Actors

| Actor | Description |
|---|---|
| **Broker** | The PERMYT server (`permyt`). Orchestrates all flows, runs AI scope evaluation, manages consent, brokers tokens. Never sees actual user data. |
| **Requester** | A service that wants access to user data. Uses this SDK. |
| **Provider** | A service that holds user data and issues tokens. Uses this SDK. Connectors (Google, Revolut) are Providers. |
| **Mobile App** | The user's device (`permyt-mobile`). Used to scan QR codes (connect) and approve/deny access requests. |

### Connect Cycle

Links a Service to a User Profile via QR code. Creates the `ServiceConnection` and materializes `ScopeConsent` records.

```
  Service                    Mobile App                   Broker                        Service
    │                            │                          │                              │
    │  1. generate_connect_token()                          │                              │
    │──────────────────────────► │                          │                              │
    │  Returns: QR payload       │                          │                              │
    │  (signed JWT + JWE data)   │                          │                              │
    │                            │                          │                              │
    │                   2. User scans QR                    │                              │
    │                            │                          │                              │
    │                            │  3. POST /profiles/{id}/connect/                        │
    │                            │  {service_id, payload, proof}                           │
    │                            │─────────────────────────►│                              │
    │                            │                          │                              │
    │                            │              4. Validate proof + nonce + timestamp       │
    │                            │                 Decrypt JWE payload                      │
    │                            │                 Create ServiceConnection                 │
    │                            │                 Materialize ScopeConsent records         │
    │                            │                 (one per scope, copies default_consent_mode)
    │                            │                          │                              │
    │                            │                          │  5. Inbound: action=user_connect
    │                            │                          │  {token (signed JWT), user_id}│
    │                            │                          │─────────────────────────────►│
    │                            │                          │                              │
    │                            │                          │      6. process_user_connect()
    │                            │                          │         Link/create account   │
    │                            │                          │◄─────────────────────────────│
    │                            │                          │                              │
    │                            │  7. Return service response                             │
    │                            │◄─────────────────────────│                              │
```

### Disconnect Cycle

When a user revokes a previously-linked service from their PERMYT app, the broker tears down its own state and notifies the service so it can drop OAuth tokens, sessions, or whatever local link the connect flow established. The service response is best-effort — the broker does not block on it.

```
  Mobile App                     Broker                          Service
      │                            │                                │
      │  1. POST /profiles/{id}/services/{service_id}/disconnect/   │
      │───────────────────────────►│                                │
      │                            │                                │
      │              2. Reject AWAITING requests + REJECTED callback │
      │                 Emit per-grant REVOKED audit logs            │
      │                            │                                │
      │                            │  3. Inbound: action=user_disconnect
      │                            │  {permyt_user_id}              │
      │                            │───────────────────────────────►│
      │                            │                                │
      │                            │            4. process_user_disconnect()
      │                            │               Revoke local credentials
      │                            │               Unlink permyt_user_id
      │                            │◄───────────────────────────────│
      │                            │                                │
      │              5. connection.delete() → DISCONNECTED audit log │
      │                                                              │
      │  6. 200 OK                                                   │
      │◄───────────────────────────│                                │
```

### Request Access Cycle

A Requester asks for user data. Broker evaluates scopes via AI, routes user approval, and brokers encrypted tokens between Requester and Provider(s).

```
  Requester                  Broker                     Mobile App                  Provider
    │                          │                            │                          │
    │  1. POST /access         │                            │                          │
    │  {user_id, description,  │                            │                          │
    │   callback_url}          │                            │                          │
    │  (signed + encrypted)    │                            │                          │
    │─────────────────────────►│                            │                          │
    │                          │                            │                          │
    │  ◄── {request_id, status: QUEUED}                     │                          │
    │                          │                            │                          │
    │              2. AI scope evaluation (status → ANALYZING)                          │
    │                 Determines minimum scopes needed       │                          │
    │                 Extracts force-input values            │                          │
    │                 ↓ missing_data → INCOMPLETE (end)      │                          │
    │                 ↓ missing_capability → UNAVAILABLE (end)                          │
    │                          │                            │                          │
    │              3. Categorize scopes via ScopeConsent     │                          │
    │                 AUTO_GRANT → pre-approved              │                          │
    │                 PROMPT_ONCE + existing grant → pre-approved/denied                │
    │                 PROMPT_ONCE (no grant) or PROMPT_ALWAYS → needs approval          │
    │                          │                            │                          │
    │                          │  4. If needs approval:     │                          │
    │                          │     status → AWAITING      │                          │
    │                          │     Push notification      │                          │
    │                          │     {pending_scopes with   │                          │
    │                          │      inputs + consent_mode}│                          │
    │                          │───────────────────────────►│                          │
    │                          │                            │                          │
    │                          │  5. User decides:          │                          │
    │                          │     ALWAYS_ALLOW / ONCE_ALLOW / ONCE_DENY / ALWAYS_DENY
    │                          │     POST /respond/         │                          │
    │                          │     {decision, scopes}     │                          │
    │                          │◄───────────────────────────│                          │
    │                          │                            │                          │
    │              6. If approved → status: PROCESSING      │                          │
    │                 POST action=token_request              │                          │
    │                 TokenRequestData: {request_id,         │                          │
    │                   permyt_user_id, service_id,          │                          │
    │                   service_public_key,                   │                          │
    │                   scope (ScopeGrant), ttl_minutes}      │                          │
    │                          │─────────────────────────────────────────────────────►│
    │                          │                            │                          │
    │                          │                            │  7. Provider issues token │
    │                          │                            │     Single-use JWT         │
    │                          │                            │     Encrypted for Requester│
    │                          │                            │     Returns: {encrypted_token,
    │                          │                            │      endpoints, expires_at} │
    │                          │◄─────────────────────────────────────────────────────│
    │                          │                            │                          │
    │  8. Callback or polling  │                            │                          │
    │     status: COMPLETED    │                            │                          │
    │     {services: [{encrypted_token, endpoints,          │                          │
    │       expires_at, public_key}]}                        │                          │
    │◄─────────────────────────│                            │                          │
    │                          │                            │                          │
    │  9. Requester decrypts token, calls Provider directly │                          │
    │     (Broker is NOT involved in steps 9-10)            │                          │
    │─────────────────────────────────────────────────────────────────────────────────►│
    │                          │                            │  10. Validate JWT, enforce│
    │                          │                            │      force inputs, return │
    │◄─────────────────────────────────────────────────────────────────────────────────│
```

### Consent & Grant Model

**Consent modes** (set per scope at connection time, stored in `ScopeConsent`):

| Mode | Behavior | GrantedScope created? |
|---|---|---|
| `AUTO_GRANT` | Auto-approve for any requester | Yes (GRANTED), automatically |
| `PROMPT_ONCE` | Ask on first request per requester, then remember | Yes, if user chooses ALWAYS_ALLOW or ALWAYS_DENY |
| `PROMPT_ALWAYS` | Always ask, never persist approval | Only if ALWAYS_DENY (denials always persist) |

**Grant decisions** (returned by user via mobile app):

| Decision | Effect |
|---|---|
| `ALWAYS_ALLOW` | Approve + persist `GrantedScope(GRANTED)` for future auto-approval |
| `ONCE_ALLOW` | One-time approval, no record persisted |
| `ONCE_DENY` | One-time denial, no record persisted |
| `ALWAYS_DENY` | Persist `GrantedScope(DENIED)` — future requests auto-rejected |

### Security Model

All service-to-Broker and Broker-to-service communication uses **ES256 signing** (proof-of-possession JWT over payload hash) + **JWE encryption** (ECDH-ES+A256KW + A256GCM). Every request includes a unique **nonce** (64-char hex) + **ISO timestamp** for replay protection. Tokens are **single-use** (must be marked used atomically).

**Encryption-for-recipient principle** — sensitive `data` is always encrypted with the *recipient's* public key:

| Flow | Encrypted with |
|---|---|
| Broker → Provider (token request) | Provider's public key |
| Provider → Requester (token response) | Requester's public key (from `service_public_key`) |
| Broker → Requester (approved access) | Requester's public key |
| Requester → Provider (service call) | Provider's public key |

### Key Data Shapes (from `permyt/typing.py`)

- **`ScopeGrant`**: `dict[str, dict[str, Any]]` — scope reference → locked force-input values (empty dict if no inputs)
- **`AccessRequest`**: `{user_id, description, callback_url?, request_id?}`
- **`AccessPayload`**: `{data (JWE), nonce, timestamp}` — outer payload PERMYT returns to requester
- **`AccessStatus`**: `{request_id, status, services?}` — response to request_access/check_access
- **`AccessResponse`**: `{payload: AccessPayload, proof}` — signed PERMYT response with approved providers
- **`ExchangeToken`**: `{user_id, token, restricted_to}` — temporary token for passing user identity between services
- **`RedeemedToken`**: `{user_id}` — response when redeeming an exchange token
- **`TokenRequestData`**: `{request_id, permyt_user_id, service_id, service_public_key, scope: ScopeGrant, ttl_minutes}`
- **`TokenMetadata`**: `{user, scope: ScopeGrant, service_public_key, expires_at}`
- **`EncryptedPayload`**: `{data (JWE), nonce, timestamp}` — generic encrypted payload with replay-prevention metadata
- **`EncryptedRequest`**: `{action?, payload: EncryptedPayload, proof}` — signed request envelope with action discriminator
- **`RequestStatus`**: `{request_id, status, services?, reason?}` — status callback data from PERMYT to requester
- **`ServiceCredential`**: `{request_id, encrypted_token, endpoints, expires_at, public_key}`
- **`ServiceCallPayload`**: `{data (JWE), nonce, timestamp}` — requester-to-provider call payload
- **`ServiceCallRequest`**: `{token, payload: ServiceCallPayload, proof}` — complete requester-to-provider request
- **`ServiceCallEndpoint`**: `{url, description?, input_fields?}`
- **`ConnectPayload`**: `{service_id, payload: EncryptedPayload, proof}` — connect flow payload (QR/NFC/button)
- **`ConnectRequest`**: `{token, permyt_user_id}` — connect callback from PERMYT to service
- **`DisconnectRequest`**: `{permyt_user_id}` — disconnect callback from PERMYT to service
- **`ConsentMode`**: `Literal["auto_grant", "prompt_once", "prompt_always"]` — consent mode for scopes
- **`ScopeInput`**: `{name, description}` — input field declaration for a scope
- **`ScopeDefinition`**: `{reference, name, description?, inputs?, default_consent_mode?, high_sensitivity?}` — scope definition for `update_scopes()`
- **`UpdateScopesResponse`**: `{created, updated, deleted}` — response from scope update

### This Project's Role: The SDK

This SDK provides the cryptographic and protocol layer for both Requesters and Providers:

- **Inbound dispatcher**: `InboundMixin` implements `handle_inbound()` — single-endpoint dispatcher that routes by `action` field to the right handler
- **Connect cycle**: `UserConnectMixin` implements `generate_connect_token()` (step 1) and `handle_user_connect()` / `process_user_connect()` (step 6)
- **Disconnect cycle**: `UserDisconnectMixin` implements `handle_user_disconnect()` / `process_user_disconnect()` — fired by the broker when a user revokes a connection from their PERMYT app. Implementors should drop OAuth tokens, sessions, and any local link keyed by `permyt_user_id`. Idempotent.
- **Request cycle (Requester)**: `RequesterMixin` implements `request_access()` (step 1), `check_access()` (step 8), `handle_approved_access()` (step 8), `call_services()` (step 9), `handle_request_status()` / `process_request_status()` (status callbacks), `request_token()` / `redeem_token()` (exchange tokens)
- **Request cycle (Provider)**: `ProviderMixin` implements `handle_token_request()` (step 7) and `handle_service_call()` (step 10)
- **Scope management**: `ScopeManagementMixin` implements `update_scopes()` — pushes the complete scope list to PERMYT, which diffs by `reference` to create/update/delete
- **All crypto**: `EncryptionMixin` handles ES256 signing, JWE encryption/decryption, proof-of-possession tokens
- **Abstract methods define the contract** — the SDK handles all protocol mechanics; implementors fill in storage, user resolution, and business logic

## Key Generation

Services need ECDSA P-256 key pairs:
```bash
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```
