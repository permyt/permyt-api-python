# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-06-02

### Added
- `TokenRevokeMixin` with `handle_token_revoke` and abstract
  `process_token_revoke` for the sibling fan-out the broker fires at every
  *other* connection on a profile when a user disconnects or blacklists a
  peer service, so each recipient can drop in-flight tokens involving the
  blocked peer before they age out.
- `TokenRevokeRequest` TypedDict (`permyt_user_id`, `blocked_service_id`,
  `blocked_service_public_key`, `reason`).
- `handle_inbound` now routes `action="token_revoke"` to the new handler.
- `LogsMixin.fetch_logs(limit, offset, user_id, log_type, request_id,
  days_back)` for pulling the calling service's paginated audit log from
  PERMYT (`POST /request/logs/`). Returns `{logs, total, limit, offset}` —
  visibility and per-row `meta` sanitisation are enforced server-side.
- `ActivityLog`, `FetchLogsResponse`, and `LogType` type definitions.

### Changed
- `process_user_disconnect` contract clarified: the disconnecting service is
  responsible for revoking its own PERMYT-issued tokens for the user. The
  broker does NOT send a separate `token_revoke` to the disconnecting service.

## [0.1.5] - 2026-05-06

### Added
- `UserDisconnectMixin` with `handle_user_disconnect` and abstract
  `process_user_disconnect`, mirroring the connect flow so providers can
  drop OAuth tokens, sessions, and local links when a user revokes a
  connection from their PERMYT app.
- `DisconnectRequest` TypedDict for the new payload shape.
- `handle_inbound` now routes `action="user_disconnect"` to the new handler.

## [0.1.3] - 2026-04-24

### Added
- `RequesterMixin.view_scopes(user_id)` — enumerate the providers and scopes
  available to a connected user across their profile. Calls the broker's
  `request/scopes/view/` endpoint and returns a `ViewScopesResponse`.
- `ServiceScopes` and `ViewScopesResponse` TypedDicts.

## [0.1.2] - 2026-04-21

### Changed
- Migrated cryptographic library from `authlib` to `joserfc` for JWT/JWE operations.
- Provider, requester, and connect methods are now optional — only implement the
  methods for the role(s) your service needs. Shared methods (`get_private_key`,
  `get_service_id`, `get_permyt_public_key`, `_validate_nonce_and_timestamp`)
  remain required.

### Fixed
- Replaced `assert` with `ValueError` for private key validation
  (`assert` is stripped when Python runs with `-O`).
- Narrowed exception handling in `call_services` to `(PermytError, RequestException)`
  to avoid silently masking non-transport errors.

### Added
- CHANGELOG.md and CONTRIBUTING.md.
- GitHub Actions CI workflow (Python 3.10–3.13).
- Requester, provider, and end-to-end integration tests (coverage 85% → 96%).

## [0.1.1] - 2026-03-15

### Added
- Scope management mixin (`update_scopes`) for pushing scope definitions to PERMYT.
- Force-input enforcement documentation and examples.

## [0.1.0] - 2026-02-01

### Added
- Initial release of the PERMYT Python SDK.
- `PermytClient` abstract base class with mixin architecture.
- JWT signing (ES256) and JWE encryption (ECDH-ES+A256KW / A256GCM).
- Requester, Provider, and Connect roles.
- `InboundMixin` single-endpoint webhook dispatcher.
- Replay protection (nonce + timestamp).
- Single-use token enforcement.
- Comprehensive type definitions (`permyt/typing.py`).
