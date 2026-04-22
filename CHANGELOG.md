# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
