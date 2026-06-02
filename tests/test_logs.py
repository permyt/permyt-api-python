"""Tests for the LogsMixin."""

from unittest.mock import MagicMock, patch

from tests.conftest import StubPermytClient


def _ok_response(payload: dict) -> MagicMock:
    return MagicMock(ok=True, json=lambda: payload)


@patch("permyt.mixins.http.requests.post")
def test_fetch_logs_builds_signed_envelope_with_defaults(mock_post, test_keys, permyt_keys):
    """fetch_logs() should POST a signed envelope with action=fetch_logs and the default page."""
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    mock_post.return_value = _ok_response({"logs": [], "total": 0, "limit": 50, "offset": 0})

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    result = client.fetch_logs()

    assert result == {"logs": [], "total": 0, "limit": 50, "offset": 0}
    assert mock_post.call_count == 1

    call_args = mock_post.call_args
    url = call_args.args[0] if call_args.args else call_args.kwargs["url"]
    assert url.endswith("/rest/request/logs/")

    body = call_args.kwargs["json"]
    assert body["action"] == "fetch_logs"
    assert body["service_id"] == "test-service"
    assert "payload" in body
    assert "proof" in body


@patch("permyt.mixins.http.requests.post")
def test_fetch_logs_omits_unset_filters(mock_post, test_keys, permyt_keys):
    """Optional filters not passed should not appear in the encrypted payload."""
    service_private, _ = test_keys
    permyt_private, permyt_public = permyt_keys

    mock_post.return_value = _ok_response({"logs": [], "total": 0, "limit": 25, "offset": 10})

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)
    client.fetch_logs(limit=25, offset=10)

    body = mock_post.call_args.kwargs["json"]
    decrypted = permyt._decrypt_data(body["payload"]["data"])
    assert decrypted == {"limit": 25, "offset": 10}


@patch("permyt.mixins.http.requests.post")
def test_fetch_logs_forwards_filters(mock_post, test_keys, permyt_keys):
    """All supplied filters land in the encrypted payload verbatim."""
    service_private, _ = test_keys
    permyt_private, permyt_public = permyt_keys

    mock_post.return_value = _ok_response({"logs": [], "total": 0, "limit": 50, "offset": 0})

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    permyt = StubPermytClient(private_key=permyt_private, permyt_public_key=permyt_public)
    client.fetch_logs(
        user_id="u-1",
        log_type="issued",
        request_id="req-9",
        days_back=7,
    )

    body = mock_post.call_args.kwargs["json"]
    decrypted = permyt._decrypt_data(body["payload"]["data"])
    assert decrypted == {
        "limit": 50,
        "offset": 0,
        "user_id": "u-1",
        "log_type": "issued",
        "request_id": "req-9",
        "days_back": 7,
    }


@patch("permyt.mixins.http.requests.post")
def test_fetch_logs_returns_broker_envelope_unchanged(mock_post, test_keys, permyt_keys):
    """Broker response (logs + pagination metadata) flows back to the caller."""
    service_private, _ = test_keys
    _, permyt_public = permyt_keys

    rows = [
        {
            "id": "log-1",
            "datetime": "2026-06-01T12:00:00+00:00",
            "log_type": "issued",
            "request_id": "req-1",
            "requester_id": "svc-r",
            "provider_id": "svc-p",
            "permyt_user_id": "u-1",
            "meta": {"scope_refs": ["professional"], "expires_at": "2026-06-01T12:30:00+00:00"},
        },
    ]
    mock_post.return_value = _ok_response({"logs": rows, "total": 1, "limit": 50, "offset": 0})

    client = StubPermytClient(private_key=service_private, permyt_public_key=permyt_public)
    result = client.fetch_logs()

    assert result["total"] == 1
    assert result["logs"] == rows
