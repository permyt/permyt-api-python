"""Tests for HTTPClientMixin.request error handling."""

from unittest.mock import MagicMock, patch

import pytest
import requests as requests_lib

from permyt.exceptions import TransportError, UnexpectedError


def _mock_response(status_code: int, text: str, json_data=None) -> MagicMock:
    resp = MagicMock()
    resp.ok = 200 <= status_code < 300
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("not json")
    return resp


def _call(client):
    return client.request(
        url="https://x/y",
        action="ping",
        data={},
        recipient_public_key=client.get_permyt_public_key(),
    )


def test_request_returns_json_on_success(client):
    with patch(
        "permyt.mixins.http.requests.post",
        return_value=_mock_response(200, '{"ok": true}', json_data={"ok": True}),
    ):
        result = _call(client)
    assert result == {"ok": True}


def test_request_raises_transport_error_on_404(client):
    with (
        patch(
            "permyt.mixins.http.requests.post",
            return_value=_mock_response(404, '{"detail": "nope"}', json_data={"detail": "nope"}),
        ),
        pytest.raises(TransportError) as exc_info,
    ):
        _call(client)
    assert exc_info.value.status_code == 404
    assert exc_info.value.code == "transport_error"
    assert "nope" in exc_info.value.extra_info


def test_request_raises_transport_error_on_500_html(client):
    with (
        patch(
            "permyt.mixins.http.requests.post",
            return_value=_mock_response(500, "<html>Server Error</html>"),
        ),
        pytest.raises(TransportError) as exc_info,
    ):
        _call(client)
    assert exc_info.value.status_code == 500
    assert "Server Error" in exc_info.value.extra_info


def test_request_raises_transport_error_on_connection_error(client):
    with (
        patch(
            "permyt.mixins.http.requests.post",
            side_effect=requests_lib.ConnectionError("boom"),
        ),
        pytest.raises(TransportError) as exc_info,
    ):
        _call(client)
    assert exc_info.value.status_code is None
    assert "boom" in exc_info.value.extra_info
    assert "ConnectionError" in str(exc_info.value)


def test_request_raises_transport_error_on_timeout(client):
    with (
        patch(
            "permyt.mixins.http.requests.post",
            side_effect=requests_lib.Timeout("slow"),
        ),
        pytest.raises(TransportError) as exc_info,
    ):
        _call(client)
    assert exc_info.value.status_code is None
    assert "Timeout" in str(exc_info.value)


def test_request_raises_unexpected_on_non_json_2xx(client):
    with (
        patch(
            "permyt.mixins.http.requests.post",
            return_value=_mock_response(200, "<html/>"),
        ),
        pytest.raises(UnexpectedError) as exc_info,
    ):
        _call(client)
    assert "<html/>" in exc_info.value.extra_info
