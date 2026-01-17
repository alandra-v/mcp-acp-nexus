"""Unit tests for CLI API client.

Tests the UDS client used by CLI commands to communicate with the proxy.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcp_acp.cli.api_client import (
    APIError,
    ProxyNotRunningError,
    api_request,
)


class TestProxyNotRunningError:
    """Tests for ProxyNotRunningError exception."""

    def test_has_helpful_message(self):
        """Error message suggests how to start proxy."""
        error = ProxyNotRunningError()

        assert "not running" in str(error).lower()
        assert "start" in str(error).lower()

    def test_is_click_exception(self):
        """Exception inherits from ClickException."""
        import click

        error = ProxyNotRunningError()

        assert isinstance(error, click.ClickException)


class TestAPIError:
    """Tests for APIError exception."""

    def test_includes_status_code_in_message(self):
        """Error message includes status code."""
        error = APIError("Not found", status_code=404)

        assert "404" in str(error)
        assert "Not found" in str(error)

    def test_stores_status_code(self):
        """Status code is accessible as attribute."""
        error = APIError("Error", status_code=500)

        assert error.status_code == 500

    def test_without_status_code(self):
        """Works without status code."""
        error = APIError("Connection failed")

        assert error.status_code is None
        assert "Connection failed" in str(error)

    def test_is_click_exception(self):
        """Exception inherits from ClickException."""
        import click

        error = APIError("test")

        assert isinstance(error, click.ClickException)


class TestApiRequest:
    """Tests for api_request function using UDS."""

    @pytest.fixture
    def mock_socket_exists(self, tmp_path):
        """Mock socket path to exist."""
        socket_path = tmp_path / "api.sock"
        socket_path.touch()  # Create a file to simulate socket existence
        with patch("mcp_acp.cli.api_client.SOCKET_PATH", socket_path):
            yield socket_path

    @pytest.fixture
    def mock_uds_client(self):
        """Mock the httpx.Client for UDS connections."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}

        with patch("mcp_acp.cli.api_client.httpx.HTTPTransport") as mock_transport:
            with patch("mcp_acp.cli.api_client.httpx.Client") as mock_client:
                client_instance = MagicMock()
                client_instance.request.return_value = mock_response
                client_instance.__enter__ = MagicMock(return_value=client_instance)
                client_instance.__exit__ = MagicMock(return_value=False)
                mock_client.return_value = client_instance
                yield {
                    "transport": mock_transport,
                    "client": mock_client,
                    "client_instance": client_instance,
                    "response": mock_response,
                }

    def test_raises_when_socket_missing(self, tmp_path):
        """Given no socket file, raises ProxyNotRunningError."""
        socket_path = tmp_path / "nonexistent.sock"

        with patch("mcp_acp.cli.api_client.SOCKET_PATH", socket_path):
            with pytest.raises(ProxyNotRunningError):
                api_request("GET", "/api/status")

    def test_get_request_success(self, mock_socket_exists, mock_uds_client):
        """Given successful GET request, returns parsed JSON."""
        mock_uds_client["response"].json.return_value = {"status": "ok", "data": [1, 2, 3]}

        result = api_request("GET", "/api/test")

        assert result == {"status": "ok", "data": [1, 2, 3]}

    def test_post_request_with_json_body(self, mock_socket_exists, mock_uds_client):
        """Given POST with JSON body, sends correct request."""
        mock_uds_client["response"].json.return_value = {"created": True}

        result = api_request("POST", "/api/create", json_data={"name": "test"})

        # Verify request was made with JSON body
        call_args = mock_uds_client["client_instance"].request.call_args
        assert call_args[1]["json"] == {"name": "test"}

    def test_handles_204_no_content(self, mock_socket_exists, mock_uds_client):
        """Given 204 response, returns empty dict."""
        mock_uds_client["response"].status_code = 204

        result = api_request("DELETE", "/api/item/1")

        assert result == {}

    def test_raises_proxy_not_running_on_connection_error(self, mock_socket_exists):
        """Given connection error on existing socket, raises ProxyNotRunningError."""
        with patch("mcp_acp.cli.api_client.httpx.HTTPTransport"):
            with patch("mcp_acp.cli.api_client.httpx.Client") as mock_client:
                mock_client.return_value.__enter__.return_value.request.side_effect = httpx.ConnectError(
                    "Connection refused"
                )

                with pytest.raises(ProxyNotRunningError):
                    api_request("GET", "/api/test")

    def test_raises_api_error_on_http_error(self, mock_socket_exists, mock_uds_client):
        """Given HTTP error status, raises APIError with status code."""
        mock_uds_client["response"].status_code = 404
        mock_uds_client["response"].json.return_value = {"detail": "Resource not found"}

        error = httpx.HTTPStatusError(
            "Not Found",
            request=MagicMock(),
            response=mock_uds_client["response"],
        )
        mock_uds_client["response"].raise_for_status.side_effect = error

        with pytest.raises(APIError) as exc_info:
            api_request("GET", "/api/missing")

        assert exc_info.value.status_code == 404
        assert "Resource not found" in str(exc_info.value)

    def test_no_auth_header_sent(self, mock_socket_exists, mock_uds_client):
        """UDS requests don't include Authorization header (OS permissions = auth)."""
        api_request("GET", "/api/test")

        call_args = mock_uds_client["client_instance"].request.call_args
        # No headers parameter or no Authorization header
        headers = call_args[1].get("headers", {})
        assert "Authorization" not in headers

    def test_uses_uds_transport(self, mock_socket_exists, mock_uds_client):
        """Request uses UDS transport with correct socket path."""
        api_request("GET", "/api/test")

        # Verify HTTPTransport was created with uds parameter
        mock_uds_client["transport"].assert_called_once()
        call_kwargs = mock_uds_client["transport"].call_args[1]
        assert "uds" in call_kwargs
        assert str(mock_socket_exists) in call_kwargs["uds"]

    def test_passes_query_params(self, mock_socket_exists, mock_uds_client):
        """Given params dict, passes as query parameters."""
        mock_uds_client["response"].json.return_value = {"entries": []}

        api_request("GET", "/api/logs", params={"limit": 50, "offset": 10})

        call_args = mock_uds_client["client_instance"].request.call_args
        assert call_args[1]["params"] == {"limit": 50, "offset": 10}

    def test_respects_custom_timeout(self, mock_socket_exists, mock_uds_client):
        """Given custom timeout, uses it for client."""
        api_request("GET", "/api/test", timeout=60.0)

        # Verify client was created with custom timeout
        mock_uds_client["client"].assert_called_once()
        call_kwargs = mock_uds_client["client"].call_args[1]
        assert call_kwargs["timeout"] == 60.0

    def test_extracts_detail_from_error_response(self, mock_socket_exists, mock_uds_client):
        """Given error with detail field, extracts it for message."""
        mock_uds_client["response"].status_code = 400
        mock_uds_client["response"].json.return_value = {"detail": "Invalid input data"}

        error = httpx.HTTPStatusError(
            "Bad Request",
            request=MagicMock(),
            response=mock_uds_client["response"],
        )
        mock_uds_client["response"].raise_for_status.side_effect = error

        with pytest.raises(APIError) as exc_info:
            api_request("POST", "/api/data", json_data={})

        assert "Invalid input data" in str(exc_info.value)

    def test_handles_non_json_error_response(self, mock_socket_exists, mock_uds_client):
        """Given error without JSON body, uses status text."""
        mock_uds_client["response"].status_code = 500
        mock_uds_client["response"].json.side_effect = json.JSONDecodeError("", "", 0)

        error = httpx.HTTPStatusError(
            "Internal Server Error",
            request=MagicMock(),
            response=mock_uds_client["response"],
        )
        mock_uds_client["response"].raise_for_status.side_effect = error

        with pytest.raises(APIError) as exc_info:
            api_request("GET", "/api/test")

        assert exc_info.value.status_code == 500

    def test_supports_all_http_methods(self, mock_socket_exists, mock_uds_client):
        """Supports GET, POST, PUT, DELETE methods."""
        for method in ["GET", "POST", "PUT", "DELETE"]:
            api_request(method, "/api/test")

            call_args = mock_uds_client["client_instance"].request.call_args
            assert call_args[0][0] == method


class TestConnectionRetry:
    """Tests for connection retry logic."""

    def test_gives_up_after_max_retries(self, tmp_path):
        """Given socket never appears, raises ProxyNotRunningError."""
        socket_path = tmp_path / "never_exists.sock"

        with patch("mcp_acp.cli.api_client.SOCKET_PATH", socket_path):
            with patch("mcp_acp.cli.api_client.time.sleep"):  # Speed up test
                with pytest.raises(ProxyNotRunningError):
                    api_request("GET", "/api/test")

    def test_retry_backoff_is_used(self, tmp_path):
        """Retry uses exponential backoff."""
        socket_path = tmp_path / "never_exists.sock"

        with patch("mcp_acp.cli.api_client.SOCKET_PATH", socket_path):
            with patch("mcp_acp.cli.api_client.time.sleep") as mock_sleep:
                with pytest.raises(ProxyNotRunningError):
                    api_request("GET", "/api/test")

                # Should have called sleep for backoff (retries - 1 times)
                # With 3 retries: 2 sleep calls (100ms, 200ms)
                assert mock_sleep.call_count == 2
