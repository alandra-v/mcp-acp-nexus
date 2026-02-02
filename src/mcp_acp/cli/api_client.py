"""API client helper for CLI commands that need runtime proxy data.

Provides a simple interface for CLI commands to call the proxy's API via UDS.
Used by runtime commands (status, sessions, approvals) that need data from
the running proxy.

Authentication: CLI uses Unix Domain Socket (UDS) where OS file permissions
provide authentication. No token needed - if you can connect to the socket,
you're the same user who started the proxy.

File-based commands (logs, policy show, config show) should read files
directly instead of using this module.
"""

from __future__ import annotations

__all__ = [
    "ProxyAPIError",
    "ProxyNotRunningError",
    "api_request",
]

import json
import time
from typing import Any

import click
import httpx

from mcp_acp.constants import DEFAULT_HTTP_TIMEOUT_SECONDS, get_proxy_socket_path


class ProxyNotRunningError(click.ClickException):
    """Raised when proxy is not running (no UDS socket)."""

    def __init__(self, proxy_name: str) -> None:
        super().__init__(
            f"Proxy '{proxy_name}' is not running.\n" f"Start it with: mcp-acp start --proxy {proxy_name}"
        )
        self.proxy_name = proxy_name


class ProxyAPIError(click.ClickException):
    """Raised when API request fails."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        if status_code:
            super().__init__(f"API error ({status_code}): {message}")
        else:
            super().__init__(f"API error: {message}")
        self.status_code = status_code


def _create_uds_client(
    proxy_name: str,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> httpx.Client:
    """Create an httpx client configured for UDS connection.

    Args:
        proxy_name: Name of the proxy to connect to.
        timeout: Request timeout in seconds.

    Returns:
        httpx.Client configured for UDS transport.

    Raises:
        FileNotFoundError: If socket file doesn't exist.
    """
    socket_path = get_proxy_socket_path(proxy_name)
    if not socket_path.exists():
        raise FileNotFoundError(f"Socket not found: {socket_path}")

    transport = httpx.HTTPTransport(uds=str(socket_path))
    return httpx.Client(
        transport=transport,
        base_url="http://localhost",  # Required but ignored for UDS
        timeout=timeout,
    )


def api_request(
    method: str,
    endpoint: str,
    *,
    proxy_name: str,
    json_data: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    max_retries: int = 3,
    backoff_ms: int = 100,
) -> dict[str, Any] | list[Any]:
    """Make an API request to a running proxy via UDS.

    No authentication token needed - OS file permissions on the UDS socket
    provide authentication. Only the user who started the proxy can connect.

    Includes retry logic with exponential backoff for startup race conditions
    (when CLI runs immediately after 'mcp-acp start').

    Args:
        method: HTTP method (GET, POST, DELETE, etc.)
        endpoint: API endpoint path (e.g., "/api/control/status")
        proxy_name: Name of the proxy to connect to.
        json_data: Optional JSON body for POST/PUT requests.
        params: Optional query parameters.
        timeout: Request timeout in seconds.
        max_retries: Maximum connection attempts (default 3).
        backoff_ms: Initial backoff in milliseconds (doubles each retry).

    Returns:
        Parsed JSON response.

    Raises:
        ProxyNotRunningError: If proxy is not running (no socket or connection refused).
        ProxyAPIError: If request fails or returns error status.
    """
    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            with _create_uds_client(proxy_name, timeout=timeout) as client:
                response = client.request(
                    method,
                    endpoint,
                    json=json_data,
                    params=params,
                )
                response.raise_for_status()

                # Handle 204 No Content
                if response.status_code == 204:
                    return {}

                result = response.json()
                if isinstance(result, (dict, list)):
                    return result
                # Unexpected JSON type - wrap in dict
                return {"value": result}

        except (FileNotFoundError, httpx.ConnectError, OSError) as e:
            # Socket not found or connection refused - retry with backoff
            last_error = e
            if attempt < max_retries - 1:
                # Exponential backoff: 100ms, 200ms, 400ms
                time.sleep(backoff_ms / 1000 * (2**attempt))
            continue

        except httpx.HTTPStatusError as e:
            # API returned error status - don't retry, it's a real error
            try:
                detail = e.response.json().get("detail", str(e))
            except (json.JSONDecodeError, KeyError):
                detail = str(e)
            raise ProxyAPIError(detail, e.response.status_code) from e

        except httpx.HTTPError as e:
            # Other HTTP errors - don't retry
            raise ProxyAPIError(str(e)) from e

    # All retries exhausted
    raise ProxyNotRunningError(proxy_name) from last_error
