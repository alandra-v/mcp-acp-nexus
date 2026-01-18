"""OAuth Device Authorization Flow (RFC 8628) for CLI authentication.

Implements the device authorization grant for command-line authentication.
User runs `mcp-acp auth login`, sees a code, opens browser to
authenticate, and tokens are stored locally.

This is the same pattern as `gh auth login`, `aws sso login`, `gcloud auth login`.

Flow:
1. Request device code from Auth0
2. Display: "Go to https://... and enter code: XXXX-XXXX"
3. Poll token endpoint until user completes authentication
4. Store tokens in keychain/encrypted file
"""

from __future__ import annotations

__all__ = [
    "DeviceCodeResponse",
    "DeviceFlow",
    "DeviceFlowDeniedError",
    "DeviceFlowError",
    "DeviceFlowExpiredError",
    "DeviceFlowResult",
    "PollOnceResult",
    "run_device_flow",
]

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

import httpx

from mcp_acp.constants import (
    DEVICE_FLOW_POLL_INTERVAL_SECONDS,
    DEVICE_FLOW_TIMEOUT_SECONDS,
    OAUTH_CLIENT_TIMEOUT_SECONDS,
)
from mcp_acp.exceptions import AuthenticationError
from mcp_acp.security.auth.token_parser import parse_token_response
from mcp_acp.security.auth.token_storage import StoredToken

if TYPE_CHECKING:
    from mcp_acp.config import OIDCConfig


@dataclass
class DeviceCodeResponse:
    """Response from device authorization request.

    Attributes:
        device_code: Code used to poll for tokens (don't show to user).
        user_code: Code user enters in browser (e.g., "HDFC-LQRT").
        verification_uri: URL user opens to authenticate.
        verification_uri_complete: URL with code embedded (optional).
        expires_in: Seconds until codes expire.
        interval: Polling interval in seconds.
    """

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None
    expires_in: int
    interval: int

    @classmethod
    def from_response(cls, data: dict) -> "DeviceCodeResponse":
        """Parse from Auth0 response."""
        return cls(
            device_code=data["device_code"],
            user_code=data["user_code"],
            verification_uri=data["verification_uri"],
            verification_uri_complete=data.get("verification_uri_complete"),
            expires_in=data["expires_in"],
            interval=data.get("interval", DEVICE_FLOW_POLL_INTERVAL_SECONDS),
        )


@dataclass
class DeviceFlowResult:
    """Result of successful device flow authentication.

    Attributes:
        token: Stored token ready for use.
        user_code: The code user entered (for logging).
    """

    token: StoredToken
    user_code: str


@dataclass(frozen=True)
class PollOnceResult:
    """Result of a single poll attempt.

    Attributes:
        status: "pending", "complete", "expired", "denied", or "error".
        token: Token if status is "complete", None otherwise.
        error_message: Error message if status is "expired", "denied", or "error".
    """

    status: str
    token: StoredToken | None = None
    error_message: str | None = None


class DeviceFlowError(AuthenticationError):
    """Device flow specific errors."""

    pass


class DeviceFlowExpiredError(DeviceFlowError):
    """Device code expired before user authenticated."""

    pass


class DeviceFlowDeniedError(DeviceFlowError):
    """User denied the authorization request."""

    pass


class DeviceFlow:
    """OAuth Device Authorization Flow implementation.

    Usage:
        flow = DeviceFlow(oidc_config)

        # Start flow - display code to user
        device_code = flow.request_device_code()
        print(f"Go to {device_code.verification_uri}")
        print(f"Enter code: {device_code.user_code}")

        # Wait for user to authenticate
        result = flow.poll_for_token(device_code)
        print(f"Authenticated as: {result.token.access_token[:20]}...")
    """

    def __init__(
        self,
        config: "OIDCConfig",
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize device flow.

        Args:
            config: OIDC configuration with issuer, client_id, audience.
            http_client: Optional httpx client (for testing).
        """
        self._config = config
        self._client = http_client or httpx.Client(timeout=OAUTH_CLIENT_TIMEOUT_SECONDS)
        self._owns_client = http_client is None

        # Build endpoints from issuer
        issuer = config.issuer.rstrip("/")
        self._device_auth_url = f"{issuer}/oauth/device/code"
        self._token_url = f"{issuer}/oauth/token"

    def __enter__(self) -> "DeviceFlow":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close HTTP client if we own it."""
        if self._owns_client:
            self._client.close()

    def request_device_code(self) -> DeviceCodeResponse:
        """Request a device code from Auth0.

        Returns:
            DeviceCodeResponse with user_code and verification_uri.

        Raises:
            DeviceFlowError: If request fails.
        """
        try:
            response = self._client.post(
                self._device_auth_url,
                data={
                    "client_id": self._config.client_id,
                    "scope": " ".join(self._config.scopes),
                    "audience": self._config.audience,
                },
            )
            response.raise_for_status()
            return DeviceCodeResponse.from_response(response.json())

        except httpx.HTTPStatusError as e:
            error_data = {}
            try:
                error_data = e.response.json()
            except Exception:
                pass
            error_msg = error_data.get("error_description", str(e))
            raise DeviceFlowError(f"Failed to request device code: {error_msg}") from e

        except httpx.HTTPError as e:
            raise DeviceFlowError(f"HTTP error requesting device code: {e}") from e

    def poll_for_token(
        self,
        device_code: DeviceCodeResponse,
        timeout: int = DEVICE_FLOW_TIMEOUT_SECONDS,
        on_poll: Callable[[], None] | None = None,
    ) -> DeviceFlowResult:
        """Poll token endpoint until user completes authentication.

        Args:
            device_code: Response from request_device_code().
            timeout: Maximum seconds to wait (default 5 minutes).
            on_poll: Optional callback called on each poll (for progress display).

        Returns:
            DeviceFlowResult with tokens.

        Raises:
            DeviceFlowExpiredError: If device code expires.
            DeviceFlowDeniedError: If user denies authorization.
            DeviceFlowError: For other errors.
        """
        interval = device_code.interval
        start_time = time.monotonic()
        deadline = start_time + min(timeout, device_code.expires_in)

        while time.monotonic() < deadline:
            if on_poll:
                on_poll()

            time.sleep(interval)

            try:
                response = self._client.post(
                    self._token_url,
                    data={
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code.device_code,
                        "client_id": self._config.client_id,
                    },
                )

                if response.status_code == 200:
                    # Success - user authenticated
                    token_data = response.json()
                    token = self._parse_token_response(token_data)
                    return DeviceFlowResult(token=token, user_code=device_code.user_code)

                # Handle error responses
                error_data = response.json()
                error = error_data.get("error", "")

                if error == "authorization_pending":
                    # User hasn't completed auth yet - continue polling
                    continue

                elif error == "slow_down":
                    # Auth0 wants us to slow down
                    interval += 5
                    continue

                elif error == "expired_token":
                    raise DeviceFlowExpiredError("Device code expired. Please run 'auth login' again.")

                elif error == "access_denied":
                    raise DeviceFlowDeniedError("Authorization was denied by user.")

                else:
                    # Unknown error
                    error_desc = error_data.get("error_description", error)
                    raise DeviceFlowError(f"Token request failed: {error_desc}")

            except httpx.HTTPError as e:
                raise DeviceFlowError(f"HTTP error polling for token: {e}") from e

        # Timeout reached
        raise DeviceFlowExpiredError(
            f"Authentication timed out after {timeout} seconds. " "Please run 'auth login' again."
        )

    def _parse_token_response(self, data: dict) -> StoredToken:
        """Parse token response from Auth0.

        Args:
            data: Token response JSON.

        Returns:
            StoredToken ready for storage.
        """
        return parse_token_response(data)

    def poll_once(self, device_code: DeviceCodeResponse) -> PollOnceResult:
        """Poll token endpoint once (non-blocking).

        Use this for async/API scenarios where you can't block.
        Returns immediately with the current status.

        Args:
            device_code: Response from request_device_code().

        Returns:
            PollOnceResult with status and token (if complete).

        Example:
            result = flow.poll_once(device_code)
            if result.status == "pending":
                # User hasn't completed auth yet
            elif result.status == "complete":
                # result.token contains the tokens
            else:
                # result.error_message has details
        """
        try:
            response = self._client.post(
                self._token_url,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code.device_code,
                    "client_id": self._config.client_id,
                },
            )

            if response.status_code == 200:
                token_data = response.json()
                token = self._parse_token_response(token_data)
                return PollOnceResult(status="complete", token=token)

            # Handle error responses
            try:
                error_data = response.json()
            except Exception:
                return PollOnceResult(
                    status="error",
                    error_message=f"Token request failed with status {response.status_code}",
                )

            error = error_data.get("error", "")

            if error == "authorization_pending":
                return PollOnceResult(status="pending")

            if error == "slow_down":
                return PollOnceResult(status="pending")

            if error == "expired_token":
                return PollOnceResult(
                    status="expired",
                    error_message="Device code expired. Please start a new login.",
                )

            if error == "access_denied":
                return PollOnceResult(
                    status="denied",
                    error_message="Authorization was denied.",
                )

            # Unknown error
            error_desc = error_data.get("error_description", error)
            return PollOnceResult(
                status="error",
                error_message=f"Token request failed: {error_desc}",
            )

        except httpx.HTTPError as e:
            return PollOnceResult(
                status="error",
                error_message=f"HTTP error polling for token: {e}",
            )


def run_device_flow(
    config: "OIDCConfig",
    display_callback: Callable[[str, str, str | None], None],
    poll_callback: Callable[[], None] | None = None,
    timeout: int = DEVICE_FLOW_TIMEOUT_SECONDS,
) -> StoredToken:
    """Run complete device flow with callbacks for display.

    Convenience function that handles the full flow.

    Args:
        config: OIDC configuration.
        display_callback: Called with (user_code, verification_uri, verification_uri_complete)
            to display authentication instructions to user.
        poll_callback: Optional callback called on each poll iteration.
        timeout: Maximum seconds to wait for authentication.

    Returns:
        StoredToken ready for storage.

    Raises:
        DeviceFlowError: If authentication fails.

    Example:
        def show_code(user_code, uri, uri_complete):
            print(f"Go to: {uri}")
            print(f"Enter code: {user_code}")

        token = run_device_flow(config, display_callback=show_code)
        storage.save(token)
    """
    with DeviceFlow(config) as flow:
        device_code = flow.request_device_code()

        display_callback(
            device_code.user_code,
            device_code.verification_uri,
            device_code.verification_uri_complete,
        )

        result = flow.poll_for_token(
            device_code,
            timeout=timeout,
            on_poll=poll_callback,
        )

        return result.token
