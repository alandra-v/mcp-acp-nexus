"""Transport utilities for backend connection.

Handles transport selection, health checks, and creation.
Supports STDIO (local process) and Streamable HTTP (remote URL) transports.
Includes mTLS support for secure proxy-to-backend authentication.
"""

import asyncio
import logging
import ssl
import time
from typing import TYPE_CHECKING, Any, Literal

import httpx
from fastmcp.client.transports import ClientTransport, StdioTransport, StreamableHttpTransport
from fastmcp.server.proxy import ProxyClient

from mcp_acp import __version__
from mcp_acp.constants import (
    APP_NAME,
    BACKEND_RETRY_BACKOFF_MULTIPLIER,
    BACKEND_RETRY_INITIAL_DELAY,
    BACKEND_RETRY_MAX_ATTEMPTS,
    HEALTH_CHECK_TIMEOUT_SECONDS,
    TRANSPORT_ERRORS,
)
from mcp_acp.exceptions import (
    BackendHTTPError,
    ProcessVerificationError,
    SSLCertificateError,
    SSLHandshakeError,
)
from mcp_acp.security.binary_attestation import (
    BinaryAttestationConfig,
    BinaryAttestationResult,
    verify_backend_binary,
)
from mcp_acp.security.mtls import (
    create_mtls_client_factory,
    get_certificate_expiry_info,
    validate_mtls_config,
)

# User-Agent header for HTTP backend connections (informational, not security)
USER_AGENT = f"{APP_NAME}/{__version__}"

if TYPE_CHECKING:
    from mcp.shared._httpx_utils import McpHttpClientFactory

    from mcp_acp.config import BackendConfig, HttpTransportConfig, MTLSConfig, StdioTransportConfig

logger = logging.getLogger(__name__)

__all__ = [
    "BinaryAttestationConfig",
    "BinaryAttestationResult",
    "USER_AGENT",
    "check_http_health",
    "check_http_health_with_retry",
    "create_backend_transport",
    "create_httpx_client_factory",
    "create_mtls_client_factory",
    "get_certificate_expiry_info",
    "validate_mtls_config",
    "verify_backend_binary",
]


# =============================================================================
# HTTP Client Factory
# =============================================================================


def create_httpx_client_factory(
    mtls_config: "MTLSConfig | None" = None,
    url: str | None = None,
    auth_headers: dict[str, str] | None = None,
) -> "McpHttpClientFactory":
    """Create an httpx client factory with User-Agent header.

    Always includes the mcp-acp User-Agent header for observability.
    Optionally configures mTLS if certificates are provided and URL is HTTPS.

    Args:
        mtls_config: Optional mTLS configuration for client certificate auth.
        url: Optional URL to check if HTTPS (mTLS only applies to HTTPS).
        auth_headers: Optional authentication headers to include in all requests.

    Returns:
        Factory callable that creates configured httpx.AsyncClient instances.
    """
    # Determine if mTLS should be used (only for HTTPS URLs)
    use_mtls = mtls_config is not None and url is not None and url.lower().startswith("https://")

    if use_mtls:
        # Get the mTLS factory and wrap it to add User-Agent
        assert mtls_config is not None  # Guaranteed by use_mtls check
        mtls_factory = create_mtls_client_factory(mtls_config)

        def factory_with_mtls(
            headers: dict[str, str] | None = None,
            timeout: httpx.Timeout | None = None,
            auth: httpx.Auth | None = None,
            **kwargs: Any,  # Accept additional args like follow_redirects
        ) -> httpx.AsyncClient:
            """Create httpx client with mTLS and User-Agent."""
            merged_headers = {"User-Agent": USER_AGENT}
            if auth_headers:
                merged_headers.update(auth_headers)
            if headers:
                merged_headers.update(headers)
            return mtls_factory(
                headers=merged_headers,
                timeout=timeout,
                auth=auth,
                **kwargs,
            )

        return factory_with_mtls

    # No mTLS - create simple factory with just User-Agent
    def factory_simple(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
        **kwargs: Any,  # Accept additional args like follow_redirects
    ) -> httpx.AsyncClient:
        """Create httpx client with User-Agent."""
        merged_headers = {"User-Agent": USER_AGENT}
        if auth_headers:
            merged_headers.update(auth_headers)
        if headers:
            merged_headers.update(headers)
        return httpx.AsyncClient(
            headers=merged_headers,
            timeout=timeout,
            auth=auth,
            **kwargs,
        )

    return factory_simple


def _load_backend_credential(credential_key: str) -> str:
    """Load backend credential from OS keychain.

    Args:
        credential_key: The keychain key (e.g., "proxy:my-proxy:backend").

    Returns:
        The credential string.

    Raises:
        ValueError: If credential not found in keychain.
        RuntimeError: If keychain access fails.
    """
    import keyring
    from keyring.errors import KeyringError

    try:
        credential = keyring.get_password(APP_NAME, credential_key)
        if credential is None:
            raise ValueError(
                f"Backend credential not found in keychain (key: {credential_key}). "
                f"Store it with: mcp-acp proxy add --api-key <key>"
            )
        return credential
    except KeyringError as e:
        raise RuntimeError(f"Failed to access keychain: {e}") from e


# =============================================================================
# Health Checks
# =============================================================================


def check_http_health(
    url: str,
    timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS,
    mtls_config: "MTLSConfig | None" = None,
) -> None:
    """Check if an HTTP endpoint is reachable.

    Tests connectivity by attempting an MCP initialize handshake.

    Args:
        url: The backend URL to test.
        timeout: Connection timeout in seconds (default: HEALTH_CHECK_TIMEOUT_SECONDS).
        mtls_config: Optional mTLS configuration for client certificate auth.

    Raises:
        TimeoutError: If connection times out.
        ConnectionError: If connection fails.
        FileNotFoundError: If mTLS certificate files don't exist.
        ValueError: If mTLS certificates are invalid.
    """
    try:
        asyncio.get_running_loop()
        in_async_context = True
    except RuntimeError:
        in_async_context = False

    if in_async_context:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, _check_async(url, timeout, mtls_config))
            future.result()
    else:
        asyncio.run(_check_async(url, timeout, mtls_config))


def check_http_health_with_retry(
    url: str,
    timeout: float = HEALTH_CHECK_TIMEOUT_SECONDS,
    mtls_config: "MTLSConfig | None" = None,
    max_attempts: int = BACKEND_RETRY_MAX_ATTEMPTS,
) -> None:
    """Check HTTP endpoint with retry and exponential backoff.

    Retries connection attempts with exponential backoff until the backend
    is reachable or max_attempts is exceeded. Used at startup to wait for
    backends that may start after the proxy.

    SSL-specific errors (SSLCertificateError, SSLHandshakeError) are NOT retried
    as they indicate configuration issues that won't resolve on their own.

    Args:
        url: The backend URL to test.
        timeout: Per-attempt connection timeout (default: HEALTH_CHECK_TIMEOUT_SECONDS).
        mtls_config: Optional mTLS configuration for client certificate auth.
        max_attempts: Maximum connection attempts (default: 3).

    Raises:
        TimeoutError: If backend not reachable after max_attempts.
        SSLCertificateError: If SSL certificate validation fails.
        SSLHandshakeError: If SSL handshake fails (e.g., client cert required).
        ConnectionError: If connection fails for non-retryable reasons.
        FileNotFoundError: If mTLS certificate files don't exist.
        ValueError: If mTLS certificates are invalid.
    """
    delay = BACKEND_RETRY_INITIAL_DELAY
    last_error: Exception | None = None
    is_https = url.lower().startswith("https://")

    for attempt in range(1, max_attempts + 1):
        try:
            check_http_health(url, timeout, mtls_config)
            # Success - backend is up
            if attempt > 1:
                logger.warning(f"Backend connected on attempt {attempt}: {url}")
            return
        except (SSLCertificateError, SSLHandshakeError) as e:
            # SSL errors are not retryable - fail immediately with clear message
            raise
        except BackendHTTPError:
            # HTTP error responses mean the backend is reachable but rejecting
            # requests - retrying won't help (especially for 4xx)
            raise
        except (TimeoutError, ConnectionError) as e:
            last_error = e

            if attempt >= max_attempts:
                # No more retries - provide context-aware error message
                if is_https and mtls_config is None:
                    # HTTPS without mTLS configured - likely requires client cert
                    raise ConnectionError(
                        f"SSL/TLS connection failed: {url}. "
                        "The server may require mTLS (client certificate authentication). "
                        "Configure mTLS in your proxy config file."
                    ) from e
                raise TimeoutError(f"Backend not reachable after {max_attempts} attempts: {url}") from e

            # Log retry attempt
            logger.warning(
                f"Waiting for backend at {url} (attempt {attempt}/{max_attempts}, retrying in {delay:.0f}s)..."
            )
            time.sleep(delay)

            # Exponential backoff
            delay = delay * BACKEND_RETRY_BACKOFF_MULTIPLIER


def create_backend_transport(
    backend_config: "BackendConfig",
    mtls_config: "MTLSConfig | None" = None,
) -> tuple[ClientTransport, Literal["streamablehttp", "stdio"]]:
    """Create backend transport with auto-detection and health checks.

    Transport selection logic:
    1. If transport explicitly set ("stdio" or "streamablehttp"): use it
       (validate config exists, check HTTP health)
    2. If transport is "auto":
       - Both configured: try HTTP first, fall back to STDIO if unreachable
       - HTTP only: use HTTP (fail if unreachable)
       - STDIO only: use STDIO
       - Neither: raise error

    Args:
        backend_config: Backend configuration.
        mtls_config: Optional mTLS configuration for client certificate auth.

    Returns:
        Tuple of (transport_instance, transport_type).

    Raises:
        ValueError: If no transport configured or config missing.
        TimeoutError: If HTTP backend times out.
        ConnectionError: If HTTP backend unreachable.
        FileNotFoundError: If mTLS certificate files don't exist.
    """
    http_config = backend_config.http
    stdio_config = backend_config.stdio
    explicit_transport = backend_config.transport

    # Determine transport type
    transport_type: Literal["streamablehttp", "stdio"]
    if explicit_transport == "streamablehttp":
        # Explicit HTTP selection - validate config exists
        if http_config is None:
            raise ValueError(
                "Streamable HTTP transport selected but http configuration is missing. "
                "Check the proxy config file (run 'mcp-acp config path --proxy <name>')."
            )
        # Use retry loop - wait for backend to become available
        check_http_health_with_retry(
            http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
        )
        transport_type = "streamablehttp"
    elif explicit_transport == "stdio":
        # Explicit STDIO selection - validate config exists
        if stdio_config is None:
            raise ValueError(
                "STDIO transport selected but stdio configuration is missing. "
                "Check the proxy config file (run 'mcp-acp config path --proxy <name>')."
            )
        transport_type = "stdio"
    else:
        # Auto-detect
        transport_type = _auto_detect(http_config, stdio_config, mtls_config)

    # Create transport
    if transport_type == "streamablehttp":
        if http_config is None:
            raise ValueError(
                "Internal error: HTTP transport selected but http_config is None. "
                "This indicates a bug in transport selection logic."
            )
        # Load backend credential if configured
        auth_headers: dict[str, str] | None = None
        if http_config.credential_key:
            credential = _load_backend_credential(http_config.credential_key)
            auth_headers = {"Authorization": f"Bearer {credential}"}
            logger.debug("Backend authentication configured via keychain")

        # Create httpx client factory with User-Agent (and optionally mTLS)
        httpx_client_factory = create_httpx_client_factory(mtls_config, http_config.url, auth_headers)

        transport: ClientTransport = StreamableHttpTransport(
            url=http_config.url,
            httpx_client_factory=httpx_client_factory,
        )
    else:
        if stdio_config is None:
            raise ValueError(
                "Internal error: STDIO transport selected but stdio_config is None. "
                "This indicates a bug in transport selection logic."
            )

        # Binary attestation verification (if configured)
        # This is a hard gate - proxy won't start if verification fails
        if stdio_config.attestation is not None:
            attestation_config = BinaryAttestationConfig(
                slsa_owner=stdio_config.attestation.slsa_owner,
                expected_sha256=stdio_config.attestation.expected_sha256,
                require_signature=stdio_config.attestation.require_signature,
            )
            attestation_result = verify_backend_binary(
                stdio_config.command,
                attestation_config,
            )
            if not attestation_result.verified:
                raise ValueError(f"Backend binary attestation failed: {attestation_result.error}")
            # sha256 is always set when verified=True, but guard for safety
            sha256_preview = attestation_result.sha256[:16] if attestation_result.sha256 else "unknown"
            logger.info(
                f"Backend binary verified: {attestation_result.binary_path} " f"(sha256={sha256_preview}...)"
            )

        transport = StdioTransport(
            command=stdio_config.command,
            args=stdio_config.args,
        )

    return transport, transport_type


def _auto_detect(
    http_config: "HttpTransportConfig | None",
    stdio_config: "StdioTransportConfig | None",
    mtls_config: "MTLSConfig | None" = None,
) -> Literal["streamablehttp", "stdio"]:
    """Auto-detect transport based on available configs.

    Priority: HTTP (if reachable after retry) > STDIO > error.

    Uses retry loop with exponential backoff (up to 30s) before falling back
    to STDIO or failing. This allows the proxy to start before the backend.

    Args:
        http_config: HTTP transport config, or None if not configured.
        stdio_config: STDIO transport config, or None if not configured.
        mtls_config: Optional mTLS configuration for client certificate auth.

    Returns:
        Transport type to use ("streamablehttp" or "stdio").

    Raises:
        ValueError: If neither transport is configured.
        TimeoutError: If HTTP-only and connection times out after retries.
        ConnectionError: If HTTP-only and server unreachable after retries.
    """
    has_http = http_config is not None
    has_stdio = stdio_config is not None

    if has_http and has_stdio:
        # Both available - retry HTTP, fall back to STDIO on timeout
        try:
            check_http_health_with_retry(
                http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
            )
            return "streamablehttp"
        except (TimeoutError, ConnectionError):
            logger.warning(f"HTTP backend not available, falling back to STDIO")
            return "stdio"

    if has_http:
        # HTTP only - retry, then fail
        check_http_health_with_retry(
            http_config.url, min(http_config.timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config
        )
        return "streamablehttp"

    if has_stdio:
        return "stdio"

    raise ValueError(
        "No transport configured. " "Check the proxy config file (run 'mcp-acp config path --proxy <name>')."
    )


async def _check_async(
    url: str,
    timeout: float,
    mtls_config: "MTLSConfig | None" = None,
) -> None:
    """Test HTTP endpoint connectivity (async implementation).

    Creates a temporary MCP client connection to verify the endpoint
    responds to the MCP initialize handshake.

    Args:
        url: Backend URL to test.
        timeout: Connection timeout in seconds.
        mtls_config: Optional mTLS configuration for client certificate auth.

    Raises:
        TimeoutError: If connection times out.
        SSLCertificateError: If SSL certificate validation fails.
        SSLHandshakeError: If SSL handshake fails (e.g., client cert rejected).
        ConnectionError: If connection fails for other reasons.
        FileNotFoundError: If mTLS certificate files don't exist.
        ValueError: If mTLS certificates are invalid.
    """
    # Create httpx client factory with User-Agent header
    # mTLS is only enabled if mtls_config provided AND url is https://
    httpx_client_factory = create_httpx_client_factory(mtls_config, url)

    transport = StreamableHttpTransport(url=url, httpx_client_factory=httpx_client_factory)
    client = ProxyClient(transport)

    try:
        async with asyncio.timeout(timeout):
            async with client:
                pass
    except asyncio.TimeoutError as e:
        raise TimeoutError(f"Connection to {url} timed out after {timeout}s") from e
    except httpx.HTTPStatusError as e:
        raise BackendHTTPError(e.response.status_code, url) from e
    except ConnectionRefusedError as e:
        raise ConnectionError(f"Backend refused connection: {url}") from e
    except ssl.SSLCertVerificationError as e:
        # Server certificate validation failed
        raise SSLCertificateError(
            f"SSL certificate verification failed for {url}: {e}. " "Check your CA bundle configuration."
        ) from e
    except ssl.SSLError as e:
        # General SSL error - often client cert rejected or handshake failure
        error_msg = str(e).lower()
        if "certificate" in error_msg or "verify" in error_msg:
            raise SSLCertificateError(f"SSL certificate error for {url}: {e}") from e
        elif "handshake" in error_msg or "alert" in error_msg:
            raise SSLHandshakeError(
                f"SSL handshake failed for {url}: {e}. "
                "The server may have rejected your client certificate."
            ) from e
        else:
            raise SSLHandshakeError(f"SSL error connecting to {url}: {e}") from e
    except TRANSPORT_ERRORS as e:
        # Known transport/network errors (httpx, connection issues, etc.)
        error_str = str(e).lower()
        if "ssl" in error_str or "certificate" in error_str:
            raise SSLHandshakeError(f"SSL error connecting to {url}: {e}") from e
        # Empty ReadError on HTTPS with mTLS configured = likely client cert rejected
        if url.lower().startswith("https://") and mtls_config is not None and not error_str:
            raise SSLHandshakeError(
                f"SSL handshake failed for {url}. " "The server may have rejected your client certificate."
            ) from e
        raise ConnectionError(f"Backend unreachable: {url} ({type(e).__name__}: {e})") from e
    except RuntimeError as e:
        # fastmcp wraps transport errors in RuntimeError
        error_str = str(e).lower()
        if "ssl" in error_str or "certificate" in error_str:
            raise SSLHandshakeError(f"SSL error connecting to {url}: {e}") from e
        # Check for empty error on HTTPS - likely mTLS required but not configured
        if url.lower().startswith("https://") and (not error_str or "client failed to connect:" in error_str):
            if mtls_config is None:
                raise ConnectionError(
                    f"Backend connection failed: {url}. "
                    "The server may require mTLS (client certificate). "
                    "Configure mTLS in your proxy config file."
                ) from e
            else:
                # mTLS configured but connection failed with empty error = cert rejected
                raise SSLHandshakeError(
                    f"SSL handshake failed for {url}. "
                    "The server may have rejected your client certificate."
                ) from e
        raise ConnectionError(f"Backend connection failed: {url} ({e})") from e
    except OSError as e:
        # General OS-level network errors (socket errors, DNS failures, etc.)
        raise ConnectionError(f"Network error connecting to {url}: {type(e).__name__}: {e}") from e
