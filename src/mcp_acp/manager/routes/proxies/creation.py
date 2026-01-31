"""Proxy creation endpoint and helpers."""

from __future__ import annotations

__all__ = ["create_proxy"]

import logging
from datetime import UTC, datetime
from pathlib import Path

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.manager.routes.proxies.snippet import get_executable_path
from mcp_acp.config import (
    BackendConfig,
    HITLConfig,
    HttpTransportConfig,
    MTLSConfig,
    PerProxyConfig,
    StdioAttestationConfig,
    StdioTransportConfig,
    generate_proxy_id,
    save_proxy_config,
)
from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import (
    find_duplicate_backend,
    get_proxy_config_path,
    get_proxy_policy_path,
    validate_proxy_name,
)
from mcp_acp.manager.models import CreateProxyRequest, CreateProxyResponse
from mcp_acp.pdp import create_default_policy
from mcp_acp.utils.policy import save_policy
from mcp_acp.utils.validation import SHA256_HEX_LENGTH, validate_sha256_hex

from . import HTTP_TRANSPORTS, STDIO_TRANSPORTS, router

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.proxies")


def _build_transport_configs(
    body: CreateProxyRequest,
) -> tuple[StdioTransportConfig | None, HttpTransportConfig | None]:
    """Build transport configurations from request.

    Args:
        body: Validated proxy creation request.

    Returns:
        Tuple of (stdio_config, http_config).

    Raises:
        APIError: If attestation_sha256 is invalid format.
    """
    stdio_config = None
    http_config = None

    if body.transport in STDIO_TRANSPORTS and body.command:
        # Build attestation config if any attestation options provided
        attestation = None
        if body.attestation_slsa_owner or body.attestation_sha256 or body.attestation_require_signature:
            # Validate SHA-256 format if provided
            normalized_sha256 = None
            if body.attestation_sha256:
                is_valid, normalized_sha256 = validate_sha256_hex(body.attestation_sha256)
                if not is_valid:
                    raise APIError(
                        status_code=400,
                        code=ErrorCode.PROXY_INVALID,
                        message=f"Invalid attestation_sha256: must be {SHA256_HEX_LENGTH} hex characters",
                        details={"proxy_name": body.name, "attestation_sha256": body.attestation_sha256},
                    )
            attestation = StdioAttestationConfig(
                slsa_owner=body.attestation_slsa_owner,
                expected_sha256=normalized_sha256,
                require_signature=body.attestation_require_signature,
            )
        stdio_config = StdioTransportConfig(
            command=body.command,
            args=body.args,
            attestation=attestation,
        )

    if body.transport in HTTP_TRANSPORTS and body.url:
        http_config = HttpTransportConfig(
            url=body.url,
            timeout=body.timeout,
        )

    return stdio_config, http_config


def _build_mtls_config(body: CreateProxyRequest) -> MTLSConfig | None:
    """Build mTLS configuration from request.

    Args:
        body: Validated proxy creation request.

    Returns:
        MTLSConfig if all mTLS options provided, None otherwise.

    Raises:
        APIError: If partial mTLS options provided or files don't exist.
    """
    # Check if any mTLS options provided
    has_any = body.mtls_cert or body.mtls_key or body.mtls_ca
    if not has_any:
        return None

    # Require all three if any is provided
    if not (body.mtls_cert and body.mtls_key and body.mtls_ca):
        raise APIError(
            status_code=400,
            code=ErrorCode.PROXY_INVALID,
            message="mTLS requires all three: mtls_cert, mtls_key, mtls_ca",
            details={"proxy_name": body.name},
        )

    # Validate paths exist
    for field_name, path_val in [
        ("mtls_cert", body.mtls_cert),
        ("mtls_key", body.mtls_key),
        ("mtls_ca", body.mtls_ca),
    ]:
        if not Path(path_val).expanduser().exists():
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message=f"mTLS {field_name} file not found: {path_val}",
                details={"proxy_name": body.name, "field": field_name, "path": path_val},
            )

    return MTLSConfig(
        client_cert_path=body.mtls_cert,
        client_key_path=body.mtls_key,
        ca_bundle_path=body.mtls_ca,
    )


def _store_api_key(
    proxy_name: str,
    api_key: str,
    http_config: HttpTransportConfig,
) -> HttpTransportConfig:
    """Store API key in keychain and return updated config.

    Args:
        proxy_name: Name of the proxy.
        api_key: API key to store.
        http_config: HTTP config to update with credential_key.

    Returns:
        Updated HttpTransportConfig with credential_key.

    Raises:
        APIError: If keychain storage fails.
    """
    try:
        from mcp_acp.security.credential_storage import BackendCredentialStorage

        cred_storage = BackendCredentialStorage(proxy_name)
        cred_storage.save(api_key)
        return http_config.model_copy(update={"credential_key": cred_storage.credential_key})
    except RuntimeError as e:
        _logger.error(
            {
                "event": "keychain_store_failed",
                "message": f"Failed to store API key in keychain for proxy '{proxy_name}'",
                "proxy_name": proxy_name,
                "error_type": type(e).__name__,
                "error_message": str(e),
            }
        )
        raise APIError(
            status_code=500,
            code=ErrorCode.PROXY_CREATION_FAILED,
            message=f"Failed to store API key in keychain: {e}",
            details={"proxy_name": proxy_name, "error": str(e)},
        )


def _check_http_health(url: str, timeout: int, mtls_config: MTLSConfig | None) -> None:
    """Check HTTP backend health before creating proxy.

    Args:
        url: Backend URL to check.
        timeout: HTTP timeout in seconds.
        mtls_config: Optional mTLS configuration.

    Raises:
        APIError: If health check fails (PROXY_INVALID for SSL/cert errors,
            BACKEND_UNREACHABLE for connectivity errors).
    """
    from mcp_acp.constants import HEALTH_CHECK_TIMEOUT_SECONDS
    from mcp_acp.utils.transport import check_http_health

    try:
        check_http_health(url, timeout=min(timeout, HEALTH_CHECK_TIMEOUT_SECONDS), mtls_config=mtls_config)
    except ValueError as e:
        # Invalid mTLS certificates
        _logger.warning(
            {
                "event": "health_check_cert_invalid",
                "message": f"Invalid mTLS certificate for {url}: {e}",
                "url": url,
                "error_type": type(e).__name__,
                "error_message": str(e),
            }
        )
        raise APIError(
            status_code=400,
            code=ErrorCode.PROXY_INVALID,
            message=f"Invalid mTLS certificate: {e}",
            details={"url": url, "error": str(e)},
        )
    except (TimeoutError, ConnectionError, OSError) as e:
        error_msg = str(e).lower()
        is_ssl_error = "ssl" in error_msg or "certificate" in error_msg
        _logger.warning(
            {
                "event": "health_check_failed",
                "message": f"Health check failed for {url}: {e}",
                "url": url,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "is_ssl_error": is_ssl_error,
            }
        )
        if is_ssl_error:
            raise APIError(
                status_code=400,
                code=ErrorCode.PROXY_INVALID,
                message=f"SSL/TLS error connecting to backend: {e}",
                details={"url": url, "error": str(e)},
            )
        raise APIError(
            status_code=400,
            code=ErrorCode.BACKEND_UNREACHABLE,
            message=f"Backend health check failed: could not reach {url}",
            details={"url": url, "error": str(e)},
        )


@router.post("/proxies", response_model=CreateProxyResponse, status_code=201)
async def create_proxy(body: CreateProxyRequest) -> CreateProxyResponse:
    """Create a new proxy configuration.

    Mirrors CLI 'mcp-acp proxy add' functionality:
    1. Validates proxy name
    2. Creates proxies/{name}/config.json
    3. Creates proxies/{name}/policy.json (default policy)
    4. Stores API key in keychain if provided
    5. Returns Claude Desktop config snippet

    Args:
        body: CreateProxyRequest with proxy configuration.

    Returns:
        CreateProxyResponse with paths and Claude Desktop snippet.

    Raises:
        APIError: If validation fails (400), proxy exists (409), or creation fails (500).
    """
    # Validate proxy name
    try:
        validate_proxy_name(body.name)
    except ValueError as e:
        raise APIError(
            status_code=400,
            code=ErrorCode.PROXY_INVALID,
            message=str(e),
            details={"proxy_name": body.name},
        )

    # Check if proxy already exists
    config_path = get_proxy_config_path(body.name)
    if config_path.exists():
        raise APIError(
            status_code=409,
            code=ErrorCode.PROXY_EXISTS,
            message=f"Proxy '{body.name}' already exists.",
            details={"proxy_name": body.name},
        )

    # Validate transport-specific requirements
    if body.transport in STDIO_TRANSPORTS and not body.command:
        raise APIError(
            status_code=400,
            code=ErrorCode.PROXY_INVALID,
            message="Command is required for stdio/auto transport.",
            details={"proxy_name": body.name, "transport": body.transport},
        )
    if body.transport == "streamablehttp" and not body.url:
        raise APIError(
            status_code=400,
            code=ErrorCode.PROXY_INVALID,
            message="URL is required for HTTP transport.",
            details={"proxy_name": body.name, "transport": body.transport},
        )

    # Build transport configs
    stdio_config, http_config = _build_transport_configs(body)

    # Build mTLS config (validates paths exist)
    mtls_config = _build_mtls_config(body)

    # Check HTTP backend health if configured (skip if user already confirmed)
    if http_config is not None and not body.skip_health_check:
        _check_http_health(http_config.url, http_config.timeout, mtls_config)

    # Check for duplicate backends (skip if user already confirmed)
    if not body.skip_duplicate_check:
        dup_name = find_duplicate_backend(stdio_config, http_config)
        if dup_name:
            raise APIError(
                status_code=400,
                code=ErrorCode.BACKEND_DUPLICATE,
                message=f"Proxy '{dup_name}' already routes to this backend.",
                details={"existing_proxy": dup_name},
            )

    # Generate proxy ID
    proxy_id = generate_proxy_id(body.server_name)

    # Build backend config
    backend_config = BackendConfig(
        server_name=body.server_name,
        transport=body.transport,
        stdio=stdio_config,
        http=http_config,
    )

    # Store API key in keychain if provided (raises APIError on failure)
    if body.api_key and http_config is not None:
        http_config = _store_api_key(body.name, body.api_key, http_config)
        backend_config = backend_config.model_copy(update={"http": http_config})

    # Create proxy config
    proxy_config = PerProxyConfig(
        proxy_id=proxy_id,
        created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        backend=backend_config,
        hitl=HITLConfig(),
        mtls=mtls_config,
    )

    # Save config
    try:
        save_proxy_config(body.name, proxy_config)
    except OSError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.PROXY_CREATION_FAILED,
            message=f"Failed to save proxy configuration: {e}",
            details={"proxy_name": body.name, "error": str(e)},
        )

    # Create default policy
    policy_path = get_proxy_policy_path(body.name)
    try:
        default_policy = create_default_policy()
        save_policy(default_policy, policy_path)
    except OSError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.PROXY_CREATION_FAILED,
            message=f"Config created but policy creation failed: {e}",
            details={"proxy_name": body.name, "config_path": str(config_path), "error": str(e)},
        )

    # Build Claude Desktop snippet
    executable_path = get_executable_path()
    claude_snippet = {
        body.name: {
            "command": executable_path,
            "args": ["start", "--proxy", body.name],
        }
    }

    return CreateProxyResponse(
        ok=True,
        proxy_name=body.name,
        proxy_id=proxy_id,
        config_path=str(config_path),
        policy_path=str(policy_path),
        claude_desktop_snippet=claude_snippet,
        message=f"Proxy '{body.name}' created successfully.",
    )
