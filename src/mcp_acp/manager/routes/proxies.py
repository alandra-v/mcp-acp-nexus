"""Proxy management endpoints (list, detail, create, config-snippet)."""

from __future__ import annotations

__all__ = ["router", "STDIO_TRANSPORTS", "HTTP_TRANSPORTS"]

import asyncio
import json
import logging
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.config import (
    BackendConfig,
    HITLConfig,
    HttpTransportConfig,
    MTLSConfig,
    PerProxyConfig,
    StdioAttestationConfig,
    StdioTransportConfig,
    generate_proxy_id,
    load_proxy_config,
    save_proxy_config,
)
from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import (
    get_proxy_config_path,
    get_proxy_policy_path,
    list_configured_proxies,
    validate_proxy_name,
)
from mcp_acp.manager.models import (
    ConfigSnippetResponse,
    CreateProxyRequest,
    CreateProxyResponse,
    Proxy,
    ProxyDeleteResponse,
    ProxyDetailResponse,
    ProxyStats,
)
from mcp_acp.manager.registry import ProxyRegistry
from mcp_acp.pdp import create_default_policy
from mcp_acp.utils.policy import save_policy
from mcp_acp.utils.validation import SHA256_HEX_LENGTH, validate_sha256_hex

from .deps import find_proxy_by_id
from .helpers import (
    PROXY_SNAPSHOT_TIMEOUT_SECONDS,
    create_uds_client,
    fetch_proxy_snapshots,
)

# Transport types that require specific configuration
STDIO_TRANSPORTS = frozenset({"stdio", "auto"})
HTTP_TRANSPORTS = frozenset({"streamablehttp", "auto"})

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.proxies")

router = APIRouter(prefix="/api/manager", tags=["proxies"])


@router.get("/proxies", response_model=list[Proxy])
async def list_proxies_enhanced(request: Request) -> list[Proxy]:
    """List all configured proxies with config and runtime data.

    Returns enhanced proxy information combining:
    - Config data (server_name, transport, created_at) from config files
    - Runtime data (status, instance_id, stats) from registry and UDS

    Shows all configured proxies, not just running ones.
    """
    reg: ProxyRegistry = request.app.state.registry

    # Get registered (running) proxies for lookup
    registered = await reg.list_proxies()
    registered_by_name = {p["name"]: p for p in registered}

    # Get all configured proxies
    configured_names = list_configured_proxies()

    # Load configs and identify running proxies
    configs: dict[str, PerProxyConfig] = {}
    running_proxies: list[tuple[str, str]] = []  # (proxy_name, socket_path)

    for proxy_name in configured_names:
        try:
            configs[proxy_name] = load_proxy_config(proxy_name)
        except (FileNotFoundError, ValueError, OSError) as e:
            _logger.warning(
                {
                    "event": "proxy_config_load_failed",
                    "message": f"Failed to load config for proxy '{proxy_name}': {e}",
                    "proxy_name": proxy_name,
                    "error_type": type(e).__name__,
                    "error_message": str(e),
                }
            )
            continue

        # Check if running
        reg_info = registered_by_name.get(proxy_name)
        if reg_info and reg_info.get("socket_path"):
            running_proxies.append((proxy_name, reg_info["socket_path"]))

    # Fetch stats concurrently for all running proxies
    async def fetch_stats(socket_path: str) -> ProxyStats | None:
        try:
            async with create_uds_client(
                socket_path,
                timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
            ) as client:
                resp = await client.get("/api/stats")
                if resp.status_code == 200:
                    stats_data = resp.json()
                    return ProxyStats(
                        requests_total=stats_data.get("requests_total", 0),
                        requests_allowed=stats_data.get("requests_allowed", 0),
                        requests_denied=stats_data.get("requests_denied", 0),
                        requests_hitl=stats_data.get("requests_hitl", 0),
                    )
        except (httpx.ConnectError, OSError, httpx.TimeoutException, json.JSONDecodeError):
            pass  # Failed to fetch stats
        return None

    # Fetch all stats concurrently
    stats_results = await asyncio.gather(
        *(fetch_stats(socket_path) for _, socket_path in running_proxies),
        return_exceptions=True,
    )
    stats_by_name: dict[str, ProxyStats | None] = {}
    for (proxy_name, _), stats_result in zip(running_proxies, stats_results):
        if isinstance(stats_result, BaseException):
            stats_by_name[proxy_name] = None
        else:
            stats_by_name[proxy_name] = stats_result

    # Build result
    result: list[Proxy] = []
    for proxy_name, config in configs.items():
        reg_info = registered_by_name.get(proxy_name)
        is_running = reg_info is not None

        # Extract command/args from stdio config, url from http config
        command = None
        args = None
        url = None
        if config.backend.stdio:
            command = config.backend.stdio.command
            args = config.backend.stdio.args or []
        if config.backend.http:
            url = config.backend.http.url

        # Determine actual backend transport
        # - "auto" resolves to stdio if command present, else streamablehttp
        # - explicit transport types are used as-is
        backend_transport = config.backend.transport
        if backend_transport == "auto":
            backend_transport = "stdio" if config.backend.stdio else "streamablehttp"

        result.append(
            Proxy(
                proxy_name=proxy_name,
                proxy_id=config.proxy_id,
                status="running" if is_running else "inactive",
                instance_id=reg_info.get("instance_id") if reg_info else None,
                server_name=config.backend.server_name,
                transport=config.backend.transport,
                command=command,
                args=args if args else None,
                url=url,
                created_at=config.created_at,
                backend_transport=backend_transport,
                mtls_enabled=config.mtls is not None,
                stats=stats_by_name.get(proxy_name),
            )
        )

    return result


@router.get("/proxies/{proxy_id}", response_model=ProxyDetailResponse)
async def get_proxy_detail(proxy_id: str, request: Request) -> ProxyDetailResponse:
    """Get full proxy detail by proxy_id.

    Returns config and runtime data for a specific proxy.

    Args:
        proxy_id: Stable proxy identifier from config.
        request: FastAPI request object.

    Returns:
        ProxyDetailResponse with config and runtime data.

    Raises:
        APIError: If proxy_id not found (404).
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, config = result
    reg: ProxyRegistry = request.app.state.registry

    # Check if running
    registered = await reg.list_proxies()
    reg_info = next((p for p in registered if p["name"] == proxy_name), None)
    is_running = reg_info is not None

    # Extract command/args from stdio config, url from http config
    command = None
    args = None
    url = None
    if config.backend.stdio:
        command = config.backend.stdio.command
        args = config.backend.stdio.args or []
    if config.backend.http:
        url = config.backend.http.url

    # Determine actual backend transport
    backend_transport = config.backend.transport
    if backend_transport == "auto":
        backend_transport = "stdio" if config.backend.stdio else "streamablehttp"

    # Fetch runtime data if running
    stats = None
    client_id = None
    pending_approvals = None
    cached_approvals = None

    if is_running and reg_info and reg_info.get("socket_path"):
        socket_path = reg_info["socket_path"]
        try:
            async with create_uds_client(
                socket_path,
                timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS,
            ) as client:
                snapshots = await fetch_proxy_snapshots(client)

                # Extract stats
                if snapshots["stats"]:
                    stats = ProxyStats(
                        requests_total=snapshots["stats"].get("requests_total", 0),
                        requests_allowed=snapshots["stats"].get("requests_allowed", 0),
                        requests_denied=snapshots["stats"].get("requests_denied", 0),
                        requests_hitl=snapshots["stats"].get("requests_hitl", 0),
                    )

                # Extract client_id
                client_id = snapshots.get("client_id")

                # Extract pending approvals
                pending_approvals = snapshots["pending"]

                # Extract cached approvals
                if snapshots["cached"]:
                    cached_approvals = snapshots["cached"].get("approvals", [])

        except (httpx.ConnectError, OSError, httpx.TimeoutException, json.JSONDecodeError) as e:
            _logger.debug("Runtime data fetch failed for proxy '%s': %s", proxy_name, e)

    return ProxyDetailResponse(
        proxy_name=proxy_name,
        proxy_id=config.proxy_id,
        status="running" if is_running else "inactive",
        instance_id=reg_info.get("instance_id") if reg_info else None,
        server_name=config.backend.server_name,
        transport=config.backend.transport,
        command=command,
        args=args if args else None,
        url=url,
        created_at=config.created_at,
        backend_transport=backend_transport,
        mtls_enabled=config.mtls is not None,
        stats=stats,
        client_id=client_id,
        pending_approvals=pending_approvals,
        cached_approvals=cached_approvals,
    )


# ==========================================================================
# Proxy Deletion
# ==========================================================================


@router.delete("/proxies/{proxy_id}", response_model=ProxyDeleteResponse)
async def delete_proxy_endpoint(
    proxy_id: str,
    request: Request,
    purge: bool = False,
) -> ProxyDeleteResponse:
    """Delete a proxy configuration.

    Soft deletes (archives) by default. Pass ?purge=true to permanently delete.

    Args:
        proxy_id: Stable proxy identifier from config.
        request: FastAPI request object.
        purge: If True, permanently delete instead of archiving.

    Returns:
        ProxyDeleteResponse with deletion summary.

    Raises:
        APIError: If proxy not found (404) or currently running (409).
    """
    from mcp_acp.manager.deletion import delete_proxy
    from mcp_acp.manager.events import SSEEventType

    # Resolve proxy_id -> proxy_name
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, _config = result
    reg: ProxyRegistry = request.app.state.registry

    # Check if proxy is running
    registered = await reg.list_proxies()
    is_running = any(p["name"] == proxy_name for p in registered)

    if is_running:
        raise APIError(
            status_code=409,
            code=ErrorCode.PROXY_RUNNING,
            message=f"Proxy '{proxy_name}' is currently running. Stop the proxy first.",
            details={"proxy_id": proxy_id, "proxy_name": proxy_name},
        )

    # Perform deletion
    try:
        delete_result = delete_proxy(proxy_name, purge=purge, deleted_by="api")
    except OSError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message=f"Failed to delete proxy: {e}",
            details={"proxy_id": proxy_id, "proxy_name": proxy_name, "error": str(e)},
        )

    # Broadcast proxy_deleted SSE event (best-effort — deletion already succeeded)
    try:
        await reg.broadcast_snapshot(
            SSEEventType.PROXY_DELETED.value,
            {
                "proxy_id": proxy_id,
                "proxy_name": proxy_name,
                "archive_name": delete_result.archive_name,
            },
        )
    except Exception:
        _logger.debug("SSE broadcast failed after proxy deletion: %s", proxy_name)

    _logger.warning(
        {
            "event": "proxy_deleted",
            "message": f"Proxy deleted: {proxy_name}",
            "proxy_name": proxy_name,
            "proxy_id": proxy_id,
            "details": {
                "purge": purge,
                "deleted_by": "api",
                "archive_name": delete_result.archive_name,
                "archived_count": len(delete_result.archived),
                "deleted_count": len(delete_result.deleted),
            },
        }
    )

    return ProxyDeleteResponse(
        archived=delete_result.archived,
        deleted=delete_result.deleted,
        archive_name=delete_result.archive_name,
        archived_size=delete_result.archived_size,
        deleted_size=delete_result.deleted_size,
    )


# ==========================================================================
# CLI Deletion Notification
# ==========================================================================


class _ProxyDeletedNotification(BaseModel):
    """Request body for CLI proxy deletion notification."""

    proxy_id: str
    proxy_name: str
    archive_name: str | None = None


@router.post("/proxies/notify-deleted")
async def notify_proxy_deleted(
    notification: _ProxyDeletedNotification,
    request: Request,
) -> dict[str, bool]:
    """Receive CLI notification that a proxy was deleted.

    Broadcasts proxy_deleted SSE event so web UI updates instantly.
    Called by CLI after local deletion completes.
    """
    from mcp_acp.manager.events import SSEEventType

    reg: ProxyRegistry = request.app.state.registry
    await reg.broadcast_snapshot(
        SSEEventType.PROXY_DELETED.value,
        {
            "proxy_id": notification.proxy_id,
            "proxy_name": notification.proxy_name,
            "archive_name": notification.archive_name,
        },
    )

    _logger.warning(
        {
            "event": "proxy_deleted",
            "message": f"Proxy deleted (CLI): {notification.proxy_name}",
            "proxy_name": notification.proxy_name,
            "proxy_id": notification.proxy_id,
            "details": {
                "deleted_by": "cli",
                "archive_name": notification.archive_name,
            },
        }
    )

    return {"ok": True}


# ==========================================================================
# Config Snippet
# ==========================================================================


def _get_executable_path() -> str:
    """Find absolute path to mcp-acp executable.

    Tries multiple methods to find the executable:
    1. shutil.which (PATH lookup)
    2. sys.argv[0] if it contains 'mcp-acp' or 'mcp_acp'
    3. Falls back to 'mcp-acp' (assumes it's in PATH)

    Returns:
        Absolute path to mcp-acp executable.
    """
    # Try PATH first
    path = shutil.which(APP_NAME)
    if path:
        return str(Path(path).resolve())

    # Try sys.argv[0] - how the current process was invoked
    argv0 = sys.argv[0] if sys.argv else ""
    if "mcp-acp" in argv0 or "mcp_acp" in argv0:
        resolved = Path(argv0).resolve()
        if resolved.exists():
            return str(resolved)

    return APP_NAME  # Fall back to name, assume it's in PATH


@router.get("/config-snippet", response_model=ConfigSnippetResponse)
async def get_config_snippet(proxy: str | None = None) -> ConfigSnippetResponse:
    """Get MCP client configuration snippet for proxies.

    Returns JSON in the standard mcpServers format used by Claude Desktop,
    Cursor, VS Code, and other MCP clients.

    Args:
        proxy: Optional proxy name to get snippet for. If not provided,
               returns snippet for all configured proxies.

    Returns:
        ConfigSnippetResponse with mcpServers dictionary and executable path.

    Raises:
        APIError: If specified proxy not found.
    """
    proxies = list_configured_proxies()

    if proxy:
        # Single proxy requested
        if proxy not in proxies:
            raise APIError(
                status_code=404,
                code=ErrorCode.PROXY_NOT_FOUND,
                message=f"Proxy '{proxy}' not found",
                details={"proxy_name": proxy, "available": proxies},
            )
        proxies_to_include = [proxy]
    else:
        # All proxies
        proxies_to_include = proxies

    executable = _get_executable_path()

    mcp_servers: dict[str, dict[str, Any]] = {}
    for name in proxies_to_include:
        mcp_servers[name] = {
            "command": executable,
            "args": ["start", "--proxy", name],
        }

    return ConfigSnippetResponse(
        mcpServers=mcp_servers,
        executable_path=executable,
    )


# ==========================================================================
# Proxy Creation Helpers
# ==========================================================================


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
    claude_snippet = {
        body.name: {
            "command": "mcp-acp",
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
