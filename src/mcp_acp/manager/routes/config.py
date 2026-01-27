"""Config management endpoints."""

from __future__ import annotations

__all__ = ["router"]

from typing import Any

from fastapi import APIRouter

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.config import (
    AuthConfigResponse,
    BackendConfigResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    HITLConfigResponse,
    HttpTransportResponse,
    LoggingConfigResponse,
    MTLSConfigResponse,
    ProxyConfigResponse,
    StdioTransportResponse,
)
from mcp_acp.config import PerProxyConfig, load_proxy_config, save_proxy_config
from mcp_acp.manager.config import get_proxy_config_path, get_proxy_log_dir
from pydantic import ValidationError as PydanticValidationError

from .deps import find_proxy_by_id

router = APIRouter(prefix="/api/manager/proxies", tags=["config"])


# ==========================================================================
# Config Helpers
# ==========================================================================


def _validation_errors_from_pydantic(e: PydanticValidationError) -> list[dict[str, Any]]:
    """Extract validation errors from a Pydantic ValidationError."""
    return [
        {
            "loc": list(err.get("loc", [])),
            "msg": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in e.errors()
    ]


def _build_config_response_from_proxy(config: PerProxyConfig, proxy_name: str) -> ConfigResponse:
    """Build API response from PerProxyConfig.

    Args:
        config: Per-proxy configuration to convert.
        proxy_name: Name of the proxy.

    Returns:
        ConfigResponse with all configuration details.
    """
    # Build backend response
    stdio_response = None
    if config.backend.stdio:
        stdio_response = StdioTransportResponse(
            command=config.backend.stdio.command,
            args=config.backend.stdio.args,
        )

    http_response = None
    if config.backend.http:
        http_response = HttpTransportResponse(
            url=config.backend.http.url,
            timeout=config.backend.http.timeout,
            credential_key=config.backend.http.credential_key,
        )

    backend_response = BackendConfigResponse(
        server_name=config.backend.server_name,
        transport=config.backend.transport,
        stdio=stdio_response,
        http=http_response,
    )

    # Build auth response (mTLS is per-proxy)
    auth_response = None
    mtls_response = None
    if config.mtls:
        mtls_response = MTLSConfigResponse(
            client_cert_path=config.mtls.client_cert_path,
            client_key_path=config.mtls.client_key_path,
            ca_bundle_path=config.mtls.ca_bundle_path,
        )
        auth_response = AuthConfigResponse(
            oidc=None,  # OIDC is at manager level, not per-proxy
            mtls=mtls_response,
        )

    # Build HITL response
    hitl_response = HITLConfigResponse(
        timeout_seconds=config.hitl.timeout_seconds,
        default_on_timeout=config.hitl.default_on_timeout,
        approval_ttl_seconds=config.hitl.approval_ttl_seconds,
    )

    # Build logging response
    # PerProxyConfig has log_level directly, not a logging object
    # Log directory is derived from proxy name
    log_dir = str(get_proxy_log_dir(proxy_name))
    logging_response = LoggingConfigResponse(
        log_dir=log_dir,
        log_level=config.log_level,
        include_payloads=config.include_payloads,
    )

    return ConfigResponse(
        backend=backend_response,
        logging=logging_response,
        auth=auth_response,
        proxy=ProxyConfigResponse(name=proxy_name),
        hitl=hitl_response,
        config_path=str(get_proxy_config_path(proxy_name)),
        requires_restart_for_changes=True,
    )


def _deep_merge(base: dict, update_vals: dict) -> dict:
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in update_vals.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ==========================================================================
# Config Endpoints
# ==========================================================================


@router.get("/{proxy_id}/config", response_model=ConfigResponse)
async def get_proxy_config(proxy_id: str) -> ConfigResponse:
    """Get configuration for a specific proxy (reads from disk).

    Works regardless of whether the proxy is running.
    Note: Config comparison is not available at manager level
    (requires running proxy's in-memory state).

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        ConfigResponse with all configuration details.
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
    return _build_config_response_from_proxy(config, proxy_name)


@router.put("/{proxy_id}/config", response_model=ConfigUpdateResponse)
async def update_proxy_config(proxy_id: str, updates: ConfigUpdateRequest) -> ConfigUpdateResponse:
    """Update configuration for a specific proxy.

    Saves to disk. Changes take effect on proxy restart.
    Note: Config comparison is not available at manager level.

    Args:
        proxy_id: Stable proxy identifier.
        updates: Configuration updates to apply.

    Returns:
        ConfigUpdateResponse with updated config and message.
    """
    result = find_proxy_by_id(proxy_id)
    if result is None:
        raise APIError(
            status_code=404,
            code=ErrorCode.PROXY_NOT_FOUND,
            message=f"Proxy with ID '{proxy_id}' not found",
            details={"proxy_id": proxy_id},
        )

    proxy_name, current_config = result
    config_path = get_proxy_config_path(proxy_name)

    # Reload config from file to get latest
    try:
        current_config = load_proxy_config(proxy_name)
    except FileNotFoundError:
        raise APIError(
            status_code=404,
            code=ErrorCode.CONFIG_NOT_FOUND,
            message="Config file not found",
            details={"path": str(config_path)},
        )
    except ValueError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.CONFIG_INVALID,
            message=f"Invalid config file: {e}",
        )

    # Apply updates
    update_dict = current_config.model_dump()

    if updates.logging:
        logging_updates = updates.logging.model_dump(exclude_none=True)
        # PerProxyConfig has log_level and include_payloads at root level, not nested
        if "log_level" in logging_updates:
            update_dict["log_level"] = logging_updates["log_level"]
        if "include_payloads" in logging_updates:
            update_dict["include_payloads"] = logging_updates["include_payloads"]

    if updates.backend:
        backend_updates = updates.backend.model_dump(exclude_none=True)
        if backend_updates:
            update_dict["backend"] = _deep_merge(update_dict["backend"], backend_updates)

    if updates.hitl:
        hitl_updates = updates.hitl.model_dump(exclude_none=True)
        if hitl_updates:
            update_dict["hitl"] = _deep_merge(update_dict["hitl"], hitl_updates)

    # Validate new config
    try:
        new_config = PerProxyConfig.model_validate(update_dict)
    except PydanticValidationError as e:
        raise APIError(
            status_code=400,
            code=ErrorCode.CONFIG_INVALID,
            message=f"Invalid configuration: {e.error_count()} validation error(s)",
            validation_errors=_validation_errors_from_pydantic(e),
        )

    # Save to file
    try:
        save_proxy_config(proxy_name, new_config)
    except Exception as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.CONFIG_SAVE_FAILED,
            message=f"Failed to save config: {e}",
        )

    return ConfigUpdateResponse(
        config=_build_config_response_from_proxy(new_config, proxy_name),
        message="Configuration saved. Restart the proxy to apply changes.",
    )
