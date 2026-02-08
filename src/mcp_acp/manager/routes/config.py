"""Config management endpoints."""

from __future__ import annotations

__all__ = ["router"]

import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Request
from pydantic import ValidationError as PydanticValidationError

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.config import (
    ApiKeyResponse,
    ApiKeySetRequest,
    AuthConfigResponse,
    BackendConfigResponse,
    ConfigComparisonResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    HITLConfigResponse,
    HttpTransportResponse,
    LoggingConfigResponse,
    MTLSConfigResponse,
    ProxyConfigResponse,
    StdioAttestationResponse,
    StdioTransportResponse,
)
from mcp_acp.config import PerProxyConfig, load_proxy_config, save_proxy_config
from mcp_acp.constants import APP_NAME
from mcp_acp.manager.config import get_proxy_config_path, get_proxy_log_dir
from mcp_acp.manager.registry import ProxyRegistry
from mcp_acp.security.credential_storage import BackendCredentialStorage

from mcp_acp.utils.policy.route_helpers import validation_errors_from_pydantic

from .deps import find_proxy_by_id, get_proxy_socket
from .helpers import PROXY_SNAPSHOT_TIMEOUT_SECONDS, create_uds_client

_logger = logging.getLogger(f"{APP_NAME}.manager.routes.config")

router = APIRouter(prefix="/api/manager/proxies", tags=["config"])


# ==========================================================================
# Config Helpers
# ==========================================================================


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
        attestation = config.backend.stdio.attestation
        attestation_response = None
        if attestation:
            attestation_response = StdioAttestationResponse(
                slsa_owner=attestation.slsa_owner,
                expected_sha256=attestation.expected_sha256,
                require_code_signature=attestation.require_signature,
            )
        stdio_response = StdioTransportResponse(
            command=config.backend.stdio.command,
            args=config.backend.stdio.args,
            attestation=attestation_response,
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


def _deep_merge(base: dict[str, Any], update_vals: dict[str, Any]) -> dict[str, Any]:
    """Deep merge updates into base dict, handling nested dicts.

    Recursively merges nested dictionaries while overwriting scalar values.

    Args:
        base: Base dictionary to merge into.
        update_vals: Dictionary of updates to apply.

    Returns:
        New dictionary with updates merged into base.
    """
    result = base.copy()
    for key, value in update_vals.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _normalize_attestation_keys(update_dict: dict[str, Any]) -> dict[str, Any]:
    """Rename API field names to internal model field names for attestation."""
    if "stdio" in update_dict and isinstance(update_dict["stdio"], dict):
        att = update_dict["stdio"].get("attestation")
        if isinstance(att, dict) and "require_code_signature" in att:
            att["require_signature"] = att.pop("require_code_signature")
    return update_dict


# ==========================================================================
# Config Endpoints
# ==========================================================================


@router.get("/{proxy_id}/config", response_model=ConfigResponse)
async def get_proxy_config(proxy_id: str, request: Request) -> ConfigResponse:
    """Get configuration for a specific proxy.

    When the proxy is running, returns the in-memory (running) config via UDS.
    Falls back to reading from disk if the proxy is not running or unreachable.

    Args:
        proxy_id: Stable proxy identifier.
        request: FastAPI request (for registry access).

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

    # Try to get the running (in-memory) config from the proxy via UDS
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)
    if socket_path:
        try:
            async with create_uds_client(socket_path, timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS) as client:
                resp = await client.get("/api/config")
                if resp.status_code == 200:
                    return ConfigResponse.model_validate(resp.json())
        except (httpx.ConnectError, httpx.TimeoutException, OSError, json.JSONDecodeError) as exc:
            _logger.debug("Could not reach proxy %s via UDS for config: %s", proxy_name, exc)

    # Proxy not running or unreachable — return config from disk
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
        logging_updates = updates.logging.model_dump(exclude_unset=True)
        # PerProxyConfig has log_level and include_payloads at root level, not nested
        if "log_level" in logging_updates:
            update_dict["log_level"] = logging_updates["log_level"]
        if "include_payloads" in logging_updates:
            update_dict["include_payloads"] = logging_updates["include_payloads"]

    if updates.backend:
        backend_updates = updates.backend.model_dump(exclude_unset=True)
        if backend_updates:
            backend_updates = _normalize_attestation_keys(backend_updates)
            update_dict["backend"] = _deep_merge(update_dict["backend"], backend_updates)

    if updates.auth:
        auth_updates = updates.auth.model_dump(exclude_unset=True)
        # mTLS is stored at PerProxyConfig root level, not nested under auth
        if "mtls" in auth_updates:
            update_dict["mtls"] = auth_updates["mtls"]

    if updates.hitl:
        hitl_updates = updates.hitl.model_dump(exclude_unset=True)
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
            validation_errors=validation_errors_from_pydantic(e),
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


@router.get("/{proxy_id}/config/compare", response_model=ConfigComparisonResponse)
async def compare_proxy_config(proxy_id: str, request: Request) -> ConfigComparisonResponse:
    """Compare running (in-memory) config with saved (file) config for a proxy.

    If the proxy is running, forwards to its /api/config/compare endpoint.
    If not running, returns has_changes=False with an informational message.

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        ConfigComparisonResponse with changes between running and saved config.
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
    saved_response = _build_config_response_from_proxy(config, proxy_name)

    # Try to reach the running proxy via UDS
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)

    if not socket_path:
        return ConfigComparisonResponse(
            running_config=saved_response,
            saved_config=saved_response,
            has_changes=False,
            changes=[],
            message="Proxy is not running. No comparison available.",
        )

    try:
        async with create_uds_client(socket_path, timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS) as client:
            resp = await client.get("/api/config/compare")
            if resp.status_code == 200:
                return ConfigComparisonResponse.model_validate(resp.json())
    except (httpx.ConnectError, httpx.TimeoutException, OSError, json.JSONDecodeError) as exc:
        _logger.debug("Could not reach proxy %s via UDS for config compare: %s", proxy_name, exc)

    return ConfigComparisonResponse(
        running_config=saved_response,
        saved_config=saved_response,
        has_changes=False,
        changes=[],
        message="Could not reach running proxy for comparison.",
    )


# ==========================================================================
# API Key Management Endpoints
# ==========================================================================


@router.put("/{proxy_id}/config/api-key", response_model=ApiKeyResponse)
async def set_api_key(proxy_id: str, request: ApiKeySetRequest) -> ApiKeyResponse:
    """Set or update backend API key for a proxy.

    Stores the key securely in the OS keychain and updates the config
    with a credential reference. The actual key is never stored in config files.

    Args:
        proxy_id: Stable proxy identifier.
        request: Request containing the API key.

    Returns:
        ApiKeyResponse with success status and credential reference.
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

    # Verify proxy has HTTP transport configured
    if config.backend.http is None:
        raise APIError(
            status_code=400,
            code=ErrorCode.VALIDATION_ERROR,
            message="Cannot set API key: proxy does not use HTTP transport",
            details={"proxy_id": proxy_id, "transport": config.backend.transport},
        )

    # Store key in keychain (reuses existing BackendCredentialStorage)
    cred_storage = BackendCredentialStorage(proxy_name)
    try:
        cred_storage.save(request.api_key)
    except RuntimeError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message=f"Failed to store API key in keychain: {e}",
        )

    # Update config with credential reference
    try:
        current_config = load_proxy_config(proxy_name)
        if current_config.backend.http is not None:
            updated_http = current_config.backend.http.model_copy(
                update={"credential_key": cred_storage.credential_key}
            )
            updated_backend = current_config.backend.model_copy(update={"http": updated_http})
            updated_config = current_config.model_copy(update={"backend": updated_backend})
            save_proxy_config(proxy_name, updated_config)
    except Exception as e:
        # Rollback: delete the stored credential
        try:
            cred_storage.delete()
        except RuntimeError as cleanup_exc:
            _logger.debug("Best-effort credential cleanup failed: %s", cleanup_exc)
        raise APIError(
            status_code=500,
            code=ErrorCode.CONFIG_SAVE_FAILED,
            message=f"Failed to update config: {e}",
        )

    return ApiKeyResponse(
        success=True,
        message="API key stored securely in keychain",
        credential_key=cred_storage.credential_key,
    )


@router.delete("/{proxy_id}/config/api-key", response_model=ApiKeyResponse)
async def delete_api_key(proxy_id: str) -> ApiKeyResponse:
    """Remove backend API key for a proxy.

    Deletes the key from the OS keychain and removes the credential
    reference from config.

    Args:
        proxy_id: Stable proxy identifier.

    Returns:
        ApiKeyResponse with success status.
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

    # Check if there's an API key to delete
    if config.backend.http is None or config.backend.http.credential_key is None:
        return ApiKeyResponse(
            success=True,
            message="No API key configured",
            credential_key=None,
        )

    # Delete from keychain
    cred_storage = BackendCredentialStorage(proxy_name)
    try:
        cred_storage.delete()
    except RuntimeError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.INTERNAL_ERROR,
            message=f"Failed to delete API key from keychain: {e}",
        )

    # Update config to remove credential reference
    try:
        current_config = load_proxy_config(proxy_name)
        if current_config.backend.http is not None:
            updated_http = current_config.backend.http.model_copy(update={"credential_key": None})
            updated_backend = current_config.backend.model_copy(update={"http": updated_http})
            updated_config = current_config.model_copy(update={"backend": updated_backend})
            save_proxy_config(proxy_name, updated_config)
    except Exception as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.CONFIG_SAVE_FAILED,
            message=f"Failed to update config: {e}",
        )

    return ApiKeyResponse(
        success=True,
        message="API key removed from keychain",
        credential_key=None,
    )
