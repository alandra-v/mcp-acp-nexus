"""Configuration API endpoints.

Provides configuration management:
- GET /api/config - Read current config (full details)
- PUT /api/config - Update config (validated, requires restart)

Routes mounted at: /api/config
"""

from __future__ import annotations

__all__ = ["router"]

from typing import Any

from fastapi import APIRouter
from pydantic import ValidationError

from mcp_acp.api.deps import ConfigDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.utils.policy.route_helpers import validation_errors_from_pydantic
from mcp_acp.api.schemas import (
    AuthConfigResponse,
    BackendConfigResponse,
    ConfigChange,
    ConfigComparisonResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    ConfigUpdateResponse,
    HITLConfigResponse,
    HttpTransportResponse,
    LoggingConfigResponse,
    MTLSConfigResponse,
    OIDCConfigResponse,
    ProxyConfigResponse,
    StdioAttestationResponse,
    StdioTransportResponse,
)
from mcp_acp.config import (
    AppConfig,
    PerProxyConfig,
    build_app_config_from_per_proxy,
    load_proxy_config,
    save_proxy_config,
)
from mcp_acp.manager.config import get_proxy_config_path, get_proxy_log_dir

router = APIRouter()


# =============================================================================
# Helpers
# =============================================================================


def _deep_merge(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Deep merge updates into base dict, handling nested dicts.

    Recursively merges nested dictionaries while overwriting scalar values.

    Args:
        base: Base dictionary to merge into.
        updates: Dictionary of updates to apply.

    Returns:
        New dictionary with updates merged into base.
    """
    result = base.copy()
    for key, value in updates.items():
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


def _compare_configs(running: dict[str, Any], saved: dict[str, Any], prefix: str = "") -> list[ConfigChange]:
    """Compare two config dicts and return list of changes.

    Args:
        running: Running (in-memory) config as dict.
        saved: Saved (file) config as dict.
        prefix: Current path prefix for nested keys.

    Returns:
        List of ConfigChange objects describing differences.
    """
    changes: list[ConfigChange] = []
    all_keys = set(running.keys()) | set(saved.keys())

    for key in all_keys:
        path = f"{prefix}.{key}" if prefix else key
        running_val = running.get(key)
        saved_val = saved.get(key)

        # Skip config_path and requires_restart_for_changes (metadata fields)
        if key in ("config_path", "requires_restart_for_changes"):
            continue

        if isinstance(running_val, dict) and isinstance(saved_val, dict):
            # Recurse into nested dicts
            changes.extend(_compare_configs(running_val, saved_val, path))
        elif running_val != saved_val:
            changes.append(
                ConfigChange(
                    field=path,
                    running_value=running_val,
                    saved_value=saved_val,
                )
            )

    return changes


def _build_config_response(config: AppConfig) -> ConfigResponse:
    """Build API response from AppConfig with full details.

    Args:
        config: Application configuration to convert.

    Returns:
        ConfigResponse with all configuration details including transport and auth.
    """
    # Build backend response with transport details
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
        )

    backend_response = BackendConfigResponse(
        server_name=config.backend.server_name,
        transport=config.backend.transport,
        stdio=stdio_response,
        http=http_response,
    )

    # Build auth response with OIDC details
    # Note: mTLS is per-proxy at config.mtls, not config.auth.mtls
    auth_response = None
    if config.auth:
        oidc_response = None
        if config.auth.oidc:
            oidc_response = OIDCConfigResponse(
                issuer=config.auth.oidc.issuer,
                client_id=config.auth.oidc.client_id,
                audience=config.auth.oidc.audience,
                scopes=config.auth.oidc.scopes,
            )

        # mTLS is per-proxy, stored at config.mtls (not config.auth.mtls)
        mtls_response = None
        if config.mtls:
            mtls_response = MTLSConfigResponse(
                client_cert_path=config.mtls.client_cert_path,
                client_key_path=config.mtls.client_key_path,
                ca_bundle_path=config.mtls.ca_bundle_path,
            )

        auth_response = AuthConfigResponse(
            oidc=oidc_response,
            mtls=mtls_response,
        )

    # Build HITL response (cache_side_effects moved to per-rule policy config)
    hitl_response = HITLConfigResponse(
        timeout_seconds=config.hitl.timeout_seconds,
        default_on_timeout=config.hitl.default_on_timeout,
        approval_ttl_seconds=config.hitl.approval_ttl_seconds,
    )

    return ConfigResponse(
        backend=backend_response,
        logging=LoggingConfigResponse(
            log_dir=str(get_proxy_log_dir(config.proxy.name)),
            log_level=config.logging.log_level,
            include_payloads=config.logging.include_payloads,
        ),
        auth=auth_response,
        proxy=ProxyConfigResponse(name=config.proxy.name),
        hitl=hitl_response,
        config_path=str(get_proxy_config_path(config.proxy.name)),
        requires_restart_for_changes=True,
    )


# =============================================================================
# Endpoints
# =============================================================================


@router.get("", response_model=ConfigResponse)
async def get_config(config: ConfigDep) -> ConfigResponse:
    """Get current configuration.

    Returns full configuration including transport and auth details.

    Note: This returns the config from memory (as loaded at startup).
    To see file changes, restart the proxy.
    """
    return _build_config_response(config)


@router.put("", response_model=ConfigUpdateResponse)
async def update_config(config: ConfigDep, updates: ConfigUpdateRequest) -> ConfigUpdateResponse:
    """Update configuration file.

    Validates changes before saving. Changes take effect on restart.

    All fields are optional - only specified fields will be updated.
    Nested objects (stdio, http, oidc, mtls) are deep-merged.

    Returns the updated configuration (from file, not memory).
    """
    config_path = get_proxy_config_path(config.proxy.name)

    # Load current config from file (stored as PerProxyConfig, convert to AppConfig)
    try:
        per_proxy = load_proxy_config(config.proxy.name)
        current_config = build_app_config_from_per_proxy(
            proxy_name=config.proxy.name,
            per_proxy=per_proxy,
            oidc=config.auth.oidc if config.auth else None,
            log_dir=config.logging.log_dir,
        )
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

    # Apply updates to a mutable dict
    update_dict = current_config.model_dump()

    if updates.logging:
        logging_updates = updates.logging.model_dump(exclude_unset=True)
        if logging_updates:
            update_dict["logging"] = _deep_merge(update_dict["logging"], logging_updates)

    if updates.backend:
        backend_updates = updates.backend.model_dump(exclude_unset=True)
        if backend_updates:
            backend_updates = _normalize_attestation_keys(backend_updates)
            update_dict["backend"] = _deep_merge(update_dict["backend"], backend_updates)

    if updates.auth:
        auth_updates = updates.auth.model_dump(exclude_unset=True)
        if auth_updates:
            # mTLS is stored at config.mtls, not config.auth.mtls
            if "mtls" in auth_updates:
                update_dict["mtls"] = auth_updates.pop("mtls")
            if auth_updates:
                # Ensure auth dict exists
                if update_dict.get("auth") is None:
                    update_dict["auth"] = {}
                update_dict["auth"] = _deep_merge(update_dict["auth"], auth_updates)

    if updates.hitl:
        hitl_updates = updates.hitl.model_dump(exclude_unset=True)
        if hitl_updates:
            update_dict["hitl"] = _deep_merge(update_dict["hitl"], hitl_updates)

    # Validate by constructing new AppConfig
    try:
        new_config = AppConfig.model_validate(update_dict)
    except ValidationError as e:
        raise APIError(
            status_code=400,
            code=ErrorCode.CONFIG_INVALID,
            message=f"Invalid configuration: {e.error_count()} validation error(s)",
            validation_errors=validation_errors_from_pydantic(e),
        )

    # Save back as PerProxyConfig (preserve proxy_id and created_at)
    updated_per_proxy = PerProxyConfig(
        proxy_id=per_proxy.proxy_id,
        created_at=per_proxy.created_at,
        backend=new_config.backend,
        hitl=new_config.hitl,
        mtls=new_config.mtls,
        log_level=new_config.logging.log_level,
        include_payloads=new_config.logging.include_payloads,
    )
    try:
        save_proxy_config(config.proxy.name, updated_per_proxy)
    except Exception as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.CONFIG_SAVE_FAILED,
            message=f"Failed to save config: {e}",
        )

    return ConfigUpdateResponse(
        config=_build_config_response(new_config),
        message="Configuration saved. Restart the client to apply changes.",
    )


@router.get("/compare", response_model=ConfigComparisonResponse)
async def compare_config(config: ConfigDep) -> ConfigComparisonResponse:
    """Compare running (in-memory) config with saved (file) config.

    Returns both configs and a list of differences. Useful for seeing
    what will change on restart, or if the file was manually edited.
    """
    config_path = get_proxy_config_path(config.proxy.name)

    # Build running config response
    running_response = _build_config_response(config)

    # Load saved config from file (stored as PerProxyConfig, convert to AppConfig)
    try:
        per_proxy = load_proxy_config(config.proxy.name)
        saved_config = build_app_config_from_per_proxy(
            proxy_name=config.proxy.name,
            per_proxy=per_proxy,
            oidc=config.auth.oidc if config.auth else None,
            log_dir=config.logging.log_dir,
        )
        saved_response = _build_config_response(saved_config)
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

    # Compare the two configs
    running_dict = running_response.model_dump()
    saved_dict = saved_response.model_dump()
    changes = _compare_configs(running_dict, saved_dict)

    has_changes = len(changes) > 0
    if has_changes:
        message = f"{len(changes)} change(s) between running and saved config. Restart to apply."
    else:
        message = "Running config matches saved config file."

    return ConfigComparisonResponse(
        running_config=running_response,
        saved_config=saved_response,
        has_changes=has_changes,
        changes=changes,
        message=message,
    )
