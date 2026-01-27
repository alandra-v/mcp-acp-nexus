"""Policy management endpoints."""

from __future__ import annotations

__all__ = ["router"]

import json
from pathlib import Path
from typing import Any

import httpx

from fastapi import APIRouter, Request

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.policy import (
    PolicyFullUpdate,
    PolicyResponse,
    PolicyRuleCreate,
    PolicyRuleMutationResponse,
    PolicyRuleResponse,
)
from mcp_acp.context.resource import SideEffect
from mcp_acp.manager.registry import ProxyRegistry
from mcp_acp.pdp import PolicyConfig, PolicyRule, RuleConditions
from mcp_acp.utils.policy import load_policy, save_policy
from pydantic import ValidationError as PydanticValidationError

from .deps import get_proxy_paths, get_proxy_socket
from .helpers import PROXY_SNAPSHOT_TIMEOUT_SECONDS, create_uds_client

router = APIRouter(prefix="/api/manager/proxies", tags=["policy"])


# ==========================================================================
# Policy Helpers
# ==========================================================================


async def _trigger_policy_reload(socket_path: str) -> bool:
    """Trigger policy reload via UDS if proxy is running.

    Args:
        socket_path: Path to the proxy's UDS socket.

    Returns:
        True if reload was triggered successfully, False otherwise.
    """
    try:
        async with create_uds_client(socket_path, timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS) as client:
            resp = await client.post("/api/control/reload-policy")
            return resp.status_code == 200
    except (httpx.ConnectError, OSError, httpx.TimeoutException):
        return False


async def _fetch_policy_version(socket_path: str) -> str | None:
    """Fetch current policy_version from a running proxy.

    Args:
        socket_path: Path to the proxy's UDS socket.

    Returns:
        Policy version string if available, None otherwise.
    """
    try:
        async with create_uds_client(socket_path, timeout=PROXY_SNAPSHOT_TIMEOUT_SECONDS) as client:
            resp = await client.get("/api/status")
            if resp.status_code == 200:
                version: str | None = resp.json().get("policy_version")
                return version
    except (httpx.ConnectError, OSError, httpx.TimeoutException, json.JSONDecodeError):
        pass
    return None


def _load_policy_or_raise(policy_path: Path) -> PolicyConfig:
    """Load policy from disk, raising APIError on error.

    Args:
        policy_path: Path to the policy JSON file.

    Returns:
        PolicyConfig loaded from the file.

    Raises:
        APIError: 404 if file not found, 500 if policy is invalid.
    """
    try:
        return load_policy(policy_path)
    except FileNotFoundError:
        raise APIError(
            status_code=404,
            code=ErrorCode.POLICY_NOT_FOUND,
            message="Policy file not found",
            details={"path": str(policy_path)},
        )
    except ValueError as e:
        raise APIError(
            status_code=500,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid policy: {e}",
        )


def _validation_errors_from_pydantic(e: PydanticValidationError) -> list[dict[str, Any]]:
    """Extract validation errors from a Pydantic ValidationError.

    Args:
        e: The Pydantic ValidationError to extract from.

    Returns:
        List of error dicts with loc, msg, and type fields.
    """
    return [
        {
            "loc": list(err.get("loc", [])),
            "msg": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in e.errors()
    ]


def _validate_conditions(conditions: dict[str, Any]) -> RuleConditions:
    """Validate and parse rule conditions.

    Args:
        conditions: Dictionary of condition fields to validate.

    Returns:
        Validated RuleConditions instance.

    Raises:
        APIError: 400 if conditions are invalid.
    """
    try:
        return RuleConditions.model_validate(conditions)
    except PydanticValidationError as e:
        raise APIError(
            status_code=400,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid conditions: {e.error_count()} validation error(s)",
            validation_errors=_validation_errors_from_pydantic(e),
        )


def _parse_cache_side_effects(values: list[str] | None) -> list[SideEffect] | None:
    """Parse string side effect values to SideEffect enum.

    Args:
        values: List of side effect string values, or None.

    Returns:
        List of SideEffect enum values, or None if input is None/empty.

    Raises:
        APIError: 400 if any value is not a valid SideEffect.
    """
    if values is None or len(values) == 0:
        return None

    result = []
    for v in values:
        try:
            result.append(SideEffect(v))
        except ValueError:
            valid_values = [e.value for e in SideEffect]
            raise APIError(
                status_code=400,
                code=ErrorCode.POLICY_INVALID,
                message=f"Invalid side effect: '{v}'",
                details={"valid_values": valid_values},
            )
    return result


def _rule_to_response(rule: PolicyRule) -> PolicyRuleResponse:
    """Convert PolicyRule to API response format.

    Args:
        rule: The PolicyRule domain model to convert.

    Returns:
        PolicyRuleResponse suitable for API serialization.
    """
    return PolicyRuleResponse(
        id=rule.id,
        effect=rule.effect,
        conditions=rule.conditions.model_dump(),
        description=rule.description,
        cache_side_effects=([e.value for e in rule.cache_side_effects] if rule.cache_side_effects else None),
    )


def _rebuild_policy(policy: PolicyConfig, new_rules: list[PolicyRule]) -> PolicyConfig:
    """Rebuild policy with new rules, preserving version and default_action.

    Args:
        policy: Original policy to copy settings from.
        new_rules: New list of rules to use.

    Returns:
        New PolicyConfig with updated rules.

    Raises:
        APIError: 400 if resulting policy is invalid.
    """
    try:
        return PolicyConfig(
            version=policy.version,
            default_action=policy.default_action,
            rules=new_rules,
        )
    except PydanticValidationError as e:
        raise APIError(
            status_code=400,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid policy: {e.error_count()} validation error(s)",
            validation_errors=_validation_errors_from_pydantic(e),
        )


# ==========================================================================
# Policy Endpoints
# ==========================================================================


@router.get("/{proxy_id}/policy", response_model=PolicyResponse)
async def get_proxy_policy(proxy_id: str, request: Request) -> PolicyResponse:
    """Get policy for a specific proxy (reads from disk).

    Works regardless of whether the proxy is running.

    Args:
        proxy_id: Stable proxy identifier.
        request: FastAPI request object.

    Returns:
        PolicyResponse with rules and metadata.
    """
    proxy_name, _, policy_path = get_proxy_paths(proxy_id)
    policy = _load_policy_or_raise(policy_path)

    # Get policy_version from running proxy if available
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)
    policy_version = await _fetch_policy_version(socket_path) if socket_path else None

    return PolicyResponse(
        version=policy.version,
        default_action=policy.default_action,
        rules_count=len(policy.rules),
        rules=[rule.model_dump() for rule in policy.rules],
        policy_version=policy_version,
        policy_path=str(policy_path),
    )


@router.put("/{proxy_id}/policy", response_model=PolicyResponse)
async def update_proxy_policy(
    proxy_id: str,
    policy_data: PolicyFullUpdate,
    request: Request,
) -> PolicyResponse:
    """Replace entire policy for a specific proxy.

    Saves to disk and triggers hot-reload if proxy is running.

    Args:
        proxy_id: Stable proxy identifier.
        policy_data: New policy configuration.
        request: FastAPI request object.

    Returns:
        Updated PolicyResponse with metadata.
    """
    proxy_name, _, policy_path = get_proxy_paths(proxy_id)

    # Build new rules
    new_rules: list[PolicyRule] = []
    for rule_data in policy_data.rules:
        conditions = _validate_conditions(rule_data.conditions)
        cache_effects = _parse_cache_side_effects(rule_data.cache_side_effects)
        new_rules.append(
            PolicyRule(
                id=rule_data.id,
                description=rule_data.description,
                effect=rule_data.effect,
                conditions=conditions,
                cache_side_effects=cache_effects,
            )
        )

    # Build and validate new policy
    try:
        new_policy = PolicyConfig(
            version=policy_data.version,
            default_action=policy_data.default_action,
            rules=new_rules,
        )
    except PydanticValidationError as e:
        raise APIError(
            status_code=400,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid policy: {e.error_count()} validation error(s)",
            validation_errors=_validation_errors_from_pydantic(e),
        )

    # Save to disk
    save_policy(new_policy, policy_path)

    # Trigger reload if proxy is running
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)
    policy_version = None

    if socket_path:
        reload_success = await _trigger_policy_reload(socket_path)
        if reload_success:
            policy_version = await _fetch_policy_version(socket_path)

    return PolicyResponse(
        version=new_policy.version,
        default_action=new_policy.default_action,
        rules_count=len(new_policy.rules),
        rules=[rule.model_dump() for rule in new_policy.rules],
        policy_version=policy_version,
        policy_path=str(policy_path),
    )


@router.get("/{proxy_id}/policy/rules", response_model=list[PolicyRuleResponse])
async def get_proxy_policy_rules(proxy_id: str) -> list[PolicyRuleResponse]:
    """Get policy rules for a specific proxy (simplified view)."""
    _, _, policy_path = get_proxy_paths(proxy_id)
    policy = _load_policy_or_raise(policy_path)
    return [_rule_to_response(rule) for rule in policy.rules]


@router.post("/{proxy_id}/policy/rules", status_code=201, response_model=PolicyRuleMutationResponse)
async def add_proxy_policy_rule(
    proxy_id: str,
    rule_data: PolicyRuleCreate,
    request: Request,
) -> PolicyRuleMutationResponse:
    """Add a new rule to proxy's policy.

    Saves to disk and triggers hot-reload if proxy is running.
    """
    proxy_name, _, policy_path = get_proxy_paths(proxy_id)
    policy = _load_policy_or_raise(policy_path)

    # Check for duplicate ID
    if rule_data.id:
        for existing in policy.rules:
            if existing.id == rule_data.id:
                raise APIError(
                    status_code=409,
                    code=ErrorCode.POLICY_RULE_DUPLICATE,
                    message=f"Rule with id '{rule_data.id}' already exists",
                    details={"rule_id": rule_data.id},
                )

    # Validate and create rule
    conditions = _validate_conditions(rule_data.conditions)
    cache_effects = _parse_cache_side_effects(rule_data.cache_side_effects)

    new_rule = PolicyRule(
        id=rule_data.id,
        description=rule_data.description,
        effect=rule_data.effect,
        conditions=conditions,
        cache_side_effects=cache_effects,
    )

    # Rebuild policy
    new_rules = list(policy.rules) + [new_rule]
    updated_policy = _rebuild_policy(policy, new_rules)
    final_rule = updated_policy.rules[-1]

    # Save to disk
    save_policy(updated_policy, policy_path)

    # Trigger reload if proxy is running
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)
    policy_version = None

    if socket_path:
        reload_success = await _trigger_policy_reload(socket_path)
        if reload_success:
            policy_version = await _fetch_policy_version(socket_path)

    return PolicyRuleMutationResponse(
        rule=_rule_to_response(final_rule),
        policy_version=policy_version,
        rules_count=len(updated_policy.rules),
    )


@router.put("/{proxy_id}/policy/rules/{rule_id}", response_model=PolicyRuleMutationResponse)
async def update_proxy_policy_rule(
    proxy_id: str,
    rule_id: str,
    rule_data: PolicyRuleCreate,
    request: Request,
) -> PolicyRuleMutationResponse:
    """Update an existing rule in proxy's policy.

    Saves to disk and triggers hot-reload if proxy is running.
    """
    proxy_name, _, policy_path = get_proxy_paths(proxy_id)
    policy = _load_policy_or_raise(policy_path)

    # Validate and find rule
    conditions = _validate_conditions(rule_data.conditions)
    cache_effects = _parse_cache_side_effects(rule_data.cache_side_effects)

    new_rules = []
    found = False
    for r in policy.rules:
        if r.id == rule_id:
            new_rules.append(
                PolicyRule(
                    id=rule_id,
                    description=rule_data.description,
                    effect=rule_data.effect,
                    conditions=conditions,
                    cache_side_effects=cache_effects,
                )
            )
            found = True
        else:
            new_rules.append(r)

    if not found:
        raise APIError(
            status_code=404,
            code=ErrorCode.POLICY_RULE_NOT_FOUND,
            message=f"Rule '{rule_id}' not found",
            details={"rule_id": rule_id},
        )

    # Rebuild and save
    updated_policy = _rebuild_policy(policy, new_rules)
    updated_rule = next(r for r in updated_policy.rules if r.id == rule_id)
    save_policy(updated_policy, policy_path)

    # Trigger reload if proxy is running
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)
    policy_version = None

    if socket_path:
        reload_success = await _trigger_policy_reload(socket_path)
        if reload_success:
            policy_version = await _fetch_policy_version(socket_path)

    return PolicyRuleMutationResponse(
        rule=_rule_to_response(updated_rule),
        policy_version=policy_version,
        rules_count=len(updated_policy.rules),
    )


@router.delete("/{proxy_id}/policy/rules/{rule_id}", status_code=204)
async def delete_proxy_policy_rule(
    proxy_id: str,
    rule_id: str,
    request: Request,
) -> None:
    """Delete a rule from proxy's policy.

    Saves to disk and triggers hot-reload if proxy is running.
    """
    proxy_name, _, policy_path = get_proxy_paths(proxy_id)
    policy = _load_policy_or_raise(policy_path)

    # Remove rule
    new_rules = [r for r in policy.rules if r.id != rule_id]

    if len(new_rules) == len(policy.rules):
        raise APIError(
            status_code=404,
            code=ErrorCode.POLICY_RULE_NOT_FOUND,
            message=f"Rule '{rule_id}' not found",
            details={"rule_id": rule_id},
        )

    # Rebuild and save
    updated_policy = _rebuild_policy(policy, new_rules)
    save_policy(updated_policy, policy_path)

    # Trigger reload if proxy is running
    reg: ProxyRegistry = request.app.state.registry
    socket_path = await get_proxy_socket(proxy_name, reg)

    if socket_path:
        await _trigger_policy_reload(socket_path)
