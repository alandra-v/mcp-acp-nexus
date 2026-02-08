"""Shared policy route helpers for API and manager endpoints.

Provides common helper functions used by both:
- api/routes/policy.py (per-proxy API)
- manager/routes/policy.py (multi-proxy management API)

These helpers handle policy loading, validation, and response
formatting with consistent error handling via APIError.
"""

from __future__ import annotations

__all__ = [
    "load_policy_or_raise",
    "parse_cache_side_effects",
    "rebuild_policy",
    "rule_to_response",
    "validate_conditions",
    "validation_errors_from_pydantic",
]

from pathlib import Path
from typing import Any

from pydantic import ValidationError as PydanticValidationError

from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas.policy import PolicyRuleResponse
from mcp_acp.context.resource import SideEffect
from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, RuleConditions
from mcp_acp.utils.policy import load_policy


def validation_errors_from_pydantic(e: PydanticValidationError) -> list[dict[str, Any]]:
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


def load_policy_or_raise(policy_path: Path) -> PolicyConfig:
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


def validate_conditions(conditions: dict[str, Any]) -> RuleConditions:
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
            validation_errors=validation_errors_from_pydantic(e),
        )


def rebuild_policy(policy: PolicyConfig, new_rules: list[PolicyRule]) -> PolicyConfig:
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
            validation_errors=validation_errors_from_pydantic(e),
        )


def parse_cache_side_effects(values: list[str] | None) -> list[SideEffect] | None:
    """Parse string side effect values to SideEffect enum.

    Args:
        values: List of side effect string values, or None.

    Returns:
        List of SideEffect enum values, or None. Empty lists are normalized to None.

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


def rule_to_response(rule: PolicyRule) -> PolicyRuleResponse:
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
