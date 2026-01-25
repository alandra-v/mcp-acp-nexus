"""Policy API endpoints.

Provides full CRUD access to policy rules:
- GET /api/policy - Read current policy with metadata
- PUT /api/policy - Replace entire policy
- GET /api/policy/rules - List rules (simplified view)
- POST /api/policy/rules - Add a new rule
- PUT /api/policy/rules/{id} - Update a rule
- DELETE /api/policy/rules/{id} - Delete a rule

Changes are saved to disk and auto-reloaded (no restart needed).

Routes mounted at: /api/policy
"""

from __future__ import annotations

__all__ = ["router"]

import json
from pathlib import Path

from fastapi import APIRouter
from pydantic import ValidationError

from mcp_acp.api.deps import PolicyPathDep, PolicyReloaderDep
from mcp_acp.api.errors import APIError, ErrorCode
from mcp_acp.api.schemas import (
    PolicyFullUpdate,
    PolicyResponse,
    PolicyRuleCreate,
    PolicyRuleMutationResponse,
    PolicyRuleResponse,
    PolicySchemaResponse,
)
from mcp_acp.context.resource import SideEffect
from mcp_acp.pdp.policy import VALID_OPERATIONS, PolicyConfig, PolicyRule, RuleConditions
from mcp_acp.pep.reloader import PolicyReloader
from mcp_acp.utils.policy import load_policy

router = APIRouter()


# =============================================================================
# Helper Functions
# =============================================================================


def _load_policy_or_raise(policy_path: Path) -> PolicyConfig:
    """Load policy from disk, raising APIError on error.

    Args:
        policy_path: Path to the policy file.

    Returns:
        PolicyConfig loaded from disk.

    Raises:
        APIError: 404 if file not found, 500 if invalid.
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


def _validate_conditions(conditions: dict) -> RuleConditions:
    """Validate and parse rule conditions, raising APIError on error."""
    try:
        return RuleConditions.model_validate(conditions)
    except ValidationError as e:
        # Extract validation errors for structured response
        validation_errors = [
            {"loc": list(err.get("loc", [])), "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in e.errors()
        ]
        raise APIError(
            status_code=400,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid conditions: {e.error_count()} validation error(s)",
            validation_errors=validation_errors,
        )


def _rebuild_policy(policy: PolicyConfig, new_rules: list[PolicyRule]) -> PolicyConfig:
    """Rebuild policy with new rules, raising APIError on validation error.

    Args:
        policy: Original policy to copy settings from.
        new_rules: New list of rules.

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
    except ValidationError as e:
        validation_errors = [
            {"loc": list(err.get("loc", [])), "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in e.errors()
        ]
        raise APIError(
            status_code=400,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid policy: {e.error_count()} validation error(s)",
            validation_errors=validation_errors,
        )


@router.get("/schema", response_model=PolicySchemaResponse)
async def get_policy_schema() -> PolicySchemaResponse:
    """Get policy schema information.

    Returns valid values for policy rule fields like operations.
    Used by frontend to avoid hardcoding these values.
    """
    return PolicySchemaResponse(operations=list(VALID_OPERATIONS))


@router.get("", response_model=PolicyResponse)
async def get_policy(reloader: PolicyReloaderDep, policy_path: PolicyPathDep) -> PolicyResponse:
    """Get current policy configuration.

    Returns the active policy with metadata including version info.
    Note: HITL configuration is now in AppConfig (see /api/config endpoint).
    """
    policy = _load_policy_or_raise(policy_path)

    return PolicyResponse(
        version=policy.version,
        default_action=policy.default_action,
        rules_count=len(policy.rules),
        rules=[rule.model_dump() for rule in policy.rules],
        policy_version=reloader.current_version,
        policy_path=str(policy_path),
    )


@router.put("", response_model=PolicyResponse)
async def update_full_policy(
    reloader: PolicyReloaderDep,
    policy_path: PolicyPathDep,
    policy_data: PolicyFullUpdate,
) -> PolicyResponse:
    """Replace entire policy configuration.

    Validates and saves the new policy, then triggers a reload.
    All existing rules are replaced with the provided rules.

    Note: HITL configuration is now in AppConfig and requires proxy restart
    to take effect. Use /api/config endpoint for HITL settings.

    Args:
        reloader: PolicyReloader dependency for triggering reload.
        policy_path: Path to the policy file (from dependency).
        policy_data: New policy configuration.

    Returns:
        Updated policy response with metadata.

    Raises:
        APIError: 400 POLICY_INVALID if policy validation fails.
        APIError: 500 POLICY_RELOAD_FAILED if reload fails.
    """
    # Build new rules from request
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

    # Build new policy
    try:
        new_policy = PolicyConfig(
            version=policy_data.version,
            default_action=policy_data.default_action,
            rules=new_rules,
        )
    except ValidationError as e:
        validation_errors = [
            {"loc": list(err.get("loc", [])), "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in e.errors()
        ]
        raise APIError(
            status_code=400,
            code=ErrorCode.POLICY_INVALID,
            message=f"Invalid policy: {e.error_count()} validation error(s)",
            validation_errors=validation_errors,
        )

    # Save and reload
    policy_version = await _save_and_reload(reloader, new_policy, policy_path)

    return PolicyResponse(
        version=new_policy.version,
        default_action=new_policy.default_action,
        rules_count=len(new_policy.rules),
        rules=[rule.model_dump() for rule in new_policy.rules],
        policy_version=policy_version,
        policy_path=str(policy_path),
    )


@router.get("/rules", response_model=list[PolicyRuleResponse])
async def get_policy_rules(policy_path: PolicyPathDep) -> list[PolicyRuleResponse]:
    """Get just the policy rules (simplified view)."""
    policy = _load_policy_or_raise(policy_path)

    return [_rule_to_response(rule) for rule in policy.rules]


async def _save_and_reload(
    reloader: PolicyReloader,
    policy: PolicyConfig,
    policy_path: Path,
) -> str | None:
    """Save policy to file and trigger reload.

    Args:
        reloader: PolicyReloader instance (from dependency injection).
        policy: The new PolicyConfig to save.
        policy_path: Path to the policy file.

    Returns:
        New policy version after reload.
    """

    # Save to file (atomically via temp file)
    temp_path = policy_path.with_suffix(".tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(policy.model_dump(), f, indent=2)
        # Set secure permissions (owner read/write only)
        temp_path.chmod(0o600)
        temp_path.replace(policy_path)
    except Exception:
        # Clean up temp file on error
        temp_path.unlink(missing_ok=True)
        raise

    # Trigger reload via PolicyReloader
    result = await reloader.reload()

    if result.status != "success":
        raise APIError(
            status_code=500,
            code=ErrorCode.POLICY_RELOAD_FAILED,
            message=f"Policy reload failed: {result.error}",
            details={"error": result.error},
        )

    return result.policy_version


def _parse_cache_side_effects(values: list[str] | None) -> list[SideEffect] | None:
    """Parse string side effect values to SideEffect enum.

    Args:
        values: List of side effect string values, or None.

    Returns:
        List of SideEffect enum values, or None. Empty lists are normalized to None.

    Raises:
        APIError: 400 if any value is invalid.
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
    """Convert PolicyRule to API response."""
    return PolicyRuleResponse(
        id=rule.id,
        effect=rule.effect,
        conditions=rule.conditions.model_dump(),
        description=rule.description,
        cache_side_effects=([e.value for e in rule.cache_side_effects] if rule.cache_side_effects else None),
    )


@router.post("/rules", status_code=201, response_model=PolicyRuleMutationResponse)
async def add_policy_rule(
    reloader: PolicyReloaderDep,
    policy_path: PolicyPathDep,
    rule_data: PolicyRuleCreate,
) -> PolicyRuleMutationResponse:
    """Add a new policy rule.

    The rule is appended to the existing rules and policy is auto-reloaded.
    If id is not provided, one will be auto-generated.
    """
    policy = _load_policy_or_raise(policy_path)

    # Check for duplicate ID if provided
    if rule_data.id:
        for existing in policy.rules:
            if existing.id == rule_data.id:
                raise APIError(
                    status_code=409,
                    code=ErrorCode.POLICY_RULE_DUPLICATE,
                    message=f"Rule with id '{rule_data.id}' already exists",
                    details={"rule_id": rule_data.id},
                )

    # Validate conditions and cache_side_effects
    conditions = _validate_conditions(rule_data.conditions)
    cache_effects = _parse_cache_side_effects(rule_data.cache_side_effects)

    # Create new rule
    new_rule = PolicyRule(
        id=rule_data.id,
        description=rule_data.description,
        effect=rule_data.effect,
        conditions=conditions,
        cache_side_effects=cache_effects,
    )

    # Append to rules and rebuild policy (will auto-generate ID if not provided)
    new_rules = list(policy.rules) + [new_rule]
    updated_policy = _rebuild_policy(policy, new_rules)

    # Get the final rule (may have auto-generated ID)
    final_rule = updated_policy.rules[-1]

    # Save and reload
    policy_version = await _save_and_reload(reloader, updated_policy, policy_path)

    return PolicyRuleMutationResponse(
        rule=_rule_to_response(final_rule),
        policy_version=policy_version,
        rules_count=len(updated_policy.rules),
    )


@router.put("/rules/{rule_id}", response_model=PolicyRuleMutationResponse)
async def update_policy_rule(
    reloader: PolicyReloaderDep,
    policy_path: PolicyPathDep,
    rule_id: str,
    rule_data: PolicyRuleCreate,
) -> PolicyRuleMutationResponse:
    """Update an existing policy rule.

    The rule is replaced and policy is auto-reloaded.
    """
    policy = _load_policy_or_raise(policy_path)

    # Validate conditions and cache_side_effects
    conditions = _validate_conditions(rule_data.conditions)
    cache_effects = _parse_cache_side_effects(rule_data.cache_side_effects)

    # Find and replace rule
    new_rules = []
    found = False
    for r in policy.rules:
        if r.id == rule_id:
            # Replace with updated rule (keep original ID)
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

    # Rebuild policy
    updated_policy = _rebuild_policy(policy, new_rules)

    # Get the updated rule
    updated_rule = next(r for r in updated_policy.rules if r.id == rule_id)

    # Save and reload
    policy_version = await _save_and_reload(reloader, updated_policy, policy_path)

    return PolicyRuleMutationResponse(
        rule=_rule_to_response(updated_rule),
        policy_version=policy_version,
        rules_count=len(updated_policy.rules),
    )


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_policy_rule(
    reloader: PolicyReloaderDep,
    policy_path: PolicyPathDep,
    rule_id: str,
) -> None:
    """Delete a policy rule.

    The rule is removed and policy is auto-reloaded.
    """
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

    # Rebuild policy and save
    updated_policy = _rebuild_policy(policy, new_rules)
    await _save_and_reload(reloader, updated_policy, policy_path)
