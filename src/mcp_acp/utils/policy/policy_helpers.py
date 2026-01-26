"""Policy loader - load and save policy configuration.

This module provides functions to load policy.json from the config directory
and save policy changes (e.g., when user adds "Always Deny" rules via HITL).

Features:
- Secure file permissions (0o700 for directory, 0o600 for file)
- Detailed validation error messages
- SHA256 checksum for integrity verification
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

from pydantic import ValidationError

from mcp_acp.pdp.policy import PolicyConfig, PolicyRule, create_default_policy
from mcp_acp.utils.file_helpers import (
    compute_file_checksum,
    get_app_dir,
    require_file_exists,
    set_secure_permissions,
)

# Re-export for convenience
__all__ = [
    "get_policy_dir",
    "get_policy_path",
    "compute_policy_checksum",
    "load_policy",
    "save_policy",
    "policy_exists",
    "create_default_policy_file",
]


def get_policy_dir() -> Path:
    """Get the OS-appropriate config directory for policy files.

    Uses the same directory as manager.json:
    - macOS: ~/Library/Application Support/mcp-acp
    - Linux: ~/.config/mcp-acp (XDG compliant)
    - Windows: C:\\Users\\<user>\\AppData\\Roaming\\mcp-acp

    Returns:
        Path to the config directory.
    """
    return get_app_dir()


def get_policy_path() -> Path:
    """Get the full path to the policy file.

    Returns:
        Path to policy.json in the config directory.
    """
    return get_policy_dir() / "policy.json"


def compute_policy_checksum(policy_path: Path) -> str:
    """Compute SHA256 checksum of policy file content.

    Used for integrity verification and detecting manual edits.

    Args:
        policy_path: Path to the policy file.

    Returns:
        str: Checksum in format "sha256:<hex_digest>".

    Raises:
        FileNotFoundError: If policy file doesn't exist.
        OSError: If policy file cannot be read.
    """
    return compute_file_checksum(policy_path)


def _needs_normalization(raw_rules: list[dict[str, object]], validated_rules: list[PolicyRule]) -> bool:
    """Check if any rule IDs were auto-generated during validation.

    Compares raw JSON rules against validated PolicyRule objects to detect
    if the ensure_rule_ids validator generated any new IDs.

    Args:
        raw_rules: Original rules from JSON file (may have None/missing IDs).
        validated_rules: Validated PolicyRule objects (always have IDs).

    Returns:
        True if any IDs were generated and file should be updated.
    """
    if len(raw_rules) != len(validated_rules):
        return False  # Length mismatch shouldn't happen, be defensive

    for i, raw_rule in enumerate(raw_rules):
        # If raw rule had no ID but validated rule has one, it was generated
        if raw_rule.get("id") is None and validated_rules[i].id is not None:
            return True

    return False


def load_policy(path: Path | None = None, *, normalize: bool = True) -> PolicyConfig:
    """Load policy configuration from file.

    Automatically normalizes the policy file by generating missing rule IDs.
    This keeps the file in sync with the runtime representation.

    Args:
        path: Path to policy.json. If None, uses default location.
        normalize: If True (default), save back to file if IDs were generated.
                   Set to False to skip normalization (e.g., for read-only checks).

    Returns:
        PolicyConfig loaded from file.

    Raises:
        FileNotFoundError: If policy file does not exist.
        ValueError: If policy file contains invalid JSON or schema.

    Note:
        If normalization save fails (e.g., permission error), a warning is logged
        but the valid policy is still returned. The file will be normalized on
        the next successful save.
    """
    policy_path = path or get_policy_path()
    require_file_exists(policy_path, file_type="policy")

    # Load raw JSON (single read)
    try:
        with open(policy_path, encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in policy file {policy_path}: {e}") from e

    # Validate (triggers ensure_rule_ids which generates missing IDs)
    try:
        policy = PolicyConfig.model_validate(raw_data)
    except ValidationError as e:
        errors = []
        for error in e.errors():
            loc = ".".join(str(x) for x in error["loc"])
            errors.append(f"  - {loc}: {error['msg']}")
        raise ValueError(
            f"Invalid policy configuration in {policy_path}:\n"
            + "\n".join(errors)
            + "\n\nEdit the policy file to fix the errors."
        ) from e

    # Auto-normalize: save back if IDs were generated
    if normalize:
        raw_rules = raw_data.get("rules", [])
        if _needs_normalization(raw_rules, policy.rules):
            try:
                save_policy(policy, policy_path)
            except OSError as e:
                # Log warning but don't fail - policy is valid, just not persisted
                logger = logging.getLogger(__name__)
                logger.warning(
                    "Failed to save normalized policy to %s: %s. "
                    "Generated rule IDs will not be persisted until next successful save.",
                    policy_path,
                    e,
                )

    return policy


def save_policy(policy: PolicyConfig, path: Path | None = None) -> None:
    """Save policy configuration to file atomically.

    Uses atomic write pattern: write to temp file, then rename.
    This prevents file corruption if write fails midway.

    Creates parent directories if they don't exist.
    Sets secure permissions (0o700 on directory, 0o600 on file).

    Args:
        policy: PolicyConfig to save.
        path: Path to save to. If None, uses default location.
    """
    policy_path = path or get_policy_path()

    # Ensure parent directory exists with secure permissions
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    set_secure_permissions(policy_path.parent, is_directory=True)

    # Convert to dict and format as JSON
    data = policy.model_dump(mode="json")
    content = json.dumps(data, indent=2) + "\n"  # Trailing newline

    # Atomic write: write to temp file in same directory, then rename
    # Same directory ensures rename is atomic (same filesystem)
    fd, temp_path = tempfile.mkstemp(
        dir=policy_path.parent,
        prefix=".policy_",
        suffix=".tmp",
    )
    try:
        # Write content to temp file
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())  # Ensure data is on disk

        # Set secure permissions on temp file before rename
        os.chmod(temp_path, 0o600)

        # Atomic rename (overwrites existing file atomically)
        os.replace(temp_path, policy_path)

    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def policy_exists(path: Path | None = None) -> bool:
    """Check if policy file exists.

    Args:
        path: Path to check. If None, uses default location.

    Returns:
        True if policy file exists.
    """
    policy_path = path or get_policy_path()
    return policy_path.exists()


def create_default_policy_file(path: Path | None = None) -> PolicyConfig:
    """Create a default policy file if it doesn't exist.

    Args:
        path: Path to create. If None, uses default location.

    Returns:
        The PolicyConfig that was created.

    Raises:
        FileExistsError: If policy file already exists.
    """
    policy_path = path or get_policy_path()

    if policy_path.exists():
        raise FileExistsError(f"Policy file already exists: {policy_path}")

    policy = create_default_policy()
    save_policy(policy, policy_path)
    return policy
