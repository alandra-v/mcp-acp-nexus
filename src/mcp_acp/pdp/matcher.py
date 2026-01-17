"""Pattern matching for policy rules.

This module provides matching functions for policy conditions:
- Path patterns: Glob-style matching (*, **, ?)
- Tool names: Glob matching (case-insensitive)
- Operations: Inferred from tool names (heuristic)
- Extensions: Exact match (case-insensitive)
- Schemes: Exact match (case-insensitive)
- Server IDs: Glob matching (case-insensitive)
- MCP methods: Glob matching (case-sensitive - methods are standardized)
- Subject IDs: Exact match (case-sensitive - usernames are case-sensitive)
- Side effects: ANY logic (matches if tool has any listed effect)

Design note: Operation inference from tool names is a HEURISTIC, not a fact.
We cannot trust tool names to accurately describe what they do.
This is provided as a convenience for policy writing, not a security guarantee.
"""

from __future__ import annotations

__all__ = [
    "infer_operation",
    "match_path_pattern",
    "match_tool_name",
]

import fnmatch
import re
import sys
from collections.abc import Callable, Sequence

from mcp_acp.context.resource import SideEffect

# =============================================================================
# Operation Inference Heuristics (UNTRUSTED)
# =============================================================================
# These help policy writers but should NOT be relied upon for security.
# Tool names may lie about what they actually do.

# Tool name patterns for read operation inference
READ_TOOL_PREFIXES: tuple[str, ...] = ("read_", "get_", "list_", "fetch_", "search_", "find_")
READ_TOOL_CONTAINS: tuple[str, ...] = ("_read", "_get", "_list", "_fetch", "_search")

# Tool name patterns for delete operation inference
DELETE_TOOL_PREFIXES: tuple[str, ...] = ("delete_", "remove_", "drop_", "clear_")
DELETE_TOOL_CONTAINS: tuple[str, ...] = ("_delete", "_remove", "_drop", "_clear")

# Tool name patterns for write operation inference
WRITE_TOOL_PREFIXES: tuple[str, ...] = (
    "write_",
    "create_",
    "edit_",
    "update_",
    "set_",
    "save_",
    "put_",
    "add_",
    "insert_",
    "append_",
)
WRITE_TOOL_CONTAINS: tuple[str, ...] = (
    "_write",
    "_create",
    "_edit",
    "_update",
    "_set",
    "_save",
    "_put",
    "_add",
    "_insert",
    "_append",
)

# Regex special characters that need escaping in glob-to-regex conversion
_REGEX_SPECIAL_CHARS = ".^$+{}[]|()"


def match_path_pattern(pattern: str, path: str | None) -> bool:
    """Match a path against a glob pattern.

    Supports:
    - * : matches any characters except /
    - ** : matches any characters including /
    - ? : matches single character

    Cross-platform: On Windows, backslashes are normalized to forward slashes.
    On Unix/macOS, paths are used as-is to preserve literal backslash characters.

    Args:
        pattern: Glob pattern (e.g., "/project/**", "**/*.key")
        path: File path to match against

    Returns:
        True if path matches pattern, False otherwise.
        Returns False if path is None.
    """
    if path is None:
        return False

    # On Windows, normalize backslashes to forward slashes for pattern matching
    # Only done on Windows to preserve literal backslashes in Unix filenames (rare but valid)
    if sys.platform == "win32":
        pattern = pattern.replace("\\", "/") if pattern else ""
        path = path.replace("\\", "/") if path else ""

    # Normalize paths (remove trailing slashes, handle empty)
    pattern = pattern.rstrip("/") if pattern else ""
    path = path.rstrip("/") if path else ""

    if not pattern or not path:
        return False

    # Convert ** to a placeholder, then convert to regex
    # ** matches anything including /
    # * matches anything except /
    # ? matches single character except /

    # Escape regex special characters except our glob chars
    regex_pattern = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                # ** matches zero or more characters including /
                # Special case: /** at end should also match the directory itself
                # e.g., /tmp/** should match /tmp, /tmp/foo, /tmp/foo/bar
                is_at_end = i + 2 >= len(pattern)
                preceded_by_slash = regex_pattern.endswith("/")

                if is_at_end and preceded_by_slash:
                    # Remove the trailing slash and make the whole /... part optional
                    regex_pattern = regex_pattern[:-1] + "(/.*)?"
                else:
                    regex_pattern += ".*"
                i += 2
            else:
                # * matches anything except /
                regex_pattern += "[^/]*"
                i += 1
        elif c == "?":
            # ? matches single character except /
            regex_pattern += "[^/]"
            i += 1
        elif c in _REGEX_SPECIAL_CHARS:
            # Escape regex special characters
            regex_pattern += "\\" + c
            i += 1
        else:
            regex_pattern += c
            i += 1

    # Anchor the pattern
    regex_pattern = "^" + regex_pattern + "$"

    try:
        return bool(re.match(regex_pattern, path))
    except re.error:
        return False


def match_tool_name(pattern: str, name: str | None) -> bool:
    """Match a tool name against a pattern (case-insensitive).

    Supports exact match or glob patterns (*, ?).

    Args:
        pattern: Tool name pattern (e.g., "bash", "write_*", "*_file")
        name: Tool name to match against

    Returns:
        True if name matches pattern, False otherwise.
        Returns False if name is None.
    """
    if name is None:
        return False

    if not pattern or not name:
        return False

    # Case-insensitive matching for consistency across platforms
    return fnmatch.fnmatch(name.lower(), pattern.lower())


def infer_operation(tool_name: str | None) -> str | None:
    """Infer operation type from tool name (HEURISTIC - NOT TRUSTED).

    This is a convenience for policy writing. Tool names may lie about
    what they actually do. Do not rely on this for security.

    Args:
        tool_name: Name of the tool

    Returns:
        Inferred operation: "read", "write", "delete", or None if unknown.
    """
    if not tool_name:
        return None

    name_lower = tool_name.lower()

    # Read operations
    if name_lower.startswith(READ_TOOL_PREFIXES) or any(s in name_lower for s in READ_TOOL_CONTAINS):
        return "read"

    # Delete operations (check before write since delete is more specific)
    if name_lower.startswith(DELETE_TOOL_PREFIXES) or any(s in name_lower for s in DELETE_TOOL_CONTAINS):
        return "delete"

    # Write operations
    if name_lower.startswith(WRITE_TOOL_PREFIXES) or any(s in name_lower for s in WRITE_TOOL_CONTAINS):
        return "write"

    # Unknown
    return None


def _match_operations(
    allowed_operations: Sequence[str] | None,
    inferred_operation: str | None,
) -> bool:
    """Check if inferred operation matches allowed operations.

    Args:
        allowed_operations: List of allowed operations from rule conditions.
                           If None, matches any operation.
        inferred_operation: Operation inferred from tool name.
                           If None, we don't know what the tool does.

    Returns:
        True if operation matches or if no constraint specified.
    """
    # No constraint = matches anything
    if allowed_operations is None:
        return True

    # We don't know what the tool does - can't match specific operations
    # This defaults to NOT matching, so the rule won't apply
    # The next rule (or default_action) will handle it
    if inferred_operation is None:
        return False

    return inferred_operation in allowed_operations


# -----------------------------------------------------------------------------
# New matching functions for extended conditions
# -----------------------------------------------------------------------------


def _match_glob_case_insensitive(pattern: str, value: str | None) -> bool:
    """Match a value against a glob pattern (case-insensitive).

    Used for backend_id and similar fields.

    Args:
        pattern: Glob pattern (e.g., "prod-*", "*-db")
        value: Value to match against

    Returns:
        True if value matches pattern, False otherwise.
    """
    if value is None:
        return False

    if not pattern or not value:
        return False

    return fnmatch.fnmatch(value.lower(), pattern.lower())


def _match_glob_case_sensitive(pattern: str, value: str | None) -> bool:
    """Match a value against a glob pattern (case-sensitive).

    Used for mcp_method where method names are standardized.

    Args:
        pattern: Glob pattern (e.g., "resources/*", "tools/call")
        value: Value to match against

    Returns:
        True if value matches pattern, False otherwise.
    """
    if value is None:
        return False

    if not pattern or not value:
        return False

    return fnmatch.fnmatch(value, pattern)


def _match_exact_case_insensitive(expected: str, value: str | None) -> bool:
    """Match a value exactly (case-insensitive).

    Used for extension, scheme, resource_type.

    Args:
        expected: Expected value (e.g., ".key", "file")
        value: Value to match against

    Returns:
        True if values match (case-insensitive), False otherwise.
    """
    if value is None:
        return False

    if not expected or not value:
        return False

    return value.lower() == expected.lower()


def _match_exact_case_sensitive(expected: str, value: str | None) -> bool:
    """Match a value exactly (case-sensitive).

    Used for subject_id where usernames are case-sensitive.

    Args:
        expected: Expected value (e.g., "alice")
        value: Value to match against

    Returns:
        True if values match exactly, False otherwise.
    """
    if value is None:
        return False

    if not expected or not value:
        return False

    return value == expected


def _match_side_effects(
    required: Sequence[SideEffect] | None,
    actual: frozenset[SideEffect] | None,
) -> bool:
    """Check if tool has ANY of the required side effects.

    Uses ANY logic: matches if tool has at least one of the listed effects.
    This is safer - if you list dangerous effects, block tools with ANY of them.

    Args:
        required: List of side effects from rule conditions.
                  If None, matches any tool (no constraint).
        actual: Tool's actual side effects.
                If None or empty, tool has no known side effects.

    Returns:
        True if no constraint, or if tool has ANY required effect.
    """
    # No constraint = matches anything
    if required is None:
        return True

    # Tool has no known side effects - can't match specific requirements
    if not actual:
        return False

    # ANY logic: tool must have at least one of the required effects
    required_set = set(required)
    return bool(required_set & actual)


# =============================================================================
# List/OR Logic Helper
# =============================================================================


def _match_any(
    patterns: str | list[str] | None,
    value: str | None,
    match_fn: Callable[[str, str | None], bool],
) -> bool:
    """Match value against single pattern or any pattern in list.

    Provides OR logic for conditions that accept lists: the condition
    matches if ANY pattern in the list matches the value.

    Args:
        patterns: Single pattern, list of patterns, or None (no constraint).
        value: Value to match against.
        match_fn: Function to match single pattern against value.
            Must have signature: (pattern: str, value: str | None) -> bool

    Returns:
        True if no constraint (patterns is None), or if value matches any pattern.
        False if empty list (no valid values = rule never matches).
    """
    # No constraint = matches anything
    if patterns is None:
        return True

    # Single value: use match function directly
    if isinstance(patterns, str):
        return match_fn(patterns, value)

    # Empty list = no valid values = never match
    if not patterns:
        return False

    # List: OR logic - match if ANY pattern matches
    return any(match_fn(p, value) for p in patterns)
