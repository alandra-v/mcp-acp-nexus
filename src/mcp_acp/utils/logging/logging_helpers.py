"""Logging helper utilities.

Provides generic utilities for telemetry logging:
- Event serialization (audit/history event model_dump with consistent options)
- Sanitization (log injection prevention, path normalization)
- Payload handling (serialization, truncation, size estimation)
- Error categorization and metadata extraction
- Arguments hashing for audit trails

For MCP-specific metadata extraction, see extractors.py.
"""

__all__ = [
    # Event serialization
    "serialize_audit_event",
    # Sanitization & path normalization
    "sanitize_for_logging",
    "normalize_file_path",
    # Payload handling
    "create_payload_dict",
    "serialize_result_summary",
    # Error handling
    "categorize_error",
    "extract_error_metadata",
    "clean_backend_error",
    # Audit trail hashing
    "create_arguments_summary",
    "create_response_summary",
    # Sensitive data hashing
    "hash_sensitive_id",
    "hash_auth_event_ids",
    "sanitize_config_snapshot",
]

import copy
import hashlib
import json
import logging
import re
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

if TYPE_CHECKING:
    from mcp_acp.telemetry.models.audit import ArgumentsSummary, ResponseSummary


# ============================================================================
# Event Serialization
# ============================================================================


def serialize_audit_event(event: BaseModel, *, json_mode: bool = False) -> dict[str, Any]:
    """Serialize a Pydantic event model for audit/history logging.

    Provides consistent serialization for all audit and history events:
    - Excludes the 'time' field (added by ISO8601Formatter at log time)
    - Excludes None values for cleaner logs

    Args:
        event: Pydantic model instance (e.g., AuthEvent, DecisionEvent, ConfigHistoryEvent).
        json_mode: If True, use mode="json" for JSON-compatible serialization of
                   datetime/enum values. Used by auth_logger for OIDC token data.

    Returns:
        dict: Serialized event data ready for logging.

    Example:
        >>> event = DecisionEvent(decision="ALLOW", tool_name="read_file", ...)
        >>> serialize_audit_event(event)
        {"decision": "ALLOW", "tool_name": "read_file", ...}

        >>> event = AuthEvent(event_type="token_validated", oidc=OIDCInfo(...), ...)
        >>> serialize_audit_event(event, json_mode=True)
        {"event_type": "token_validated", "oidc": {...}, ...}
    """
    if json_mode:
        return event.model_dump(mode="json", exclude={"time"}, exclude_none=True)
    return event.model_dump(exclude={"time"}, exclude_none=True)


# ============================================================================
# Sanitization & Path Normalization
# ============================================================================


def sanitize_for_logging(value: str) -> str:
    """Sanitize string values for safe JSONL logging.

    Prevents log injection by escaping newlines and control characters.
    This ensures that malicious filenames cannot break JSONL format or
    inject fake log entries.

    Args:
        value: String value to sanitize (e.g., file path, user input).

    Returns:
        str: Sanitized string safe for JSONL logging.

    Example:
        >>> sanitize_for_logging("/tmp/file\\nwith\\nnewlines")
        '/tmp/file\\\\nwith\\\\nnewlines'
    """
    if not isinstance(value, str):
        return str(value)

    # Escape newlines and carriage returns to prevent log injection
    sanitized = value.replace("\n", "\\n").replace("\r", "\\r")

    # Escape other control characters (optional, but safer)
    sanitized = sanitized.replace("\t", "\\t")

    return sanitized


def normalize_file_path(file_path: str, system_logger: logging.Logger | None = None) -> str:
    """Normalize and resolve file path to canonical absolute form.

    Security benefits:
    - Resolves symlinks to show true target location
    - Resolves relative paths (../, ./) to absolute paths
    - Shows canonical path for audit trail accuracy

    This is critical for zero-trust auditing to prevent path traversal
    obfuscation in logs.

    Args:
        file_path: File path to normalize (can be relative or absolute).
        system_logger: Optional logger for warnings (failures won't break flow).

    Returns:
        str: Sanitized, absolute, canonical file path.

    Example:
        >>> normalize_file_path("../../secrets/key.txt")
        '/home/user/secrets/key.txt'  # Resolved to absolute path
    """
    try:
        # Resolve to absolute path, resolve symlinks, normalize
        path = Path(file_path).resolve()
        # Convert to string and sanitize for logging
        return sanitize_for_logging(str(path))
    except (OSError, ValueError, RuntimeError) as e:
        # Path resolution failed (invalid path, permission denied, etc.)
        # Log warning if logger provided, but don't break flow
        if system_logger:
            system_logger.warning(
                {
                    "event": "path_normalization_failed",
                    "path": file_path,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "message": "Failed to normalize path - using original (may contain symlinks)",
                }
            )
        # Still sanitize the original path to prevent log injection
        return sanitize_for_logging(file_path)


# ============================================================================
# Payload Handling (Serialization, Truncation, Size Estimation)
# ============================================================================


def create_payload_dict(
    obj: Any,
    max_length: int = 1000,
    include_full: bool = True,
) -> dict[str, Any]:
    """Create payload dictionary for logging with size metadata.

    Returns dict with either 'payload' (full) or 'payload_truncated' (partial)
    plus 'payload_length' field.

    Args:
        obj: Object to serialize
        max_length: Maximum length before truncation
        include_full: Whether to include full payload if under max_length

    Returns:
        dict with payload data and metadata fields

    Example:
        >>> create_payload_dict({"key": "value"}, max_length=1000)
        {
            "payload": {"key": "value"},
            "payload_length": 16
        }

        >>> create_payload_dict({"data": "x" * 2000}, max_length=100)
        {
            "payload_truncated": '{"data": "xxxx...',
            "payload_length": 2011
        }
    """
    # Try to serialize
    try:
        json_str = json.dumps(obj, default=str)
    except (TypeError, ValueError) as e:
        # Serialization failed - return error info with fallback
        return {
            "payload": str(obj),
            "serialization_error": str(e),
        }

    # Calculate size
    length = len(json_str)

    payload_dict: dict[str, Any] = {
        "payload_length": length,
    }

    # Add payload (full or truncated)
    if length > max_length:
        # Truncate with ellipsis
        payload_dict["payload_truncated"] = json_str[:max_length] + "..."
    elif include_full:
        # Include full payload (parse back to object for cleaner logs)
        try:
            payload_dict["payload"] = json.loads(json_str)
        except json.JSONDecodeError:
            # Should not happen, but fallback to string
            payload_dict["payload"] = json_str

    return payload_dict


def serialize_result_summary(result: Any, max_length: int = 1000) -> dict[str, Any]:
    """Create a summary of a result for logging.

    For lists, includes count. For large objects, includes truncated representation.

    Args:
        result: Result object to summarize
        max_length: Maximum length for serialization

    Returns:
        dict with result summary
    """
    if result is None:
        return {}

    summary: dict[str, Any] = {}

    # Special handling for lists
    if isinstance(result, list):
        summary["count"] = len(result)
        # For tool lists, extract names
        if result and hasattr(result[0], "name"):
            summary["tools"] = [item.name for item in result]
        elif result and hasattr(result[0], "uri"):
            summary["resources"] = [str(item.uri) for item in result[:10]]  # Limit to 10

    # Use standard payload serialization
    payload_data = create_payload_dict(result, max_length=max_length, include_full=False)
    summary.update(payload_data)

    return summary


# ============================================================================
# Error Handling
# ============================================================================


def categorize_error(error: Exception) -> str:
    """Categorize exception for filtering and alerting.

    Maps exception types to error categories for easier filtering, alerting,
    and analysis. Add new error patterns here as they emerge.

    Args:
        error: The exception to categorize

    Returns:
        str: Error category (e.g., "network", "timeout", "auth", "system")

    Categories:
        - network: Connection errors, network failures
        - timeout: Timeout-specific errors
        - auth: Authentication/authorization failures
        - filesystem: File system operations
        - serialization: JSON/data serialization errors
        - backend: MCP backend server errors
        - system: Generic system errors
        - unknown: Unrecognized error types
    """
    error_type = type(error).__name__

    # Network-related errors
    if error_type in ("TimeoutError", "ConnectionError", "ConnectionRefusedError", "ConnectionResetError"):
        return "network"

    # Timeout-specific (subset of network but worth distinguishing for alerting)
    if "timeout" in error_type.lower() or "Timeout" in error_type:
        return "timeout"

    # Authentication/authorization errors (for future OAuth integration)
    if error_type in ("PermissionError", "AuthenticationError", "UnauthorizedError"):
        return "auth"

    # File system errors
    if error_type in ("FileNotFoundError", "IsADirectoryError", "NotADirectoryError"):
        return "filesystem"

    # Serialization errors
    if error_type in ("TypeError", "ValueError", "JSONDecodeError"):
        return "serialization"

    # Backend/server errors (MCP-specific)
    if hasattr(error, "code") and error.code:
        return "backend"

    # Generic system errors
    if error_type in ("OSError", "RuntimeError", "IOError"):
        return "system"

    # Unknown error type - return generic category
    return "unknown"


def extract_error_metadata(error: Exception) -> dict[str, Any]:
    """Extract comprehensive metadata from an exception.

    Args:
        error: The exception to extract metadata from

    Returns:
        dict with error metadata:
            - error: str representation
            - error_type: exception class name
            - error_traceback: full traceback string
            - error_code: error code if available (MCP errors)
            - error_category: categorized error type
    """
    metadata: dict[str, Any] = {
        "error": str(error),
        "error_type": type(error).__name__,
        "error_traceback": traceback.format_exc(),
        "error_category": categorize_error(error),
    }

    # Include error code if available (MCP errors)
    if hasattr(error, "code"):
        metadata["error_code"] = error.code

    return metadata


def clean_backend_error(error: str) -> str:
    """Transform backend error messages to clarify proxy→backend failures.

    FastMCP's ProxyClient uses "Client" terminology because from its perspective,
    the proxy IS the client connecting to the backend server. This is confusing
    for operators who think of Claude Desktop as "the client".

    This function:
    1. Replaces "Client failed to connect" with "Proxy failed to connect"
    2. Prefixes all backend errors with "Proxy→Backend:" for clarity

    Use this for audit/system logs. Debug logs should keep raw errors.

    Args:
        error: Original error message from FastMCP or transport layer.

    Returns:
        Cleaned error message with clear source indication.

    Example:
        >>> clean_backend_error("Client failed to connect: Connection closed")
        "Proxy→Backend: Proxy failed to connect: Connection closed"
    """
    cleaned = error

    # Replace misleading "Client" terminology
    # FastMCP: "Client failed to connect: {inner_error}"
    if "client failed to connect" in error.lower():
        cleaned = re.sub(
            r"(?i)client failed to connect",
            "Proxy failed to connect",
            cleaned,
        )

    # Prefix all backend errors for explicit clarity
    if not cleaned.startswith("Proxy→Backend:"):
        cleaned = f"Proxy→Backend: {cleaned}"

    return cleaned


# ============================================================================
# Audit Trail Hashing
# ============================================================================


def create_arguments_summary(message: Any) -> "ArgumentsSummary | None":
    """Create summary of request arguments without sensitive data.

    Hashes the arguments for audit trail integrity verification without
    storing the actual sensitive argument values.

    Args:
        message: Request message object (may have params attribute).

    Returns:
        ArgumentsSummary with hash and length, or None if no params.
    """
    # Import here to avoid circular import
    from mcp_acp.telemetry.models.audit import ArgumentsSummary

    try:
        if not hasattr(message, "params") or not message.params:
            return None

        # Serialize params to get hash and length
        params_str = json.dumps(
            (message.params.model_dump() if hasattr(message.params, "model_dump") else str(message.params)),
            default=str,
        )
        params_bytes = params_str.encode("utf-8")

        return ArgumentsSummary(
            redacted=True,
            body_hash=hashlib.sha256(params_bytes).hexdigest(),
            payload_length=len(params_bytes),
        )
    except (AttributeError, TypeError, ValueError):
        return None


def create_response_summary(response: Any) -> "ResponseSummary | None":
    """Create summary of response metadata without sensitive data.

    Captures response size and hash for forensic analysis without
    storing potentially sensitive response content.

    Args:
        response: Response object from backend (may be None, dict, Pydantic model, etc.).

    Returns:
        ResponseSummary with size and hash, or None if response cannot be processed.
    """
    # Import here to avoid circular import
    from mcp_acp.telemetry.models.audit import ResponseSummary

    if response is None:
        return None

    try:
        # Serialize response to get consistent hash and size
        if hasattr(response, "model_dump"):
            response_data = response.model_dump()
        elif hasattr(response, "__dict__"):
            response_data = response.__dict__
        else:
            response_data = response

        response_str = json.dumps(response_data, default=str, sort_keys=True)
        response_bytes = response_str.encode("utf-8")

        return ResponseSummary(
            size_bytes=len(response_bytes),
            body_hash=hashlib.sha256(response_bytes).hexdigest(),
        )
    except (AttributeError, TypeError, ValueError):
        return None


# ============================================================================
# Sensitive Data Hashing
# ============================================================================


def hash_sensitive_id(value: str, prefix_length: int = 8) -> str:
    """Hash a sensitive ID for logging while preserving some identifiability.

    Creates a shortened hash that allows log correlation without exposing
    the full identifier. The hash is deterministic, so the same input always
    produces the same output.

    Args:
        value: The sensitive ID to hash (e.g., subject_id, session_id).
        prefix_length: Number of hex characters to keep (default: 8).
                      8 chars = 32 bits of entropy, enough for log correlation
                      while being compact.

    Returns:
        str: Hashed value in format "sha256:<prefix>" (e.g., "sha256:a1b2c3d4").

    Example:
        >>> hash_sensitive_id("auth0|<user_id>")
        'sha256:a1b2c3d4'

        >>> hash_sensitive_id("user123:wvshAZY3R2kM5PMWESGz7k14OJxcyNKmYGlWUL-s1N8")
        'sha256:e5f6g7h8'
    """
    if not value:
        return "sha256:empty"

    hash_bytes = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"sha256:{hash_bytes[:prefix_length]}"


def hash_auth_event_ids(event_data: dict[str, Any]) -> dict[str, Any]:
    """Hash sensitive IDs in an auth event dict before logging.

    Creates a new dict with sensitive identifiers replaced by their hashed
    versions. This preserves log correlation ability while protecting PII.
    The original dict is not modified.

    Hashed fields:
    - bound_session_id: Full session ID (user:token format)
    - subject.subject_id: User identifier from OIDC token

    Args:
        event_data: Serialized auth event dictionary.

    Returns:
        dict: New dictionary with sensitive IDs hashed.

    Example:
        >>> event = {"bound_session_id": "user123:token456", "subject": {"subject_id": "auth0|abc"}}
        >>> hashed = hash_auth_event_ids(event)
        >>> hashed
        {'bound_session_id': 'sha256:a1b2c3d4', 'subject': {'subject_id': 'sha256:e5f6g7h8'}}
        >>> event["bound_session_id"]  # Original unchanged
        'user123:token456'
    """
    result = copy.deepcopy(event_data)

    # Hash bound_session_id if present
    if "bound_session_id" in result and result["bound_session_id"]:
        result["bound_session_id"] = hash_sensitive_id(result["bound_session_id"])

    # Hash subject.subject_id if present
    if "subject" in result and isinstance(result["subject"], dict):
        if "subject_id" in result["subject"] and result["subject"]["subject_id"]:
            result["subject"]["subject_id"] = hash_sensitive_id(result["subject"]["subject_id"])

    return result


# Fields to redact from config snapshots (paths to sensitive data)
_SENSITIVE_CONFIG_FIELDS = frozenset(
    {
        "client_key_path",  # mTLS private key location
        "client_secret",  # OIDC client secret (if ever added)
        "private_key",  # Any private key content
        "password",  # Any password field
        "secret",  # Any secret field
    }
)


def sanitize_config_snapshot(config: dict[str, Any]) -> dict[str, Any]:
    """Remove sensitive fields from a config snapshot before logging.

    Recursively traverses the config dict and removes fields that could
    expose sensitive information (private key paths, secrets, etc.).

    Args:
        config: Configuration dictionary to sanitize.

    Returns:
        dict: New dictionary with sensitive fields removed.

    Example:
        >>> sanitize_config_snapshot({
        ...     "auth": {
        ...         "mtls": {
        ...             "client_cert_path": "/path/to/cert.pem",
        ...             "client_key_path": "/path/to/key.pem",
        ...         }
        ...     }
        ... })
        {'auth': {'mtls': {'client_cert_path': '/path/to/cert.pem'}}}
    """
    if not isinstance(config, dict):
        return config

    result: dict[str, Any] = {}
    for key, value in config.items():
        # Skip sensitive fields
        if key in _SENSITIVE_CONFIG_FIELDS:
            continue

        # Recursively sanitize nested dicts
        if isinstance(value, dict):
            result[key] = sanitize_config_snapshot(value)
        elif isinstance(value, list):
            # Handle lists of dicts
            result[key] = [
                sanitize_config_snapshot(item) if isinstance(item, dict) else item for item in value
            ]
        else:
            result[key] = value

    return result
