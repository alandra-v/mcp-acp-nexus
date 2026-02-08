"""Metadata extraction helpers for MCP operations.

Extracts structured metadata from MCP tool calls, file operations,
initialize handshakes, and client info for audit and debug logging.
"""

from __future__ import annotations

__all__ = [
    "ClientInfo",
    "detect_operation_type",
    "extract_client_info",
    "extract_dest_path",
    "extract_file_metadata",
    "extract_file_path",
    "extract_initialize_metadata",
    "extract_source_path",
    "extract_tool_metadata",
    "redact_sensitive_content",
]

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastmcp.server.middleware.middleware import MiddlewareContext


@dataclass(frozen=True, slots=True)
class ClientInfo:
    """Client metadata extracted from initialize request.

    Attributes:
        name: Client application name (e.g., "claude-desktop", "mcp-inspector").
        version: Client version string.
        protocol_version: MCP protocol version.
    """

    name: str | None = None
    version: str | None = None
    protocol_version: str | None = None


from mcp_acp.constants import DEST_PATH_ARGS, PATH_ARGUMENT_NAMES, SOURCE_PATH_ARGS
from mcp_acp.utils.logging.logging_helpers import (
    normalize_file_path,
    sanitize_for_logging,
)

# Content-related argument names to redact during logging
CONTENT_ARGUMENT_NAMES: tuple[str, ...] = (
    "content",
    "data",
    "text",
    "body",
)

# MIME type hints for common file extensions
MIME_TYPE_HINTS: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".json": "application/json",
    ".py": "text/x-python",
    ".js": "text/javascript",
    ".html": "text/html",
    ".css": "text/css",
    ".xml": "application/xml",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


def extract_file_path(arguments: dict[str, Any], system_logger: logging.Logger | None = None) -> str | None:
    """Extract and normalize file path from tool arguments.

    Looks for common path-related argument names, then normalizes
    the path to canonical absolute form and sanitizes for logging.

    Args:
        arguments: Tool call arguments.
        system_logger: Optional logger for warnings.

    Returns:
        str | None: Normalized, sanitized file path if found, None otherwise.
    """
    if not arguments:
        return None

    # Check common path argument names
    for key in PATH_ARGUMENT_NAMES:
        if key in arguments:
            raw_path = str(arguments[key])
            # Normalize and sanitize the path for security
            return normalize_file_path(raw_path, system_logger)

    return None


def extract_source_path(arguments: dict[str, Any], system_logger: logging.Logger | None = None) -> str | None:
    """Extract and normalize source path from tool arguments.

    Used for copy/move operations where source path is specified separately.

    Args:
        arguments: Tool call arguments.
        system_logger: Optional logger for warnings.

    Returns:
        str | None: Normalized, sanitized source path if found, None otherwise.
    """
    if not arguments:
        return None

    for key in SOURCE_PATH_ARGS:
        if key in arguments and arguments[key]:
            raw_path = str(arguments[key])
            return normalize_file_path(raw_path, system_logger)

    return None


def extract_dest_path(arguments: dict[str, Any], system_logger: logging.Logger | None = None) -> str | None:
    """Extract and normalize destination path from tool arguments.

    Used for copy/move operations where destination path is specified separately.

    Args:
        arguments: Tool call arguments.
        system_logger: Optional logger for warnings.

    Returns:
        str | None: Normalized, sanitized destination path if found, None otherwise.
    """
    if not arguments:
        return None

    for key in DEST_PATH_ARGS:
        if key in arguments and arguments[key]:
            raw_path = str(arguments[key])
            return normalize_file_path(raw_path, system_logger)

    return None


def detect_operation_type(tool_name: str, arguments: dict[str, Any]) -> str:
    """Detect the type of file operation from tool name and arguments.

    Args:
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.

    Returns:
        str: Operation type - "read", "write", "delete", "list", or "other".
    """
    tool_lower = tool_name.lower()

    # Check tool name first
    if "write" in tool_lower or "create" in tool_lower or "edit" in tool_lower:
        return "write"
    elif "read" in tool_lower or "get" in tool_lower:
        return "read"
    elif "delete" in tool_lower or "remove" in tool_lower:
        return "delete"
    elif "list" in tool_lower or "search" in tool_lower:
        return "list"

    # Check arguments for hints
    if arguments:
        if "content" in arguments or "data" in arguments:
            return "write"

    return "other"


def extract_file_metadata(file_path: str, content: str | bytes | None = None) -> dict[str, Any]:
    """Extract file metadata for audit logging (NO CONTENT, NO HASHING).

    Note: file_path should already be normalized by extract_file_path() before
    calling this function. This function extracts metadata from the normalized path.

    Args:
        file_path: Path to the file (should be normalized).
        content: Optional file content (to determine size).

    Returns:
        dict[str, Any]: Dictionary with file metadata (extension, size, mime type hint).
    """
    path = Path(file_path)
    metadata: dict[str, Any] = {
        "file_extension": path.suffix,
        "file_name": sanitize_for_logging(path.name),  # Sanitize filename too
    }

    # Add size if content provided
    if content is not None:
        if isinstance(content, str):
            metadata["file_size_bytes"] = len(content.encode("utf-8"))
        elif isinstance(content, bytes):
            metadata["file_size_bytes"] = len(content)

    # Basic mime type hint based on extension (optional)
    if path.suffix in MIME_TYPE_HINTS:
        metadata["mime_type_hint"] = MIME_TYPE_HINTS[path.suffix]

    return metadata


def redact_sensitive_content(arguments: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive file content from arguments before logging.

    Replaces actual content with size indicator to prevent PII/secrets in logs.

    Args:
        arguments: Original tool call arguments.

    Returns:
        dict[str, Any]: New dictionary with content redacted.
    """
    if not arguments:
        return {}

    redacted = arguments.copy()

    # Redact content fields
    for key in CONTENT_ARGUMENT_NAMES:
        if key in redacted:
            original = redacted[key]
            if isinstance(original, str):
                size = len(original.encode("utf-8"))
                redacted[key] = f"[REDACTED - {size} bytes]"
            elif isinstance(original, bytes):
                size = len(original)
                redacted[key] = f"[REDACTED - {size} bytes]"
            elif original is not None:
                redacted[key] = f"[REDACTED - {type(original).__name__}]"

    return redacted


def extract_tool_metadata(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    system_logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Extract comprehensive audit metadata from a tool call.

    This is the main extraction function that combines all metadata extraction.

    Args:
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.
        system_logger: Optional logger for warnings.

    Returns:
        dict[str, Any]: Dictionary with extracted metadata containing:
            - tool_name: Name of the tool.
            - operation_type: Type of operation (read/write/delete/list/other).
            - file_path: Extracted file path (if present).
            - source_path: Source path for copy/move operations (if present).
            - dest_path: Destination path for copy/move operations (if present).
            - file_metadata: File extension, size, type (if applicable).
            - arguments_redacted: Arguments with sensitive content removed.
    """
    if arguments is None:
        arguments = {}

    metadata: dict[str, Any] = {
        "tool_name": tool_name,
        "operation_type": detect_operation_type(tool_name, arguments),
    }

    # Extract file path
    file_path = extract_file_path(arguments, system_logger)
    if file_path:
        metadata["file_path"] = file_path

        # Extract file metadata (extension, name)
        content = arguments.get("content") or arguments.get("data")
        file_meta = extract_file_metadata(file_path, content)
        metadata.update(file_meta)

    # Extract source/dest paths for copy/move operations
    source_path = extract_source_path(arguments, system_logger)
    if source_path:
        metadata["source_path"] = source_path

    dest_path = extract_dest_path(arguments, system_logger)
    if dest_path:
        metadata["dest_path"] = dest_path

    # Redact sensitive content from arguments
    metadata["arguments_redacted"] = redact_sensitive_content(arguments)

    return metadata


def extract_initialize_metadata(
    initialize_result: Any, system_logger: logging.Logger | None = None
) -> dict[str, Any]:
    """Extract metadata from MCP initialize handshake result.

    Args:
        initialize_result: The InitializeResult from MCP handshake
        system_logger: Optional logger for extraction errors

    Returns:
        dict with extracted metadata (protocol_version, server_info, etc.)
    """
    metadata: dict[str, Any] = {}

    # Protocol version (required field)
    if hasattr(initialize_result, "protocolVersion"):
        metadata["protocol_version"] = initialize_result.protocolVersion

    # Server info (critical for security auditing)
    if hasattr(initialize_result, "serverInfo") and initialize_result.serverInfo:
        try:
            if hasattr(initialize_result.serverInfo, "name"):
                metadata["server_name"] = initialize_result.serverInfo.name
            if hasattr(initialize_result.serverInfo, "version"):
                metadata["server_version"] = initialize_result.serverInfo.version
            metadata["server_info"] = initialize_result.serverInfo.model_dump()
        except (AttributeError, TypeError) as e:
            metadata["server_info_error"] = str(e)
            if system_logger:
                system_logger.warning(
                    {
                        "event": "metadata_extraction_failed",
                        "context": "initialize",
                        "field": "server_info",
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }
                )

    # Capabilities
    if hasattr(initialize_result, "capabilities") and initialize_result.capabilities:
        try:
            metadata["capabilities"] = initialize_result.capabilities.model_dump()
        except (AttributeError, TypeError) as e:
            metadata["capabilities_error"] = str(e)
            if system_logger:
                system_logger.warning(
                    {
                        "event": "metadata_extraction_failed",
                        "context": "initialize",
                        "field": "capabilities",
                        "error": str(e),
                        "error_type": type(e).__name__,
                    }
                )

    # Instructions
    if hasattr(initialize_result, "instructions") and initialize_result.instructions:
        metadata["instructions"] = initialize_result.instructions

    return metadata


def extract_client_info(context: "MiddlewareContext[Any]") -> ClientInfo:
    """Extract client info from MCP initialize request.

    Safely extracts client metadata from the initialize message params.
    Returns empty ClientInfo if extraction fails or method is not initialize.

    Args:
        context: Middleware context containing the request.

    Returns:
        ClientInfo with extracted fields (all optional).
    """
    if context.method != "initialize":
        return ClientInfo()

    return _extract_client_info_from_message(context.message)


def _extract_client_info_from_message(message: Any) -> ClientInfo:
    """Extract client info from message params.

    Args:
        message: The request message (may have params attribute).

    Returns:
        ClientInfo with extracted fields.
    """
    try:
        if not hasattr(message, "params") or not message.params:
            return ClientInfo()

        params = message.params
        name = None
        version = None
        protocol_version = None

        # Extract clientInfo
        if hasattr(params, "clientInfo") and params.clientInfo:
            client_info = params.clientInfo
            if hasattr(client_info, "name") and client_info.name:
                name = client_info.name
            if hasattr(client_info, "version") and client_info.version:
                version = client_info.version

        # Extract protocol version
        if hasattr(params, "protocolVersion") and params.protocolVersion:
            protocol_version = params.protocolVersion

        return ClientInfo(
            name=name,
            version=version,
            protocol_version=protocol_version,
        )

    except (AttributeError, TypeError):
        return ClientInfo()
