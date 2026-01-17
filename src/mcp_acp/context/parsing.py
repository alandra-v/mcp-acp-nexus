"""Resource parsing utilities for paths and URIs.

Provides safe parsing of file paths and URIs into ResourceInfo objects.
Used by context building for ABAC policy evaluation.

SECURITY: Path parsing does NOT resolve symlinks to prevent TOCTOU attacks.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp_acp.constants import DEST_PATH_ARGS, PATH_ARGUMENT_NAMES, SOURCE_PATH_ARGS
from mcp_acp.context.provenance import Provenance
from mcp_acp.context.resource import ResourceInfo

__all__ = [
    "parse_path_resource",
    "parse_uri_resource",
    "extract_resource_info",
]


def parse_path_resource(raw_path: str) -> ResourceInfo:
    """Parse file path into ResourceInfo.

    SECURITY: We do NOT resolve symlinks or call .resolve(). This prevents
    TOCTOU attacks where an attacker creates a symlink pointing to a sensitive
    file. Policy evaluation uses the path as provided by the client - if client
    requests "/tmp/link", policy matches against "/tmp/link", not the target.

    We only normalize the path (collapse . and ..) without following symlinks.

    Args:
        raw_path: Raw file path string.

    Returns:
        ResourceInfo with path details.
    """
    try:
        # Use os.path.normpath to collapse . and .. without resolving symlinks
        # This is safer than .resolve() which follows symlinks
        normalized = os.path.normpath(raw_path)
        norm_path = Path(normalized)

        return ResourceInfo(
            path=normalized,
            filename=norm_path.name,
            extension=norm_path.suffix if norm_path.suffix else None,
            parent_dir=str(norm_path.parent),
            provenance=Provenance.MCP_REQUEST,
        )
    except (ValueError, OSError):
        # Path normalization failed, return as-is
        return ResourceInfo(
            path=raw_path,
            provenance=Provenance.MCP_REQUEST,
        )


def parse_uri_resource(uri: str) -> ResourceInfo:
    """Parse URI into ResourceInfo.

    Args:
        uri: URI string.

    Returns:
        ResourceInfo with URI details.
    """
    try:
        parsed = urlparse(uri)
        result = ResourceInfo(
            uri=uri,
            scheme=parsed.scheme if parsed.scheme else None,
            provenance=Provenance.MCP_REQUEST,
        )

        # If it's a file:// URI, extract path info too
        if parsed.scheme == "file" and parsed.path:
            path = Path(parsed.path)
            return ResourceInfo(
                uri=uri,
                scheme=parsed.scheme,
                path=parsed.path,
                filename=path.name,
                extension=path.suffix if path.suffix else None,
                parent_dir=str(path.parent),
                provenance=Provenance.MCP_REQUEST,
            )

        return result
    except (ValueError, AttributeError):
        return ResourceInfo(uri=uri, provenance=Provenance.MCP_REQUEST)


def extract_resource_info(arguments: dict[str, Any] | None) -> ResourceInfo | None:
    """Extract resource info from file paths in arguments.

    Extracts:
    - path: First generic path found (from PATH_ARGUMENT_NAMES)
    - source_path: Source path for move/copy operations
    - dest_path: Destination path for move/copy operations

    For tools like move_file(source, destination), both source_path and dest_path
    will be populated. The 'path' field will contain the first path found
    (usually source) for backwards compatibility.

    Args:
        arguments: Request arguments.

    Returns:
        ResourceInfo if any path found, None otherwise.
    """
    if arguments is None:
        return None

    # Extract source path
    source_path: str | None = None
    for key in SOURCE_PATH_ARGS:
        if key in arguments and arguments[key]:
            source_path = str(arguments[key])
            break

    # Extract destination path
    dest_path: str | None = None
    for key in DEST_PATH_ARGS:
        if key in arguments and arguments[key]:
            dest_path = str(arguments[key])
            break

    # Extract generic path (for backwards compatibility and single-path tools)
    # Use PATH_ARGUMENT_NAMES but exclude "uri" - URIs handled separately
    generic_path: str | None = None
    for key in PATH_ARGUMENT_NAMES:
        if key == "uri":
            continue
        if key in arguments and arguments[key]:
            generic_path = str(arguments[key])
            break

    # Determine the primary path (for backwards compat)
    # Priority: explicit generic path > source_path > dest_path
    primary_path = generic_path or source_path or dest_path

    if primary_path is None:
        return None

    # Parse the primary path to get filename, extension, etc.
    resource_info = parse_path_resource(primary_path)

    # Return with source/dest paths added
    return ResourceInfo(
        uri=resource_info.uri,
        scheme=resource_info.scheme,
        path=resource_info.path,
        source_path=source_path,
        dest_path=dest_path,
        filename=resource_info.filename,
        extension=resource_info.extension,
        parent_dir=resource_info.parent_dir,
        provenance=resource_info.provenance,
    )
