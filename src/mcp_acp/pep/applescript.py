"""AppleScript utilities for HITL dialogs on macOS.

Provides safe string escaping and output parsing for AppleScript dialogs.
Used by HITL (Human-in-the-Loop) approval flows.

Note: Startup error popups are in cli/startup_alerts.py (pre-start, not runtime).
"""

from __future__ import annotations

import re

__all__ = [
    "escape_applescript_string",
    "parse_applescript_record",
]


def escape_applescript_string(s: str) -> str:
    """Escape a string for safe use in AppleScript.

    Escapes backslashes, double quotes, and control characters to prevent
    AppleScript injection and ensure proper dialog rendering.

    Args:
        s: The string to escape.

    Returns:
        Escaped string safe for AppleScript interpolation.

    Example:
        >>> escape_applescript_string('Path: /tmp/test"file')
        'Path: /tmp/test\\\\"file'
        >>> escape_applescript_string('line1\\nline2')
        'line1 line2'
    """
    # Replace control characters with spaces (they could break dialog rendering)
    # Do this first before escaping backslashes
    s = s.replace("\n", " ")
    s = s.replace("\r", " ")
    s = s.replace("\t", " ")
    # Escape backslashes (order matters - must be before quotes)
    s = s.replace("\\", "\\\\")
    # Escape double quotes
    s = s.replace('"', '\\"')
    return s


def parse_applescript_record(output: str) -> dict[str, str]:
    """Parse AppleScript record output into a dictionary.

    AppleScript returns records like: {button returned:"Allow", gave up:false}
    This parser handles the format robustly, accounting for potential spacing
    variations in future macOS versions.

    Args:
        output: Raw osascript stdout output.

    Returns:
        Dictionary of key-value pairs from the record.
        Values are returned as strings (e.g., "true", "false", "Allow").

    Example:
        >>> parse_applescript_record('{button returned:"Allow", gave up:false}')
        {'button returned': 'Allow', 'gave up': 'false'}
    """
    result: dict[str, str] = {}

    # Match key:value pairs where value is either quoted or unquoted
    # Pattern handles: key:"quoted value" or key:unquoted_value
    # Unquoted values can contain word chars, spaces, and parentheses (e.g., "Allow (10m)")
    # Values are terminated by comma or end of record (})
    pattern = r'(\w+(?:\s+\w+)*)\s*:\s*(?:"([^"]*)"|([^,}]+))'

    for match in re.finditer(pattern, output):
        key = match.group(1)
        # Value is either in group 2 (quoted) or group 3 (unquoted)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        if value:
            value = value.strip()  # Clean up whitespace from unquoted values
        result[key] = value

    return result
