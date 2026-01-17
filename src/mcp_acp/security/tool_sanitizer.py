"""Tool list sanitization for MCP tools/list responses.

Sanitizes tool descriptions and inputSchema property descriptions to protect
against prompt injection attacks from untrusted backend MCP servers.

This module wraps the core sanitize_description() function with MCP-specific
handling for ListToolsResult objects.

Usage:
    from mcp_acp.security.tool_sanitizer import ToolListSanitizer

    sanitizer = ToolListSanitizer(decision_logger, system_logger)
    result = sanitizer.sanitize(result, request_id, session_id)
"""

from __future__ import annotations

__all__ = ["ToolListSanitizer"]

import logging
from typing import Any

from mcp.types import ListToolsResult

from mcp_acp.security.sanitizer import sanitize_description


class ToolListSanitizer:
    """Sanitizes tool descriptions in MCP tools/list responses.

    Protects against prompt injection by sanitizing descriptions from
    untrusted backend servers.

    IMPORTANT: This class modifies Tool objects IN PLACE for simplicity.
    This is acceptable because:
    - FastMCP creates fresh ListToolsResult per request (no caching)
    - We own this middleware and control the data flow
    - Creating new Tool objects would add complexity for little benefit

    Risk: If FastMCP ever caches ListToolsResult, this would corrupt the
    cache. If that happens, refactor to create new Tool objects instead.
    """

    def __init__(
        self,
        decision_logger: logging.Logger,
        system_logger: logging.Logger,
    ) -> None:
        """Initialize the sanitizer.

        Args:
            decision_logger: Logger for decision/audit events (decisions.jsonl).
            system_logger: Logger for system warnings (system.jsonl).
        """
        self._decision_logger = decision_logger
        self._system_logger = system_logger

    def _sanitize_input_schema(
        self,
        schema: dict[str, Any] | None,
        tool_name: str,
        request_id: str,
        session_id: str,
    ) -> None:
        """Sanitize descriptions in inputSchema properties.

        Modifies schema in place. Property descriptions can also contain
        prompt injection attempts, so we sanitize them too.

        Args:
            schema: The inputSchema dict to sanitize (modified in place).
            tool_name: Tool name for logging.
            request_id: Request correlation ID.
            session_id: Session ID.
        """
        if not schema or "properties" not in schema:
            return

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return

        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict) or "description" not in prop_def:
                continue

            prop_desc = prop_def.get("description")
            if not isinstance(prop_desc, str):
                continue

            sanitization = sanitize_description(prop_desc)
            prop_def["description"] = sanitization.text

            if sanitization.modifications or sanitization.suspicious_patterns:
                self._decision_logger.info(
                    {
                        "event": "input_schema_sanitized",
                        "tool_name": tool_name,
                        "property": prop_name,
                        "modifications": sanitization.modifications,
                        "suspicious_patterns": sanitization.suspicious_patterns,
                        "request_id": request_id,
                        "session_id": session_id,
                    }
                )

                if sanitization.suspicious_patterns:
                    self._system_logger.warning(
                        {
                            "event": "suspicious_input_schema",
                            "message": f"Tool '{tool_name}' property '{prop_name}' contains suspicious patterns",
                            "tool_name": tool_name,
                            "property": prop_name,
                            "patterns": sanitization.suspicious_patterns,
                            "request_id": request_id,
                            "session_id": session_id,
                        }
                    )

    def sanitize(
        self,
        result: ListToolsResult,
        request_id: str,
        session_id: str,
    ) -> ListToolsResult:
        """Sanitize tool descriptions in tools/list response.

        Sanitizes:
        - tool.description
        - tool.inputSchema.properties.*.description

        Args:
            result: The ListToolsResult from the backend (modified in place).
            request_id: Request correlation ID for logging.
            session_id: Session ID for logging.

        Returns:
            The same result object with sanitized descriptions.
        """
        for tool in result.tools:
            # Sanitize main description
            if tool.description:
                sanitization = sanitize_description(tool.description)
                tool.description = sanitization.text

                if sanitization.modifications or sanitization.suspicious_patterns:
                    self._decision_logger.info(
                        {
                            "event": "tool_description_sanitized",
                            "tool_name": tool.name,
                            "modifications": sanitization.modifications,
                            "suspicious_patterns": sanitization.suspicious_patterns,
                            "original_length": sanitization.original_length,
                            "sanitized_length": len(sanitization.text),
                            "request_id": request_id,
                            "session_id": session_id,
                        }
                    )

                    if sanitization.suspicious_patterns:
                        self._system_logger.warning(
                            {
                                "event": "suspicious_tool_description",
                                "message": f"Tool '{tool.name}' description contains suspicious patterns",
                                "tool_name": tool.name,
                                "patterns": sanitization.suspicious_patterns,
                                "request_id": request_id,
                                "session_id": session_id,
                            }
                        )

            # Sanitize inputSchema property descriptions
            if tool.inputSchema:
                self._sanitize_input_schema(
                    tool.inputSchema,
                    tool.name,
                    request_id,
                    session_id,
                )

        return result
