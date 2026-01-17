"""Environment model - contextual information about the request.

All fields are facts observable by the proxy at request time.
"""

from __future__ import annotations

__all__ = ["Environment"]

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class Environment(BaseModel):
    """Contextual information about the request.

    All fields are facts observable by the proxy.

    Attributes:
        timestamp: UTC timestamp when context was built
        request_id: Request correlation ID
        session_id: FastMCP session identifier
        mcp_client_name: Client application name (from initialize)
        mcp_client_version: Client version (from initialize)
        proxy_instance: Proxy instance ID (for multi-instance deployments)
    """

    # Time
    timestamp: datetime

    # Request correlation
    request_id: str
    session_id: str

    # MCP client info (from initialize request)
    mcp_client_name: str | None = None
    mcp_client_version: str | None = None

    # Proxy info (for multi-instance deployments)
    proxy_instance: str | None = None

    model_config = ConfigDict(frozen=True)
