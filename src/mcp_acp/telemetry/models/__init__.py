"""Pydantic models for all telemetry logs (audit, system, and wire debug logs)."""

from mcp_acp.telemetry.models.audit import (
    AuthEvent,
    DeviceHealthChecks,
    OperationEvent,
    SubjectIdentity,
)
from mcp_acp.telemetry.models.system import ConfigHistoryEvent, SystemEvent
from mcp_acp.telemetry.models.wire import (
    BackendErrorEvent,
    BackendResponseEvent,
    ClientRequestEvent,
    ProxyErrorEvent,
    ProxyRequestEvent,
    ProxyResponseEvent,
)

__all__ = [
    # Audit models
    "AuthEvent",
    "DeviceHealthChecks",
    "OperationEvent",
    "SubjectIdentity",
    # System models
    "ConfigHistoryEvent",
    "SystemEvent",
    # Wire/debug models
    "ClientRequestEvent",
    "ProxyResponseEvent",
    "ProxyErrorEvent",
    "ProxyRequestEvent",
    "BackendResponseEvent",
    "BackendErrorEvent",
]
