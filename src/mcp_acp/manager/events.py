"""SSE event types for UI notifications.

This module defines all event types used for Server-Sent Events (SSE)
communication between the proxy/manager and the web UI.

Events are categorized by domain:
- pending_*: HITL approval lifecycle
- backend_*: Backend connection status
- tls_*: TLS/mTLS errors
- auth_*: Authentication events
- policy_*: Policy reload events
- rate_limit_*: Rate limiting events
- cache_*: Approval cache events
- request_*: Request processing events
- critical_*: Security-critical events (proxy shutdown)
"""

from __future__ import annotations

__all__ = [
    "EventSeverity",
    "SSEEventType",
]

from enum import Enum
from typing import Literal


class SSEEventType(str, Enum):
    """SSE event types for UI notifications.

    Events are grouped by domain:
    - pending_*: HITL approval lifecycle
    - backend_*: Backend connection status
    - tls_*: TLS/mTLS errors
    - auth_*: Authentication events
    - policy_*: Policy reload events
    - rate_limit_*: Rate limiting events
    - cache_*: Approval cache events
    - request_*: Request processing events
    - critical_*: Security-critical events (proxy shutdown)
    """

    # Existing HITL events
    SNAPSHOT = "snapshot"
    PENDING_CREATED = "pending_created"
    PENDING_RESOLVED = "pending_resolved"
    PENDING_TIMEOUT = "pending_timeout"
    PENDING_NOT_FOUND = "pending_not_found"

    # Backend connection
    BACKEND_CONNECTED = "backend_connected"
    BACKEND_RECONNECTED = "backend_reconnected"
    BACKEND_DISCONNECTED = "backend_disconnected"
    BACKEND_TIMEOUT = "backend_timeout"
    BACKEND_REFUSED = "backend_refused"

    # TLS/mTLS
    TLS_ERROR = "tls_error"
    MTLS_FAILED = "mtls_failed"
    CERT_VALIDATION_FAILED = "cert_validation_failed"

    # Authentication
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_SESSION_EXPIRING = "auth_session_expiring"
    TOKEN_REFRESH_FAILED = "token_refresh_failed"
    TOKEN_VALIDATION_FAILED = "token_validation_failed"
    AUTH_FAILURE = "auth_failure"

    # Policy
    POLICY_RELOADED = "policy_reloaded"
    POLICY_RELOAD_FAILED = "policy_reload_failed"
    POLICY_FILE_NOT_FOUND = "policy_file_not_found"
    POLICY_ROLLBACK = "policy_rollback"
    CONFIG_CHANGE_DETECTED = "config_change_detected"

    # Rate limiting
    RATE_LIMIT_TRIGGERED = "rate_limit_triggered"
    RATE_LIMIT_APPROVED = "rate_limit_approved"
    RATE_LIMIT_DENIED = "rate_limit_denied"

    # Cache
    CACHE_CLEARED = "cache_cleared"
    CACHE_ENTRY_DELETED = "cache_entry_deleted"
    CACHED_SNAPSHOT = "cached_snapshot"

    # Request processing
    REQUEST_ERROR = "request_error"
    HITL_PARSE_FAILED = "hitl_parse_failed"
    TOOL_SANITIZATION_FAILED = "tool_sanitization_failed"

    # Proxy lifecycle
    PROXY_DELETED = "proxy_deleted"

    # Live updates
    STATS_UPDATED = "stats_updated"
    NEW_LOG_ENTRIES = "new_log_entries"
    INCIDENTS_UPDATED = "incidents_updated"

    # Critical events (proxy shutdown)
    CRITICAL_SHUTDOWN = "critical_shutdown"
    AUDIT_INIT_FAILED = "audit_init_failed"
    DEVICE_HEALTH_FAILED = "device_health_failed"
    SESSION_HIJACKING = "session_hijacking"
    AUDIT_TAMPERING = "audit_tampering"
    AUDIT_MISSING = "audit_missing"
    AUDIT_PERMISSION_DENIED = "audit_permission_denied"
    HEALTH_DEGRADED = "health_degraded"
    HEALTH_MONITOR_FAILED = "health_monitor_failed"


# Severity type for toast styling in the web UI
EventSeverity = Literal["success", "warning", "error", "critical", "info"]
