"""Application-wide constants for mcp-acp.

Constants that define application behavior.
For user-configurable settings per deployment, see config.py.
"""

import os

__all__ = [
    # Application identity
    "APP_NAME",
    # Protected directories
    "PROTECTED_CONFIG_DIR",
    # Transport configuration
    "TRANSPORT_TYPES",
    "TRANSPORT_TYPE_FROM_INDEX",
    "TRANSPORT_TYPE_TO_INDEX",
    "DEFAULT_HTTP_TIMEOUT_SECONDS",
    "MIN_HTTP_TIMEOUT_SECONDS",
    "MAX_HTTP_TIMEOUT_SECONDS",
    "HEALTH_CHECK_TIMEOUT_SECONDS",
    "BACKEND_RETRY_MAX_ATTEMPTS",
    "BACKEND_RETRY_INITIAL_DELAY",
    "BACKEND_RETRY_BACKOFF_MULTIPLIER",
    # mTLS certificate monitoring
    "CERT_EXPIRY_WARNING_DAYS",
    "CERT_EXPIRY_CRITICAL_DAYS",
    # Audit log integrity monitoring
    "AUDIT_HEALTH_CHECK_INTERVAL_SECONDS",
    "DEVICE_HEALTH_CHECK_INTERVAL_SECONDS",
    "DEFAULT_DEVICE_FAILURE_THRESHOLD",
    "SKIP_DEVICE_HEALTH_CHECK",
    # OAuth device flow
    "OAUTH_CLIENT_TIMEOUT_SECONDS",
    "DEVICE_FLOW_POLL_INTERVAL_SECONDS",
    "DEVICE_FLOW_TIMEOUT_SECONDS",
    # Authentication
    "JWKS_CACHE_TTL_SECONDS",
    # Backend transport errors
    "BASE_TRANSPORT_ERRORS",
    "TRANSPORT_ERRORS",
    # HITL configuration
    "DEFAULT_HITL_TIMEOUT_SECONDS",
    "MIN_HITL_TIMEOUT_SECONDS",
    "MAX_HITL_TIMEOUT_SECONDS",
    # Approval caching
    "DEFAULT_APPROVAL_TTL_SECONDS",
    "MIN_APPROVAL_TTL_SECONDS",
    "MAX_APPROVAL_TTL_SECONDS",
    # File metadata extraction
    "PATH_ARGUMENT_NAMES",
    "SOURCE_PATH_ARGS",
    "DEST_PATH_ARGS",
    # MCP method classification
    "DISCOVERY_METHODS",
    # Management API server
    "DEFAULT_API_PORT",
    "SOCKET_CONNECT_TIMEOUT_SECONDS",
    "API_SERVER_STARTUP_TIMEOUT_SECONDS",
    "API_SERVER_POLL_INTERVAL_SECONDS",
    "API_SERVER_SHUTDOWN_TIMEOUT_SECONDS",
    "HTTP_SERVER_BACKLOG",
    "CLI_NOTIFICATION_TIMEOUT_SECONDS",
    "CLI_POLICY_RELOAD_TIMEOUT_SECONDS",
    # Runtime directory (UDS socket)
    "RUNTIME_DIR",
    "SOCKET_PATH",
    # Manager daemon
    "MANAGER_SOCKET_PATH",
    "MANAGER_PID_PATH",
    "MANAGER_LOCK_PATH",
    "get_proxy_socket_path",
    # History versioning
    "INITIAL_VERSION",
    # Crash recovery
    "CRASH_BREADCRUMB_FILENAME",
]

from pathlib import Path

from platformdirs import user_config_dir, user_runtime_dir

# ============================================================================
# Application Identity
# ============================================================================

# Application name used for directory names, service names, etc.
APP_NAME: str = "mcp-acp"

# ============================================================================
# Protected Configuration Directory (Built-in Security)
# ============================================================================

# OS-specific config directory that MCP tools CANNOT access.
# This is a built-in protection that cannot be overridden by user policy.
# Prevents MCP tools from modifying policy, config, or audit logs.
#
# Platform-specific paths:
# - macOS: ~/Library/Application Support/mcp-acp/
# - Linux: ~/.config/mcp-acp/
# - Windows: %APPDATA%\mcp-acp\
#
# Note: Resolved with os.path.realpath() to prevent symlink bypass.
PROTECTED_CONFIG_DIR: str = os.path.realpath(user_config_dir(APP_NAME))

# ============================================================================
# Transport Configuration
# ============================================================================

# Transport types for CLI and config
# - stdio: Spawn local process (npx, uvx, python)
# - http: Connect to remote HTTP/SSE server (stored as "streamablehttp" in config)
# - auto: Try HTTP first, fall back to STDIO
TRANSPORT_TYPES: tuple[str, ...] = ("stdio", "http", "auto")

# Index-to-type mapping for CLI menus (allows numeric shortcuts)
TRANSPORT_TYPE_FROM_INDEX: dict[str, str] = {"0": "stdio", "1": "http", "2": "auto"}
TRANSPORT_TYPE_TO_INDEX: dict[str, str] = {"stdio": "0", "http": "1", "auto": "2"}

# Default HTTP connection timeout (seconds)
# Used as default in HttpTransportConfig and CLI when user doesn't specify
DEFAULT_HTTP_TIMEOUT_SECONDS: int = 30

# Timeout validation range (seconds)
MIN_HTTP_TIMEOUT_SECONDS: int = 1
MAX_HTTP_TIMEOUT_SECONDS: int = 300  # 5 minutes

# Maximum timeout for HTTP health checks (seconds)
# Health checks use min(user_timeout, HEALTH_CHECK_TIMEOUT_SECONDS) to stay fast
HEALTH_CHECK_TIMEOUT_SECONDS: float = 10.0

# Backend connection retry configuration (startup only)
# When HTTP backend is not immediately available, retry with exponential backoff
# 3 attempts: immediate → wait 2s → retry → wait 4s → retry → fail (~6s total)
BACKEND_RETRY_MAX_ATTEMPTS: int = 3  # Maximum connection attempts
BACKEND_RETRY_INITIAL_DELAY: float = 2.0  # Initial delay between retries (seconds)
BACKEND_RETRY_BACKOFF_MULTIPLIER: float = 2.0  # Exponential backoff multiplier

# ============================================================================
# mTLS Certificate Monitoring
# ============================================================================

# Certificate expiry warning thresholds (days)
# Used by transport.py to warn operators about expiring certificates
CERT_EXPIRY_WARNING_DAYS: int = 14  # Warning if expires within 14 days
CERT_EXPIRY_CRITICAL_DAYS: int = 7  # Critical warning if expires within 7 days

# ============================================================================
# Audit Log Integrity Monitoring
# ============================================================================

# How often the background AuditHealthMonitor checks audit log integrity (seconds)
# This catches tampering during idle periods between requests (defense in depth)
AUDIT_HEALTH_CHECK_INTERVAL_SECONDS: float = 30.0

# How often the background DeviceHealthMonitor checks device posture (seconds)
# Device state can change during operation (e.g., user disables SIP)
# 5 minutes balances responsiveness with minimal overhead
DEVICE_HEALTH_CHECK_INTERVAL_SECONDS: float = 300.0

# Fail immediately on first health check failure (Zero Trust - fail fast)
# Transient issues are rare for device posture (FileVault/SIP don't flap)
DEFAULT_DEVICE_FAILURE_THRESHOLD: int = 1

# Skip device health checks (FileVault/SIP verification)
# Set to True on Linux/Windows where these macOS-specific checks are unavailable.
# WARNING: Disabling this reduces Zero Trust compliance - use only on non-macOS.
SKIP_DEVICE_HEALTH_CHECK: bool = False

# ============================================================================
# OAuth Device Flow (RFC 8628)
# ============================================================================

# Timeout for OAuth HTTP requests (device code, token polling, refresh)
# Used by device_flow.py and token_refresh.py
OAUTH_CLIENT_TIMEOUT_SECONDS: int = 30

# Default polling interval for device flow (seconds)
# Auth0 typically returns 5 in the device code response
DEVICE_FLOW_POLL_INTERVAL_SECONDS: int = 5

# Maximum time to wait for user to complete device flow authentication (seconds)
# 5 minutes is standard for device flows
DEVICE_FLOW_TIMEOUT_SECONDS: int = 300

# ============================================================================
# Authentication
# ============================================================================

# JWKS (JSON Web Key Set) cache TTL (seconds)
# Shorter TTL reduces window for revoked key acceptance while still avoiding
# excessive requests to the JWKS endpoint (10 minutes)
# Note: Identity is validated per-request (true Zero Trust, no caching)
JWKS_CACHE_TTL_SECONDS: int = 600

# ============================================================================
# Backend Transport Error Detection
# ============================================================================

# Base transport errors for detecting backend disconnection (STDIO-focused)
BASE_TRANSPORT_ERRORS: tuple[type[Exception], ...] = (
    BrokenPipeError,
    EOFError,
    ConnectionError,
    ConnectionResetError,
    ConnectionAbortedError,
)

# HTTP transport errors (httpx) - added at runtime if httpx is available
# These are combined with BASE_TRANSPORT_ERRORS into TRANSPORT_ERRORS
# See: _build_transport_errors() below


def _build_transport_errors() -> tuple[type[Exception], ...]:
    """Build complete tuple of transport error types including httpx if available.

    Returns:
        Tuple of exception types that indicate transport/connection failures.
    """
    errors: list[type[Exception]] = list(BASE_TRANSPORT_ERRORS)

    # Add HTTP transport errors (httpx) if available
    # httpx is a dependency of fastmcp's StreamableHttpTransport
    try:
        import httpx

        # Use base classes to catch all subclasses:
        # - NetworkError: ConnectError, CloseError, ReadError, WriteError
        # - TimeoutException: ConnectTimeout, ReadTimeout, WriteTimeout, PoolTimeout
        # - ProtocolError: RemoteProtocolError, LocalProtocolError
        errors.extend(
            [
                httpx.NetworkError,
                httpx.TimeoutException,
                httpx.ProtocolError,
            ]
        )
    except ImportError:
        pass  # httpx not available, HTTP errors won't be detected by type

    return tuple(errors)


# Complete tuple of transport error types (includes httpx if available)
TRANSPORT_ERRORS: tuple[type[Exception], ...] = _build_transport_errors()

# ============================================================================
# HITL (Human-in-the-Loop) Configuration
# ============================================================================

# Default HITL dialog timeout (seconds)
# How long to wait for user to respond before auto-denying
#
# IMPORTANT: Client Timeout Considerations
# ----------------------------------------
# MCP clients (like Claude Desktop, custom integrations) have their own
# request timeouts. If the client timeout is shorter than the HITL timeout,
# the client will timeout before the user can respond, causing the request
# to fail even if the user later approves.
#
# Recommendations:
# 1. HITL timeout should be LESS than client request timeout
# 2. If using HITL with long timeouts, configure clients with longer timeouts
# 3. Consider DEFAULT_HTTP_TIMEOUT_SECONDS (30s) when setting HITL timeout
#
# Example conflict scenarios:
# - Client timeout: 30s, HITL timeout: 30s → Client times out during approval
# - Client timeout: 60s, HITL timeout: 30s → Safe, 30s buffer for user response
#
DEFAULT_HITL_TIMEOUT_SECONDS: int = 60

# HITL timeout validation range (seconds)
MIN_HITL_TIMEOUT_SECONDS: int = 5  # Minimum time for user to read and respond
MAX_HITL_TIMEOUT_SECONDS: int = 300  # 5 minutes max

# ============================================================================
# Approval Caching (HITL Fatigue Reduction)
# ============================================================================

# Default TTL for cached HITL approvals (seconds)
# After approval, user won't see dialog for same operation until TTL expires
DEFAULT_APPROVAL_TTL_SECONDS: int = 600  # 10 minutes

# Approval TTL validation range (seconds)
MIN_APPROVAL_TTL_SECONDS: int = 300  # 5 minutes minimum
MAX_APPROVAL_TTL_SECONDS: int = 900  # 15 minutes maximum

# ============================================================================
# File Metadata Extraction
# ============================================================================

# Common path-related argument names to check when extracting file paths
# Used by context/context.py and utils/logging/extractors.py
PATH_ARGUMENT_NAMES: tuple[str, ...] = (
    "path",
    "uri",
    "file_path",
    "filepath",
    "file",
    "filename",
)

# Source path argument names (for move/copy operations)
# Matched by tools like move_file(source, destination), copy_path(source, destination)
SOURCE_PATH_ARGS: tuple[str, ...] = (
    "source",
    "src",
    "from",
    "from_path",
    "source_path",
    "origin",
)

# Destination path argument names (for move/copy operations)
DEST_PATH_ARGS: tuple[str, ...] = (
    "destination",
    "destination_path",
    "dest",
    "to",
    "to_path",
    "dest_path",
    "target",
    "target_path",
)

# ============================================================================
# MCP Method Classification
# ============================================================================

# Discovery methods - metadata/listing operations that don't modify state
# These are allowed by default without explicit policy rules
# Category: DISCOVERY (vs ACTION which requires policy evaluation)
#
# NOTE: prompts/get is NOT included because it returns prompt content
# which could contain sensitive information. It requires policy evaluation.
DISCOVERY_METHODS: frozenset[str] = frozenset(
    {
        "initialize",
        "ping",
        "tools/list",
        "resources/list",
        "resources/templates/list",
        "prompts/list",
        # "prompts/get" - EXCLUDED: returns content, needs policy evaluation
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
    }
)

# ============================================================================
# Management API Server
# ============================================================================

# Default port for the management API server (serves UI and /api endpoints)
# Runs inside the proxy process to share memory (sessions, approval cache)
DEFAULT_API_PORT: int = 8765

# Timeout for stale socket connection test (seconds)
# Used when checking if another proxy instance is running
SOCKET_CONNECT_TIMEOUT_SECONDS: float = 1.0

# Timeout for API servers to become ready (seconds)
# Proxy waits for HTTP port to accept connections before continuing
API_SERVER_STARTUP_TIMEOUT_SECONDS: float = 2.0

# Poll interval when waiting for API server to start (seconds)
API_SERVER_POLL_INTERVAL_SECONDS: float = 0.1

# Timeout for graceful API server shutdown (seconds)
# After this, task is cancelled
API_SERVER_SHUTDOWN_TIMEOUT_SECONDS: float = 5.0

# Socket listen backlog for HTTP server
# Number of unaccepted connections before refusing new ones
HTTP_SERVER_BACKLOG: int = 100

# Timeout for CLI proxy notifications (seconds)
# Used for quick health checks (login/logout/reload notifications)
CLI_NOTIFICATION_TIMEOUT_SECONDS: float = 5.0

# Timeout for policy reload command (seconds)
# Longer than notifications because it reads and validates policy file
CLI_POLICY_RELOAD_TIMEOUT_SECONDS: float = 10.0

# ============================================================================
# Runtime Directory (Unix Domain Socket)
# ============================================================================

# Runtime directory for ephemeral files (sockets)
# Platform-specific:
#   - macOS: ~/Library/Caches/TemporaryItems/mcp-acp/
#   - Linux: $XDG_RUNTIME_DIR/mcp-acp/ (auto-cleaned on logout)
#
# Note: This implementation is macOS-only. Linux support can be added later.
RUNTIME_DIR: Path = Path(user_runtime_dir(APP_NAME))

# Unix Domain Socket for CLI communication
# OS file permissions provide authentication (no token needed)
# CLI connects via UDS, browser uses HTTP with token
SOCKET_PATH: Path = RUNTIME_DIR / "api.sock"

# Manager daemon paths
# Manager serves UI and aggregates proxy state
MANAGER_SOCKET_PATH: Path = RUNTIME_DIR / "manager.sock"
MANAGER_PID_PATH: Path = RUNTIME_DIR / "manager.pid"
MANAGER_LOCK_PATH: Path = RUNTIME_DIR / "manager.lock"


def get_proxy_socket_path(name: str) -> Path:
    """Get socket path for a specific proxy.

    Args:
        name: Proxy name.

    Returns:
        Path to proxy's socket (<runtime_dir>/proxy_{name}.sock).
    """
    return RUNTIME_DIR / f"proxy_{name}.sock"


# ============================================================================
# History Versioning
# ============================================================================

# Initial version for new history files
INITIAL_VERSION = "v1"

# ============================================================================
# Crash Recovery
# ============================================================================

# Breadcrumb file written by ShutdownCoordinator on crash/security failure
# Contains timestamp, failure_type, exit_code, reason, and context
# Used by:
# - IntegrityStateManager: detect recent crash for auto-repair
# - UI incidents page: show crash history to user
# - Startup popup: alert user to recent crash
CRASH_BREADCRUMB_FILENAME = ".last_crash"
