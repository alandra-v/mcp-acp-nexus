"""Proxy server implementation using FastMCP and ProxyClient.

This module provides the core proxy functionality that forwards all MCP requests
from clients (via STDIO) to backend servers with bidirectional logging.

Supported backend transports:
- STDIO: Spawns backend server as a child process
- Streamable HTTP: Connects to an HTTP endpoint

This module is designed for programmatic use:
- Import create_proxy(config) to integrate into applications or CLI
- The CLI (cli.py) handles user interaction, startup messages, and error display

Security:
- Audit logs use fail-closed handlers that trigger shutdown if compromised
- Startup validation ensures audit logs are writable before accepting requests
"""

from __future__ import annotations

__all__ = [
    "create_proxy",
]

import asyncio
import os
import signal
import subprocess
import webbrowser
from contextlib import asynccontextmanager
from typing import AsyncIterator, Literal

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware

from mcp_acp.config import AppConfig
from mcp_acp.constants import (
    API_SERVER_POLL_INTERVAL_SECONDS,
    API_SERVER_SHUTDOWN_TIMEOUT_SECONDS,
    API_SERVER_STARTUP_TIMEOUT_SECONDS,
    AUDIT_HEALTH_CHECK_INTERVAL_SECONDS,
    DEFAULT_API_PORT,
    DEVICE_HEALTH_CHECK_INTERVAL_SECONDS,
    HTTP_SERVER_BACKLOG,
    PROTECTED_CONFIG_DIR,
    SKIP_DEVICE_HEALTH_CHECK,
    SOCKET_CONNECT_TIMEOUT_SECONDS,
)
from mcp_acp.exceptions import (
    AuditFailure,
    AuthenticationError,
    DeviceHealthError,
    SessionBindingViolationError,
)
from mcp_acp.manager import ManagerClient, ProxyState, ensure_manager_running, set_global_proxy_state
from mcp_acp.manager.config import get_proxy_policy_path
from mcp_acp.pep import create_context_middleware, create_enforcement_middleware, PolicyReloader
from mcp_acp.pips.auth import SessionManager
from mcp_acp.security import create_identity_provider, SessionRateTracker
from mcp_acp.security.posture import DeviceHealthMonitor, check_device_health
from mcp_acp.security.integrity import IntegrityStateManager
from mcp_acp.security.integrity.audit_handler import verify_audit_writable
from mcp_acp.security.integrity.audit_monitor import AuditHealthMonitor
from mcp_acp.security.shutdown import ShutdownCoordinator, sync_emergency_shutdown
from mcp_acp.telemetry.audit import create_audit_logging_middleware, create_auth_logger
from mcp_acp.telemetry.models.audit import SubjectIdentity
from mcp_acp.telemetry.debug.client_logger import (
    create_client_logging_middleware,
)
from mcp_acp.telemetry.debug.logging_proxy_client import (
    create_logging_proxy_client,
)
from mcp_acp.utils.logging.logging_context import get_session_id
from mcp_acp.telemetry.system.system_logger import (
    configure_system_logger_file,
    configure_system_logger_hash_chain,
    get_system_logger,
)
from mcp_acp.utils.history_logging.base import configure_history_logging_hash_chain
from mcp_acp.utils.config import (
    get_log_dir,
    get_log_path,
)
from mcp_acp.utils.policy import load_policy
from mcp_acp.utils.transport import create_backend_transport


def create_proxy(
    config: AppConfig,
    config_version: str | None = None,
    policy_version: str | None = None,
    enable_ui: bool = True,
    proxy_id: str | None = None,
) -> tuple[FastMCP, str]:
    """Create a transparent proxy that forwards all requests to backend.

    This function creates a FastMCP proxy server using ProxyClient to connect
    to a backend MCP server using the provided configuration.

    Transport selection (handled by create_backend_transport):
    - If config.backend.transport is "stdio" or "streamablehttp", use that transport
    - If config.backend.transport is "auto", auto-detect:
      - Prefer Streamable HTTP if configured and reachable
      - Fall back to STDIO if HTTP unavailable or not configured

    Logging:
    - Audit logs (ALWAYS enabled): <log_dir>/mcp-acp/proxies/default/audit/operations.jsonl
    - Decision logs (ALWAYS enabled): <log_dir>/mcp-acp/proxies/default/audit/decisions.jsonl
    - Debug wire logs (when log_level == "DEBUG"):
      - Client<->Proxy: <log_dir>/mcp-acp/proxies/default/debug/client_wire.jsonl
      - Proxy<->Backend: <log_dir>/mcp-acp/proxies/default/debug/backend_wire.jsonl
    - All logs include correlation IDs (request_id, session_id)
    - JSONL format with ISO 8601 timestamps

    Middleware order (outer to inner):
    - Context: Sets up request context (request_id, session_id, tool_context)
    - Audit: Logs all operations including denials
    - Client logging: Wire-level debugging
    - Enforcement: Policy evaluation and blocking (innermost)

    Security - Device Health Check:
    - Runs at startup as a hard gate - proxy won't start if device is unhealthy
    - Checks disk encryption (FileVault) and device integrity (SIP) on macOS
    - Zero Trust: device posture must be verified before accepting requests

    Security - Health Monitors (Background):
    - Audit Health Monitor: Runs every 30 seconds to verify audit log integrity
    - Device Health Monitor: Runs every 5 minutes to verify device posture
    - Both trigger fail-closed shutdown if checks fail
    - Started automatically when proxy starts via lifespan context manager
    - Defense in depth: catches issues during idle periods between requests

    Args:
        config: Application configuration (built from per-proxy config).
        config_version: Current config version from config history (e.g., "v1").
        policy_version: Current policy version from policy history (e.g., "v1").
        enable_ui: Whether to enable the web UI for HITL approvals. Defaults to True.
        proxy_id: Stable proxy identifier from config (e.g., "px_a1b2c3d4:server-name").
            Used for SSE event correlation with API data. If None, falls back to
            instance ID.

    Returns:
        Tuple of (FastMCP proxy instance, actual transport type used).
        Transport type is "stdio" or "streamablehttp".

    Raises:
        ValueError: If transport config is missing for selected transport.
        FileNotFoundError: If STDIO backend command is not found in PATH.
        PermissionError: If insufficient permissions to execute backend command.
        TimeoutError: If HTTP backend connection times out.
        ConnectionError: If HTTP backend is unreachable.
        RuntimeError: If backend server fails to start or initialize.
        AuditFailure: If audit logs cannot be written at startup.
        DeviceHealthError: If device health checks fail at startup.
    """
    # =========================================================================
    # PHASE 1: Startup Validation
    # Verify all prerequisites before accepting any requests (Zero Trust)
    # =========================================================================

    # Extract log path parameters for all log path functions
    proxy_name = config.proxy.name
    log_dir = config.logging.log_dir

    # Configure system logger file handler with user's log_dir
    configure_system_logger_file(get_log_path(proxy_name, "system", log_dir))

    # Validate audit logs are writable BEFORE starting
    # If this fails, we raise AuditFailure and don't start
    audit_path = get_log_path(proxy_name, "operations", log_dir)
    decisions_path = get_log_path(proxy_name, "decisions", log_dir)
    auth_log_path = get_log_path(proxy_name, "auth", log_dir)
    system_log_path = get_log_path(proxy_name, "system", log_dir)
    config_history_path = get_log_path(proxy_name, "config_history", log_dir)
    policy_history_path = get_log_path(proxy_name, "policy_history", log_dir)
    # Verify all monitored logs are writable - raises AuditFailure if not
    # This also creates the files if they don't exist (required for AuditHealthMonitor)
    # No popup here - start.py handles user-facing popups to avoid duplicates
    verify_audit_writable(audit_path)
    verify_audit_writable(decisions_path)
    verify_audit_writable(auth_log_path)
    verify_audit_writable(system_log_path)
    verify_audit_writable(config_history_path)
    verify_audit_writable(policy_history_path)

    # Create integrity state manager for tamper-evident hash chains
    # This must happen after verify_audit_writable (files exist) but before loggers are created
    log_dir_path = get_log_dir(proxy_name, log_dir)
    integrity_manager = IntegrityStateManager(log_dir_path)
    integrity_manager.load_state()

    # Configure hash chain on system logger (already has file handler from configure_system_logger_file)
    configure_system_logger_hash_chain(integrity_manager, log_dir_path)

    # Configure hash chain for history loggers (config_history.jsonl, policy_history.jsonl)
    configure_history_logging_hash_chain(integrity_manager, log_dir_path)

    # Get system logger early for use throughout startup
    system_logger = get_system_logger()

    # Verify hash chain integrity on startup (Zero Trust - hard fail if compromised)
    # This detects log tampering that occurred while proxy was stopped
    # auto_repair_on_crash=True allows automatic recovery from crash scenarios
    # where files were recreated during shutdown (inode mismatch)
    verification = integrity_manager.verify_on_startup(
        [
            audit_path,
            decisions_path,
            auth_log_path,
            system_log_path,
            config_history_path,
            policy_history_path,
        ],
        auto_repair_on_crash=True,
    )

    # Log any warnings (including auto-repair notifications)
    for warning in verification.warnings:
        system_logger.warning(
            {
                "event": "integrity_verification_warning",
                "message": warning,
                "action": "startup_verification",
                "auto_repair_enabled": True,
                "had_crash_breadcrumb": True,  # Warning only appears if crash was detected
            }
        )

    if not verification.success:
        # Aggregate all errors into a single message
        error_details = "; ".join(verification.errors)
        raise AuditFailure(f"Audit log integrity verification failed: {error_details}")

    # Run device health check (hard gate - proxy won't start if unhealthy)
    # Zero Trust: device posture must be verified before accepting any requests
    # Skip on non-macOS platforms where checks are unavailable
    if not SKIP_DEVICE_HEALTH_CHECK:
        device_health = check_device_health()
        if not device_health.is_healthy:
            # No popup here - start.py handles user-facing popups to avoid duplicates
            raise DeviceHealthError(str(device_health))

    # =========================================================================
    # Security Infrastructure
    # Create fail-closed shutdown system and background health monitors
    # =========================================================================

    # Create shutdown coordinator for fail-closed behavior
    # Note: log_dir_path and system_logger were already set above during integrity verification
    shutdown_coordinator = ShutdownCoordinator(log_dir_path, system_logger, proxy_name=proxy_name)

    # Create shutdown callback with hybrid approach:
    # Try async coordinator if event loop is running, fall back to sync
    def on_critical_failure(reason: str) -> None:
        """Handle critical security failure requiring shutdown.

        Detects failure type from reason string to set correct exit code and logging.
        """
        # Determine failure type from reason
        if "session binding" in reason.lower():
            failure_type = SessionBindingViolationError.failure_type
            exit_code = SessionBindingViolationError.exit_code
            source = "session_binding"
        else:
            # Default to audit failure for backwards compatibility
            failure_type = AuditFailure.failure_type
            exit_code = AuditFailure.exit_code
            source = "audit_handler"

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                shutdown_coordinator.initiate_shutdown(
                    failure_type=failure_type,
                    reason=reason,
                    exit_code=exit_code,
                    context={"source": source},
                )
            )
        except RuntimeError:
            # No event loop running - use sync fallback
            sync_emergency_shutdown(log_dir_path, failure_type, reason, exit_code=exit_code)

    # Create AuditHealthMonitor for background integrity checking
    # This runs periodic checks even during idle periods (defense in depth)
    # Monitors all audit and system log files for tampering/deletion
    audit_monitor = AuditHealthMonitor(
        audit_paths=[
            audit_path,  # audit/operations.jsonl
            decisions_path,  # audit/decisions.jsonl
            auth_log_path,  # audit/auth.jsonl
            system_log_path,  # system/system.jsonl
            config_history_path,  # system/config_history.jsonl
            policy_history_path,  # system/policy_history.jsonl
        ],
        shutdown_coordinator=shutdown_coordinator,
        check_interval_seconds=AUDIT_HEALTH_CHECK_INTERVAL_SECONDS,
        integrity_state_manager=integrity_manager,
        log_dir=log_dir_path,
    )

    # Create auth logger for authentication event audit trail
    # Pass integrity_manager for hash chain support on auth.jsonl
    auth_logger = create_auth_logger(
        auth_log_path,
        on_critical_failure,
        state_manager=integrity_manager,
        log_dir=log_dir_path,
        proxy_id=config.proxy.proxy_id,
        proxy_name=proxy_name,
    )

    # Wire auth logger to shutdown coordinator for session_ended logging on fatal errors
    # This ensures session end is logged even when os._exit() bypasses finally blocks
    shutdown_coordinator.set_auth_logger(auth_logger)

    # Create DeviceHealthMonitor for periodic device posture verification
    # Device state can change during operation (e.g., user disables SIP)
    # Skip on non-macOS platforms where checks are unavailable
    device_monitor: DeviceHealthMonitor | None = None
    if not SKIP_DEVICE_HEALTH_CHECK:
        device_monitor = DeviceHealthMonitor(
            shutdown_coordinator=shutdown_coordinator,
            auth_logger=auth_logger,
            check_interval_seconds=DEVICE_HEALTH_CHECK_INTERVAL_SECONDS,
        )

    # =========================================================================
    # PHASE 3: Backend Connection
    # Establish connection to backend MCP server and create proxy
    # =========================================================================

    # Create backend transport (handles detection, validation, health checks)
    # Pass mTLS config for client certificate authentication to HTTP backends
    # Note: mTLS is per-proxy config, not in manager's AuthConfig
    mtls_config = getattr(config.auth, "mtls", None) if config.auth else None
    transport, transport_type = create_backend_transport(config.backend, mtls_config)

    # Determine if debug wire logging is enabled
    debug_enabled = config.logging.log_level == "DEBUG"

    # Create LoggingProxyClient with transport (logs to backend_wire.jsonl)
    logging_backend_client = create_logging_proxy_client(
        transport,
        log_path=get_log_path(proxy_name, "backend_wire", log_dir),
        transport_type=transport_type,
        debug_enabled=debug_enabled,
    )

    # Create proxy with logging-wrapped backend client
    proxy = FastMCP.as_proxy(
        logging_backend_client,
        name=config.proxy.name,
    )

    # Create session manager for user-bound sessions
    # Sessions use format <user_id>:<session_id> per MCP spec
    session_manager = SessionManager()

    # Create rate tracker for detecting runaway LLM loops
    # Uses defaults: 30 calls/tool/minute triggers HITL dialog
    # Created here so lifespan can cleanup on shutdown
    rate_tracker = SessionRateTracker()

    # =========================================================================
    # PHASE 4: Lifecycle Management
    # Define proxy lifespan: start/stop monitors, manage sessions
    # =========================================================================

    @asynccontextmanager
    async def proxy_lifespan(app: FastMCP) -> AsyncIterator[None]:
        """Manage proxy lifecycle: start/stop health monitors, log session."""
        # Note: app parameter required by FastMCP's _lifespan_manager
        session_identity: SubjectIdentity | None = None
        bound_session_id: str | None = None
        end_reason: Literal["normal", "timeout", "error", "auth_expired", "session_binding_violation"] = (
            "normal"
        )
        sighup_registered: bool = False

        try:
            await audit_monitor.start()
            if device_monitor is not None:
                await device_monitor.start()
        except Exception as e:
            # Log failure and re-raise - Zero Trust requires monitoring
            system_logger.error(
                {
                    "event": "health_monitor_start_failed",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            raise

        # Validate identity and create user-bound session
        uds_server: uvicorn.Server | None = None
        http_server: uvicorn.Server | None = None
        api_task: asyncio.Task | None = None
        manager_client: ManagerClient | None = None
        try:
            session_identity = await identity_provider.get_identity()
            # Create session bound to user identity (format: <user_id>:<session_id>)
            # This prevents session hijacking across users per MCP spec
            bound_session = session_manager.create_session(session_identity)
            bound_session_id = bound_session.bound_id
            auth_logger.log_session_started(
                bound_session_id=bound_session_id,
                subject=session_identity,
            )

            # Store bound user ID for session binding validation on each request
            # This allows detecting if a different user tries to use the session
            from mcp_acp.utils.logging.logging_context import set_bound_user_id

            set_bound_user_id(session_identity.subject_id)

            # Store session info on shutdown coordinator for session_ended logging
            # This allows session_ended to be logged even on os._exit() shutdown
            # (stored directly, not ContextVars, to work across async tasks/threads)
            shutdown_coordinator.set_session_info(bound_session_id, session_identity)

            # Create policy reloader for SIGHUP handling (works with or without UI)
            # enforcement_middleware is captured from enclosing scope (created after lifespan definition)
            policy_reloader = PolicyReloader(
                middleware=enforcement_middleware,
                system_logger=system_logger,
                policy_path=get_proxy_policy_path(proxy_name),
                policy_history_path=get_log_path(proxy_name, "policy_history", log_dir),
                initial_version=policy_version,
            )
            # Wire proxy_state for SSE event emission
            policy_reloader.set_proxy_state(proxy_state)

            # ===================================================================
            # ALWAYS: UDS Socket Setup (needed for CLI access regardless of UI)
            # ===================================================================
            # Architecture:
            # - UDS server always starts for CLI access (mcp-acp status, policy reload, etc.)
            # - If manager is running: proxy skips HTTP server (manager serves UI on 8765)
            # - If manager not running AND enable_ui: proxy starts its own HTTP server on 8765
            # - HITL approvals fall back to osascript dialogs when UI is disabled

            # Lazy import to avoid circular import (proxy -> api -> cli -> proxy)
            import atexit
            import logging
            import socket as socket_module

            from mcp_acp.api.server import create_api_app
            from mcp_acp.constants import RUNTIME_DIR, get_proxy_socket_path

            # Get per-proxy socket path
            socket_path = get_proxy_socket_path(proxy_name)

            def is_port_in_use(port: int) -> bool:
                """Check if TCP port is accepting connections."""
                with socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM) as s:
                    return s.connect_ex(("127.0.0.1", port)) == 0

            def cleanup_stale_socket() -> None:
                """Remove stale socket file if exists and not connectable."""
                if not socket_path.exists():
                    return

                # Try to connect - if it fails, socket is stale
                try:
                    test_sock = socket_module.socket(socket_module.AF_UNIX)
                    test_sock.settimeout(SOCKET_CONNECT_TIMEOUT_SECONDS)
                    test_sock.connect(str(socket_path))
                    test_sock.close()
                    # Connected successfully - another instance running
                    raise RuntimeError(
                        f"Another proxy '{proxy_name}' is already running (socket: {socket_path})"
                    )
                except (ConnectionRefusedError, FileNotFoundError, OSError):
                    # Stale socket, remove it
                    socket_path.unlink(missing_ok=True)

            # Cleanup stale UDS socket from previous crash
            cleanup_stale_socket()

            # Create runtime directory with secure permissions
            try:
                RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            except OSError as e:
                system_logger.error(
                    {
                        "event": "uds_socket_creation_failed",
                        "message": f"Failed to create runtime directory: {e}",
                        "component": "proxy",
                        "path": str(RUNTIME_DIR),
                        "error": str(e),
                    }
                )
                raise

            # Suppress uvicorn's error logging during shutdown
            for logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
                logging.getLogger(logger_name).setLevel(logging.CRITICAL)

            # Always create UDS app for CLI access
            uds_app = create_api_app(token=None, is_uds=True, proxy_name=proxy_name)

            # UDS server for CLI (always runs, separate socket from manager)
            uds_config = uvicorn.Config(
                uds_app,
                uds=str(socket_path),
                log_config=None,
                ws="none",  # We use SSE, not WebSockets
            )
            uds_server = uvicorn.Server(uds_config)

            # ===================================================================
            # CONDITIONAL: HTTP Server Setup (only when UI is enabled)
            # ===================================================================
            # Type: socket.socket | None (can't use socket_module.socket in annotation)
            http_socket: "socket_module.socket | None" = None
            http_app = None  # Type inferred from create_api_app() return
            manager_serves_ui = False

            if enable_ui:
                from mcp_acp.api.security import generate_token
                from mcp_acp.manager import is_manager_available

                # Try to start manager FIRST (before binding to port 8765)
                # This ensures manager gets the port if it can start
                # If manager starts successfully, proxy will skip its own HTTP server
                ensure_manager_running()

                # Check if manager is now running (serves UI on port 8765)
                # If so, proxy skips its own HTTP server to avoid port conflict
                manager_serves_ui = is_manager_available()

                # HTTP server only if manager is NOT running
                if not manager_serves_ui:
                    # Generate API token (for browser HTTP only)
                    api_token = generate_token()
                    http_app = create_api_app(token=api_token, is_uds=False, proxy_name=proxy_name)

                    # HTTP server for browser
                    # Create socket with SO_REUSEADDR to avoid TIME_WAIT issues
                    http_socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
                    http_socket.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
                    try:
                        http_socket.bind(("127.0.0.1", DEFAULT_API_PORT))
                    except OSError as e:
                        import errno

                        if e.errno == errno.EADDRINUSE:
                            raise RuntimeError(
                                f"Port {DEFAULT_API_PORT} is already in use.\n"
                                f"Another process is using this port. "
                                f"Stop it or use --headless to disable the management UI."
                            ) from e
                        raise
                    http_socket.listen(HTTP_SERVER_BACKLOG)
                    http_socket.setblocking(False)

                    http_config = uvicorn.Config(
                        http_app,
                        fd=http_socket.fileno(),
                        log_config=None,
                        ws="none",  # We use SSE, not WebSockets
                    )
                    http_server = uvicorn.Server(http_config)
                else:
                    http_server = None
                    system_logger.info(
                        {
                            "event": "manager_serves_ui",
                            "message": "Manager already running, proxy skipping HTTP server",
                            "component": "proxy",
                        }
                    )
            else:
                http_server = None

            # ===================================================================
            # Run API Servers (UDS always, HTTP conditionally)
            # ===================================================================
            async def run_api_servers() -> None:
                """Run API servers concurrently.

                Uses uvicorn's _serve() to avoid signal handler conflicts.
                Gracefully handles CancelledError on shutdown.
                """
                try:
                    if http_server is not None:
                        await asyncio.gather(
                            uds_server._serve(),
                            http_server._serve(),
                        )
                    else:
                        # Only UDS server (manager serves HTTP or UI disabled)
                        await uds_server._serve()
                except asyncio.CancelledError:
                    pass  # Clean shutdown

            api_task = asyncio.create_task(run_api_servers())

            # Wait for servers to be ready
            if http_server is not None:
                # Poll until HTTP port accepts connections
                max_polls = int(API_SERVER_STARTUP_TIMEOUT_SECONDS / API_SERVER_POLL_INTERVAL_SECONDS)
                for _ in range(max_polls):
                    await asyncio.sleep(API_SERVER_POLL_INTERVAL_SECONDS)
                    if api_task.done():
                        exc = api_task.exception()
                        if exc:
                            system_logger.error(
                                {
                                    "event": "api_server_startup_failed",
                                    "message": f"API server failed to start: {exc}",
                                    "component": "proxy",
                                    "error": str(exc),
                                    "error_type": type(exc).__name__,
                                }
                            )
                            raise RuntimeError(f"HTTP server failed to start: {exc}") from exc
                    if is_port_in_use(DEFAULT_API_PORT):
                        break

                if not is_port_in_use(DEFAULT_API_PORT):
                    if api_task.done():
                        exc = api_task.exception()
                        if exc:
                            raise RuntimeError(f"HTTP server failed to start: {exc}") from exc
                    system_logger.error(
                        {
                            "event": "api_server_startup_timeout",
                            "message": f"HTTP server not listening after {API_SERVER_STARTUP_TIMEOUT_SECONDS}s",
                            "component": "proxy",
                            "port": DEFAULT_API_PORT,
                        }
                    )
                    raise RuntimeError(
                        f"HTTP server not listening on port {DEFAULT_API_PORT} "
                        f"after {API_SERVER_STARTUP_TIMEOUT_SECONDS}s"
                    )
            else:
                # Just wait briefly for UDS server to start
                await asyncio.sleep(API_SERVER_POLL_INTERVAL_SECONDS)

            # Set socket permissions after creation (0600 = owner read/write only)
            if socket_path.exists():
                socket_path.chmod(0o600)

            # Define socket cleanup function
            def cleanup_socket() -> None:
                """Remove UDS socket file on process exit."""
                try:
                    socket_path.unlink(missing_ok=True)
                except OSError as e:
                    system_logger.warning(
                        {
                            "event": "uds_socket_cleanup_failed",
                            "message": f"Failed to cleanup socket: {e}",
                            "component": "proxy",
                            "path": str(socket_path),
                            "error": str(e),
                        }
                    )

            atexit.register(cleanup_socket)

            # Wire shared state to apps (always UDS, conditionally HTTP)
            apps_to_wire = [uds_app]
            if http_app is not None:
                apps_to_wire.append(http_app)
            for api_app in apps_to_wire:
                api_app.state.policy_reloader = policy_reloader
                api_app.state.proxy_state = proxy_state
                api_app.state.identity_provider = identity_provider
                api_app.state.config = config
                api_app.state.approval_store = enforcement_middleware.approval_store

            # ===================================================================
            # CONDITIONAL: Browser Opening (only when UI is enabled)
            # ===================================================================
            if enable_ui:
                # Auto-open management UI in browser
                # If manager is running, it serves UI; otherwise proxy serves it
                ui_url = f"http://127.0.0.1:{DEFAULT_API_PORT}"
                if not manager_serves_ui:
                    try:
                        webbrowser.open(ui_url)
                    except Exception:
                        try:
                            subprocess.run(
                                [
                                    "osascript",
                                    "-e",
                                    f'display notification "{ui_url}" with title "MCP-ACP Extended" subtitle "Management UI ready"',
                                ],
                                check=False,
                                capture_output=True,
                            )
                        except Exception:
                            pass  # Non-fatal

            # ===================================================================
            # Manager Registration (only when UI enabled, skip in headless mode)
            # ===================================================================
            # Connect to manager for event aggregation and centralized UI.
            # In headless mode, proxy runs fully standalone without manager.
            if enable_ui:
                manager_client = ManagerClient(
                    proxy_name=proxy_name,
                    instance_id=proxy_state.proxy_id,
                    proxy_api_socket_path=str(socket_path),
                    proxy_id=config.proxy.proxy_id,
                )
                if await manager_client.connect():
                    config_summary = {
                        "backend_id": config.backend.server_name,
                        "transport": transport_type,
                        "api_port": DEFAULT_API_PORT if not manager_serves_ui else None,
                    }
                    if await manager_client.register(config_summary=config_summary):
                        proxy_state.set_manager_client(manager_client)
                        # Wire identity provider to receive manager token updates
                        if hasattr(identity_provider, "set_manager_client"):
                            identity_provider.set_manager_client(manager_client)
                        # Wire HITL handler for disconnect notifications
                        # This allows pending web UI approvals to fall back to osascript
                        manager_client.set_hitl_handler(enforcement_middleware.hitl_handler)
                    else:
                        system_logger.warning(
                            {
                                "event": "manager_registration_failed",
                                "message": "Failed to register with manager",
                            }
                        )

            # Setup SIGHUP handler for policy hot reload (Unix only)
            def handle_sighup() -> None:
                """Handle SIGHUP signal by scheduling policy reload."""
                asyncio.create_task(policy_reloader.reload())

            loop = asyncio.get_event_loop()
            try:
                loop.add_signal_handler(signal.SIGHUP, handle_sighup)
                sighup_registered = True
            except (ValueError, OSError, AttributeError):
                # Windows or signal not available in this context
                sighup_registered = False
                system_logger.warning(
                    {"event": "sighup_handler_not_available", "reason": "platform_unsupported"}
                )

        except AuthenticationError as e:
            # Auth failed at startup - log with placeholder (no user to bind to)
            import secrets

            auth_failed_id = f"auth_failed:{secrets.token_urlsafe(8)}"
            auth_logger.log_session_ended(
                bound_session_id=auth_failed_id,
                end_reason="auth_expired",
                error_type=type(e).__name__,
                error_message=str(e),
            )
            # No popup here - start.py handles user-facing popups
            # This avoids duplicate popups when called from CLI
            raise

        try:
            yield
        except AuthenticationError as e:
            end_reason = "auth_expired"
            system_logger.critical(
                {
                    "event": "auth_failed_during_session",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            # No popup - this happens during operation, not before start
            # Error is logged to system log and auth.jsonl
            raise
        except SessionBindingViolationError as e:
            end_reason = "session_binding_violation"
            system_logger.critical(
                {
                    "event": "session_binding_violation",
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "bound_user_id": bound_session_id.split(":")[0] if bound_session_id else None,
                    "message": "Identity changed mid-session - possible session hijacking attempt",
                }
            )
            # This is a critical security event - proxy must shutdown
            # CriticalSecurityFailure exceptions trigger process exit
            raise
        except Exception as e:
            end_reason = "error"
            system_logger.error(
                {
                    "event": "proxy_error",
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )
            raise
        finally:
            # Remove SIGHUP handler (before stopping API server)
            if sighup_registered:
                try:
                    loop = asyncio.get_event_loop()
                    loop.remove_signal_handler(signal.SIGHUP)
                except (ValueError, OSError, AttributeError):
                    pass  # Signal handler already removed or not available

            # Stop API servers (graceful shutdown)
            # Both UDS and HTTP servers share a single task via asyncio.gather
            if uds_server is not None or http_server is not None:
                if uds_server is not None:
                    uds_server.should_exit = True
                if http_server is not None:
                    http_server.should_exit = True

                if api_task is not None:
                    try:
                        await asyncio.wait_for(api_task, timeout=API_SERVER_SHUTDOWN_TIMEOUT_SECONDS)
                    except asyncio.TimeoutError:
                        api_task.cancel()
                    except asyncio.CancelledError:
                        pass

                # Only log on error shutdown, not on normal Ctrl+C
                if end_reason != "normal":
                    system_logger.warning(
                        {
                            "event": "api_servers_stopped",
                            "message": "API servers stopped (UDS and HTTP)",
                            "component": "proxy",
                            "end_reason": end_reason,
                        }
                    )

                # Note: UDS socket file cleanup is NOT done here because os._exit() in signal
                # handlers bypasses finally blocks. Stale socket detection at startup
                # (cleanup_stale_socket) handles orphaned UDS sockets instead.
                #
                # However, we DO close the HTTP socket here to release the port binding.
                # This helps avoid TIME_WAIT issues on graceful shutdown.
                # (If os._exit() is called, the OS will clean up the TCP socket anyway)
                if http_socket is not None:
                    try:
                        http_socket.close()
                    except (NameError, OSError):
                        pass  # Socket not created or already closed

            # Disconnect from manager (if connected)
            if manager_client is not None:
                proxy_state.set_manager_client(None)  # Stop event forwarding
                await manager_client.disconnect()

            if device_monitor is not None:
                await device_monitor.stop()
            await audit_monitor.stop()
            # Log session_ended with bound session ID and MCP session for correlation
            if bound_session_id:
                auth_logger.log_session_ended(
                    bound_session_id=bound_session_id,
                    mcp_session_id=get_session_id(),  # For correlation with operations/decisions
                    subject=session_identity,
                    end_reason=end_reason,
                )
                # Invalidate session in manager
                session_manager.invalidate_session(bound_session_id)
                # Clean up rate tracking data to prevent memory leak
                rate_tracker.clear()

            # Check if monitors crashed - if so, it's a fatal error
            # (Monitors trigger shutdown on crash via ShutdownCoordinator)
            if audit_monitor._crashed:
                system_logger.error(
                    {
                        "event": "audit_health_monitor_crash_detected",
                        "message": "Monitor crashed during shutdown check",
                    }
                )
            if device_monitor is not None and device_monitor._crashed:
                system_logger.error(
                    {
                        "event": "device_health_monitor_crash_detected",
                        "message": "Monitor crashed during shutdown check",
                    }
                )

    # Set the lifespan on the proxy (replaces default_lifespan)
    # NOTE: _lifespan is a private API. FastMCP may change this in future versions.
    # If FastMCP adds a public lifespan parameter to as_proxy() or Settings, migrate to that.
    # Tested with FastMCP 2.x - verify after upgrades.
    proxy._lifespan = proxy_lifespan

    # =========================================================================
    # PHASE 5: Identity Provider
    # Create authentication provider for Zero Trust identity verification
    # =========================================================================

    # Create identity provider (Zero Trust - auth is mandatory)
    # OIDCIdentityProvider validates JWT from keychain
    # Raises AuthenticationError if auth not configured (no fallback)
    # Note: transport="stdio" because clients connect via STDIO (Claude Desktop).
    # transport_type is the BACKEND transport, not client transport.
    # Future: When HTTP client transport is added, this will need updating.
    # create_identity_provider raises AuthenticationError if auth not configured
    # No popup here - start.py handles user-facing popups to avoid duplicates
    identity_provider = create_identity_provider(config, transport="stdio", auth_logger=auth_logger)

    # =========================================================================
    # PHASE 6: Middleware Chain
    # Register middleware in order: DoS → Context → Audit → Client → Enforcement
    # First-added = outermost (runs first on requests)
    # =========================================================================

    # DoS protection: FastMCP's rate limiter as outermost layer
    # Token bucket: 10 req/s sustained, 50 burst capacity
    # This catches request flooding before any processing
    #
    # NOTE: Both rate limiters (this + SessionRateTracker) are unidirectional
    # (client → proxy only). Backend → proxy notifications bypass middleware
    # via ProxyClient handlers. Risk is low since backend can only spam during
    # active requests, and a malicious backend is a larger threat than spam.
    dos_rate_limiter = RateLimitingMiddleware(
        max_requests_per_second=10.0,
        burst_capacity=50,
        global_limit=True,  # Single limit for STDIO proxy
    )
    proxy.add_middleware(dos_rate_limiter)

    # Register context middleware
    # Sets up request_id, session_id, and tool_context for all downstream middleware
    context_middleware = create_context_middleware()
    proxy.add_middleware(context_middleware)

    # Register audit logging middleware (ALWAYS enabled)
    # Logs single event per operation to audit/operations.jsonl
    # Uses fail-closed handler that triggers shutdown if log is compromised
    audit_middleware = create_audit_logging_middleware(
        log_path=audit_path,
        shutdown_coordinator=shutdown_coordinator,
        shutdown_callback=on_critical_failure,
        backend_id=config.backend.server_name,
        identity_provider=identity_provider,
        transport=transport_type,
        config_version=config_version,
        state_manager=integrity_manager,
        log_dir=log_dir_path,
        proxy_id=config.proxy.proxy_id,
        proxy_name=proxy_name,
    )
    proxy.add_middleware(audit_middleware)

    # Register client logging middleware (logs to client_wire.jsonl)
    #
    # Note: We intentionally don't use FastMCP's ErrorHandlingMiddleware here.
    # Backend MCP errors are already properly formatted and forwarded as-is.
    # Proxy-level errors (transport failures, internal errors) surface as raw
    # exceptions - this is acceptable since they're rare and the raw messages
    # provide useful diagnostic context. See docs/architecture.md for details.
    client_middleware = create_client_logging_middleware(
        log_path=get_log_path(proxy_name, "client_wire", log_dir),
        transport=transport_type,
        debug_enabled=debug_enabled,
        include_payloads=config.logging.include_payloads,
    )
    proxy.add_middleware(client_middleware)

    # Load policy and register enforcement middleware (innermost)
    # Evaluates policy and blocks denied requests before they reach the backend.
    # Contains per-tool rate tracking (SessionRateTracker) for runaway loop detection.
    # Logs every decision to audit/decisions.jsonl with fail-closed handler
    policy = load_policy(get_proxy_policy_path(proxy_name))

    # Build protected directories tuple (config dir + log dir)
    # These paths are protected from MCP tool access - built-in security
    # Use os.path.realpath() to resolve ALL symlinks for security
    # Protect the mcp-acp logs directory (parent of proxies/<name>)
    protected_dirs = (
        PROTECTED_CONFIG_DIR,
        os.path.realpath(log_dir_path.parent.parent),  # .../mcp-acp/
    )

    # rate_tracker created earlier (before lifespan) for cleanup access
    enforcement_middleware = create_enforcement_middleware(
        policy=policy,
        hitl_config=config.hitl,
        protected_dirs=protected_dirs,
        identity_provider=identity_provider,
        backend_id=config.backend.server_name,
        log_path=decisions_path,
        shutdown_callback=on_critical_failure,
        policy_version=policy_version,
        rate_tracker=rate_tracker,
        state_manager=integrity_manager,
        log_dir=log_dir_path,
        proxy_name=proxy_name,
        proxy_id=config.proxy.proxy_id,
    )
    proxy.add_middleware(enforcement_middleware)

    # Create ProxyState aggregating all state for UI exposure
    # Wraps ApprovalStore and SessionManager - proxy is source of truth
    # Compute mtls_enabled: True if HTTPS backend with mTLS config
    backend_url = config.backend.http.url if config.backend.http else None
    mtls_enabled = (
        mtls_config is not None and backend_url is not None and backend_url.lower().startswith("https://")
    )
    proxy_state = ProxyState(
        backend_id=config.backend.server_name,
        api_port=DEFAULT_API_PORT,
        approval_store=enforcement_middleware.approval_store,
        session_manager=session_manager,
        command=config.backend.stdio.command if config.backend.stdio else None,
        args=config.backend.stdio.args if config.backend.stdio else None,
        url=backend_url,
        backend_transport=transport_type,
        mtls_enabled=mtls_enabled,
        proxy_id=proxy_id,
    )

    # Set global proxy state for SSE emission from non-middleware code paths
    # (e.g., LoggingProxyClient connection failures that bypass middleware)
    set_global_proxy_state(proxy_state)

    # Wire proxy state to HITL handler for web UI integration
    # This allows HITL to check is_ui_connected and use web approvals
    enforcement_middleware.set_proxy_state(proxy_state)

    # Wire proxy state to shutdown coordinator for critical_shutdown SSE event
    shutdown_coordinator.set_proxy_state(proxy_state)

    # Wire proxy state to identity provider for auth SSE events
    # OIDCIdentityProvider emits token_refresh_failed, auth_login, auth_logout
    if hasattr(identity_provider, "set_proxy_state"):
        identity_provider.set_proxy_state(proxy_state)

    return proxy, transport_type
