"""Manager package for MCP-ACP proxy coordination.

Manager daemon serves UI and coordinates proxies.
- daemon.py: Manager daemon process (HTTP + UDS servers)
- registry.py: Proxy registry for tracking connected proxies
- client.py: Manager client for proxy-to-manager communication
- lifecycle.py: Manager daemon lifecycle utilities (availability check, auto-start)
- state.py: ProxyState for API exposure
- protocol.py: Shared NDJSON protocol utilities
- events.py: SSE event types
- models.py: Pydantic models for API responses
- pending.py: Pending approval request handling
- routes.py: FastAPI routes and HTTP helpers

Architecture:
    - Manager serves UI and routes API requests
    - Proxies register with manager via UDS
    - Manager aggregates SSE events from all proxies
    - Proxy still owns state (approvals, sessions)
"""

from __future__ import annotations

# Client (proxy side)
from .client import (
    ManagerClient,
)

# Lifecycle (manager auto-start)
from .lifecycle import (
    ensure_manager_running,
    is_manager_available,
)

# Config
from .config import (
    ManagerConfig,
    get_manager_config_path,
    get_manager_log_dir,
    get_manager_system_log_path,
    load_manager_config,
    save_manager_config,
)

# Daemon functions
from .daemon import (
    get_manager_pid,
    is_manager_running,
    run_manager,
    stop_manager,
)

# Registry (manager side)
from .registry import (
    ProxyConnection,
    ProxyRegistry,
    get_proxy_registry,
)

# Utilities
from .utils import (
    test_socket_connection,
    wait_for_condition,
)

# Events
from .events import (
    EventSeverity,
    SSEEventType,
)

# Models
from .models import (
    CachedApprovalSummary,
    PendingApprovalInfo,
    Proxy,
    ProxyRuntimeInfo,
    ProxyStats,
)

# Pending approvals
from .pending import PendingApprovalRequest

# State
from .state import (
    ProxyState,
    get_global_proxy_state,
    set_global_proxy_state,
)

__all__ = [
    # Client
    "ManagerClient",
    # Lifecycle
    "ensure_manager_running",
    "is_manager_available",
    # Config
    "ManagerConfig",
    "get_manager_config_path",
    "get_manager_log_dir",
    "get_manager_system_log_path",
    "load_manager_config",
    "save_manager_config",
    # Daemon
    "get_manager_pid",
    "is_manager_running",
    "run_manager",
    "stop_manager",
    # Registry
    "ProxyConnection",
    "ProxyRegistry",
    "get_proxy_registry",
    # Utils
    "test_socket_connection",
    "wait_for_condition",
    # Events
    "EventSeverity",
    "SSEEventType",
    # Models
    "CachedApprovalSummary",
    "PendingApprovalInfo",
    "Proxy",
    "ProxyRuntimeInfo",
    "ProxyStats",
    # Pending
    "PendingApprovalRequest",
    # State
    "ProxyState",
    "get_global_proxy_state",
    "set_global_proxy_state",
]
