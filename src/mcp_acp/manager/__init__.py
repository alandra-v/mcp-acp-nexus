"""Manager package for UI backend infrastructure.

Phase 3+: Manager daemon serves UI and coordinates proxies.
- daemon.py: Manager daemon process (HTTP + UDS servers)
- registry.py: Proxy registry for tracking connected proxies
- client.py: Manager client for proxy-to-manager communication
- state.py: ProxyState for API exposure

Architecture (Phase 3):
    - Manager serves UI and routes API requests
    - Proxies register with manager via UDS
    - Manager aggregates SSE events from all proxies
    - Proxy still owns state (approvals, sessions)

Architecture (Pre-Phase 3, current):
    - Proxy owns all state (approvals, sessions)
    - ProxyState aggregates state for API exposure
    - API routes live in api/routes/ (not here)
"""

from .client import (
    PROTOCOL_VERSION,
    ManagerClient,
    ManagerConnectionError,
    is_manager_available,
)
from .config import (
    ManagerConfig,
    get_manager_config_path,
    get_manager_log_dir,
    get_manager_system_log_path,
    load_manager_config,
    save_manager_config,
)
from .daemon import (
    get_manager_pid,
    is_manager_running,
    run_manager,
    stop_manager,
)
from .registry import (
    ProxyConnection,
    ProxyRegistry,
    get_proxy_registry,
)
from .state import (
    CachedApprovalSummary,
    PendingApprovalInfo,
    PendingApprovalRequest,
    ProxyInfo,
    ProxyState,
    get_global_proxy_state,
    set_global_proxy_state,
)

__all__ = [
    # Client (proxy side)
    "ManagerClient",
    "ManagerConnectionError",
    "PROTOCOL_VERSION",
    "is_manager_available",
    # Config
    "ManagerConfig",
    "get_manager_config_path",
    "get_manager_log_dir",
    "get_manager_system_log_path",
    "load_manager_config",
    "save_manager_config",
    # Daemon functions
    "get_manager_pid",
    "is_manager_running",
    "run_manager",
    "stop_manager",
    # Registry (manager side)
    "ProxyConnection",
    "ProxyRegistry",
    "get_proxy_registry",
    # State classes
    "CachedApprovalSummary",
    "PendingApprovalInfo",
    "PendingApprovalRequest",
    "ProxyInfo",
    "ProxyState",
    "get_global_proxy_state",
    "set_global_proxy_state",
]
