"""Manager daemon for serving UI and coordinating proxies.

The manager daemon:
- Serves the web UI (React app) on HTTP port 8765
- Listens on UDS (manager.sock) for proxy registrations
- Aggregates SSE events from all proxies
- Routes API requests to proxies

Lifecycle:
- Started via `mcp-acp manager start` or auto-started by proxy
- Runs as a daemon (survives parent process exit)
- Stopped via `mcp-acp manager stop` or SIGTERM
"""

from __future__ import annotations

from .lifecycle import get_manager_pid, is_manager_running, stop_manager
from .server import run_manager

__all__ = [
    "get_manager_pid",
    "is_manager_running",
    "run_manager",
    "stop_manager",
]
