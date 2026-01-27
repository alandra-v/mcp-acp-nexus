### Application Lifecycle [6002] Class and API Activity [6003] Class
Application Activity Category

The manager system log schema draws inspiration from two OCSF classes. From Application Lifecycle (6002), the schema adopts the concepts of service start/stop events and resource registration, capturing when the daemon starts, stops, and when proxies connect or disconnect. From API Activity (6003), it incorporates API request tracking including paths, status codes, and durations. Together, these influences provide a structured approach for representing manager daemon operations, while field names are simplified and adapted to the manager's operational context.

**Log file**: `<log_dir>/mcp-acp/manager/system.jsonl`

**Model**: `ManagerSystemEvent` in `manager/models.py`

**Level filter**: WARNING+ to file, INFO+ to console

Note: This schema uses standard Python logging (no hash chains). Additional fields beyond those listed may appear.

## Core
time — ISO 8601 timestamp (UTC), e.g.:
    "2025-01-21T10:30:00.123Z"
event — short machine-friendly event name, e.g.:
    "manager_started"
    "manager_stopped"
    "idle_shutdown_triggered"
    "proxy_connection_error"
    "registration_timeout"
    "snapshot_broadcast_failed"
message — human-readable summary, e.g.:
    "Manager started successfully"
    "Manager shutdown complete"
    "Proxy connection error: Connection refused"

## Proxy context
proxy_name — name of affected proxy, e.g.:
    "default"
    "secure-filesystem"
instance_id — unique proxy instance identifier
socket_path — UDS path for proxy communication

## API context (for routing events)
path — API request path, e.g.:
    "/api/config"
    "/api/approvals/pending"
status_code — HTTP response status code (for error responses)
duration_ms — request duration in milliseconds

## SSE context
subscriber_count — current number of SSE subscribers

## Error details
error_type — exception class name, e.g. "ConnectionRefusedError", "TimeoutError"
error_message — short error text from exception

## Idle shutdown context
proxy_count — number of connected proxies at shutdown check
sse_count — number of SSE subscribers (browser tabs)
seconds_idle — seconds since last activity

## Log levels by event

Daemon lifecycle (start/stop/shutdown) — INFO → console + file
Token service started — INFO → console + file
Browser opened — INFO → console + file
Stale socket/PID cleanup — INFO → console + file
Idle shutdown triggered — INFO → console + file
Registration errors — WARNING → console + file
Proxy connection errors — WARNING → console + file
Protocol errors (invalid JSON, unknown message) — WARNING → console + file
Snapshot broadcast failures — WARNING → console + file
Shutdown timeout — WARNING → console + file
File logging failures — WARNING → console + file
