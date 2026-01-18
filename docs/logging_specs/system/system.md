### Process Activity [1007] Class and Application Error [6008] Class
System Activity Category and Application Activity Category

The system log schema is designed using the OCSF Process Activity (1007) and Application Error (6008) classes as conceptual foundations. From Process Activity, the schema adopts the ideas of identifying the responsible component, capturing operational context (such as session, request, and backend identifiers), and describing the nature of the activity or failure. From Application Error, it incorporates structured error details including exception type, error message, and optional stack traces. Together, these influences provide a robust, standardized framing for representing operational issues in the MCP proxy, while field names and structure are simplified and adapted to the requirements of the Model Context Protocol domain.

**Log file**: `logs/system/system.jsonl`

**Model**: `SystemEvent` in `telemetry/models/system.py`

Note: This schema allows additional fields beyond those listed (extra = "allow").

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
sequence — monotonically increasing entry number (added by HashChainFormatter)
prev_hash — SHA-256 hash of previous entry, or "GENESIS" for first entry
entry_hash — SHA-256 hash of this entry (for chain verification)
level — "WARNING" | "ERROR" | "CRITICAL" (from logging level)
event — short machine-friendly event name, e.g.:
    "proxy_start_failed"
    "backend_unreachable"
    "config_reload_failed"
    "audit_write_failed"
message — optional, human-readable summary, e.g.:
    "Failed to connect to backend secure-filesystem-server after 3 retries"

## Component / context
component — optional, where it happened, e.g.:
    "proxy"
    "backend_client"
    "policy_engine"
    "logger"
session_id — optional, if this problem is tied to a specific MCP session
request_id — optional, if tied to a specific MCP operation
backend_id — optional, if relevant (e.g. backend unreachable)
config_version — optional, if the issue is config-related or you know current version

## Error details (for ERROR/CRITICAL especially)
error_type — optional exception class name, e.g. "TimeoutError", "JSONDecodeError"
error_message — optional short error text (from exception)
stacktrace — optional stringified traceback (only if you want to log it)

## Extra payload
details — optional dict for any extra structured stuff:
    {"retry_count": 3, "timeout_ms": 5000}
    {"failed_fields": ["policy_id"]}
