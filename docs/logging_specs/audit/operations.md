### API Activity [6003] Class
Application Activity Category

The schema follows the same conceptual structure as OCSF API Activity (actor, action, resource, outcome, time, duration) but uses a project-specific field naming.

**Log file**: `logs/audit/operations.jsonl`

**Model**: `OperationEvent` in `telemetry/models/audit.py`

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
sequence — monotonically increasing entry number (added by HashChainFormatter)
prev_hash — SHA-256 hash of previous entry, or "GENESIS" for first entry
entry_hash — SHA-256 hash of this entry (for chain verification)
session_id — ID of the MCP session
request_id — per-MCP operation ID (JSON-RPC id)
method — MCP method, e.g. "tools/call", "tools/list", "resources/read", etc.
status — "Success" | "Failure"
error_code — optional, MCP/JSON-RPC error code (e.g., -32700, -32603) on failure
message — optional, short human-readable description

## Identity
subject — SubjectIdentity object (required):
  - subject_id: OIDC 'sub' claim
  - subject_claims: optional dict of selected safe claims (e.g. preferred_username, email)

## Client/Backend
client_id — optional, MCP client application name (from clientInfo.name)
backend_id — internal ID of the MCP backend / server
transport — optional, "stdio" or "streamablehttp"

## MCP operation details
tool_name — optional, only set if method == "tools/call" (e.g. "read_file")
file_path — optional, file path from request arguments
file_extension — optional, file extension (e.g. ".py", ".txt")
source_path — optional, source path for copy/move operations
dest_path — optional, destination path for copy/move operations
arguments_summary — optional ArgumentsSummary object:
  - redacted: bool (true, full args not logged)
  - body_hash: optional SHA256 hex hash of the args
  - payload_length: optional size in bytes of the request payload

## Response metadata
response_summary — optional ResponseSummary object:
  - size_bytes: response payload size in bytes
  - body_hash: SHA256 hash of response payload

## Config
config_version — optional, version string from loaded config

## Duration
duration — DurationInfo object (required):
  - duration_ms: total operation duration in milliseconds (float)
