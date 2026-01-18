### Authentication events

The authentication log schema records Zero Trust authentication events for the proxy. Each entry captures token validation failures, session lifecycle events, and device health check failures. Based on OCSF Authentication (3002) and Authorize Session (3003) classes, adapted for MCP. By correlating each event with the session and identity, the auth log enables security auditing, compliance verification, and forensic analysis.

Note: Success events for per-request token validation and periodic device health checks are not logged to reduce noise. Only failures and session lifecycle events are logged for security auditing.

**Log file**: `logs/audit/auth.jsonl`

**Model**: `AuthEvent` in `telemetry/models/audit.py`

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
sequence — monotonically increasing entry number (added by HashChainFormatter)
prev_hash — SHA-256 hash of previous entry, or "GENESIS" for first entry
entry_hash — SHA-256 hash of this entry (for chain verification)
event_type — "token_invalid" | "token_refreshed" | "token_refresh_failed" | "session_started" | "session_ended" | "device_health_failed"
status — "Success" | "Failure"

## Session IDs (two different concepts)
bound_session_id — optional, security-bound session ID format "<user_id>:<session_uuid>" for auth binding
mcp_session_id — optional, plain MCP session UUID for correlation with operations/decisions/wire logs

## Correlation
request_id — optional, JSON-RPC request ID (for per-request token validation)

## Identity
subject — optional SubjectIdentity object (null if token couldn't be parsed):
  - subject_id: OIDC 'sub' claim
  - subject_claims: optional dict of selected safe claims (e.g. preferred_username, email)

## OIDC/OAuth details
oidc — optional OIDCInfo object:
  - issuer: OIDC 'iss' claim (e.g. "https://your-tenant.auth0.com")
  - provider: optional friendly name (e.g. "google", "auth0")
  - client_id: optional upstream client_id
  - audience: optional list of audiences
  - scopes: optional list of granted scopes
  - token_type: optional, "access" | "id" | "proxy"
  - token_exp: optional ISO 8601 expiration time
  - token_iat: optional ISO 8601 issued-at time
  - token_expired: optional boolean, whether token was expired at validation

## Device health (for device_health_failed events)
device_checks — optional DeviceHealthChecks object:
  - disk_encryption: "pass" | "fail" | "unknown" (FileVault on macOS)
  - device_integrity: "pass" | "fail" | "unknown" (SIP enabled on macOS)

Result meanings:
- pass: Check succeeded, device is compliant
- fail: Check succeeded, device is NOT compliant
- unknown: Could not determine status (treated as unhealthy for Zero Trust)

## Context
method — optional MCP method (for per-request validation)
message — optional human-readable status message

## Errors (for failure events)
error_type — optional error class name (e.g. "TokenExpiredError", "InvalidSignatureError")
error_message — optional detailed error message

## Session end (for session_ended event)
end_reason — optional, "normal" | "timeout" | "error" | "auth_expired" | "session_binding_violation"

## Extra details
details — optional dict of additional structured data
