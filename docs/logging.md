# Logging

## Primary Goals

Logging supports the Zero Trust security model with three primary goals:

1. **Audit trail**: Complete record of who accessed what, when, and with what outcome
2. **Policy enforcement monitoring**: Every policy decision is logged for compliance and debugging
3. **Incident response & forensics**: Sufficient detail to reconstruct events during security investigations

**Fail-closed on log failure**: If audit logging fails (e.g., disk full, file deleted), the proxy shuts down rather than operate without an audit trail. This is a core Zero Trust requirement. See [Security](security.md) for details on audit log integrity protection.

---

## Log Structure

```
<log_dir>/mcp_acp_logs/
├── audit/                        # Security audit logs (ALWAYS enabled)
│   ├── operations.jsonl          # MCP operation audit trail
│   ├── decisions.jsonl           # Policy evaluation decisions + HITL outcomes
│   └── auth.jsonl                # Authentication events
├── debug/                        # Wire-level debug logs (DEBUG level only)
│   ├── client_wire.jsonl         # Client ↔ Proxy communication
│   └── backend_wire.jsonl        # Proxy ↔ Backend communication
└── system/                       # System/operational events
    ├── system.jsonl              # Operational logs, errors, backend disconnections
    ├── config_history.jsonl      # Configuration changes (versioned)
    └── policy_history.jsonl      # Policy changes (versioned)

<config_dir>/emergency_audit.jsonl  # Fallback when primary audit fails
<config_dir>/bootstrap.jsonl        # Startup validation errors
<log_dir>/.last_crash               # Breadcrumb for crash popup
<log_dir>/shutdowns.jsonl           # Security shutdown history
```

---

## Configuration

Log directory is specified via `--log-dir` during `mcp-acp init` (recommended: `~/.mcp-acp`).

**Log level options:**
- `info` (default): Audit and system logs only
- `debug`: Enables wire-level debug logs with full request/response payloads

See [Configuration](configuration.md) for full CLI options.

---

## Audit Logs (`audit/`)

Security audit trail - **ALWAYS enabled, cannot be disabled**.

### operations.jsonl

MCP operation audit trail following the **Kipling method (5W1H)**: Who (subject), What (method, tool), When (timestamp), Where (backend, path), Why (policy decision), How (arguments, transport).

**See**: [logging_specs/audit/operations.md](logging_specs/audit/operations.md) for full schema.

### decisions.jsonl

Every policy evaluation decision, including HITL outcomes. Captures matched rules, final decision, performance metrics, and approval details.

**See**: [logging_specs/audit/decisions.md](logging_specs/audit/decisions.md) for full schema.

### auth.jsonl

Authentication events for Zero Trust compliance. Based on OCSF Authentication (3002) and Authorize Session (3003) classes.

**Note**: Success events for per-request token validation and device health checks are not logged to reduce noise. Only failures and session lifecycle events are logged.

**See**: [logging_specs/audit/auth.md](logging_specs/audit/auth.md) for full schema.

---

## Debug Logs (`debug/`)

Wire-level MCP communication with full request/response payloads.

**Only enabled when `log_level=debug`** - disabled by default for privacy.

- `client_wire.jsonl`: Client ↔ Proxy communication
- `backend_wire.jsonl`: Proxy ↔ Backend communication

Event types: `client_request`, `proxy_response`, `proxy_error`, `proxy_request`, `backend_response`, `backend_error`

---

## System Logs (`system/`)

Operational system events - **only WARNING, ERROR, CRITICAL levels are logged to file**.

### system.jsonl

Operational issues and errors (backend disconnections, path normalization failures, etc.).

**See**: [logging_specs/system/system.md](logging_specs/system/system.md) for full schema.

### config_history.jsonl

Configuration change audit trail with versioning and checksums.

**See**: [logging_specs/system/config_history.md](logging_specs/system/config_history.md) for full schema.

### policy_history.jsonl

Policy change audit trail with versioning and checksums.

**See**: [logging_specs/system/policy_history.md](logging_specs/system/policy_history.md) for full schema.

---

## Emergency & Startup Logs

### emergency_audit.jsonl

Location: `<config_dir>/emergency_audit.jsonl`

Last-resort fallback when primary audit logging fails. Lives in config directory (not `log_dir`) to survive log directory deletion.

**Fallback chain**: Primary audit log → `system.jsonl` → `emergency_audit.jsonl`. After any fallback, the proxy shuts down.

### bootstrap.jsonl

Location: `<config_dir>/bootstrap.jsonl`

Startup validation errors when config or policy is invalid and `log_dir` is unavailable. Records validation failures with timestamp, error type, and message.

### shutdowns.jsonl

Location: `<log_dir>/shutdowns.jsonl`

JSONL history of security shutdowns for the Incidents page. Records failure type, reason, exit code, and context.

### .last_crash

Location: `<log_dir>/.last_crash`

Simple text breadcrumb for crash popup display (overwritten each shutdown).

---

## Log Format

- **JSONL**: One JSON object per line
- **ISO 8601 timestamps**: Milliseconds precision, UTC (e.g., `2025-12-03T10:30:45.123Z`)
- **Hash chain fields** (audit and system logs):
  - `sequence`: Monotonically increasing entry number
  - `prev_hash`: SHA-256 of previous entry (or `"GENESIS"` for first)
  - `entry_hash`: SHA-256 of this entry

---

## Correlation IDs

- `request_id`: Per request/response pair
- `session_id`: Per client connection

---

## Schema Design

Log schemas are inspired by [OCSF (Open Cybersecurity Schema Framework)](https://schema.ocsf.io/):

| Log Type | OCSF Inspiration |
|----------|------------------|
| `operations.jsonl` | API Activity (6003) |
| `decisions.jsonl` | Authorization (3003) |
| `auth.jsonl` | Authentication (3002), Authorize Session (3003) |
| `system.jsonl` | Process Activity (1007), Application Error (6008) |
| `config_history.jsonl` | OWASP, NIST SP 800-92/800-128, CIS Control 8 |
| `policy_history.jsonl` | OWASP, NIST SP 800-92/800-128, CIS Control 8 |

**Full schemas**: See `docs/logging_specs/` for Pydantic models, JSON schemas, and detailed field documentation.

---

## SIEM Readiness

| Feature | Status |
|---------|--------|
| Structured format (JSONL) | Machine-readable, easily parsed |
| OCSF-inspired schemas | Industry standard, 120+ vendor support |
| ISO 8601 timestamps | Standardized, sortable, timezone-aware |
| Correlation IDs | Cross-event correlation via session_id, request_id |
| Consistent field names | Unified queries across log types |
| Log level filtering | WARNING+ only for system logs |
| Payload redaction | Hashes preserve forensic value without PII |

**For full SIEM integration**: Add log forwarder (syslog/HTTP/S3), full OCSF compliance, log enrichment.

---

## Security

**Payload redaction**: Arguments are never logged in full - only SHA256 hash and byte length. Full payloads only in debug logs.

**Blocking I/O**: All audit logging is synchronous with `fsync`. This guarantees the log is on disk before continuing (~1-5ms latency).

**Audit log integrity**: Protected by hash chains (tamper detection), per-write inode checks (file replacement detection), and background monitoring (every 30 seconds). Full chain verification runs at startup and can be triggered manually with `mcp-acp audit verify`. On integrity failure, the proxy shuts down. Use `mcp-acp audit status` to check protection status, and `mcp-acp audit repair` to recover from crashes or fix broken chains.

**Atomic writes**: Config and policy history use atomic writes to prevent corruption.

---

## See Also

- [Security](security.md) for audit log integrity and fail-closed behavior
- [Configuration](configuration.md) for log directory settings
- [logging_specs/](logging_specs/) for detailed field schemas and Pydantic models
