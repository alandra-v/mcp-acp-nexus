# Logging

## Primary Goals

Logging supports the Zero Trust security model with three primary goals:

1. **Audit trail**: Complete record of who accessed what, when, and with what outcome
2. **Policy enforcement monitoring**: Every policy decision is logged for compliance and debugging
3. **Incident response & forensics**: Sufficient detail to reconstruct events during security investigations

**Fail-closed on log failure**: If audit logging fails (e.g., disk full, file deleted), the proxy shuts down rather than operate without an audit trail. See [Security](security.md) for details.

---

## Log Structure

```
<log_dir>/mcp-acp/
├── manager/                        # Manager daemon logs
│   └── system.jsonl                # Manager operational logs
└── proxies/<name>/                 # Per-proxy logs
    ├── audit/                      # Security audit logs (ALWAYS enabled)
    │   ├── operations.jsonl        # MCP operation audit trail
    │   ├── decisions.jsonl         # Policy evaluation decisions + HITL outcomes
    │   └── auth.jsonl              # Authentication events
    ├── system/                     # System/operational events
    │   ├── system.jsonl            # Operational logs, errors, backend disconnections
    │   ├── config_history.jsonl    # Configuration changes (versioned)
    │   └── policy_history.jsonl    # Policy changes (versioned)
    ├── debug/                      # Wire-level debug logs (DEBUG level only)
    │   ├── client_wire.jsonl       # Client ↔ Proxy communication
    │   └── backend_wire.jsonl      # Proxy ↔ Backend communication
    ├── .integrity_state            # Hash chain state file
    ├── .last_crash                 # Breadcrumb for crash popup
    └── shutdowns.jsonl             # Security shutdown history

<config_dir>/emergency_audit.jsonl  # Fallback when primary audit fails
<config_dir>/bootstrap.jsonl        # Startup validation errors
```

**Default log directory** (`<log_dir>`):
- macOS: `~/Library/Logs`
- Linux: `$XDG_STATE_HOME` (defaults to `~/.local/state`)
- Windows: `~/AppData/Local`

---

## Configuration

Log settings are configured in two places:

**Manager** (`manager.json`):
```json
{
  "log_dir": "~/Library/Logs",
  "log_level": "INFO"
}
```
- `log_dir`: Base directory for all logs (manager and proxies). Platform default if not specified.
- `log_level`: Manager daemon logging level (`DEBUG` or `INFO`). Controls what gets written to `manager/system.jsonl`.

**Per-proxy** (`proxies/<name>/config.json`):
```json
{
  "log_level": "INFO"
}
```
- `log_level`: Proxy logging level (`DEBUG` or `INFO`). `DEBUG` enables wire-level debug logs for that proxy.

See [Configuration](configuration.md) for full options.

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

## System Logs (`system/`)

### system.jsonl

Operational issues and errors (backend disconnections, path normalization failures, etc.). **Only WARNING, ERROR, CRITICAL levels are logged to file.**

**See**: [logging_specs/system/system.md](logging_specs/system/system.md) for full schema.

### config_history.jsonl

Configuration change audit trail with versioning and checksums.

**See**: [logging_specs/system/config_history.md](logging_specs/system/config_history.md) for full schema.

### policy_history.jsonl

Policy change audit trail with versioning and checksums.

**See**: [logging_specs/system/policy_history.md](logging_specs/system/policy_history.md) for full schema.

---

## Debug Logs (`debug/`)

Wire-level MCP communication with full request/response payloads. Only created when proxy `log_level=DEBUG`.

- `client_wire.jsonl`: Client ↔ Proxy communication
- `backend_wire.jsonl`: Proxy ↔ Backend communication

Event types: `client_request`, `proxy_response`, `proxy_error`, `proxy_request`, `backend_response`, `backend_error`

---

## Manager Logs (`manager/`)

The manager daemon has its own log directory separate from proxy logs.

### system.jsonl

Manager operational logs including:
- Daemon startup/shutdown events
- Proxy registration and connection events
- SSE event aggregation
- API routing errors

**Log destinations:**
- **stderr** (foreground mode): INFO+ always visible
- **File**: Respects `log_level` in manager.json (`INFO` or `DEBUG`)

Not hash-chain protected (uses standard Python logging format).

**See**: [logging_specs/manager/system.md](logging_specs/manager/system.md) for full schema.

---

## Emergency & Startup Logs

### emergency_audit.jsonl

Location: `<config_dir>/emergency_audit.jsonl`

Last-resort fallback when primary audit logging fails. Lives in config directory (not `log_dir`) to survive log directory deletion.

**Fallback chain**: Primary audit log → `system.jsonl` → `emergency_audit.jsonl`. After any fallback, the proxy shuts down.

### bootstrap.jsonl

Location: `<config_dir>/bootstrap.jsonl`

Startup validation errors when config or policy is invalid.

### shutdowns.jsonl

Location: `<log_dir>/mcp-acp/proxies/<name>/shutdowns.jsonl`

JSONL history of security shutdowns for the Incidents page.

### .last_crash

Location: `<log_dir>/mcp-acp/proxies/<name>/.last_crash`

Simple text breadcrumb for crash popup display (overwritten each shutdown).

---

## Log Format

- **JSONL**: One JSON object per line
- **ISO 8601 timestamps**: Milliseconds precision, UTC (e.g., `2025-12-03T10:30:45.123Z`)
- **Correlation IDs**: `request_id` (per request), `session_id` (per connection)

---

## Hash Chain Integrity

Certain logs are protected by cryptographic hash chains for tamper detection.

**Protected files:**
- `audit/operations.jsonl`
- `audit/decisions.jsonl`
- `audit/auth.jsonl`
- `system/system.jsonl`

**Not protected:** `config_history.jsonl`, `policy_history.jsonl`, debug logs, manager logs.

### Hash Chain Fields

Protected log entries include:
- `sequence`: Monotonically increasing entry number per file
- `prev_hash`: SHA-256 of previous entry (or `"GENESIS"` for first)
- `entry_hash`: SHA-256 of this entry

### Integrity State File

Location: `<log_dir>/mcp-acp/proxies/<name>/.integrity_state`

Tracks per-file state (`last_hash`, `last_sequence`, `last_inode`, `last_dev`) for between-run verification. Written atomically after each audit write.

### Verification

- **Startup**: Full chain verification runs automatically
- **Runtime**: Background health monitor checks last 10 entries every 30 seconds
- **Manual**: `mcp-acp audit verify`

### Limitations

This is **self-attesting** with no external attestation. An attacker with write access to both log files AND `.integrity_state` can truncate logs undetected.

**Mitigations for high-security environments**:
- Forward logs to remote syslog server
- Use append-only filesystem attributes (`chattr +a` on Linux, `chflags uappend` on macOS)
- Regular external backups to immutable storage

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

**Full schemas**: See `docs/logging_specs/` for detailed field documentation.

---

## Security

**File permissions**: Directories use `0o700` (owner only), audit files use `0o600` (owner read/write).

**Protected by policy**: MCP tools cannot access the log directory regardless of policy rules.

**Payload redaction**: Arguments are never logged in full - only SHA256 hash and byte length. Full payloads only in debug logs.

**Log injection prevention**: Newlines and carriage returns are escaped in logged strings.

**Blocking I/O**: Audit logging is synchronous with `fsync` to guarantee data reaches disk.

**File identity checks**: Before each audit write, the handler verifies the file exists with the same inode/device. If deleted or replaced, the proxy shuts down.

**Background monitoring**: `AuditHealthMonitor` runs every 30 seconds, checking file existence, identity, writeability, and hash chain integrity.

**Atomic writes**: Integrity state uses atomic writes (temp file + rename) to prevent corruption.

See [Security](security.md#audit-and-logging-security) for complete details including OS-level append-only protection.

---

## See Also

- [Security](security.md) for audit log integrity and fail-closed behavior
- [Configuration](configuration.md) for log directory settings
- [logging_specs/](logging_specs/) for detailed field schemas
