# Security

## Overview

This proxy implements a Zero Trust security model: all operations are denied by default, every request is evaluated independently, and all errors result in denial. The proxy enforces policy at the MCP protocol layer, providing access control, audit logging, and human oversight for AI tool operations.

For the full Zero Trust architecture and PEP/PDP design, see [Architecture](architecture.md).

---

## Protection Capabilities

### MCP and Agentic AI Threats

| Threat | How the Proxy Helps |
|--------|---------------------|
| **Tool poisoning** (malicious tool descriptions inducing unsafe actions) | Policy gating blocks tool invocations; tool description sanitization strips injection attempts |
| **Confused-deputy attacks** (clients/servers tricked into misusing authority) | Per-request policy evaluation (no cached trust); HITL requires explicit user consent |
| **Cross-tool contamination** (benign tools chained into exfiltration) | Policy rules restrict by tool name, path pattern, and side effects |
| **Credential theft and misuse** (token impersonation, privilege escalation) | Tokens validated per-request; session binding prevents hijacking |
| **Expanded attack surface** (agent integrations multiply entry points) | Default-deny policy; protected paths block access to proxy internals |
| **Accountability gaps** (unclear attribution for autonomous agent actions) | Immutable audit trail with subject ID, request ID, session ID |
| **Runaway LLM loops** (repeated tool calls from confused model) | Per-tool rate limiting triggers HITL when threshold exceeded |
| **Request flooding** (DoS attacks) | Token bucket rate limiter on all incoming requests |

---

## Limitations and Out of Scope

### What This Proxy Does NOT Protect Against

| Limitation | Explanation | Recommendation |
|-----------|-------------|----------------|
| **Prompt injection** | The proxy operates at the MCP protocol layer, not the prompt layer. It cannot see or filter prompts sent to the model. | Use prompt-level defenses in your LLM application |
| **Model behavior** | Cannot guarantee the model will behave benignly or follow instructions correctly. | Implement application-level guardrails |
| **Out-of-band channels** | Only the MCP channel is proxied. Data exfiltration via other means (network, clipboard if tool allowed) is not detected. | Restrict network access at OS/firewall level |
| **Backend server vulnerabilities** | The proxy enforces policy on requests, but cannot protect against vulnerabilities in the backend MCP server itself. | Keep backend servers updated; use trusted servers |
| **Memory exhaustion** | No limits on response sizes yet. Large responses could exhaust memory. | Monitor resource usage; set OS-level limits |

### Dependencies Disclaimer

This proxy depends on third-party libraries including FastMCP, Pydantic, httpx, and others. These dependencies may contain security vulnerabilities. Dependencies are defined in `pyproject.toml`.

**Recommendations:**
- Regularly update dependencies: `uv sync --upgrade` or `pip install --upgrade`
- Monitor security advisories (GitHub Dependabot, Snyk, or `pip-audit`)
- Pin dependency versions in production (`uv.lock`) and test updates before deploying

---

## Startup Security

### Configuration Validation

Before accepting any requests, the proxy validates all configuration:

- **Pydantic schema validation**: Configuration (`mcp_acp_config.json`) and policy (`policy.json`) files are validated against strict Pydantic models. This catches:
  - Invalid JSON syntax
  - Missing required fields
  - Invalid field types (e.g., string where number expected)
  - Invalid enum values (e.g., unknown transport type)
  - Policy rules with empty conditions (would match everything)
- **File permissions**: Config files use `0o600` (owner read/write only). Directories use `0o700` (owner only).
- **Atomic writes**: Config and policy files are written atomically (write to temp file, fsync, rename) to prevent corruption on crash or power loss.

### Audit Writability Verification

At startup, the proxy verifies it can write to audit log files before accepting any requests. If audit logs are not writable, the proxy refuses to start.

### Bootstrap Log

When configuration validation fails, normal logging is unavailable (the `log_dir` setting cannot be read from invalid config). In this case, errors are logged to a bootstrap log in a predictable location:

- **Location**: `<config_dir>/bootstrap.jsonl`
- **Purpose**: Ensures validation failures are always recorded even when config is corrupt
- **Contents**: Timestamp, error type, error message

### Protected Paths Initialization

At startup, the proxy resolves protected directories using `os.path.realpath()`:

- **Config directory**: Contains policy, config, and emergency audit files
- **Log directory**: Contains all audit and system logs

This resolution happens once at startup, preventing symlink-based bypass attempts. These paths are then checked before policy evaluation for every request.

### Device Health Checks (macOS)

Before accepting requests, the proxy verifies device security posture:

| Check | Requirement | Why |
|-------|-------------|-----|
| **FileVault** | Must be enabled | Ensures disk encryption protects tokens and logs at rest |
| **SIP** | Must be enabled | Prevents malware from tampering with system binaries |

This is a **hard gate** - the proxy refuses to start if either check fails (exit code 14).

**Runtime Monitoring**: Device health is re-checked every 5 minutes during operation. If the device becomes unhealthy (e.g., FileVault disabled), the proxy triggers a security shutdown.

**Non-macOS Platforms**: Device health checks are skipped on Linux/Windows. The proxy starts but without hardware security verification.

### Binary Attestation (STDIO Backends)

Before spawning STDIO backend processes, the proxy can verify binary integrity via hash verification, code signature (macOS), and SLSA provenance. All configured checks must pass (fail-closed).

See [Authentication](auth.md#binary-attestation-stdio-backends) for configuration and verification details.

### Startup Failure Handling

If startup fails due to configuration or validation errors:

1. Error logged to bootstrap log (config_dir)
2. Error logged to config_history.jsonl or policy_history.jsonl as `*_validation_failed` event
3. Proxy exits with non-zero status
4. Human-readable error message printed to stderr

---

## Runtime Security

### Access Control

**Policy Check Priority**: Every request is evaluated in this order (first match wins):

1. **Protected paths** - config/log directories blocked unconditionally (cannot be overridden)
2. **Discovery bypass** - `initialize`, `tools/list`, etc. allowed for protocol function
3. **Policy rules** - user-defined rules evaluated with combining algorithm (HITL > DENY > ALLOW)
4. **Default action** - DENY if no rules match

**Policy Enforcement**: Every non-discovery request is evaluated against policy rules. See [Policies](policies.md) for rule syntax, combining algorithm, and HITL configuration.

**Protected Paths**: The config and log directories cannot be accessed by MCP tools, regardless of policy rules. This prevents backend servers from:

- Modifying policy files to grant themselves more access
- Tampering with audit logs to hide malicious activity
- Reading configuration to discover security settings
- Deleting emergency audit files

This check happens before policy evaluation:

1. Request path is normalized
2. Checked against protected directories (resolved at startup with `realpath()`)
3. If match: immediately denied
4. If no match: proceeds to policy evaluation

This is a built-in protection that cannot be overridden by user policy.

**Discovery Method Bypass**: Certain MCP methods bypass policy evaluation entirely because they are required for the protocol to function and do not modify state. See `DISCOVERY_METHODS` in `constants.py` for the complete list.

These are logged with `final_rule: "discovery_bypass"` for audit trail.

**Important exclusion**: `prompts/get` is NOT in the bypass list because it returns actual prompt content, which may contain secrets or sensitive instructions. Unlike `prompts/list` (which only returns metadata), `prompts/get` fetches the full prompt template and must be subject to policy evaluation.

**Provenance Tracking**: Every security-relevant fact carries its source:

| Source | Trust Level |
|--------|-------------|
| `TOKEN`, `MTLS` | Cryptographically verified |
| `DIRECTORY` | From identity directory lookup |
| `PROXY_CONFIG` | Operator-controlled configuration |
| `MCP_METHOD` | From protocol method name |
| `MCP_REQUEST` | From request arguments (client-provided) |
| `DERIVED` | Computed from other facts |
| `CLIENT_HINT` | Client self-reported (untrusted) |

Currently tracked for audit purposes. Infrastructure for future trust-level policy requirements.

### Rate Limiting

Two rate limiters protect against different threats:

| Layer | Purpose | Configuration |
|-------|---------|---------------|
| **DoS protection** | Prevents request flooding | Token bucket: 10 req/s sustained, 50 burst capacity |
| **Tool call limiting** | Detects runaway LLM loops | Per-tool sliding window: 30 calls/60s triggers HITL |

**DoS Rate Limiter**: Outermost middleware layer. Catches flooding attacks before any request processing. Uses FastMCP's token bucket algorithm with global limit.

**Tool Call Rate Limiter**: Per-session, per-tool tracking. When a tool exceeds the threshold within the window, triggers HITL approval dialog. If approved, counter resets. Detects:
- Runaway LLM loops (model repeatedly calling same tool)
- Data exfiltration attempts (bulk reads)
- Credential abuse patterns

Both limiters are unidirectional (client → proxy only). Backend notifications bypass rate limiting.

### Session Management

**Session Binding**: Each session is bound to the authenticated user identity at creation. Format: `<user_id>:<session_id>` where session_id uses 256 bits of cryptographic entropy (`secrets.token_urlsafe(32)`).

**Session TTL**: Sessions expire after 8 hours from creation. This is shorter than typical token lifetimes to limit the window for session-based attacks.

**Per-Request Validation**: On every request, the session manager verifies the current user identity matches the session's bound identity. If mismatched (indicating potential session hijacking), the proxy triggers an immediate security shutdown (exit code 15).

**Session Lifecycle Events**: Session start/end logged to `audit/auth.jsonl` with subject ID for audit trail.

### Authentication

**OIDC Token Validation**: Every request requires a valid OIDC token. Tokens are validated per-request (Zero Trust - no cached trust decisions). Validation includes:
- Signature verification against issuer's JWKS
- Issuer (`iss`) and audience (`aud`) claim verification
- Expiration (`exp`) and not-before (`nbf`) claim checks

**JWKS Caching**: The issuer's JSON Web Key Set is cached for 10 minutes to reduce IdP load. Token validation itself is never cached - only the public keys used to verify signatures.

**Token Storage**: Tokens are stored securely in the OS keychain via the `keyring` library (macOS tested). If keychain is unavailable, falls back to Fernet-encrypted file storage in the protected config directory. No plaintext tokens are stored.

**Token Refresh**: When tokens expire, automatic refresh is attempted using the refresh token. If refresh fails, the user must re-authenticate.

### mTLS (Mutual TLS) for HTTP Backends

For HTTP/SSE backends requiring client certificate authentication, the proxy supports mTLS with certificate expiry monitoring (warning at 14 days, critical at 7 days, blocked if expired).

See [Backend Authentication](backend_auth.md) for configuration and certificate requirements.

### Tool Description Sanitization

Tool descriptions from untrusted MCP servers are sanitized before being passed to clients:

| Step | Protection |
|------|------------|
| Unicode normalization (NFKC) | Collapses homoglyphs (Cyrillic 'а' → Latin 'a') |
| Control character removal | Strips non-printable characters |
| Markdown link stripping | Removes URLs, keeps link text |
| HTML tag stripping | Removes `<tag>` elements |
| Length truncation | Maximum 500 characters |
| Suspicious pattern detection | Logs warnings for injection attempts |

**Suspicious patterns detected** (logged but not removed to avoid false positives):
- Instruction overrides ("ignore previous instructions")
- Role assumption ("you are", "act as", "pretend")
- System prompt references

Sanitization also applies to input schema property descriptions (argument hints). All modifications logged to `decisions.jsonl`.

### Audit and Logging Security

**Immutable Audit Trail**: Audit logging cannot be disabled. Every operation and policy decision is recorded to:

- `audit/operations.jsonl` - what was requested and outcome
- `audit/decisions.jsonl` - policy evaluation details and HITL outcomes

**Fail-Closed Integrity Monitoring**: Two layers of protection ensure audit log integrity:

**1. Per-Write Checks (FailClosedAuditHandler)**: Verifies file integrity before every write:
- At startup: records file's device ID and inode
- Before each write: stats file and compares device/inode
- On mismatch: triggers emergency shutdown

**2. Background Monitoring (AuditHealthMonitor)**: Periodic checks during idle periods:
- Runs every 30 seconds as a background task
- Verifies both `operations.jsonl` and `decisions.jsonl`
- Detects tampering even when no requests are being processed
- Defense in depth: catches issues the per-write handler might miss during idle periods

Together, these detect:
- File deletion (even while file descriptor is open - "ghost inode" on Unix)
- File replacement (different inode)
- File moved and recreated
- Permission changes

**Fallback Chain**: If primary audit logging fails, the proxy attempts fallback logging before shutdown:

1. **Primary**: `audit/operations.jsonl` or `audit/decisions.jsonl`
2. **Fallback 1**: `system/system.jsonl`
3. **Fallback 2**: `<config_dir>/emergency_audit.jsonl` (survives log_dir deletion)

After any fallback, the proxy must shut down because the primary audit trail is compromised.

**Log Security Measures**:

| Measure | Purpose |
|---------|---------|
| Pydantic strict models | Log events validated with `extra="forbid"`; rejects unknown fields and malformed entries |
| Log injection prevention | Newlines and carriage returns escaped in logged strings; prevents fake JSONL entries via malicious filenames |
| Append-only mode | Logs opened with `mode="a"`; new entries appended, existing content preserved |
| Directory permissions (0o700) | Prevent unauthorized access to log directories |
| Audit file permissions (0o600) | Audit logs (`operations.jsonl`, `decisions.jsonl`, `auth.jsonl`) have explicit owner-only permissions |
| Debug file permissions (umask) | Debug logs (`client_wire.jsonl`, `backend_wire.jsonl`) use system umask (non-sensitive, disabled by default) |
| Never log content | Only hashes and sizes logged; prevents secrets in logs |
| Content redaction | Sensitive argument values replaced with `[REDACTED - N bytes]` |
| fsync on writes | Ensures data reaches disk |
| Integrity verification | Detects file tampering or deletion via inode checks |
| Fallback chain | Emergency logging survives primary log deletion |
| Protected by policy | MCP tools cannot access log directory regardless of policy rules |
| Correlation IDs | request_id and session_id link related events |

**Hash Chain Integrity**: Audit logs use SHA-256 hash chains linking each entry to the previous. Detects deleted, inserted, reordered, or modified entries. Verify with `mcp-acp audit verify`. Verified automatically at startup (fails with exit code 10 if tampered).

**Crash Recovery**: If the proxy crashes after saving state but before writing a log entry, startup verification fails with "hash mismatch". Run `mcp-acp audit repair` to reset state to match the actual log. This requires manual intervention to prevent attackers from silently deleting the last entry.

**Limitation**: Hash chains are self-attesting. An attacker with write access to both logs AND `.integrity_state` can truncate logs undetected. Mitigate with remote syslog forwarding, append-only filesystem attributes, or external backups.

### OS-Level Append-Only Protection

Prevents modification even with root access—files can only be appended to.

**Linux:**
```bash
sudo chattr +a ~/.mcp-acp-nexus/logs/mcp_acp_logs/audit/*.jsonl
# Verify: lsattr shows 'a' flag
# Remove: sudo chattr -a <path>
```

**macOS:**
```bash
chflags uappend ~/.mcp-acp-nexus/logs/mcp_acp_logs/audit/*.jsonl
# System-level (requires root to remove): sudo chflags sappend <path>
# Remove: chflags nouappend <path>
```

**Windows:** No equivalent. Forward logs to SIEM instead.

**Trade-offs:** Breaks log rotation (remove attribute first). Not supported on NFS/Docker volumes. New files need attribute re-applied. Not enabled by default.

**Path Normalization Strategies**: Three different strategies are used for different security purposes:

| Context | Method | Why |
|---------|--------|-----|
| Policy evaluation | `os.path.normpath()` | Matches client intent; prevents TOCTOU symlink attacks |
| Protected paths | `os.path.realpath()` | Resolves symlinks once at startup; prevents bypass |
| Audit logging | `Path.resolve()` | Shows canonical path for forensic accuracy |

**Why normpath for policy (TOCTOU prevention)**:

- Attacker creates `/tmp/innocent -> /etc/shadow`
- Policy allows `/tmp/**`, denies `/etc/**`
- With `.resolve()`: path becomes `/etc/shadow` at check time, but symlink could change before backend uses it
- With `.normpath()`: policy matches `/tmp/innocent` (what client requested)

Principle: Policy paths are identifiers, not filesystem references. Policy matches what the client requested, not what it might resolve to.

**Known Limitation - Symlink Bypass**: Because policy evaluation does not resolve symlinks,
an attacker with write access to an allowed directory could create symlinks to bypass deny rules.
See "Symlink Considerations" section below for mitigation guidance.

**Config and Policy History Logs**: Changes to configuration and policy are tracked in versioned history logs:

- `system/config_history.jsonl` - config lifecycle events
- `system/policy_history.jsonl` - policy lifecycle events

Events tracked:
- `*_created` - initial creation via CLI
- `*_loaded` - loaded at proxy startup
- `*_updated` - updated via CLI
- `manual_change_detected` - file modified outside CLI (detected via checksum)
- `*_validation_failed` - invalid JSON or schema

Each event includes version number, checksum, and snapshot for forensic analysis.

### HITL Security Design

**Synchronous Blocking**: HITL approval uses synchronous `subprocess.run()`, not async. This is a deliberate security choice - blocking the request pipeline ensures the operation cannot proceed until approval completes. Async would risk race conditions where the operation might execute before approval finishes.

**AppleScript Injection Prevention**: User-provided values displayed in HITL dialogs are escaped to prevent injection:
- Control characters (`\n`, `\r`, `\t`) replaced with spaces - prevents dialog rendering exploits
- Backslashes escaped before quotes - order matters for correct escaping
- Double quotes escaped - prevents breaking out of string literals

**Timeout Behavior**: HITL timeout defaults to DENY (fail-safe). The default timeout is 60 seconds (range: 5-300 seconds). The minimum ensures users have time to read the prompt.

**Approval Caching**: To reduce dialog fatigue, approvals are cached with a 10-minute TTL (range: 5-15 minutes). Cached approvals match on (subject_id, tool_name, normalized_path). Tools with side effects are not cached by default.

### Error Handling

Every error condition defaults to DENY (fail-closed):

| Scenario | Behavior |
|----------|----------|
| Context build error | DENY |
| Policy evaluation error | DENY |
| HITL timeout | DENY |
| HITL dialog error | DENY |
| AppleScript parse error | DENY |
| Unsupported platform for HITL | DENY (with warning log) |
| No matching policy rule | DENY (default_action) |
| Protected path access | DENY |
| Audit log write failure | DENY + shutdown |

**Backend Disconnection**: Transport-level errors (BrokenPipeError, ConnectionError, httpx errors) are detected and logged as `backend_disconnected` events to system.jsonl. The proxy cannot continue serving requests after backend disconnection.

---

## Shutdown Security

### Critical Security Failure Detection

Shutdown is triggered when security invariants are violated:

**Audit Integrity Failures:**
- Audit log file deleted
- Audit log file replaced (different inode)
- Audit log becomes unwritable
- Write to audit log fails

**Session Binding Violations:**
- Request arrives with different user identity than session was bound to
- Indicates potential session hijacking attempt

### Shutdown Sequence

**For Audit Integrity Failures:**
1. `FailClosedAuditHandler.emit()` detects integrity failure
2. Sets `is_compromised = True` flag
3. Attempts to log event via fallback chain
4. Writes breadcrumb file with failure details
5. Schedules delayed exit (100ms allows error response to flush)
6. Returns error to client (`-32603 INTERNAL_ERROR`)
7. Calls `os._exit(10)` - cannot be caught by exception handlers

**For Session Binding Violations:**
1. `build_decision_context()` detects identity mismatch
2. Raises `SessionBindingViolationError`
3. Middleware catches and calls shutdown callback
4. Logs `session_ended` with `end_reason: session_binding_violation`
5. Writes breadcrumb file with failure details
6. Schedules delayed exit (100ms allows error response to flush)
7. Calls `os._exit(15)` - cannot be caught by exception handlers

### Shutdown Logging

On critical security failure, shutdown events are logged to multiple destinations:

**1. Shutdowns Log** (`<log_dir>/shutdowns.jsonl`):
- JSONL format for programmatic access (displayed in UI Incidents page)
- Contains: timestamp, event type, failure type, reason, exit code, context

**2. Breadcrumb File** (`<log_dir>/.last_crash`):
- Human-readable format for post-incident analysis
- Format:
  ```
  <timestamp>
  failure_type: <type>
  exit_code: <code>
  reason: <reason>
  context: <json>
  ```

**3. System Log** (`<log_dir>/system/system.jsonl`):
- Best-effort logging to primary system log
- May fail if filesystem issues caused the shutdown

### Exit Codes

| Code | Meaning | Triggered By |
|------|---------|--------------|
| 10 | Audit log integrity failure | File deletion, replacement, write failure, or hash chain tampering at startup |
| 11 | Policy enforcement failure | Reserved for future use |
| 12 | Identity verification failure | JWKS endpoint unreachable and cache expired |
| 13 | Authentication error | No token in keychain, expired token that cannot be refreshed, invalid signature, OIDC issuer/audience validation failure |
| 14 | Device health check failure | FileVault/SIP not enabled (macOS) |
| 15 | Session binding violation | Identity changed mid-session (potential hijacking) |

### Post-Shutdown Client Behavior

After shutdown, MCP clients may auto-restart the proxy. The restarted proxy receives requests without proper initialization, causing `-32602 Invalid request parameters` errors. This is expected behavior - users must manually reconnect their MCP client.

---

## Symlink Considerations

Policy evaluation does **not** resolve symlinks. This preserves compatibility with macOS
(where `/tmp` → `/private/tmp`) and user symlinks in workflows.

**Implication**: An attacker with write access to an allowed directory could create a symlink
to bypass deny rules. For example, `/tmp/allowed/link` → `/etc/shadow` would match an
`allow /tmp/allowed/**` rule.

**Mitigations**:
- Use HITL instead of ALLOW for directories where untrusted symlinks might exist
- Restrict filesystem write access to allowed directories
- Protected paths (config dir, log dir) are symlink-safe via `realpath()` at startup

For most deployments where you control the allowed directories, this is low risk.

---

## See Also

- [Architecture](architecture.md) - Zero Trust principles, PEP/PDP separation, request flow
- [Authentication](auth.md) - User authentication, binary attestation, device health, session binding
- [Backend Authentication](backend_auth.md) - mTLS configuration, certificate management
- [Policies](policies.md) - Policy syntax, HITL configuration, combining algorithm
- [Logging](logging.md) - Log structure, formats, correlation IDs
