# Security

## Overview

This proxy implements a Zero Trust security model: all operations are denied by default, every request is evaluated independently, and all errors result in denial. The proxy enforces policy at the MCP protocol layer, providing access control, audit logging, and human oversight for AI tool operations.

For the full Zero Trust compliance evaluation (NIST SP 800-207), see [Zero Trust Compliance](zero-trust-compliance.md).

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

- **Schema validation**: Configuration (`config.json`) and policy (`policy.json`) files are validated against strict schemas at startup. This catches:
  - Invalid JSON syntax
  - Missing required fields
  - Invalid field types (e.g., string where number expected)
  - Invalid enum values (e.g., unknown transport type)
  - Policy rules with empty conditions (would match everything)
- **File permissions**: Config files use `0o600` (owner read/write only). Directories use `0o700` (owner only).

### Audit Writability Verification

At startup, the proxy verifies it can write to audit log files before accepting any requests. If audit logs are not writable, the proxy refuses to start.

### Bootstrap Log

When configuration validation fails, normal logging is unavailable (the `log_dir` setting cannot be read from invalid config). In this case, errors are logged to a bootstrap log:

- **Location**: `<config_dir>/bootstrap.jsonl`
- **Purpose**: Ensures validation failures are always recorded even when config is corrupt

### Protected Paths

At startup, the proxy resolves protected directories (following symlinks to their real paths). The config and log directories are then blocked from MCP tool access on every request, regardless of policy rules. This prevents backend servers from modifying policy, tampering with audit logs, or reading security configuration.

### Device Health Checks (macOS)

Before accepting requests, the proxy verifies device security posture:

| Check | Requirement | Why |
|-------|-------------|-----|
| **FileVault** | Must be enabled | Ensures disk encryption protects tokens and logs at rest |
| **SIP** | Must be enabled | Prevents malware from tampering with system binaries |

This is a **hard gate** — the proxy refuses to start if either check fails (exit code 14).

**Runtime Monitoring**: Device health is re-checked every 5 minutes. If the device becomes unhealthy, the proxy triggers a security shutdown.

**Non-macOS Platforms**: Device health checks are skipped on Linux/Windows. The proxy starts but without hardware security verification.

### Binary Attestation (STDIO Backends)

Before spawning STDIO backend processes, the proxy can verify binary integrity via hash verification, code signature (macOS), and SLSA provenance. All configured checks must pass (fail-closed).

See [Backend Authentication](backend_auth.md#binary-attestation-stdio-backends) for configuration and verification details.

---

## Runtime Security

### Access Control

**Policy Check Priority**: Every request is evaluated in this order (first match wins):

1. **Protected paths** — config/log directories blocked unconditionally (cannot be overridden)
2. **Discovery bypass** — `initialize`, `tools/list`, etc. allowed for protocol function
3. **Policy rules** — user-defined rules evaluated with combining algorithm (HITL > DENY > ALLOW)
4. **Default action** — DENY if no rules match

See [Policies](../reference/policies.md) for rule syntax, combining algorithm, and HITL configuration.

**Discovery bypass** applies to methods required for the protocol to function (`initialize`, `tools/list`, `resources/list`, `prompts/list`, etc.). Note that `prompts/get` is NOT bypassed because it returns actual prompt content that may contain secrets — it must go through policy evaluation.

### Rate Limiting

Two rate limiters protect against different threats:

| Layer | Purpose | Configuration |
|-------|---------|---------------|
| **DoS protection** | Prevents request flooding | Token bucket: 10 req/s sustained, 50 burst capacity |
| **Tool call limiting** | Detects runaway LLM loops | Per-tool sliding window: 30 calls/60s triggers HITL |

The DoS rate limiter is the outermost middleware layer. The tool call rate limiter tracks per-session, per-tool usage — when a tool exceeds the threshold, it triggers a HITL approval dialog. If approved, the counter resets.

Both limiters are unidirectional (client → proxy only). Backend notifications bypass rate limiting.

### Session Management

**Session Binding**: Each session is bound to the authenticated user identity at creation. Session IDs use 256 bits of cryptographic entropy.

**Session TTL**: Sessions expire after 8 hours, limiting the window for session-based attacks.

**Per-Request Validation**: On every request, the proxy verifies the current user identity matches the session's bound identity. A mismatch triggers an immediate security shutdown (exit code 15).

### Authentication

**OIDC Token Validation**: Every request requires a valid OIDC token, validated per-request (no cached trust decisions). Validation includes:
- Signature verification against issuer's JWKS
- Issuer (`iss`) and audience (`aud`) claim verification
- Expiration (`exp`) and issued-at (`iat`) claim checks

**JWKS Caching**: The issuer's JSON Web Key Set is cached for 10 minutes to reduce IdP load. Token validation itself is never cached — only the public keys used to verify signatures.

**Token Storage**: Tokens are stored securely in the OS keychain via the `keyring` library. If keychain is unavailable, falls back to Fernet-encrypted file storage. No plaintext tokens are stored.

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

Sanitization also applies to input schema property descriptions (argument hints).

### Audit and Logging

**Immutable Audit Trail**: Audit logging cannot be disabled. Every operation and policy decision is recorded to:

- `audit/operations.jsonl` — what was requested and outcome
- `audit/decisions.jsonl` — policy evaluation details and HITL outcomes
- `audit/auth.jsonl` — session lifecycle, authentication, and device health events

**Fail-Closed Integrity**: The proxy monitors audit log integrity continuously — both on every write and via periodic background checks every 30 seconds. If log files are deleted, replaced, or become unwritable, the proxy shuts down immediately (exit code 10). If primary audit logging fails, a fallback chain attempts to log to `system/system.jsonl` and then `<config_dir>/emergency_audit.jsonl` before shutdown.

**Hash Chain Integrity**: Audit logs use SHA-256 hash chains linking each entry to the previous. Detects deleted, inserted, reordered, or modified entries. Verify with `mcp-acp audit verify`. Full chain verification also runs automatically at startup (fails with exit code 10 if tampered).

**Crash Recovery**: If the proxy crashes and startup verification fails with "hash mismatch", run `mcp-acp audit repair` to fix. This requires manual intervention to prevent attackers from silently deleting entries.

**Limitation**: Hash chains are self-attesting. An attacker with write access to both logs and `.integrity_state` can truncate logs undetected. Mitigate with remote syslog forwarding, append-only filesystem attributes, or external backups.

**OS-Level Append-Only Protection**: For additional tamper resistance, you can set append-only attributes on audit files:

- **Linux**: `sudo chattr +a <audit-path>/*.jsonl` (remove with `sudo chattr -a`)
- **macOS**: `chflags uappend <audit-path>/*.jsonl` (system-level: `sudo chflags sappend`)
- **Windows**: No equivalent — forward logs to SIEM instead.

Note: Breaks log rotation (remove attribute first). Not supported on NFS/Docker volumes. Not enabled by default.

**Log Security**: All log entries are validated against strict schemas, newlines/carriage returns are escaped to prevent log injection, and content is never logged — only hashes and sizes (sensitive values are replaced with `[REDACTED - N bytes]`). Audit files have `0o600` permissions (owner-only).

**Config and Policy History**: Changes to configuration and policy are tracked in `system/config_history.jsonl` and `system/policy_history.jsonl`, including version numbers, checksums, and snapshots. Manual edits outside the CLI are detected via checksum comparison.

### Human-in-the-Loop (HITL)

**Approval Routing**: HITL requests are routed to the web UI when the manager is connected (preferred). Falls back to native macOS dialogs. On non-macOS platforms without the web UI, HITL requests are auto-denied.

**Timeout**: Defaults to DENY after 60 seconds (range: 5-300 seconds).

**Approval Caching**: To reduce dialog fatigue, approvals can be cached with a 10-minute TTL (range: 5-15 minutes). Cached approvals match on (subject_id, tool_name, normalized_path). Users can choose "Allow once" to explicitly skip caching. Tools with code execution side effects are never cached.

### Error Handling

Every error condition defaults to DENY (fail-closed):

| Scenario | Behavior |
|----------|----------|
| Context build error | DENY |
| Policy evaluation error | DENY |
| HITL timeout | DENY |
| HITL dialog error | DENY |
| No matching policy rule | DENY (default_action) |
| Protected path access | DENY |
| Audit log write failure | DENY + shutdown |

---

## Shutdown Security

The proxy shuts down immediately when security invariants are violated:

- **Audit integrity failures** — log file deleted, replaced, or unwritable (exit code 10)
- **Session binding violations** — user identity changed mid-session (exit code 15)

On shutdown, events are logged to `shutdowns.jsonl` (displayed in the UI Incidents page) and a breadcrumb file (`.last_crash`) with failure details for post-incident analysis.

### Exit Codes

| Code | Meaning | Triggered By |
|------|---------|--------------|
| 10 | Audit log integrity failure | File deletion, replacement, write failure, or hash chain tampering at startup |
| 11 | Policy enforcement failure | Reserved for future use |
| 12 | Identity verification failure | JWKS endpoint unreachable and cache expired |
| 13 | Authentication error | No token in keychain, expired token that cannot be refreshed, invalid signature, OIDC issuer/audience validation failure |
| 14 | Device health check failure | FileVault/SIP not enabled (macOS) |
| 15 | Session binding violation | Identity changed mid-session (potential hijacking) |
| 16 | Configuration error | Missing or invalid config, missing auth section |

### Post-Shutdown Client Behavior

After shutdown, MCP clients may auto-restart the proxy. The restarted proxy receives requests without proper initialization, causing `-32602 Invalid request parameters` errors. This is expected — users must manually reconnect their MCP client.

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
- Protected paths (config dir, log dir) are symlink-safe (resolved at startup)

For most deployments where you control the allowed directories, this is low risk.

---

## See Also

- [Zero Trust Compliance](zero-trust-compliance.md) - NIST SP 800-207 evaluation, tenet coverage, gap analysis
- [Architecture](../reference/architecture.md) - System architecture, request flow, component design
- [Authentication](auth.md) - User authentication, device health, session binding
- [Backend Authentication](backend_auth.md) - mTLS, binary attestation, API key management
- [Policies](../reference/policies.md) - Policy syntax, HITL configuration, combining algorithm
- [Logging](logging.md) - Log structure, formats, correlation IDs
