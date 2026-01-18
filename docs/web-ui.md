# Web UI

## Overview

The proxy is **CLI-first** — it runs fully standalone without any web interface, and all functionality is available through command-line tools. See [Usage](usage.md) for CLI commands.

The web UI is an **optional add-on** for users who prefer a graphical interface for monitoring and approvals. It runs on localhost with multiple hardening layers: Host header validation, Origin checks, CSRF protection, token authentication, and Private Network Access headers. For minimal attack surface, you can disable the UI entirely.

---

## Accessing the UI

The UI is enabled by default and starts automatically with the proxy:

```
http://localhost:8765
```

The UI is accessible without login for viewing. However, **approving HITL requests requires OIDC authentication** (see Features → HITL Approval Requirements).

---

## Disabling the UI

```bash
mcp-acp start --no-ui
```

Or in Claude Desktop config:

```json
{
  "mcpServers": {
    "mcp-acp": {
      "command": "/path/to/mcp-acp",
      "args": ["start", "--no-ui"]
    }
  }
}
```

When disabled:
- No HTTP server runs (port 8765 not opened)
- HITL approvals use native system dialogs (osascript on macOS)
- All functionality remains available via CLI

---

## Security Model

### Localhost-Only Binding

The API server binds exclusively to `127.0.0.1`. Remote connections are not possible. Host header validation prevents DNS rebinding attacks.

### Authentication

- **Production**: HttpOnly cookie (`api_token`) with `SameSite=Strict`, automatically set on page load
- **Token generation**: 32 bytes of cryptographic randomness (64 hex characters)
- **Token validation**: Constant-time comparison to prevent timing attacks

### CSRF Protection

Multiple layers:
- **SameSite=Strict cookies**: Prevents cross-site cookie submission
- **Origin header validation**: Required for all mutations (POST, PUT, DELETE)
- **Host header validation**: Blocks DNS rebinding attacks

### Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'; ...
Cache-Control: no-store
Referrer-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### Request Limits

Maximum request size: 1MB

### CLI Access via Unix Domain Socket

CLI commands use a Unix Domain Socket for local communication. Authentication relies on OS file permissions (socket is owner-only, mode 0600), bypassing HTTP authentication while maintaining security.

---

## Features

### Dashboard

- **Proxy status**: Uptime, backend connection, transport type
- **Live statistics**: Request counts (allowed/denied/HITL)
- **Pending approvals**: Real-time HITL requests with approve/deny buttons
- **Cached approvals**: View and clear cached HITL decisions
- **Activity log**: Recent operations with filtering

### Policy & Config

- View current policy rules and configuration
- Add/edit/delete policy rules (changes auto-reload)
- JSON editor for advanced policy editing

### Incidents

- Security shutdown history
- Bootstrap errors
- Emergency audit entries

### Real-time Updates

- SSE (Server-Sent Events) for live notifications
- Audio chime when new HITL request arrives
- Error sound for critical events (backend disconnect, auth failures)
- Toast notifications for system events

### Background Tab Alerts

When the UI is in a background tab:
- Page title updates with pending count (e.g., "(2) MCP ACP")
- Audio notifications still play

### HITL Approval Requirements

**Important**: Approving or denying requests from the UI requires OIDC authentication. The approver must be the same user who initiated the MCP session (session binding).

If not logged in, use native system dialogs instead (see Fallback Behavior).

### Fallback Behavior

If the UI is not open when a HITL approval is needed, the proxy falls back to native system dialogs (osascript on macOS). These steal focus and play a system sound.

### Connection Status

A banner displays when the backend disconnects, showing reconnection attempts.

---

## See Also

- [Usage](usage.md) — CLI commands
- [Configuration](configuration.md) — Config file format
- [Logging](logging.md) — Audit logs
- [API Reference](api_reference.md) — REST API and SSE events
