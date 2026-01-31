# Web UI

## Overview

The proxy is **CLI-first** — it runs fully standalone without any web interface, and all functionality is available through command-line tools. See [Usage](usage.md) for CLI commands.

The web UI is an **optional add-on** for monitoring, approvals, policy editing, and configuration. It runs on localhost only, with token authentication and CSRF protection. For minimal attack surface, you can disable it entirely.

---

## Accessing the UI

The manager daemon serves the UI and starts automatically when a proxy launches:

```
http://localhost:8765
```

The UI is accessible without login for viewing. **Approving HITL requests requires OIDC authentication** — the approver must be the same user who initiated the MCP session (session binding).

## Disabling the UI

Pass `--headless` to run without the manager or web UI:

```bash
mcp-acp start --headless
```

Or in Claude Desktop config:

```json
{
  "mcpServers": {
    "mcp-acp": {
      "command": "/path/to/mcp-acp",
      "args": ["start", "--headless"]
    }
  }
}
```

When headless:
- No manager daemon runs (port 8765 not opened)
- HITL approvals use native system dialogs (osascript on macOS)
- All functionality remains available via CLI

---

## Pages

The UI has four pages, accessible from the header navigation:

| Page | Path | Purpose |
|------|------|---------|
| Proxy List | `/` | All configured proxies at a glance |
| Proxy Detail | `/proxy/:id` | Per-proxy monitoring, policy, config, logs |
| Incidents | `/incidents` | Security events timeline |
| Auth | `/auth` | Authentication status and login |

The header also contains:
- **Pending** button — opens a side drawer with all pending HITL approvals (badge shows count)
- **Incidents** link — badge shows unread count since last visit
- **Auth dropdown** — current user and logout

### Proxy List

The landing page. Shows a card for each configured proxy with:
- Name, server name, status indicator (green = running)
- Real-time stats: Total Requests, Denied, HITL
- Click a card to open the proxy detail page

Actions:
- **Filter chips** (All / Running / Inactive) — persisted across sessions
- **Add Proxy** — opens a creation form (name, server name, transport, command/args or URL, advanced options). On success shows a Claude Desktop config snippet to copy.
- **Export All Client Configs** — copies the combined MCP client JSON for all proxies to the clipboard

### Proxy Detail

Four tabs in a left sidebar:

#### Overview

- **Transport Flow** — visual diagram: Client ↔ Proxy ↔ Backend, with connection status colors and mTLS indicator
- **Session Statistics** — four live-updating stat boxes (Total, Allowed, Denied, HITL)
- **Pending Approvals** — HITL requests waiting for a decision. Each shows tool name, resource path, subject ID, a live countdown timer (turns red below 10 seconds), and action buttons: Deny, Allow (with cache TTL), Allow once
- **Cached Decisions** — previously approved decisions with expiration countdowns. Clear all or delete individually.
- **Activity** — summary of recent proxy activity

#### Audit

- **Log Viewer** — browse audit, system, and debug logs with filters:
  - Folder selector (audit / system / debug)
  - Log type (decisions, operations, auth, system, config_history, policy_history, wire logs)
  - Time range (5m / 1h / 24h / all)
  - Filters: decision, HITL outcome, log level, session ID, request ID, policy/config version
  - Expandable rows to view full JSON entries
  - "Load More" pagination
- **Log Integrity** — audit log verification status. Red sidebar indicator when integrity issues are detected.

Debug logs are only available when `log_level` is set to `DEBUG` in proxy config.

#### Policy

Two editing modes, toggled at the top:

- **Visual Editor** — shows policy version, rule count, and default action. Each rule displays its effect (allow/deny/hitl), conditions, and has edit/delete buttons. "Add Rule" opens a form dialog for description, effect, conditions, and cache side effects.
- **JSON** — raw policy JSON editor with save button

Changes are saved to disk and automatically reloaded by the proxy without restart.

#### Config

A form covering all proxy settings:

- **Backend** — server name, transport (auto/stdio/streamable HTTP), command + args (stdio), URL + timeout (HTTP)
- **Logging** — log level (INFO/DEBUG), include payloads toggle (debug only)
- **HITL** — timeout (5–300s), approval cache TTL (300–900s)
- **Authentication** — OIDC settings (issuer, client ID, audience, scopes), API key management (set/update/remove, stored in OS keychain), binary attestation (SLSA), mTLS certificate paths
- **Save / Discard** — the form highlights with an orange border when there are unsaved changes. Config changes are saved to disk but require a proxy restart to take effect.

### Incidents

A timeline of security events across all proxies:

- Filter by proxy name and incident type (Shutdowns / Startup / Emergency Audit)
- Incidents new since your last visit glow to stand out
- "Load More" for pagination

The header badge clears when you visit the page.

### Auth

Shows current authentication state:

- Status (authenticated or not), email, name, subject ID, token expiration, refresh token status
- **Login** — starts an OAuth device flow: shows a device code, opens the identity provider verification page, polls for completion
- **Logout** — clears local credentials
- **Logout (federated)** — also signs out from the identity provider
- OIDC configuration details (issuer, client ID, audience, scopes) — read-only

---

## Approvals

HITL approval requests appear in two places:

1. **Header drawer** — click the "Pending" button to open a side sheet listing all pending approvals across all proxies. Each shows the proxy name, tool, path, subject, countdown, and action buttons.
2. **Proxy Detail → Overview** — the same approvals scoped to that proxy.

For each approval you can:
- **Allow** — approve and cache the decision for the configured TTL (similar requests auto-approved)
- **Allow once** — one-time approval, not cached
- **Deny** — reject the request

If no action is taken before the timeout, the request is automatically denied.

### Notifications

- Audio chime when a new approval arrives
- Error sound for critical events (backend disconnect, auth failures)
- Toast notifications for system events
- Document title updates to `🔴 (N) MCP ACP` when approvals are pending in a background tab

### Fallback

If the UI is not open when a HITL approval is needed, the proxy falls back to native system dialogs (osascript on macOS).

---

## Connection Status

A banner at the top of the page shows the SSE connection state:

- **Connected** — hidden (normal operation)
- **Reconnecting** — shown with spinner, auto-retries in background
- **Disconnected** — shown after repeated failures, with a manual retry button

---

## Manager Lifecycle

The manager daemon serves the web UI and coordinates multiple proxies.

### Auto-Start

The manager starts automatically when:
- A proxy starts and `--headless` is not set (default)
- You run `mcp-acp manager start` manually

### Idle Shutdown

The manager shuts down after **5 minutes of inactivity** to conserve resources.

**Idle conditions** (all must be true):
- No proxies connected
- No browser tabs with the UI open
- No API activity for 5 minutes

The manager waits 60 seconds after startup before checking, giving time to start proxies or open the UI.

Status checks (`mcp-acp manager status`) and SSE keepalives do not count as activity.

---

## See Also

- [Usage](usage.md) — CLI commands
- [Configuration](configuration.md) — Config file format
- [Logging](../security/logging.md) — Audit logs
- [API Reference](../reference/api_reference.md) — REST API and SSE events
