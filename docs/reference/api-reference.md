# API Reference

The system exposes two HTTP APIs: a **Per-Proxy API** running inside each proxy process, and a **Manager API** running as a centralized daemon that coordinates multiple proxies.

```
┌─────────────────────────────────────────────────────────────────┐
│  Manager Daemon (HTTP on port 8765)                             │
│                                                                 │
│  /api/manager/*    → Manager-owned endpoints                    │
│  /api/events       → Manager SSE stream                         │
│  /api/proxy/{name}/* → Forwarded to proxy UDS  ──┐              │
│  /api/*            → Fallback to single proxy  ──┤              │
│                                                  │              │
│  /*                → Static SPA files            │              │
└──────────────────────────────────────────────────┼──────────────┘
                                                   │
                    ┌──────────────────────────────┘
                    │ UDS (Unix Domain Socket)
                    ▼
┌──────────────────────────────────────┐
│  Per-Proxy Process                   │
│                                      │
│  /api/approvals/*  /api/policy/*     │
│  /api/auth/*       /api/config/*     │
│  /api/logs/*       /api/control/*    │
│  /api/proxies/*    /api/incidents/*  │
│  /api/stats        /api/auth-sessions│
└──────────────────────────────────────┘
```

The **web UI** connects to the Manager on port 8765. The Manager handles proxy lifecycle, authentication, and per-proxy config/policy/logs directly, then forwards remaining `/api/*` requests to the appropriate proxy via UDS.

The **CLI** communicates with individual proxies over UDS (OS file permissions = authentication), or with the Manager over UDS/HTTP.

---

## Authentication

**UDS connections**: Authenticated by OS file permissions (same user only). No token required.

**HTTP connections**: Require a session token passed via:
- `Authorization: Bearer <token>` header, or
- `api_token` cookie (HttpOnly, set automatically when loading the web UI)

Both the Manager and each proxy generate their own token on startup. In production the token is delivered as an HttpOnly cookie when serving the SPA. In dev mode (Vite on port 3000), fetch it from `GET /api/manager/auth/dev-token` or `GET /api/auth/dev-token` and pass it as a Bearer header.

**SSE endpoints** (`/api/approvals/pending`, `/api/events`) also accept `?token=<token>` as a query parameter, since the browser `EventSource` API cannot send custom headers.

---

## Per-Proxy API

These endpoints run inside each proxy process. When accessed through the Manager, prefix with `/api/proxy/{proxy_name}/` (e.g., `/api/proxy/filesystem/approvals/pending`).

### Proxies

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/proxies` | List all running proxies (includes stats) |
| `GET` | `/api/proxies/{proxy_id}` | Get proxy details (includes stats) |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/stats` | Request counters and rolling latency medians |

Returns `503` if the proxy is still starting (ProxyState not yet initialized).

**Response:**

```json
{
  "requests_total": 100,
  "requests_allowed": 80,
  "requests_denied": 15,
  "requests_hitl": 5,
  "latency": {
    "proxy_latency_ms": 14.2,
    "policy_eval_ms": 3.1,
    "hitl_wait_ms": 1200.0
  }
}
```

**Latency fields** are rolling medians over the last 1000 samples. Values are `null` when no samples have been recorded for that metric.

| Field | Description |
|-------|-------------|
| `proxy_latency_ms` | End-to-end time through proxy (allowed, non-discovery, non-HITL requests only) |
| `policy_eval_ms` | Policy engine evaluation time (all policy-evaluated requests) |
| `hitl_wait_ms` | Human-in-the-loop wait time (all HITL outcomes: cache hits, approved, denied, timeout) |

### Sessions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth-sessions` | List active authentication sessions |

Query parameters:
- `proxy_id`: Accepted but **not implemented** — all sessions are returned regardless of this value

### Approvals (Cached)

Previously approved HITL decisions stored in memory.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals/cached` | List cached HITL approvals with TTL info |
| `DELETE` | `/api/approvals/cached` | Clear all cached approvals |
| `DELETE` | `/api/approvals/cached/entry` | Delete specific cached approval |

Query parameters for `/entry`:
- `subject_id`: User's OIDC subject ID (required)
- `tool_name`: Tool name (required)
- `path`: Resource path (optional)

### Approvals (Pending)

HITL requests currently waiting for user decision. **Requires OIDC authentication** — approver must be the original requester (session binding).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/approvals/pending` | SSE stream for pending approvals |
| `GET` | `/api/approvals/pending/list` | List pending approvals (non-SSE) |
| `POST` | `/api/approvals/pending/{id}/approve` | Approve and cache |
| `POST` | `/api/approvals/pending/{id}/allow-once` | Approve without caching |
| `POST` | `/api/approvals/pending/{id}/deny` | Deny pending request |

### Control

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/control/status` | Get proxy status (uptime, policy version, reload count) |
| `POST` | `/api/control/reload-policy` | Hot-reload policy from disk |

### Policy

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/policy` | Get current policy with metadata |
| `GET` | `/api/policy/schema` | Get valid values for policy rule fields (e.g., operations) |
| `PUT` | `/api/policy` | Replace entire policy (validates, saves, auto-reloads) |
| `GET` | `/api/policy/rules` | List all policy rules |
| `POST` | `/api/policy/rules` | Add a new rule (auto-generates ID if not provided) |
| `PUT` | `/api/policy/rules/{id}` | Update a rule |
| `DELETE` | `/api/policy/rules/{id}` | Delete a rule |

**Note**: All changes trigger automatic policy reload without proxy restart. Uses last-known-good pattern — validation errors revert to previous policy.

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config` | Get current configuration |
| `PUT` | `/api/config` | Update configuration (requires proxy restart to apply) |
| `GET` | `/api/config/compare` | Compare running vs saved config |

**Note**: Config updates use deep merge — nested objects are merged, not replaced entirely.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth/status` | Get authentication status and user info |
| `POST` | `/api/auth/login` | Start OAuth device flow |
| `GET` | `/api/auth/login/poll` | Poll for device flow completion |
| `POST` | `/api/auth/logout` | Clear local credentials (keychain) |
| `POST` | `/api/auth/logout-federated` | Get federated logout URL + clear local |
| `POST` | `/api/auth/notify-login` | Notify proxy of CLI login |
| `POST` | `/api/auth/notify-logout` | Notify proxy of CLI logout |
| `GET` | `/api/auth/dev-token` | Get API token (dev mode only, 404 in production) |

Query parameters for `/login/poll`:
- `code`: The `user_code` from the `/login` response (required)

### Logs

Structured log access with filtering and pagination.

**Audit logs:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs/decisions` | Policy decision logs |
| `GET` | `/api/logs/operations` | Operation audit logs |
| `GET` | `/api/logs/auth` | Authentication event logs |

**System logs:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs/system` | System logs (WARNING, ERROR, CRITICAL) |
| `GET` | `/api/logs/config_history` | Configuration change history |
| `GET` | `/api/logs/policy_history` | Policy change history |

**Debug logs** (only when `log_level=DEBUG`):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs/client_wire` | Client ↔ Proxy wire logs |
| `GET` | `/api/logs/backend_wire` | Proxy ↔ Backend wire logs |

**Metadata:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/logs/metadata` | Available log files and filter options |

**Common query parameters:**
- `time_range`: `5m` | `1h` | `24h` | `all` (default: `5m`)
- `limit`: 1-1000 (default: 100)
- `before`: ISO timestamp cursor for pagination

**Filtering parameters:**
- `session_id`: Filter by session
- `bound_session_id`: Filter by bound (auth) session ID (decisions and auth logs only)
- `request_id`: Filter by request
- `policy_version`: Filter by policy version
- `config_version`: Filter by config version
- `decision`: Filter decisions by `allow` | `deny` | `hitl`
- `hitl_outcome`: Filter by `allowed` | `denied` | `timeout` (decisions log only)
- `event_type`: Filter by event type (auth, system, config_history, policy_history, wire logs)
- `level`: Filter system logs by `WARNING` | `ERROR` | `CRITICAL`

### Incidents

Security-related events and shutdown history.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/incidents/summary` | Summary with counts and latest critical timestamp |
| `GET` | `/api/incidents/shutdowns` | Security shutdown logs (from `shutdowns.jsonl`) |
| `GET` | `/api/incidents/bootstrap` | Bootstrap/startup error logs |
| `GET` | `/api/incidents/emergency` | Emergency audit logs (audit fallback) |

Query parameters for `/shutdowns`, `/bootstrap`, `/emergency`:
- `time_range`: `5m` | `1h` | `24h` | `all` (default: `all`)
- `limit`: 1-1000 (default: 100)
- `before`: ISO timestamp cursor for pagination

---

## Manager API

The Manager is a separate daemon that manages multiple proxies. It provides proxy lifecycle management, centralized authentication, and per-proxy configuration/policy/logs.

All Manager-owned endpoints are prefixed with `/api/manager/`.

### Request Routing

```
Incoming request to Manager (port 8765)
│
├─ /api/manager/*       → Handled by Manager directly
├─ /api/events          → Manager SSE stream
├─ /api/proxy/{name}/*  → Forwarded to named proxy via UDS
├─ /api/*               → Fallback routing:
│                          • 1 proxy registered  → forward to it
│                          • 0 proxies           → 503 "No proxies connected"
│                          • 2+ proxies          → 400 "Specify proxy using /api/proxy/{name}/..."
└─ /*                   → Static SPA files (or index.html for SPA routing)
```

### Manager Status

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/status` | Manager health (running, pid, proxies_connected) |

### Manager Authentication

These endpoints manage authentication at the Manager level. The Manager distributes tokens to connected proxies via UDS.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/auth/status` | Auth state (configured, authenticated, user info, provider details) |
| `POST` | `/api/manager/auth/login` | Start OAuth device flow (with automatic background polling) |
| `POST` | `/api/manager/auth/logout` | Clear local credentials |
| `POST` | `/api/manager/auth/logout-federated` | Get federated logout URL + clear local |
| `POST` | `/api/manager/auth/reload` | Reload tokens from storage and broadcast to proxies |
| `POST` | `/api/manager/auth/clear` | Clear tokens (logout all proxies) |
| `GET` | `/api/manager/auth/dev-token` | Get API token (dev mode only, 404 in production) |

Unlike the per-proxy auth endpoints, the Manager has no `/login/poll` (it polls automatically in the background and notifies via SSE) and no `/notify-login` or `/notify-logout` (the Manager is the source of truth for auth state).

### Proxy Lifecycle

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/proxies` | List all configured proxies |
| `GET` | `/api/manager/proxies/{proxy_id}` | Get proxy detail |
| `POST` | `/api/manager/proxies` | Create a new proxy |
| `DELETE` | `/api/manager/proxies/{proxy_id}` | Delete a proxy |
| `GET` | `/api/manager/config-snippet` | Generate MCP client JSON snippet |

Query parameters for `DELETE`:
- `purge`: Delete config/policy files on disk (optional, default: false)

Query parameters for `/config-snippet`:
- `proxy`: Single proxy name (optional, returns all if omitted)

### Per-Proxy Configuration (via Manager)

The Manager reads/writes proxy config and policy files directly on disk — these requests are **not** forwarded to the proxy process.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/proxies/{proxy_id}/config` | Get proxy configuration |
| `PUT` | `/api/manager/proxies/{proxy_id}/config` | Update proxy configuration |
| `PUT` | `/api/manager/proxies/{proxy_id}/config/api-key` | Store HTTP backend API key in OS keychain |
| `DELETE` | `/api/manager/proxies/{proxy_id}/config/api-key` | Remove HTTP backend API key from OS keychain |

### Per-Proxy Policy (via Manager)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/proxies/{proxy_id}/policy` | Get proxy policy |
| `PUT` | `/api/manager/proxies/{proxy_id}/policy` | Replace entire policy |
| `GET` | `/api/manager/proxies/{proxy_id}/policy/rules` | List policy rules |
| `POST` | `/api/manager/proxies/{proxy_id}/policy/rules` | Add a rule (201) |
| `PUT` | `/api/manager/proxies/{proxy_id}/policy/rules/{rule_id}` | Update a rule |
| `DELETE` | `/api/manager/proxies/{proxy_id}/policy/rules/{rule_id}` | Delete a rule (204) |

### Per-Proxy Logs (via Manager)

Mirrors the Per-Proxy log endpoints. Same query parameters and filtering. All paths are prefixed with `/api/manager/proxies/{proxy_id}/logs/`.

| Path suffix | Description |
|-------------|-------------|
| `/decisions` | Policy decision logs |
| `/operations` | Operation audit logs |
| `/auth` | Authentication event logs |
| `/system` | System logs |
| `/config_history` | Configuration change history |
| `/policy_history` | Policy change history |
| `/client_wire` | Client wire logs (debug only) |
| `/backend_wire` | Backend wire logs (debug only) |
| `/metadata` | Log file metadata |

### Per-Proxy Audit Integrity (via Manager)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/proxies/{proxy_id}/audit/verify` | Verify audit log integrity (hash chain validation) |
| `POST` | `/api/manager/proxies/{proxy_id}/audit/repair` | Repair audit integrity state |

### Manager Incidents (Aggregated)

Aggregates incidents across all proxies.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/manager/incidents` | Incidents from all proxies (filterable) |
| `GET` | `/api/manager/incidents/summary` | Summary with counts across all proxies |

Query parameters for `/incidents`:
- `proxy`: Filter by proxy name (optional)
- `incident_type`: `shutdown` | `bootstrap` | `emergency` (optional)
- `time_range`: `5m` | `1h` | `24h` | `all` (default: `all`)
- `limit`: 1-1000 (default: 100)
- `before`: ISO timestamp cursor for pagination

Query parameters for `/incidents/summary`:
- `since`: ISO timestamp — only count incidents after this time (optional)

### Manager SSE Events

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/events` | Aggregated SSE stream from all connected proxies |

On connect, sends snapshots of each proxy's current state (pending approvals, cached approvals, request stats). Then streams real-time events from all proxies.

This is the endpoint the web UI subscribes to. See [SSE Events](#sse-events) below for event types.

---

## SSE Events

Two SSE endpoints exist:

| Endpoint | Scope | Used by |
|----------|-------|---------|
| `/api/approvals/pending` | Single proxy | Direct proxy access |
| `/api/events` | All proxies (aggregated) | Web UI via Manager |

Both emit the same event types. Each event includes a `proxy_id` field identifying the source proxy.

### Event Types

**HITL Lifecycle:**
- `snapshot` — Initial pending approvals on connection
- `cached_snapshot` — Initial cached approvals on connection
- `pending_created` — New approval request
- `pending_resolved` — Approval decided (allow/deny)
- `pending_timeout` — Approval timed out
- `pending_not_found` — Approval already resolved/expired

**Cache Operations:**
- `cache_cleared` — All cached approvals cleared
- `cache_entry_deleted` — Single cache entry removed

**Backend Connection:**
- `backend_connected` — Backend connection established
- `backend_reconnected` — Backend recovered after failure
- `backend_disconnected` — Backend connection lost
- `backend_timeout` — Backend request timeout
- `backend_refused` — Backend connection refused

**TLS/mTLS:**
- `tls_error` — General TLS error
- `mtls_failed` — mTLS authentication failed
- `cert_validation_failed` — Certificate validation failed

**Authentication:**
- `auth_login` — User logged in
- `auth_logout` — User logged out
- `auth_session_expiring` — Session expiring soon
- `token_refresh_failed` — Token refresh failed
- `token_validation_failed` — Token validation failed
- `auth_failure` — Authentication error

**Policy:**
- `policy_reloaded` — Policy hot-reloaded
- `policy_reload_failed` — Policy reload error
- `policy_file_not_found` — Policy file missing
- `policy_rollback` — Rollback to previous policy
- `config_change_detected` — Config file changed

**Rate Limiting:**
- `rate_limit_triggered` — Rate limit exceeded
- `rate_limit_approved` — Rate limit override approved
- `rate_limit_denied` — Rate limit override denied

**Request Processing:**
- `request_error` — Request processing error
- `hitl_parse_failed` — HITL request parsing failed
- `tool_sanitization_failed` — Tool/path sanitization failed

**Proxy Lifecycle:**
- `proxy_deleted` — Proxy removed

**Live Updates:**
- `stats_updated` — Request statistics changed
- `new_log_entries` — New log entries available
- `incidents_updated` — Incident data changed

**Critical Events (Proxy Shutdown):**
- `critical_shutdown` — Proxy shutting down
- `audit_init_failed` — Audit system initialization failed
- `device_health_failed` — Device health check failed
- `session_hijacking` — Session binding violation detected
- `audit_tampering` — Audit log tampering detected
- `audit_missing` — Audit file missing
- `audit_permission_denied` — Audit permission denied
- `health_degraded` — Health status degraded
- `health_monitor_failed` — Health monitor failed

### Event Format

```json
{
  "type": "pending_created",
  "severity": "info",
  "timestamp": "2025-01-10T12:00:00.000Z",
  "proxy_id": "px_a1b2c3d4:my-server",
  "approval": {
    "id": "def456",
    "tool_name": "read_file",
    "path": "/etc/passwd",
    "subject_id": "user@example.com",
    "timeout_seconds": 60
  }
}
```

**Severity levels:** `success`, `info`, `warning`, `error`, `critical`

---

## Error Responses

All endpoints return standard HTTP status codes:

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created (for POST creating resources) |
| `204` | No content (for DELETE) |
| `400` | Bad request (invalid parameters) |
| `401` | Unauthorized (missing/invalid token) |
| `404` | Not found |
| `409` | Conflict (duplicate ID, proxy already running) |
| `422` | Validation error (invalid request body) |
| `500` | Internal server error |
| `502` | Bad gateway (upstream error, e.g., OAuth) |
| `503` | Service unavailable (provider not ready, no proxies connected) |
| `504` | Gateway timeout (proxy request timed out) |

### Structured Error Format

All errors return a structured response with error codes for programmatic handling:

```json
{
  "detail": {
    "code": "APPROVAL_NOT_FOUND",
    "message": "Pending approval not found",
    "details": {"approval_id": "abc123"}
  }
}
```

### Error Codes

| Domain | Codes |
|--------|-------|
| Auth | `AUTH_REQUIRED`, `AUTH_FORBIDDEN`, `AUTH_PROVIDER_UNAVAILABLE`, `AUTH_DEVICE_FLOW_FAILED`, `AUTH_DEVICE_FLOW_LIMIT` |
| Approval | `APPROVAL_NOT_FOUND`, `APPROVAL_UNAUTHORIZED`, `CACHED_APPROVAL_NOT_FOUND` |
| Policy | `POLICY_NOT_FOUND`, `POLICY_INVALID`, `POLICY_RULE_NOT_FOUND`, `POLICY_RULE_DUPLICATE`, `POLICY_RELOAD_FAILED` |
| Config | `CONFIG_NOT_FOUND`, `CONFIG_INVALID`, `CONFIG_SAVE_FAILED` |
| Proxy | `PROXY_NOT_FOUND`, `PROXY_INVALID`, `PROXY_EXISTS`, `PROXY_RUNNING`, `PROXY_CREATION_FAILED`, `BACKEND_UNREACHABLE`, `BACKEND_DUPLICATE` |
| Resource | `NOT_FOUND`, `LOG_NOT_AVAILABLE`, `CONFLICT` |
| Validation | `VALIDATION_ERROR` (includes `validation_errors` array with field-level details) |
| Internal | `INTERNAL_ERROR`, `NOT_IMPLEMENTED`, `UPSTREAM_ERROR`, `SERVICE_UNAVAILABLE` |

**Validation error example:**

```json
{
  "detail": {
    "code": "VALIDATION_ERROR",
    "message": "effect: Input should be 'allow', 'deny' or 'hitl'",
    "validation_errors": [
      {"loc": ["body", "effect"], "msg": "Input should be 'allow', 'deny' or 'hitl'", "type": "literal_error"}
    ]
  }
}
```

---

## See Also

- [Architecture](architecture.md) for system overview
- [Configuration](../getting-started/configuration.md) for config file format
- [Policies](policies.md) for policy rule syntax
