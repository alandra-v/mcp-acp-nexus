# API Reference

The Management API provides HTTP endpoints for monitoring, configuration, and HITL approvals. It runs inside the proxy process and is accessible via:

- **Unix Domain Socket (UDS)**: For CLI communication (OS file permissions = authentication)
- **HTTP**: For browser/web UI (token-based authentication)

---

## Authentication

**UDS connections**: Authenticated by OS file permissions (same user only).

**HTTP connections**: Require a session token passed via:
- `Authorization: Bearer <token>` header, or
- `api_token` cookie (HttpOnly in production)

Tokens are issued during device flow authentication or injected into the UI on page load.

---

## Endpoints

### Proxies

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/proxies` | List all running proxies (includes stats) |
| `GET` | `/api/proxies/{proxy_id}` | Get proxy details (includes stats) |

### Sessions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/auth-sessions` | List active user sessions |

Query parameters:
- `proxy_id`: Filter by proxy (optional, for multi-proxy future)

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
- `path`: File path (required)

### Approvals (Pending)

HITL requests currently waiting for user decision. **Requires OIDC authentication** - approver must be the original requester (session binding).

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
| `PUT` | `/api/policy` | Replace entire policy (validates, saves, auto-reloads) |
| `GET` | `/api/policy/rules` | List all policy rules |
| `POST` | `/api/policy/rules` | Add a new rule (auto-generates ID if not provided) |
| `PUT` | `/api/policy/rules/{id}` | Update a rule |
| `DELETE` | `/api/policy/rules/{id}` | Delete a rule |

**Note**: All changes trigger automatic policy reload without proxy restart. Uses last-known-good pattern - validation errors revert to previous policy.

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config` | Get current configuration |
| `PUT` | `/api/config` | Update configuration (requires proxy restart to apply) |
| `GET` | `/api/config/compare` | Compare running vs saved config |

**Note**: Config updates use deep merge - nested objects are merged, not replaced entirely.

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
- `code`: Device code from `/login` response (required)

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
- `time_range`: `5m` | `1h` | `24h` | `all` (default: `1h`)
- `limit`: 1-1000 (default: 100)
- `before`: ISO timestamp cursor for pagination

**Filtering parameters:**
- `session_id`: Filter by session
- `request_id`: Filter by request
- `policy_version`: Filter by policy version
- `config_version`: Filter by config version
- `decision`: Filter decisions by `allow` | `deny` | `hitl`
- `hitl_outcome`: Filter by `user_allowed` | `user_denied` | `timeout`
- `event_type`: Filter auth logs by event type
- `level`: Filter system logs by `WARNING` | `ERROR` | `CRITICAL`

### Incidents

Security-related events and shutdown history.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/incidents/summary` | Summary with counts and latest critical timestamp |
| `GET` | `/api/incidents/shutdowns` | Security shutdown logs (from `shutdowns.jsonl`) |
| `GET` | `/api/incidents/bootstrap` | Bootstrap/startup error logs |
| `GET` | `/api/incidents/emergency` | Emergency audit logs (audit fallback) |

---

## SSE Events

The `/api/approvals/pending` endpoint provides Server-Sent Events for real-time updates.

### Event Types

**HITL Lifecycle:**
- `snapshot` - Initial pending approvals on connection
- `cached_snapshot` - Initial cached approvals on connection
- `pending_created` - New approval request
- `pending_resolved` - Approval decided (allow/deny)
- `pending_timeout` - Approval timed out
- `pending_not_found` - Approval already resolved/expired

**Cache Operations:**
- `cache_cleared` - All cached approvals cleared
- `cache_entry_deleted` - Single cache entry removed

**Backend Connection:**
- `backend_connected` - Backend connection established
- `backend_reconnected` - Backend recovered after failure
- `backend_disconnected` - Backend connection lost
- `backend_timeout` - Backend request timeout
- `backend_refused` - Backend connection refused

**TLS/mTLS:**
- `tls_error` - General TLS error
- `mtls_failed` - mTLS authentication failed
- `cert_validation_failed` - Certificate validation failed

**Authentication:**
- `auth_login` - User logged in
- `auth_logout` - User logged out
- `auth_session_expiring` - Session expiring soon
- `token_refresh_failed` - Token refresh failed
- `token_validation_failed` - Token validation failed
- `auth_failure` - Authentication error

**Policy:**
- `policy_reloaded` - Policy hot-reloaded
- `policy_reload_failed` - Policy reload error
- `policy_file_not_found` - Policy file missing
- `policy_rollback` - Rollback to previous policy
- `config_change_detected` - Config file changed

**Rate Limiting:**
- `rate_limit_triggered` - Rate limit exceeded
- `rate_limit_approved` - Rate limit override approved
- `rate_limit_denied` - Rate limit override denied

**Request Processing:**
- `request_error` - Request processing error
- `hitl_parse_failed` - HITL request parsing failed
- `tool_sanitization_failed` - Tool/path sanitization failed

**Live Updates:**
- `stats_updated` - Request statistics changed
- `new_log_entries` - New log entries available

**Critical Events (Proxy Shutdown):**
- `critical_shutdown` - Proxy shutting down
- `audit_init_failed` - Audit system initialization failed
- `device_health_failed` - Device health check failed
- `session_hijacking` - Session binding violation detected
- `audit_tampering` - Audit log tampering detected
- `audit_missing` - Audit file missing
- `audit_permission_denied` - Audit permission denied
- `health_degraded` - Health status degraded
- `health_monitor_failed` - Health monitor failed

### Event Format

```json
{
  "type": "pending_created",
  "severity": "info",
  "timestamp": "2025-01-10T12:00:00.000Z",
  "proxy_id": "abc123:my-server",
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
| `409` | Conflict (duplicate ID) |
| `422` | Validation error (invalid request body) |
| `500` | Internal server error |
| `502` | Bad gateway (upstream error, e.g., OAuth) |
| `503` | Service unavailable (provider not ready) |

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

**Error codes by domain:**

| Domain | Codes |
|--------|-------|
| Auth | `AUTH_REQUIRED`, `AUTH_FORBIDDEN`, `AUTH_PROVIDER_UNAVAILABLE`, `AUTH_DEVICE_FLOW_FAILED` |
| Approval | `APPROVAL_NOT_FOUND`, `APPROVAL_UNAUTHORIZED`, `CACHED_APPROVAL_NOT_FOUND` |
| Policy | `POLICY_NOT_FOUND`, `POLICY_INVALID`, `POLICY_RULE_NOT_FOUND`, `POLICY_RULE_DUPLICATE`, `POLICY_RELOAD_FAILED` |
| Config | `CONFIG_NOT_FOUND`, `CONFIG_INVALID`, `CONFIG_SAVE_FAILED` |
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
- [Configuration](configuration.md) for config file format
- [Policies](policies.md) for policy rule syntax
