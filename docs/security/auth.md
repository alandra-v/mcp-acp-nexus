# Authentication

## Overview

Authentication supports the Zero Trust security model:

1. **User Identity**: Prove WHO the user is via OAuth/OIDC
2. **Device Posture**: Validate device meets security requirements (disk encryption, SIP)
3. **Session Binding**: Link all requests to authenticated identity

Authentication is **mandatory** - the proxy refuses to start without valid credentials.

---

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FIRST TIME SETUP (one-time)                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. User runs: mcp-acp init  (configures OIDC)                            │
│ 2. User runs: mcp-acp auth login                                         │
│    └── Browser opens → login page                                           │
│    └── User authenticates (username/password, SSO, MFA)                     │
│    └── Token stored in OS Keychain                                          │
│ 3. User configures Claude Desktop to use proxy                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EVERY SESSION (automatic)                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. User opens Claude Desktop                                                │
│ 2. Claude Desktop starts proxy via STDIO                                    │
│ 3. Proxy startup:                                                           │
│    a. Load token from Keychain                                              │
│    b. Validate JWT (signature, issuer, audience, expiry)                    │
│    c. If expired → try refresh with refresh_token                           │
│    d. Run device health checks (disk encryption, SIP)                       │
│    e. If all pass → proxy ready                                             │
│    f. If ANY fail → proxy exits with error popup                            │
│ 4. Per-request: validate identity (every request)                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## CLI Commands

```bash
mcp-acp auth login              # Authenticate via browser
mcp-acp auth login --no-browser # Display code only, don't open browser
mcp-acp auth status             # Check authentication state
mcp-acp auth status --json      # Output as JSON
mcp-acp auth logout             # Clear stored credentials
mcp-acp auth logout --federated # Also log out of IdP in browser
```

### auth login

Authenticates using OAuth 2.0 Device Flow (RFC 8628):

1. Requests device code from identity provider
2. Displays user code and verification URL
3. Opens browser automatically (unless `--no-browser`)
4. Polls for tokens until user completes authentication
5. Stores tokens in keychain
6. Notifies running manager to broadcast to proxies

**Timeout**: 5 minutes to complete authentication.

### auth status

Displays current authentication state including token validity, user info, and mTLS certificate status.

### auth logout

Removes stored credentials from keychain and clears HITL approval cache.

**What gets cleared:**
- Tokens from OS keychain
- In-memory identity cache
- HITL approval cache (prevents stale approvals on re-login)

Use `--federated` to also log out of the identity provider in browser (recommended when switching users).

---

## Token Storage

Tokens are stored securely using OS-native credential storage:

| Platform | Backend |
|----------|---------|
| macOS | Keychain |
| Linux | Secret Service (D-Bus) |
| Windows | Credential Locker |

**Fallback**: When keychain is unavailable (headless server), tokens are stored in an encrypted file using Fernet (AES-128-CBC) with PBKDF2-SHA256 key derivation.

---

## JWT Validation

Every request validates the JWT:

1. **Signature**: Verify using JWKS from identity provider
2. **Issuer**: Must match configured `oidc.issuer`
3. **Audience**: Must match configured `oidc.audience`
4. **Expiration**: Token must not be expired

**JWKS Caching**: Public keys are cached for 10 minutes. If cache expires and JWKS endpoint is unreachable, proxy shuts down (fail-closed).

**Per-Request Validation**: Identity is validated on every request - logout and token revocation take effect immediately.

---

## Device Health Checks

Before proxy startup and every 5 minutes during operation, device security posture is validated:

| Check | macOS | Requirement |
|-------|-------|-------------|
| Disk Encryption | `fdesetup status` | FileVault must be enabled |
| System Integrity | `csrutil status` | SIP must be enabled |

If device becomes unhealthy during operation, proxy shuts down immediately.

---

## Token Lifetimes

| Token | Typical Lifetime | Strategy |
|-------|------------------|----------|
| Access Token | 24 hours | Validate per-request |
| Refresh Token | 30 days | Auto-refresh silently |
| ID Token | 24 hours | Extract user claims |

### Automatic Token Refresh

When access token expires, the proxy automatically refreshes using the refresh token. If refresh fails, user must re-authenticate.

### Session Expiry Warning

The proxy emits an SSE event (`auth_session_expiring`) 15 minutes before token expiration, allowing the UI to warn users.

### When Refresh Token Expires

1. Proxy emits SSE event: `token_refresh_failed`
2. Popup notification: "Authentication expired"
3. User runs: `mcp-acp auth login`
4. User restarts Claude Desktop

---

## Configuration

```json
{
  "auth": {
    "oidc": {
      "issuer": "https://your-tenant.auth0.com/",
      "client_id": "your-client-id",
      "audience": "https://your-api.example.com",
      "scopes": ["openid", "profile", "email", "offline_access"]
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `issuer` | OIDC provider URL |
| `client_id` | OAuth client ID for Device Flow |
| `audience` | API identifier for token validation |
| `scopes` | OAuth scopes (default includes `offline_access` for refresh) |

---

## Session Binding

Sessions are bound to user identity to prevent session hijacking:

- Session ID format: `<user_id>:<session_uuid>`
- Session TTL: 8 hours (shorter than token lifetime)
- Every request validates that the token identity matches the session-bound user

### Session Binding Violation

If a request arrives with a different user identity than the session was bound to:

1. Proxy shuts down immediately (exit code 15)
2. Incident logged for investigation

This fail-closed behavior prevents session hijacking if an attacker obtains different credentials mid-session.

---

## Subject Claims

Validated tokens populate the ABAC Subject model:

| Field | Source | Description |
|-------|--------|-------------|
| `id` | JWT `sub` claim | User identifier (usable in policy via `subject_id` condition) |
| `issuer` | JWT `iss` claim | Identity provider URL |
| `scopes` | JWT `scope` claim | Granted OAuth scopes |
| `token_age_s` | Computed from `iat` | Seconds since token was issued |

**Policy support**: Currently only `subject_id` can be used in policy rules. Other claims are available in the Subject model for audit logging and future policy extensions.

---

## Fail-Closed Behavior

Authentication failures result in proxy shutdown:

| Failure | Exit Code | Recovery |
|---------|-----------|----------|
| No token in keychain | 13 | `auth login` |
| Token expired + refresh failed | 13 | `auth login` |
| Invalid signature | 13 | `auth login` |
| Issuer/audience mismatch | 13 | Check config |
| JWKS endpoint unreachable | 12 | Check network |
| Device unhealthy | 14 | Enable FileVault/SIP |
| Session binding violation | 15 | Investigate |

---

## Audit Logging

Authentication events are logged to `audit/auth.jsonl`:

- `token_invalid`: Validation failure
- `token_refreshed`: Successful token refresh
- `token_refresh_failed`: Refresh failure
- `session_started`: Proxy startup with valid auth
- `session_ended`: Proxy shutdown
- `device_health_failed`: Device checks failed

Success events for per-request validation are not logged to reduce noise.

See [logging_specs/audit/auth.md](../reference/logging_specs/audit/auth.md) for full schema.

---

## Supported Identity Providers

The proxy uses standard protocols and works with any compliant provider:

| Protocol | Standard | Purpose |
|----------|----------|---------|
| OAuth 2.0 Device Flow | RFC 8628 | CLI authentication |
| OpenID Connect | OIDC Core 1.0 | Identity, JWT tokens |
| JWKS | RFC 7517 | Public keys for verification |

### Provider Setup

1. Create an application supporting **Device Authorization Grant**
2. Note the **Client ID** (no secret needed for Device Flow)
3. Create an API/Resource Server for the **audience** claim
4. Ensure **JWKS endpoint** is accessible

---

## See Also

- [Backend Authentication](backend_auth.md) for mTLS and binary attestation
- [API Reference](../reference/api_reference.md) for auth endpoints
- [Security](security.md) for security architecture
- [Configuration](../getting-started/configuration.md) for full config reference
