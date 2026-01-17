# Authentication

## Overview

Authentication supports the Zero Trust security model:

1. **User Identity**: Prove WHO the user is via OAuth/OIDC
2. **Device Posture**: Validate device meets security requirements (disk encryption, SIP)
3. **Binary Attestation**: Verify backend binary integrity before spawning (STDIO)
4. **Session Binding**: Link all requests to authenticated identity

Authentication is **mandatory** - the proxy refuses to start without valid credentials.

---

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FIRST TIME SETUP (one-time)                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. User runs: mcp-acp-nexus init  (configures OIDC)                      │
│ 2. User runs: mcp-acp-nexus auth login                                   │
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
mcp-acp-nexus auth login              # Authenticate via browser
mcp-acp-nexus auth login --no-browser # Display code only, don't open browser
mcp-acp-nexus auth status             # Check authentication state
mcp-acp-nexus auth status --json      # Output as JSON
mcp-acp-nexus auth logout             # Clear stored credentials
mcp-acp-nexus auth logout --federated # Also log out of IdP in browser
```

### auth login

Authenticates using OAuth 2.0 Device Flow (RFC 8628):

1. Requests device code from identity provider
2. Displays user code and verification URL
3. Opens browser automatically (unless `--no-browser`)
4. Polls for tokens until user completes authentication
5. Stores tokens in keychain
6. Notifies running proxy via API

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

## Binary Attestation (STDIO Backends)

For STDIO backends, the proxy can verify the backend binary before spawning it. This prevents execution of tampered or unauthorized binaries.

### Configuration

Add `attestation` to the `stdio` config:

```json
{
  "backend": {
    "transport": "stdio",
    "stdio": {
      "command": "node",
      "args": ["server.js"],
      "attestation": {
        "expected_sha256": "3be943172b502b245545fbfd57706c210fabb9ee058829c5bf00c3f67c8fb474",
        "require_signature": true,
        "slsa_owner": "github-username"
      }
    }
  }
}
```

All attestation fields are optional. If `attestation` is omitted or `null`, no verification is performed.

### Verification Modes

| Field | Description | Platform |
|-------|-------------|----------|
| `expected_sha256` | Binary hash must match (hex string, 64 chars) | All |
| `require_signature` | Require valid code signature via `codesign -v` | macOS only |
| `slsa_owner` | Verify SLSA provenance via `gh attestation verify --owner` | All (requires `gh` CLI) |

All configured checks must pass. If any check fails, the proxy refuses to start.

### Hash Verification

Verifies the binary hasn't been modified:

```bash
# Get hash for configuration
shasum -a 256 $(which node)
# Output: 3be943172b502b245545fbfd57706c210fabb9ee058829c5bf00c3f67c8fb474  /opt/homebrew/bin/node
```

The proxy resolves the command via `PATH`, follows symlinks with `realpath()`, then computes SHA-256. Hash comparison uses constant-time `hmac.compare_digest()`.

### Code Signature Verification (macOS)

Verifies the binary has a valid Apple code signature:

```bash
# What the proxy runs internally
codesign -v --strict /path/to/binary
```

System binaries (`/bin/ls`, `/usr/bin/node`) are signed. Scripts and most npm packages are not.

**Default**: `false` (opt-in). Set `require_signature: true` to enable.

### SLSA Provenance Verification

Verifies the binary was built by a trusted CI/CD pipeline using [SLSA](https://slsa.dev/) attestations:

```bash
# What the proxy runs internally
gh attestation verify --owner <slsa_owner> /path/to/binary
```

**Requirements**:
- `gh` CLI installed and authenticated (`gh auth login`)
- Binary must have GitHub attestation from the specified owner

**Use case**: Standalone binaries distributed via GitHub releases (e.g., Go/Rust compiled tools). Does not apply to npm packages.

### Applicability

| Binary Type | Hash | Codesign | SLSA |
|-------------|------|----------|------|
| System binaries (`/bin/ls`) | Yes | Yes | No |
| Node.js (`node`) | Yes | Yes (if from official installer) | No |
| npm packages (via `npx`) | Verify `node` binary | Verify `node` binary | No |
| GitHub release binaries | Yes | Rarely | Yes |

For npm-based MCP servers, attestation verifies the `node` binary, not the JavaScript package. npm has its own integrity model via `package-lock.json` checksums.

### Failure Behavior

If any configured attestation check fails:

1. Error logged with details (expected vs actual hash, signature error, etc.)
2. Proxy refuses to start
3. Human-readable error message displayed

This is fail-closed - the backend is never spawned if attestation fails.

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
3. User runs: `mcp-acp-nexus auth login`
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

Validated tokens populate the ABAC Subject model for policy evaluation:

| Field | Source | Example Policy Use |
|-------|--------|-------------------|
| `id` | JWT `sub` claim | User-specific rules |
| `issuer` | JWT `iss` claim | Provider restrictions |
| `scopes` | JWT `scope` claim | `subject.scopes contains "admin"` |
| `token_age_s` | Computed from `iat` | `subject.token_age_s < 3600` |

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

See [logging_specs/audit/auth.md](logging_specs/audit/auth.md) for full schema.

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

- [mTLS](mtls.md) for backend authentication
- [API Reference](api_reference.md) for auth endpoints
- [Security](security.md) for security architecture
- [Configuration](configuration.md) for full config reference
