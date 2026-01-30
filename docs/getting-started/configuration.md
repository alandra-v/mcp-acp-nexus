# Configuration

> **Zero Trust by Default**: Authentication is mandatory. Policy `default_action` is always `deny`. The proxy fails fast on configuration errors rather than falling back to insecure defaults.

## How to Configure

Configuration is a two-step process: initialize authentication, then add proxies.

**Step 1: Initialize authentication** (creates `manager.json`, shared across all proxies):

```bash
# Interactive setup (recommended)
mcp-acp init

# Non-interactive setup
mcp-acp init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id your-client-id \
  --oidc-audience your-api-audience
```

**Init options**:
- `--non-interactive` - Skip prompts (requires all OIDC flags)
- `--oidc-issuer`, `--oidc-client-id`, `--oidc-audience` - Authentication (required)
- `--force` - Overwrite existing config without prompting

**Step 2: Add a proxy** (creates per-proxy `config.json` and `policy.json`):

```bash
# Interactive setup (recommended)
mcp-acp proxy add

# Non-interactive STDIO backend
mcp-acp proxy add --name filesystem \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"

# Non-interactive HTTP backend with mTLS
mcp-acp proxy add --name my-api \
  --server-name my-api \
  --connection-type http \
  --url https://localhost:3000/mcp \
  --mtls-cert /path/to/client.crt \
  --mtls-key /path/to/client.key \
  --mtls-ca /path/to/ca-bundle.crt
```

**Proxy add options**:
- `--name, -n` - Proxy name (1-64 chars, alphanumeric/hyphens/underscores, cannot start with `_` or `.`, reserved: `manager`, `all`, `default`)
- `--server-name` - Display name for the backend server
- `--connection-type` - `stdio`, `http`, or `auto`
- `--command`, `--args` - STDIO backend command and arguments (comma-separated)
- `--url`, `--timeout` - HTTP backend URL and timeout (1-300s, default: 30)
- `--api-key` - API key or bearer token for HTTP backend auth (stored securely in keychain)
- `--mtls-cert`, `--mtls-key`, `--mtls-ca` - mTLS for HTTPS backends (all three required if any provided)
- `--attestation-slsa-owner`, `--attestation-sha256`, `--attestation-require-signature` - Binary attestation for STDIO backends

To manage existing configuration (all subcommands accept `--manager` or `--proxy <name>`):

```bash
mcp-acp config show --manager              # View manager config
mcp-acp config show --proxy my-proxy       # View proxy config (--json for machine-readable)
mcp-acp config path                        # Show all config file paths
mcp-acp config edit --proxy my-proxy       # Edit in $EDITOR (validates after save)
mcp-acp config validate                    # Validate all configs
```

**No config hot reload**: Config changes require proxy restart. Policy supports hot-reload via `mcp-acp policy reload`, `SIGHUP`, or the management API. All configuration changes are logged to `config_history.jsonl` for audit.

---

## Where Configuration is Stored

Configuration is stored in an OS-specific application directory:

| OS | Location |
|----|----------|
| macOS | `~/Library/Application Support/mcp-acp/` |
| Linux | `~/.config/mcp-acp/` |
| Windows | `C:\Users\<user>\AppData\Roaming\mcp-acp\` |

**Files**:
```
<config_dir>/
├── manager.json                    # Shared settings (OIDC auth, ui_port, log_dir)
└── proxies/
    └── <name>/
        ├── config.json             # Per-proxy settings (backend, HITL, mTLS, logging)
        └── policy.json             # Per-proxy security policies
```

**Log directory**: Platform-specific default (configurable in `manager.json`). Logs are stored in `mcp-acp/`:

| Platform | Default log_dir |
|----------|----------------|
| macOS | `~/Library/Logs` |
| Linux | `~/.local/state` (XDG) |

```
<log_dir>/mcp-acp/
├── manager/                    # Manager daemon logs
│   └── system.jsonl
└── proxies/                    # Proxy logs (one subfolder per proxy)
    └── <name>/                 # Proxy name (default: "default")
        ├── debug/              # Only created when log_level=DEBUG
        │   ├── client_wire.jsonl
        │   └── backend_wire.jsonl
        ├── system/
        │   ├── system.jsonl
        │   ├── config_history.jsonl
        │   └── policy_history.jsonl
        └── audit/              # Always enabled (security audit trail)
            ├── operations.jsonl
            ├── decisions.jsonl
            └── auth.jsonl
```

**File permissions**: Config directory is `0o700` (owner only), config files are `0o600`. Writes are atomic to prevent corruption. See [Security](../security/security.md) for details.

**Bootstrap log**: If config is invalid and `log_dir` is unavailable, errors are written to `bootstrap.jsonl` in the config directory.

---

## What is Configured

### manager.json

Shared settings created by `mcp-acp init`. OIDC authentication is shared across all proxies.

```json
{
  "ui_port": 8765,
  "log_dir": "~/Library/Logs",
  "auth": {
    "oidc": {
      "issuer": "https://your-tenant.auth0.com",
      "client_id": "your-client-id",
      "audience": "your-api-audience",
      "scopes": ["openid", "profile", "email", "offline_access"]
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `ui_port` | HTTP port for web UI (default: 8765, range: 1024-65535) |
| `log_dir` | Base directory for all logs (platform default, see log directory table above) |
| `auth.oidc.issuer` | OIDC issuer URL (must start with `https://`) |
| `auth.oidc.client_id` | Auth0 application client ID |
| `auth.oidc.audience` | API audience for token validation |
| `auth.oidc.scopes` | OAuth scopes (default: `["openid", "profile", "email", "offline_access"]`) |

### Per-Proxy config.json

Per-proxy settings created by `mcp-acp proxy add`. Each proxy has independent backend, HITL, mTLS, and logging configuration.

```json
{
  "proxy_id": "px_a1b2c3d4:server-filesystem",
  "created_at": "2025-12-03T10:30:45.123Z",
  "backend": {
    "server_name": "filesystem",
    "transport": "stdio",
    "stdio": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  },
  "hitl": {
    "timeout_seconds": 60,
    "approval_ttl_seconds": 600
  },
  "log_level": "INFO",
  "include_payloads": true
}
```

Optional sections not shown: `backend.stdio.attestation`, `backend.http`, `mtls`. See field tables below for all options.

### Proxy Identity

| Field | Description |
|-------|-------------|
| `proxy_id` | Stable identifier (`px_{uuid8}:{sanitized_backend_name}`), auto-generated on creation |
| `created_at` | ISO 8601 timestamp of proxy creation |

### Backend Settings

| Field | Description |
|-------|-------------|
| `backend.server_name` | Display name for the backend server |
| `backend.transport` | `"stdio"`, `"streamablehttp"`, or `"auto"` (default: `"auto"`) |
| `backend.stdio.command` | Command to spawn backend (e.g., `npx`) |
| `backend.stdio.args` | Arguments for the command |
| `backend.stdio.attestation.expected_sha256` | Expected SHA-256 hash of the binary (optional) |
| `backend.stdio.attestation.require_signature` | Require valid code signature, macOS only (optional) |
| `backend.stdio.attestation.slsa_owner` | GitHub owner for SLSA provenance verification (optional) |
| `backend.http.url` | Backend Streamable HTTP server URL |
| `backend.http.timeout` | Streamable HTTP connection timeout in seconds (default: 30, min: 1, max: 300) |
| `backend.http.credential_key` | Keychain reference for API key/bearer token (set via `--api-key`, see [Backend Auth](../security/backend_auth.md)) |

### mTLS Settings

mTLS is configured per-proxy (different backends may need different certificates).

| Field | Description |
|-------|-------------|
| `mtls.client_cert_path` | Client certificate path, PEM format |
| `mtls.client_key_path` | Client private key path, PEM format |
| `mtls.ca_bundle_path` | CA bundle for server verification, PEM format |

### Logging Settings

Logging is configured per-proxy. The base `log_dir` is in `manager.json`.

| Field | Description |
|-------|-------------|
| `log_level` | `"DEBUG"` or `"INFO"` (default: `"INFO"`). DEBUG enables wire logs for this proxy |
| `include_payloads` | Include full message payloads in debug logs (default: `true`) |

### HITL Settings

Human-in-the-Loop settings are configured in the per-proxy `config.json` (not policy.json).

| Field | Description |
|-------|-------------|
| `hitl.timeout_seconds` | User response timeout (default: 60, min: 5, max: 300) |
| `hitl.default_on_timeout` | Action on timeout (always "deny", cannot be changed) |
| `hitl.approval_ttl_seconds` | Cached approval lifetime (default: 600, min: 300, max: 900) |

**Note**: `cache_side_effects` is configured per-rule in policy.json, not in config. See [Policies](../reference/policies.md#hitl-configuration) for details.

### policy.json

Security policies are configured separately. See [Policies](../reference/policies.md) for full syntax.

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    { "id": "allow-reads", "effect": "allow", "conditions": { "operations": ["read"] } }
  ]
}
```

**Note:** HITL settings (timeout, caching) are in the per-proxy `config.json`, not `policy.json`.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EDITOR` | — | Editor for `config edit` (checked first) |
| `VISUAL` | — | Fallback editor for `config edit` |
| `MCP_ACP_CORS_ORIGINS` | — | CORS origins for management API (comma-separated). Required for Vite dev mode. |

**Editor fallback order**:
1. `$EDITOR` environment variable
2. `$VISUAL` environment variable
3. Platform default: `notepad` (Windows) or `vi` (macOS/Linux)

---

## Configuration Validation

- **Syntax**: JSON parsing with clear error messages
- **Schema**: Pydantic validation of all fields and types
- **Permissions**: Config directory `0o700`, files `0o600` (Unix)
- **Atomic writes**: Prevents corruption during saves
- **Symlink protection**: Paths resolved via `realpath()` to prevent bypass attacks

**Validation constraints** (enforced by Pydantic):
- `issuer`, `client_id`, `audience`: Non-empty strings (`issuer` must start with `https://`)
- `ui_port`: 1024-65535
- `log_dir`, `server_name`, `command`: Non-empty strings
- `http.url`: Must start with `http://` or `https://`
- `http.timeout`: 1-300 seconds
- `log_level`: Must be `"DEBUG"` or `"INFO"`
- `transport`: Must be `"stdio"`, `"streamablehttp"`, or `"auto"`
- `proxy_id`: Must match `px_{8 hex chars}:{lowercase-alphanumeric-dashes}`
- `hitl.timeout_seconds`: 5-300 seconds
- `hitl.approval_ttl_seconds`: 300-900 seconds

**Proxy name validation** (enforced at creation time):
- 1-64 characters
- Must start with alphanumeric character
- Only alphanumeric, hyphens, underscores allowed
- Reserved names: `manager`, `all`, `default`

---

## What is NOT Configured

### Environment Variables for Backend

Environment variables cannot be passed to backend processes.

**Why**:
- STDIO: Proxy spawns the process, could pass env vars
- Streamable HTTP: Proxy connects to already-running server, cannot pass env vars
- This asymmetry makes a unified feature misleading
- Env vars often contain secrets, creating audit trail issues

**Workaround**: Set env vars externally when starting Streamable HTTP servers.

### Runtime Overrides

No CLI flags to override config at runtime. All settings come from config files.

### Client Transport

Client-to-proxy communication is STDIO only. HTTP client transport not supported (required for ChatGPT integration).

---

## See Also

- [Usage](usage.md) for CLI commands
- [API Reference](../reference/api_reference.md) for config API endpoints
- [Policies](../reference/policies.md) for policy configuration
- [Backend Auth](../security/backend_auth.md) for API key and mTLS configuration
- [Logging](../security/logging.md) for log file details
- [Security](../security/security.md) for file permissions, atomic writes, audit integrity
