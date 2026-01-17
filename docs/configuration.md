# Configuration

> **Zero Trust by Default**: Authentication is mandatory. Policy `default_action` is always `deny`. The proxy fails fast on configuration errors rather than falling back to insecure defaults.

## How to Configure

Configuration is created via the `mcp-acp-nexus init` command:

```bash
# Interactive setup (recommended)
mcp-acp-nexus init

# Non-interactive setup
mcp-acp-nexus init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id your-client-id \
  --oidc-audience your-api-audience \
  --log-dir ~/.mcp-acp-nexus \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

**Init options**:
- `--non-interactive` - Skip prompts (requires all options to be specified)
- `--oidc-issuer`, `--oidc-client-id`, `--oidc-audience` - Authentication (required)
- `--mtls-cert`, `--mtls-key`, `--mtls-ca` - mTLS for HTTPS backends (optional)
- `--attestation-slsa-owner`, `--attestation-sha256`, `--attestation-require-signature` - Binary attestation for STDIO backends (optional)
- `--log-dir`, `--log-level`, `--include-payloads/--no-include-payloads` - Logging configuration
- `--server-name`, `--connection-type`, `--command`, `--args`, `--url`, `--timeout` - Backend configuration
- `--force` - Overwrite existing config without prompting

To manage existing configuration:

```bash
# View current config
mcp-acp-nexus config show
mcp-acp-nexus config show --json    # Machine-readable format

# Show file location
mcp-acp-nexus config path

# Edit via CLI (validates after save)
mcp-acp-nexus config edit

# Or edit manually

# Validate config file
mcp-acp-nexus config validate
mcp-acp-nexus config validate --path /path/to/config.json  # Validate alternate file
```

**No hot reload**: Changes require proxy restart.

**Config history**: All configuration changes are logged to `config_history.jsonl` for audit:

| Event | Description |
|-------|-------------|
| `config_created` | Initial creation via `mcp-acp-nexus init` |
| `config_loaded` | Loaded at proxy startup |
| `config_updated` | Updated via `mcp-acp-nexus config edit` |
| `manual_change_detected` | File modified outside of CLI (detected on next load) |
| `config_validation_failed` | Invalid JSON or schema validation error |

---

## Where Configuration is Stored

Configuration is stored in an OS-specific application directory:

| OS | Location |
|----|----------|
| macOS | `~/Library/Application Support/mcp-acp-nexus/` |
| Linux | `~/.config/mcp-acp-nexus/` |
| Windows | `C:\Users\<user>\AppData\Roaming\mcp-acp-nexus\` |

**Files**:
- `mcp_acp_config.json` - operational settings (auth, logging, backend, proxy, HITL)
- `policy.json` - security policies (rules only; HITL settings are in config)

**Log directory**: User-specified via `--log-dir` during init. Logs are stored in a `mcp_acp_logs/` subdirectory:

```
<log_dir>/
└── mcp_acp_logs/
    ├── debug/                  # Only created when log_level=DEBUG
    │   ├── client_wire.jsonl
    │   └── backend_wire.jsonl
    ├── system/
    │   ├── system.jsonl
    │   ├── config_history.jsonl
    │   └── policy_history.jsonl
    └── audit/                  # Always enabled (security audit trail)
        ├── operations.jsonl
        ├── decisions.jsonl
        └── auth.jsonl
```

**File permissions**: Config directory is `0o700` (owner only), config files are `0o600`. Writes are atomic to prevent corruption. See [Security](security.md) for details.

**Bootstrap log**: If config is invalid and `log_dir` is unavailable, errors are written to `bootstrap.jsonl` in the config directory.

---

## What is Configured

### mcp_acp_config.json

```json
{
  "auth": {
    "oidc": {
      "issuer": "https://your-tenant.auth0.com",
      "client_id": "your-client-id",
      "audience": "your-api-audience",
      "scopes": ["openid", "profile", "email", "offline_access"]
    },
    "mtls": {
      "client_cert_path": "/path/to/client.crt",
      "client_key_path": "/path/to/client.key",
      "ca_bundle_path": "/path/to/ca-bundle.crt"
    }
  },
  "logging": {
    "log_dir": "~/.mcp-acp-nexus",
    "log_level": "INFO",
    "include_payloads": true
  },
  "backend": {
    "server_name": "filesystem",
    "transport": "auto",
    "stdio": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "attestation": {
        "expected_sha256": "abc123...",
        "require_signature": true,
        "slsa_owner": "github-username"
      }
    },
    "http": {
      "url": "http://localhost:3000/mcp",
      "timeout": 30
    }
  },
  "proxy": {
    "name": "mcp-acp-nexus"
  },
  "hitl": {
    "timeout_seconds": 60,
    "approval_ttl_seconds": 600
  }
}
```

### Authentication Settings

| Field | Description |
|-------|-------------|
| `auth.oidc.issuer` | OIDC issuer URL (e.g., `https://tenant.auth0.com`) |
| `auth.oidc.client_id` | Auth0 application client ID |
| `auth.oidc.audience` | API audience for token validation |
| `auth.oidc.scopes` | OAuth scopes (default: `["openid", "profile", "email", "offline_access"]`) |
| `auth.mtls.client_cert_path` | Client certificate path, PEM format (optional, for mTLS backends) |
| `auth.mtls.client_key_path` | Client private key path, PEM format |
| `auth.mtls.ca_bundle_path` | CA bundle for server verification, PEM format |

### Logging Settings

| Field | Description |
|-------|-------------|
| `log_dir` | Base directory for logs (required, logs stored in `mcp_acp_logs/` subdirectory) |
| `log_level` | `DEBUG` or `INFO`. DEBUG enables wire logs |
| `include_payloads` | Include full payloads in debug logs |

### Backend Settings

| Field | Description |
|-------|-------------|
| `server_name` | Display name for the backend server |
| `transport` | `"stdio"`, `"streamablehttp"`, or `"auto"` (default: `"auto"`) |
| `stdio.command` | Command to spawn backend (e.g., `npx`) |
| `stdio.args` | Arguments for the command |
| `stdio.attestation.expected_sha256` | Expected SHA-256 hash of the binary (optional) |
| `stdio.attestation.require_signature` | Require valid code signature, macOS only (optional) |
| `stdio.attestation.slsa_owner` | GitHub owner for SLSA provenance verification (optional) |
| `http.url` | Backend Streamable HTTP server URL |
| `http.timeout` | Streamable HTTP connection timeout in seconds (default: 30, min: 1, max: 300) |

### Transport Selection

- `"transport": "stdio"` - Use STDIO only (requires `stdio` config)
- `"transport": "streamablehttp"` - Use Streamable HTTP only (requires `http` config)
- `"transport": "auto"` - Auto-detect: prefers HTTP if reachable, falls back to STDIO

**Auto-detection logic at runtime**:
1. If transport is explicitly set (`"stdio"` or `"streamablehttp"`):
   - Use specified transport if available
   - **Fail** if specified transport not available (no silent fallback)
2. If transport is `"auto"`:
   - Try Streamable HTTP with retry (3 attempts, ~6s total)
   - If still unreachable → fall back to STDIO

**Startup retry**: HTTP backends are retried with exponential backoff (2s → 4s) to allow starting the proxy before the backend is ready.

**Streamable HTTP preferred**: MCP spec positions it as the modern default.

### HITL Settings

Human-in-the-Loop settings are configured in `mcp_acp_config.json` (not policy.json).

| Field | Description |
|-------|-------------|
| `hitl.timeout_seconds` | User response timeout (default: 60, min: 5, max: 300) |
| `hitl.default_on_timeout` | Action on timeout (always "deny", cannot be changed) |
| `hitl.approval_ttl_seconds` | Cached approval lifetime (default: 600, min: 300, max: 900) |

**Note**: `cache_side_effects` is configured per-rule in policy.json, not in config. See [Policies](policies.md#hitl-configuration) for details.

### policy.json

Security policies are configured separately. See [Policies](policies.md) for full syntax.

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    { "id": "allow-reads", "effect": "allow", "conditions": { "operations": ["read"] } }
  ]
}
```

**Note:** HITL settings (timeout, caching) are in `mcp_acp_config.json`, not `policy.json`.

---

## API Endpoints

The Management API provides configuration endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/config` | Get current configuration (from memory) |
| `PUT` | `/api/config` | Update configuration file (requires restart) |
| `GET` | `/api/config/compare` | Compare running vs saved config |

See [API Reference](api_reference.md) for full endpoint documentation.

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
- `issuer`, `client_id`, `audience`: Non-empty strings
- `log_dir`, `server_name`, `command`: Non-empty strings
- `http.url`: Must start with `http://` or `https://`
- `http.timeout`: 1-300 seconds
- `log_level`: Must be `"DEBUG"` or `"INFO"`
- `transport`: Must be `"stdio"`, `"streamablehttp"`, or `"auto"`

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

### Multiple Backend Servers

Only one backend server is supported. Multi-server support planned for the future.

### Client Transport

Client-to-proxy communication is STDIO only. HTTP client transport not supported (required for ChatGPT integration).

---

## See Also

- [Usage](usage.md) for CLI commands
- [API Reference](api_reference.md) for config API endpoints
- [Policies](policies.md) for policy configuration
- [Logging](logging.md) for log file details
- [Security](security.md) for file permissions, atomic writes, audit integrity
