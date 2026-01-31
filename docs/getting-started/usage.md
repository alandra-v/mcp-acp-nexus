# Usage

## How It Works

```
MCP Client (Claude Desktop / Cursor / VS Code)
    │
    │ starts
    ▼
mcp-acp start --proxy <name>
    │
    │ spawns (STDIO) or connects to (HTTP)
    ▼
MCP Backend Server (filesystem, API, etc.)
```

The MCP client starts the proxy, and the proxy spawns/connects to the backend server. You don't manually start the proxy when using a client — it starts automatically.

Unless running with `--headless`, the proxy automatically starts the **manager daemon** if it isn't already running. The manager serves the web UI and coordinates multiple proxies for real-time monitoring and HITL approvals via the browser. You can also start it manually with `mcp-acp manager start`.

Use `mcp-acp <command> --help` for detailed options on any command.

---

## Quick Start

```bash
# Initialize authentication (one-time)
mcp-acp init

# Log in via browser
mcp-acp auth login

# Add a proxy for your backend
mcp-acp proxy add
```

The `init` and `proxy add` commands are interactive by default — they prompt for all required values. See [Non-interactive setup](#non-interactive-setup) for scripted/CI use.

After adding a proxy, configure your MCP client to use it. The easiest way:

```bash
# Generate the JSON config snippet
mcp-acp install mcp-json

# Or for a specific proxy, copied to clipboard
mcp-acp install mcp-json --proxy filesystem --copy
```

Paste the output into your client's config file (Claude Desktop, Cursor, VS Code).

### Manual client configuration (Claude Desktop)

```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/full/path/to/mcp-acp",
      "args": ["start", "--proxy", "filesystem"]
    }
  }
}
```

Add `"--headless"` to the args to run without the manager (uses system dialogs for HITL instead of the web UI).

**Find the full path:**

```bash
which mcp-acp
# Or if in a venv: /path/to/venv/bin/mcp-acp
```

After editing, restart your MCP client.

### Non-interactive setup

For scripts and CI, pass all values as flags:

```bash
# Initialize auth
mcp-acp init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id YOUR_CLIENT_ID \
  --oidc-audience https://your-api.example.com

# Authenticate
mcp-acp auth login

# Add a proxy
mcp-acp proxy add --name filesystem \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

---

## Status

Check what's running:

```bash
# All proxies
mcp-acp status

# Specific proxy (detailed: uptime, policy rules, auth sessions)
mcp-acp status --proxy filesystem

# Machine-readable
mcp-acp status --json
```

Manager status (daemon + connected proxies):

```bash
mcp-acp manager status
```

---

## Policy

Policies define what operations are allowed, denied, or require human approval. See [Policies](../reference/policies.md) for the rule format.

```bash
# View current policy
mcp-acp policy show --proxy filesystem

# Edit in $EDITOR (validates on save)
mcp-acp policy edit --proxy filesystem

# Add a single rule via editor
mcp-acp policy add --proxy filesystem

# Validate without applying
mcp-acp policy validate --proxy filesystem

# Hot-reload in a running proxy (no restart needed)
mcp-acp policy reload --proxy filesystem

# Show policy file path
mcp-acp policy path --proxy filesystem
```

Policy changes via `edit` and `add` are saved to disk. If the proxy is running, use `reload` to apply them without restarting. The web UI policy editor reloads automatically.

---

## Configuration

```bash
# View proxy config
mcp-acp config show --proxy filesystem

# View manager config
mcp-acp config show --manager

# Edit in $EDITOR (validates on save, creates backup)
mcp-acp config edit --proxy filesystem

# Validate all configs
mcp-acp config validate

# Show config file paths
mcp-acp config path
```

Config changes require a proxy restart to take effect (unlike policy, which supports hot reload).

---

## Logs

All operations are logged to JSONL files. See [Logging](../security/logging.md) for the log format.

```bash
# List available log files
mcp-acp logs list --proxy filesystem

# Show recent entries (default: 50)
mcp-acp logs show --proxy filesystem --type decisions
mcp-acp logs show --proxy filesystem --type operations --limit 100

# Tail in real-time
mcp-acp logs tail --proxy filesystem --type system
```

Log types: `decisions`, `operations`, `auth`, `system`, `config-history`, `policy-history`.

---

## Audit Integrity

Audit logs are protected by hash chains for tamper detection.

```bash
# Verify all proxies
mcp-acp audit verify

# Verify specific proxy or log file
mcp-acp audit verify --proxy filesystem
mcp-acp audit verify --proxy filesystem --file decisions

# Repair integrity state after crash or verification failure
mcp-acp audit repair --proxy filesystem
```

Exit codes: 0 = passed, 1 = tampering detected, 2 = unable to verify.

---

## Approval Cache

When a HITL request is approved with caching, similar future requests are auto-approved until the cache entry expires.

```bash
# View cached approvals
mcp-acp approvals cache --proxy filesystem

# Clear a specific entry (by number from cache output)
mcp-acp approvals clear --proxy filesystem --entry 1

# Clear all cached approvals
mcp-acp approvals clear --proxy filesystem --all
```

Requires a running proxy.

---

## Authentication

```bash
# Log in (opens browser for device flow)
mcp-acp auth login

# Check auth status (token info, user details, OIDC config)
mcp-acp auth status

# Log out (clears local credentials)
mcp-acp auth logout

# Log out and sign out of identity provider
mcp-acp auth logout --federated

# List active OIDC sessions on a running proxy
mcp-acp auth sessions list --proxy filesystem
```

Tokens are stored in the OS keychain. Re-run `mcp-acp init` to change OIDC settings.

---

## Proxy Management

```bash
# Add a new proxy (interactive)
mcp-acp proxy add

# List configured proxies
mcp-acp proxy list

# Delete a proxy (archives config and logs)
mcp-acp proxy delete --proxy filesystem

# Delete permanently (no archive)
mcp-acp proxy delete --proxy filesystem --purge

# List archived proxies
mcp-acp proxy list --deleted

# Permanently remove archived data
mcp-acp proxy purge <archive-name>
```

### HTTP backend API keys

For HTTP backends that require authentication:

```bash
# Set or update API key (stored in OS keychain)
mcp-acp proxy auth set-key --proxy my-api

# Remove API key
mcp-acp proxy auth delete-key --proxy my-api
```

### Advanced proxy add options

The `proxy add` command also accepts flags for:
- **Attestation** — `--attestation-slsa-owner`, `--attestation-sha256`, `--attestation-require-signature` (STDIO backends)
- **HTTP** — `--url`, `--timeout`, `--api-key` (HTTP backends)
- **mTLS** — `--mtls-cert`, `--mtls-key`, `--mtls-ca` (HTTP backends with mutual TLS)

See `mcp-acp proxy add --help` for all options.

---

## Manager

The manager daemon serves the web UI and coordinates multiple proxies. It starts automatically with the first proxy (unless `--headless`).

```bash
# Start manually
mcp-acp manager start

# Start in foreground (logs to terminal)
mcp-acp manager start --foreground

# Check status
mcp-acp manager status

# Stop
mcp-acp manager stop
```

The manager shuts down automatically after 5 minutes of inactivity when no proxies are connected and no browser tabs are open. See [Web UI](web-ui.md) for details.

---

## See Also

- [Configuration](configuration.md) — Config file format
- [Policies](../reference/policies.md) — Policy rules and syntax
- [Logging](../security/logging.md) — Log file details
- [Web UI](web-ui.md) — Optional graphical interface
- [API Reference](../reference/api_reference.md) — REST API and SSE events
