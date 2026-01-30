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

The MCP client starts the proxy, and the proxy spawns/connects to the backend server. You don't manually start the proxy when using a client - it starts automatically.

Unless running with `--headless`, the proxy automatically starts the **manager daemon** if it isn't already running. The manager serves the web UI and coordinates multiple proxies for real-time monitoring and HITL approvals via the browser. You can also start it manually with `mcp-acp manager start` (use `--foreground` to see logs in the terminal).

Use `mcp-acp <command> --help` for detailed options on any command.

---

## Quick Start

```bash
# 1. Initialize authentication (one-time)
mcp-acp init

# 2. Log in via browser
mcp-acp auth login

# 3. Add a proxy for your backend
mcp-acp proxy add

# 4. Start the manager for web UI (optional)
mcp-acp manager start
```

### Non-interactive setup

```bash
# Initialize auth
mcp-acp init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id YOUR_CLIENT_ID \
  --oidc-audience https://your-api.example.com

# Authenticate
mcp-acp auth login

# Add proxy
mcp-acp proxy add --name filesystem \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

---

## MCP Client Integration

### Generate config automatically

```bash
# Generate JSON for all proxies
mcp-acp install mcp-json

# For a specific proxy, copy to clipboard
mcp-acp install mcp-json --proxy filesystem --copy
```

This outputs the JSON snippet to paste into your client's config file (Claude Desktop, Cursor, VS Code).

### Manual configuration (Claude Desktop)

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

---

## See Also

- [Configuration](configuration.md) - Config file format
- [Policies](../reference/policies.md) - Policy rules and syntax
- [Logging](../security/logging.md) - Log file details
- [Web UI](web-ui.md) - Optional graphical interface
