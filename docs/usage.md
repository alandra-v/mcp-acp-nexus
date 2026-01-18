# Usage

## How It Works

```
MCP Client (Claude Desktop / MCP Inspector)
    │
    │ starts
    ▼
mcp-acp proxy
    │
    │ spawns (STDIO) or connects to (HTTP)
    ▼
MCP Backend Server (filesystem server)
```

The MCP client starts the proxy, and the proxy spawns/connects to the backend server. You don't manually start the proxy when using a client - it starts automatically.

---

## CLI Commands

Use `mcp-acp <command> --help` for detailed options.

| Command | Description |
|---------|-------------|
| `init` | Initialize configuration (interactive wizard or `--non-interactive`) |
| `start` | Start proxy manually (use `--no-ui` to disable web UI) |
| `auth login` | Authenticate via browser (OAuth Device Flow) |
| `auth logout` | Clear stored credentials (use `--federated` for full logout) |
| `auth status` | Show authentication state and token info |
| `config show` | Display current configuration |
| `config path` | Show config file location |
| `config edit` | Edit config in `$EDITOR` |
| `config validate` | Validate config file |
| `policy show` | Display current policy rules |
| `policy path` | Show policy file location |
| `policy edit` | Edit policy in `$EDITOR` |
| `policy add` | Add a new rule via editor |
| `policy validate` | Validate policy file |
| `policy reload` | Reload policy in running proxy |
| `status` | Show proxy runtime status (requires running proxy) |
| `approvals cache` | Show cached HITL approvals |
| `approvals clear` | Clear cached approvals |
| `logs list` | List available log files |
| `logs show` | Show recent log entries |
| `logs tail` | Tail log file in real-time |
| `sessions list` | List active sessions |

**Config location** (macOS): `~/Library/Application Support/mcp-acp/`

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (config/policy invalid, missing files) |
| 10 | Audit log integrity failure |
| 12 | Identity verification failure (JWKS unreachable) |
| 13 | Authentication error (not authenticated, token expired) |
| 14 | Device health check failed (FileVault/SIP on macOS) |
| 15 | Session binding violation (identity changed mid-session) |

---

## Claude Desktop Integration

### Step 1: Open Claude Desktop config

```bash
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

### Step 2: Add the proxy

```json
{
  "mcpServers": {
    "mcp-acp": {
      "command": "/full/path/to/mcp-acp",
      "args": ["start"]
    }
  }
}
```

To disable the web UI (uses system dialogs for HITL instead):

```json
{
  "mcpServers": {
    "mcp-acp": {
      "command": "/full/path/to/mcp-acp",
      "args": ["start", "--no-ui"]
    }
  }
}
```

**Find the full path:**

```bash
which mcp-acp
# Or if in a venv: /path/to/venv/bin/mcp-acp
```

### Step 3: Restart Claude Desktop

```bash
killall Claude
# Then relaunch Claude Desktop
```

---

## Example Workflows

### First-time setup

```bash
# 1. Initialize (interactive wizard)
mcp-acp init

# 2. Authenticate
mcp-acp auth login

# 3. Test manually (optional)
mcp-acp start
```

### Non-interactive setup

```bash
mcp-acp init --non-interactive \
  --log-dir ~/.mcp-acp \
  --server-name filesystem \
  --connection-type http \
  --url http://localhost:3000/mcp \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id YOUR_CLIENT_ID \
  --oidc-audience https://your-api.example.com
```

---

## See Also

- [Configuration](configuration.md) - Config file format
- [Policies](policies.md) - Policy rules and syntax
- [Logging](logging.md) - Log file details
- [Web UI](ui.md) - Optional graphical interface
