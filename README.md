**Zero Trust Access Control Proxy for the Model Context Protocol - MCP ACP**

A security-first proxy that sits between MCP clients and servers, providing policy-based access control, comprehensive audit logging, and human oversight for AI tool operations.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Quickstart

```bash
# 1. Clone and install
git clone https://github.com/alandra-v/mcp-acp-nexus.git
cd mcp-acp-nexus
python3 -m venv venv && source venv/bin/activate
pip install -e .

# 2. Initialize and authenticate
mcp-acp init
mcp-acp auth login

# 3. Add to Claude Desktop (~/.../Claude/claude_desktop_config.json)
{
  "mcpServers": {
    "mcp-acp": {
      "command": "/path/to/venv/bin/mcp-acp",
      "args": ["start"]
    }
  }
}
```

See [Installation](docs/installation.md) and [Usage](docs/usage.md) for details.

---

## What This Is

A Zero Trust proxy that sits between AI agents and the tools they use. Nothing is trusted by default—every request is authenticated, evaluated against policy, and logged. Sensitive operations require explicit human approval before execution.

```
MCP Client ──▶ mcp-acp-nexus ──▶ MCP Server
   (Claude)     (Policy + Audit)     (Backend)
```

See [Architecture](docs/architecture.md).

---

## Security

| Feature | Description |
|---------|-------------|
| **Default Deny** | All operations denied unless explicitly allowed by policy |
| **OIDC Authentication** | JWT validation per-request (not cached), automatic refresh |
| **ABAC Policy Engine** | Evaluate subject, action, resource, environment attributes |
| **HITL Approval** | Sensitive operations require user consent (native dialogs or web UI) |
| **Binary Attestation** | Verify backend integrity via SHA-256 hash, macOS codesign, SLSA provenance |
| **mTLS** | Mutual TLS for HTTP backends with certificate expiry monitoring |
| **Rate Limiting** | Token bucket for DoS protection, per-tool limits for runaway loop detection |
| **Session Binding** | Sessions bound to authenticated identity; mismatch triggers shutdown |
| **Protected Paths** | Config and log directories blocked unconditionally (cannot be overridden) |
| **Tool Sanitization** | Strip injection attempts from tool descriptions (homoglyphs, markdown, HTML) |
| **Immutable Audit** | Tamper detection via inode monitoring; fallback chain on failure |
| **Fail-Closed** | All errors default to deny; critical failures trigger immediate shutdown |
| **Device Health** | Verify FileVault and SIP enabled at startup (macOS) |

See [Security](docs/security.md).

---

## Policies

Policies define what operations are allowed, denied, or require human approval (HITL).

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    { "id": "allow-reads", "effect": "allow", "conditions": { "operations": ["read"] } },
    { "id": "hitl-writes", "effect": "hitl", "conditions": { "operations": ["write"] } },
    { "id": "deny-secrets", "effect": "deny", "conditions": { "path_pattern": "**/secrets/**" } }
  ]
}
```

**Conditions** (AND logic within a rule, OR logic for lists):

| Condition | Description |
|-----------|-------------|
| `tool_name` | Glob pattern matching tool names (`read_*`, `bash`) |
| `path_pattern` | Glob pattern for file paths (`/project/**`, `*.py`) |
| `source_path` | Source path for copy/move operations |
| `dest_path` | Destination path for copy/move operations |
| `operations` | Inferred operation type: `read`, `write`, `delete` |
| `extension` | File extension (`.py`, `.json`) |
| `subject_id` | User identity from OIDC token |
| `description` | Rule description (for documentation, included in logs) |

**Rule combining**: HITL > DENY > ALLOW (most restrictive wins). No rules match → deny.

See [Policies](docs/policies.md).

---

## Configuration

```bash
mcp-acp init              # Interactive setup
mcp-acp config show       # View config
mcp-acp policy show       # View policy

# Non-interactive setup (for scripts/CI)
mcp-acp init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id your-client-id \
  --oidc-audience your-api-audience \
  --log-dir ~/.mcp-acp \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

See [Configuration](docs/configuration.md).

---

## Telemetry & Logging

All operations logged to JSONL files in `<log_dir>/mcp_acp_logs/`:

- `audit/` - Operations, decisions, auth events (cannot be disabled)
- `system/` - System events, config/policy history (cannot be disabled)
- `debug/` - Wire logs (only when `log_level=DEBUG`)

See [Logging](docs/logging.md).

---

## Web UI

The proxy includes a web UI at `http://localhost:8765` when running.

**Features:**
- HITL approval queue (approve, deny, allow-once)
- Policy editor (view and modify rules)
- Log viewer
- Cached approvals management

On macOS, HITL uses native dialogs by default. The web UI is the primary HITL interface on Linux and Windows.

See [Web UI](docs/web-ui.md).

---

## Compatibility

### Platform Support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| Authentication (OIDC) | Full | Full | Full |
| Policy engine (ABAC) | Full | Full | Full |
| Audit logging | Full | Full | Full |
| Token storage | Full | Full | Full |
| HITL dialogs | Native | Web UI only | Web UI only |
| Device health (FileVault/SIP) | Basic | Skipped | Skipped |
| CLI via UDS | Full | Full | Limited* |

\* Windows UDS requires Windows 10 build 17063+; CLI commands may need HTTP fallback.

**macOS** is the primary platform with full feature support. Note: Device health checks are basic POC-level (FileVault on/off, SIP on/off) - not a comprehensive device posture solution.

**Linux** supports all core features; HITL uses web UI, device health checks unavailable.

**Windows** has additional limitations: UDS support is limited, CLI may require HTTP API.

#### Running on Linux/Windows

Device health checks must be disabled. Set in `src/mcp_acp/constants.py`:

```python
SKIP_DEVICE_HEALTH_CHECK: bool = True  # Required for Linux/Windows
```

---

## Limitations

| Limitation | Details |
|------------|---------|
| Single backend | One MCP server per proxy instance |
| Client transport | STDIO only (no HTTP client support) |
| Prompt injection | Operates at MCP layer, not prompt layer |
| Operation inference | Read/write/delete inferred from tool names (heuristic) |

See [Security Limitations](docs/security.md#limitations-and-out-of-scope).

---

## Roadmap

**mcp-acp-nexus** is Stage 3 of a three-stage architecture:

| Stage | Repository | Focus |
|-------|------------|-------|
| **1** | mcp-acp-core | Single-user proxy with policy engine, audit logging, HITL |
| **2** | mcp-acp-extended | OIDC authentication, mTLS, binary attestation, web UI |
| **3** | mcp-acp-nexus (this repo) | Manager, multiple proxies (one per backend), health monitoring, web UI lifecycle controls |

Each stage builds upon the previous, sharing core abstractions while adding capabilities.

See [Roadmap](docs/roadmap.md) for planned features beyond stage 3.

---

## Documentation

- [Installation](docs/installation.md) - Prerequisites and setup
- [Usage](docs/usage.md) - CLI commands and Claude Desktop integration
- [Configuration](docs/configuration.md) - Config file format
- [Policies](docs/policies.md) - Policy rules and HITL
- [Security](docs/security.md) - Security model
- [Architecture](docs/architecture.md) - System design
- [Logging](docs/logging.md) - Log formats
- [Auth](docs/auth.md) - OIDC setup
- [Web UI](docs/web-ui.md) - Optional graphical interface

---

## License

MIT License - see [LICENSE](LICENSE) for details.
