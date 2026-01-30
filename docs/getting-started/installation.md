# Installation

## Prerequisites

- **Python 3.11+** (3.11, 3.12, or 3.13)
- **pip** or **uv** package manager
- **Node.js 18+** (for MCP servers that use npx)
- **OIDC Provider** (Auth0, Okta, Azure AD, etc.) with Device Flow enabled - see [Auth](../security/auth.md)

## Platform Requirements

### macOS (Full Support)

The proxy requires the following security features enabled:

| Requirement | Check Command | How to Enable |
|-------------|---------------|---------------|
| **FileVault** (disk encryption) | `fdesetup status` | System Settings → Privacy & Security → FileVault |
| **SIP** (System Integrity Protection) | `csrutil status` | Enabled by default; requires Recovery Mode to disable |

Both checks are **hard gates** - the proxy will not start if either is disabled.

### Linux/Windows (Experimental)

The proxy can run on Linux and Windows, but device health checks (FileVault/SIP) are automatically skipped since these are macOS-specific features. This reduces Zero Trust compliance but allows basic operation.

---

## Install from Source

```bash
git clone https://github.com/alandra-v/mcp-acp-nexus.git
cd mcp-acp-nexus

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Or with dev dependencies (for testing/linting)
pip install -e ".[dev]"
```

## Verify Installation

```bash
# Make sure venv is activated
source venv/bin/activate

mcp-acp --version
# mcp-acp 0.1.0
```

## MCP Backend Servers

The proxy requires an MCP server to connect to. Tested servers:

### @modelcontextprotocol/server-filesystem (Official)

STDIO transport only.

```bash
# Runs via npx (no install required)
npx -y @modelcontextprotocol/server-filesystem /path/to/allowed/dir
```

See: [github.com/modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)

### cyanheads/filesystem-mcp-server

Supports both STDIO and HTTP transports.

```bash
# Install globally
npm install -g @cyanheads/filesystem-mcp-server

# Or run via npx
npx -y @cyanheads/filesystem-mcp-server
```

See: [github.com/cyanheads/filesystem-mcp-server](https://github.com/cyanheads/filesystem-mcp-server)

## Next Steps

See [Usage](usage.md) for first-time setup, CLI commands, and Claude Desktop integration.
