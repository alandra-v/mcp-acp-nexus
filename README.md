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

# 2. Initialize authentication (one-time)
mcp-acp init

# 3. Log in via browser
mcp-acp auth login

# 4. Add a proxy for your backend
mcp-acp proxy add

# 5. Generate MCP client config and copy to clipboard
mcp-acp install mcp-json --copy
```

Paste the output into your client's config file (Claude Desktop, Cursor, VS Code) and restart the client.

See [Installation](docs/getting-started/installation.md) and [Usage](docs/getting-started/usage.md) for details.

---

## What This Is

A Zero Trust proxy that sits between AI agents and the tools they use. Nothing is trusted by default — every request is authenticated, evaluated against policy, and logged. Sensitive operations require explicit human approval before execution.

```
MCP Client ──> mcp-acp ──> MCP Server
   (Claude)     (Policy + Audit)     (Backend)
```

The MCP client starts the proxy, and the proxy spawns or connects to the backend server. Unless running with `--headless`, the proxy automatically starts the **manager daemon**, which serves the web UI and coordinates multiple proxies.

See [Architecture](docs/reference/architecture.md) and [Zero Trust Compliance](docs/security/zero-trust-compliance.md).

---

## Security

| Feature | Description |
|---------|-------------|
| **Default Deny** | All operations denied unless explicitly allowed by policy |
| **OIDC Authentication** | JWT validated per-request (signature, issuer, audience, expiry); JWKS cached 10 min |
| **ABAC Policy Engine** | Evaluate subject, action, resource, environment attributes; 12 condition types |
| **HITL Approval** | Sensitive operations require user consent via web UI or native macOS dialogs |
| **Session Binding** | Sessions bound to authenticated identity; mismatch triggers immediate shutdown |
| **Device Health** | Verify FileVault and SIP at startup and every 5 minutes (macOS); hard gate on failure |
| **Binary Attestation** | Verify STDIO backend integrity via SHA-256 hash, macOS codesign, SLSA provenance |
| **Backend Auth** | API key/bearer token for HTTP backends, stored in OS keychain (never in config files) |
| **mTLS** | Mutual TLS for HTTP backends with certificate expiry monitoring (warning at 14d, critical at 7d) |
| **Rate Limiting** | Token bucket DoS protection (10 req/s, 50 burst); per-tool rate limiting triggers HITL on runaway loops |
| **Protected Paths** | Config and log directories blocked unconditionally (cannot be overridden by policy) |
| **Tool Sanitization** | Strip injection attempts from tool descriptions (homoglyphs, markdown, HTML, control chars) |
| **Immutable Audit** | SHA-256 hash chain with inode monitoring; fail-closed on tampering; emergency fallback chain |
| **Fail-Closed** | All errors default to deny; audit/integrity failures trigger immediate shutdown |
| **Token Storage** | Tokens stored in OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Locker); encrypted file fallback |
| **Startup Validation** | Config and policy validated against strict schemas; audit writability verified before accepting requests |

### Trust Model

The proxy starts with a default-deny posture and an empty policy — all non-discovery operations are blocked. Security adoption is gradual and entirely user-driven:

1. **Deny by default.** On first run, everything is blocked. Discovery methods (`tools/list`, `resources/list`) are allowed so the client can enumerate capabilities.
2. **Manual policy refinement.** The user reviews audit logs to see what was denied and why, then adds allow/deny/HITL rules via CLI (`policy add/edit`) or the web UI. Policies can be hot-reloaded without restarting the proxy.
3. **HITL approval caching.** When a user approves an operation via HITL dialog, the approval is cached by `(user, tool, path)` for a configurable TTL (default 10 minutes). This reduces repeated prompts within a session but does not permanently expand access — cache is cleared on policy reload and operations involving `code_exec` side effects are never cached.

Unlike systems employing machine learning for behavioral analysis, the proxy's adaptation is entirely user-driven. Trust boundaries expand only through explicit policy rules or time-bounded approval caching, ensuring the operator maintains complete control over the security posture. The system does not learn from operational patterns or suggest policy changes yet.

See [Security](docs/security/security.md), [Authentication](docs/security/auth.md), and [Backend Authentication](docs/security/backend_auth.md).

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
| `operations` | Inferred operation type: `read`, `write`, `delete` (heuristic) |
| `extension` | File extension (`.py`, `.json`) |
| `scheme` | URL scheme (`file`, `s3`) |
| `backend_id` | Server identifier glob pattern |
| `resource_type` | Resource type: `tool`, `resource`, `prompt`, `server` |
| `mcp_method` | MCP method name glob pattern |
| `subject_id` | User identity from OIDC token |
| `side_effects` | Tool side effect types (`code_exec`, `fs_write`, `network_egress`) |

**Rule combining**: HITL > DENY > ALLOW (most restrictive wins). No rules match -> deny.

See [Policies](docs/reference/policies.md).

---

## Configuration

Configuration is a two-step process: initialize authentication (shared), then add proxies (per-proxy).

```bash
# Step 1: Initialize OIDC authentication (creates manager.json)
mcp-acp init

# Step 2: Add a proxy (creates per-proxy config.json and policy.json)
mcp-acp proxy add

# View configuration
mcp-acp config show --manager            # Manager config (OIDC, ui_port, log_dir)
mcp-acp config show --proxy filesystem   # Proxy config (backend, HITL, mTLS, logging)

# View policy
mcp-acp policy show --proxy filesystem

# Non-interactive setup (for scripts/CI)
mcp-acp init --non-interactive \
  --oidc-issuer https://your-tenant.auth0.com \
  --oidc-client-id your-client-id \
  --oidc-audience your-api-audience

mcp-acp proxy add --name filesystem \
  --server-name filesystem \
  --connection-type stdio \
  --command npx \
  --args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

Backend connection types: `stdio` (spawn local process), `http` (connect to remote server with optional mTLS and API key auth), `auto` (try HTTP first, fall back to STDIO).

See [Configuration](docs/getting-started/configuration.md).

---

## Telemetry & Logging

All operations logged to JSONL files:

```
<log_dir>/mcp-acp/
├── manager/
│   └── system.jsonl                # Manager daemon events
└── proxies/<name>/
    ├── audit/                      # Security audit trail (always enabled)
    │   ├── operations.jsonl        # MCP operations with outcomes
    │   ├── decisions.jsonl         # Policy decisions and HITL outcomes
    │   └── auth.jsonl              # Authentication and session events
    ├── system/                     # Operational events (always enabled)
    │   ├── system.jsonl            # Warnings, errors, backend disconnections
    │   ├── config_history.jsonl    # Configuration changes (versioned)
    │   └── policy_history.jsonl    # Policy changes (versioned)
    └── debug/                      # Wire-level traces (only when log_level=DEBUG)
        ├── client_wire.jsonl       # Client <-> Proxy
        └── backend_wire.jsonl      # Proxy <-> Backend
```

Audit logs are protected by SHA-256 hash chains for tamper detection. Verify with `mcp-acp audit verify`. If audit logging fails, the proxy shuts down (fail-closed).

See [Logging](docs/security/logging.md).

---

## Web UI

The web UI is an **optional add-on** that provides everything the CLI does, except for initial setup (`mcp-acp init`) and daemon lifecycle (`mcp-acp manager start/stop`). It runs at `http://localhost:8765` when the manager is running.

By default, the proxy automatically starts the manager (and the web UI) when launched by an MCP client. Pass `--headless` to run standalone without the manager or web UI.

**Pages:**

| Page | Features |
|------|----------|
| **Proxy List** | Status cards with live stats; add proxy; export client configs |
| **Proxy Detail** | Transport flow diagram, session statistics, pending/cached HITL approvals, log viewer with filters, policy editor (visual + JSON), config editor, audit log integrity status |
| **Incidents** | Security event timeline across all proxies (shutdowns, startup failures, emergency audit) |
| **Auth** | Login/logout via OAuth device flow, OIDC config display, token status |

HITL approvals appear in a header drawer across all pages with audio notifications, live countdowns, and approve/deny/allow-once actions. When the UI is not open, HITL falls back to native macOS dialogs (or auto-deny on other platforms).

See [Web UI](docs/getting-started/web-ui.md).

---

## Compatibility

**macOS** is the primary development and deployment platform. All features are built and tested on macOS.

**Linux and Windows are not tested.** The codebase includes platform-aware code in several areas (path handling, token storage, clipboard, permissions), but neither platform has been validated. Linux is likely close to working for core functionality. Windows has known hard blockers including unguarded use of Unix domain sockets, `fcntl` file locking, and Unix-only subprocess parameters.

---

## Limitations

This is a single-tenant, host-local academic prototype. Enterprise IAM, multi-tenancy, high availability, and distributed architectures are out of scope.

- **Client transport is STDIO only.** MCP clients (Claude Desktop, Cursor) connect to the proxy via STDIO process inheritance. Backend transport supports both STDIO and Streamable HTTP. See [HTTP Client Support](docs/design/http-client-support.md) for future client transport design.
- **No prompt-layer visibility.** The proxy operates at the MCP protocol layer. It evaluates and blocks tool calls but cannot see or filter the prompts that led to them.
- **Policy engine is not confidence-aware.** The `operations` condition infers read/write/delete from tool name patterns, but the policy engine treats inferred values the same as verified ones. The context layer already tracks attribute provenance (`context/provenance.py`) and tool side-effect sources (`side_effects_provenance`), but the policy engine cannot yet condition on confidence or provenance. See [Roadmap](docs/design/roadmap.md) for planned confidence-based policies.
- **Side effects are coarse-grained.** Tool side effects are assigned from a hardcoded map of ~78 tools. Categories like `fs_write` cover create, modify, and delete equally; `network_egress` does not distinguish between protocols, hosts, or HTTP methods. Tools not in the map get unknown side effects and silently bypass `side_effects` policy conditions. The map is global — the same tool name always gets the same side effects regardless of which backend serves it. Matching uses ANY logic only (no negation or ALL semantics).
- **No response size limits.** Backends can return arbitrarily large responses. There is no memory exhaustion protection.

See [Security Limitations](docs/security/security.md#limitations-and-out-of-scope).

---

## Roadmap

**mcp-acp-nexus** is Stage 3 of a three-stage architecture:

| Stage | Focus |
|-------|-------|
| **1** | Single-user proxy with policy engine, audit logging, HITL |
| **2** | OIDC authentication, mTLS, binary attestation, web UI |
| **3 (current)** | Manager daemon, multiple proxies (one per backend), health monitoring, web UI lifecycle |

Planned improvements: tool registry, policy engine enhancements (confidence policies, dry-run simulation, policy templates, resource groups), content inspection, HTTP client support, third-party policy engine integration (OPA, Cedar).

See [Roadmap](docs/design/roadmap.md) for details.

---

## Documentation

### Getting Started
- [Installation](docs/getting-started/installation.md) - Prerequisites and setup
- [Usage](docs/getting-started/usage.md) - CLI commands and client integration
- [Configuration](docs/getting-started/configuration.md) - Config file format and options
- [Web UI](docs/getting-started/web-ui.md) - Web interface features

### Security
- [Security](docs/security/security.md) - Security model and threat protections
- [Authentication](docs/security/auth.md) - OIDC setup, device health, session binding
- [Backend Authentication](docs/security/backend_auth.md) - mTLS, binary attestation, API keys
- [Logging](docs/security/logging.md) - Log structure, hash chains, integrity
- [Zero Trust Compliance](docs/security/zero-trust-compliance.md) - NIST SP 800-207 evaluation

### Reference
- [Architecture](docs/reference/architecture.md) - System design, middleware stack, modules
- [Policies](docs/reference/policies.md) - Policy rules, conditions, HITL configuration
- [API Reference](docs/reference/api_reference.md) - REST API and SSE events
- [Decision Context](docs/reference/decision_context.md) - ABAC context attributes
- [Request Flow Diagrams](docs/reference/request_flow_diagrams.md) - Sequence diagrams
- [Logging Specs](docs/reference/logging_specs/) - Detailed log field schemas

### Design
- [Roadmap](docs/design/roadmap.md) - Planned features and future work
- [HTTP Client Support](docs/design/http-client-support.md) - Future HTTP client transport design

---

## License

MIT License - see [LICENSE](LICENSE) for details.
