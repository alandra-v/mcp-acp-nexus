# Decision Context

The DecisionContext is the core data structure used for policy evaluation. It follows the ABAC (Attribute-Based Access Control) model with four components: Subject, Action, Resource, and Environment.

## Core Principles

1. **Context describes reality, not intent**
2. **Policies express distrust, not optimism**
3. **Facts carry provenance** - know where each piece of information came from
4. **You cannot trust tool names, descriptions, or declared behavior**

---

## How Context Is Used

| Usage | Description |
|-------|-------------|
| **Policy rule matching** | Context attributes (tool_name, path, operations, side_effects, subject_id, etc.) are matched against policy rule conditions |
| **Audit logging** | All context attributes logged to `decisions.jsonl` for forensics |
| **HITL dialogs** | Context (tool name, path, side effects, user) displayed for approval decisions |
| **Discovery bypass** | Discovery methods (tools/list, resources/list, etc.) automatically allowed |

**Important**: Context is used for **matching**, not **decision-making**. The policy engine matches context attributes against rules - it does not analyze context to make autonomous decisions.

---

## Zero Trust Architecture

The proxy follows NIST SP 800-207 Zero Trust Architecture:

| Component | Role |
|-----------|------|
| **Context Builder** (`context/`) | Builds DecisionContext from request data |
| **PDP** - Policy Decision Point (`pdp/`) | Evaluates policies, returns ALLOW/DENY/HITL |
| **PEP** - Policy Enforcement Point (`pep/`) | Intercepts requests, enforces decisions |
| **PIPs** - Policy Information Points (`pips/`) | External attribute sources (identity providers) |

### Request Flow

```
Client Request
       ↓
┌─────────────────────────────┐
│  PEP (Enforcement)          │
│  ├─ Builds context          │
│  ├─ Calls PDP → decision    │
│  └─ Enforces decision       │
└─────────────────────────────┘
       ↓ (if ALLOW)
Backend Server
```

---

## DecisionContext Structure

```
DecisionContext
├── subject          # WHO - identity of requester
├── action           # WHAT - operation being performed
├── resource         # ON WHAT - target of operation
└── environment      # CONTEXT - request metadata
```

---

## Provenance

Every security-relevant fact should carry its source. This allows policies to make trust decisions based on how information was obtained.

```python
class Provenance(str, Enum):
    """Source of a fact in the decision context.

    Trust hierarchy (high to low):
    - TOKEN, MTLS: Cryptographically verified
    - DIRECTORY: From trusted identity store
    - PROXY_CONFIG: Admin-controlled configuration
    - MCP_METHOD, MCP_REQUEST: From protocol (not verified)
    - DERIVED: Computed by proxy (document assumptions)
    - CLIENT_HINT: Client-provided, NOT TRUSTED
    """
    TOKEN = "token"                  # Validated OIDC/OAuth token claim
    DIRECTORY = "directory"          # IdP/LDAP/DB lookup
    MTLS = "mtls"                    # mTLS peer certificate
    PROXY_CONFIG = "proxy_config"    # Static proxy configuration
    MCP_METHOD = "mcp_method"        # From MCP method semantics
    MCP_REQUEST = "mcp_request"      # From MCP request arguments
    DERIVED = "derived"              # Computed by proxy (heuristics/defaults)
    CLIENT_HINT = "client_hint"      # Client-provided, NOT TRUSTED
```

### Which Fields Need Provenance?

Only fields where trust level matters for policy decisions:

| Field | Why Provenance Matters |
|-------|----------------------|
| `subject.id` | Is this from a validated token or a guess? |
| `subject.scopes` | Can we trust these permissions? |
| `resource.server.id` | Is this from config or discovery? |
| `resource.tool.name` | Where did we get the tool name? |
| `resource.tool.side_effects` | From registry or guessed? |
| `action.intent` | Is this known or inferred? |

---

## Subject (WHO)

The identity making the request. Populated from validated OIDC tokens.

| Field | Description |
|-------|-------------|
| `id` | User identifier (OIDC `sub` claim) |
| `issuer` | OIDC issuer URL (`iss` claim) |
| `audience` | Intended recipients (`aud` claim) |
| `client_id` | OAuth client ID (`azp` claim) |
| `scopes` | Granted OAuth scopes |
| `token_age_s` | Seconds since token was issued |
| `auth_time` | When user originally authenticated |
| `provenance` | Source tracking for trust decisions |

---

## Action (WHAT)

The operation being performed.

| Field | Description |
|-------|-------------|
| `mcp_method` | Raw MCP method (`tools/call`, `resources/read`) |
| `name` | Normalized form (`tools.call`, `resources.read`) |
| `intent` | Known intent (`read`) or `None` if unknown |
| `category` | `DISCOVERY` (metadata) or `ACTION` (does something) |
| `provenance.intent` | Source of intent (`MCP_METHOD` if known, `None` otherwise) |

**Design principle**: We report what we KNOW, not what we guess. For `tools/call`, intent is always `None` because we cannot trust tool names.

### Action Categories

| mcp_method | category | why |
|------------|----------|-----|
| `tools/call` | `ACTION` | Tool execution - cannot trust what it does |
| `resources/read` | `ACTION` | Content access with known `read` intent |
| `prompts/get` | `ACTION` | Returns actual content, may contain sensitive data |
| `initialize`, `ping` | `DISCOVERY` | Protocol methods - auto-allowed |
| `tools/list`, `resources/list`, `prompts/list` | `DISCOVERY` | Metadata listing - auto-allowed |
| `resources/templates/list` | `DISCOVERY` | Template discovery - auto-allowed |
| `notifications/*` | `DISCOVERY` | Async notifications - auto-allowed |

**Note**: `prompts/get` is NOT discovery - it returns actual prompt content which may contain sensitive instructions, API keys, or business logic.

---

## Resource (ON WHAT)

The target of the operation.

### Resource Types

| Type | When Used |
|------|-----------|
| `tool` | `tools/call` requests |
| `resource` | `resources/read` requests |
| `prompt` | `prompts/*` requests |
| `server` | Other MCP methods |

### Server Info

| Field | Description |
|-------|-------------|
| `id` | Backend server name (from config) |
| `provenance` | Source of server ID (`PROXY_CONFIG`) |

### Tool Info (for `tools/call`)

| Field | Description |
|-------|-------------|
| `name` | Tool name from request |
| `provenance` | Where we got the tool name (`MCP_REQUEST`) |
| `side_effects` | Known effects (e.g., `fs_write`, `code_exec`, `network_egress`) |
| `side_effects_provenance` | Where side effects came from (`PROXY_CONFIG` from manual map) |
| `version` | Tool version (future: from registry) |
| `risk_tier` | Risk classification (future: from registry) |

Side effects are looked up from `context/tool_side_effects.py`. Policies can match on tool names directly or use side effects for broader rules.

### Resource Info (for file/URI access)

| Field | Description |
|-------|-------------|
| `uri` | Full URI if provided |
| `scheme` | URI scheme (`file`, `http`, `db`, `s3`, etc.) |
| `path` | Normalized file path (primary path for single-path tools) |
| `source_path` | Source path for move/copy operations |
| `dest_path` | Destination path for move/copy operations |
| `filename` | Base filename |
| `extension` | File extension |
| `parent_dir` | Parent directory |
| `provenance` | Where we got this info (`MCP_REQUEST`) |

---

## Environment (CONTEXT)

Contextual information about the request.

| Field | Description |
|-------|-------------|
| `timestamp` | UTC timestamp when context was built |
| `request_id` | Request correlation ID |
| `session_id` | Session identifier |
| `mcp_client_name` | Client application name (from initialize) |
| `mcp_client_version` | Client version (from initialize) |
| `proxy_instance` | Proxy instance ID (future: multi-instance deployments) |

---

## Example

A `tools/call` request to `write_file` targeting `/home/user/.env`:

| Component | Key Fields |
|-----------|------------|
| **Subject** | `id="user-123"`, `issuer="https://auth0.com"` |
| **Action** | `mcp_method="tools/call"`, `category=ACTION`, `intent=None` |
| **Resource** | `type=TOOL`, `tool.name="write_file"`, `tool.side_effects=[fs_write]` |
| **Resource** | `resource.path="/home/user/.env"`, `resource.extension=None` |
| **Environment** | `request_id="req-123"`, `session_id="sess-456"` |

Note: `intent=None` for tools/call because we cannot trust tool names to determine intent.

---

## See Also

- [Policies](policies.md) - Policy rule syntax and conditions
- [Security](security.md) - Overall security architecture
- [Logging](logging.md) - Decision audit logging
