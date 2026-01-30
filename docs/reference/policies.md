# Policies

## Overview

Policies define what operations are allowed, denied, or require human approval.

- **Default action**: Explicit DENY (zero trust)
- **Glob patterns**: Path matching with `*`, `**`, `?`
- **Operations**: read, write, delete (inferred from tool names - see caveat below)
- **Effects**: allow, deny, hitl (human-in-the-loop)
- **Fully configurable**: Users define their own rules

---

## How Policy Evaluation Works

```
┌────────────────────┐
│ Subject Attributes ├──┐
└────────────────────┘  │
┌────────────────────┐  │    ┌───────────────┐
│ Resource Attributes├──┼───►│ Policy Engine ├───► ALLOW / DENY / HITL
└────────────────────┘  │    └───────────────┘
┌────────────────────┐  │
│ Action Attributes  ├──┤
└────────────────────┘  │
┌────────────────────┐  │
│ Env Attributes     ├──┘
└────────────────────┘
```

```
1. MCP request arrives at proxy
2. Context is built from request (ABAC attributes)
3. Policy engine evaluates rules against context
4. Decision returned: ALLOW, DENY, or HITL
5. Decision enforced and logged
```

### Context Building (ABAC Model)

The proxy builds a `DecisionContext` with four attribute categories:

| Category | Attributes | Source |
|----------|------------|--------|
| **Subject** | `id`, `issuer`, `scopes`, `client_id`, `audience` | OIDC token |
| **Action** | `mcp_method`, `name`, `intent`, `category` | MCP request |
| **Resource** | `tool_name`, `path`, `source_path`, `dest_path`, `extension`, `backend_id`, `side_effects` | MCP request arguments |
| **Environment** | `timestamp`, `session_id`, `request_id`, `mcp_client_name`, `mcp_client_version` | Runtime context |

**External PIPs**: When OIDC authentication is configured, the proxy queries the external IdP for JWKS (key validation) and token refresh. Tool side effects use a local mapping (see `tool_side_effects.py`).

### Policy Engine

Evaluation order:
1. **Protected paths check**: DENY if accessing config or log directories (cannot be overridden by policy)
2. **Discovery bypass**: ALLOW if discovery method (see [Discovery Bypass](#discovery-bypass))
3. **Collect matching rules**: Find all rules where conditions match the context
4. **Apply combining algorithm**: **HITL > DENY > ALLOW** (most restrictive wins)
5. **Select most specific rule**: Within each effect level, select the most specific rule for logging
6. **Default action**: If no rules match → DENY

**Fail-closed**: Any error in context building or policy evaluation results in DENY.

### Rule Specificity

When multiple rules with the same effect match, the **most specific rule** is selected as the `final_rule` for logging. Specificity is calculated as:

```
Score = (condition_count × 100) + exactness_bonus + path_depth_bonus
```

**Scoring components:**

| Component | Points | Description |
|-----------|--------|-------------|
| Condition count | +100 each | Each non-null condition adds 100 points |
| Exactness bonus | +10 each | Patterns without wildcards (*, ?, **) get a bonus |
| Path depth bonus | +1 each | Path segments before the first wildcard |

**Example scores:**

| Rule conditions | Score | Breakdown |
|-----------------|-------|-----------|
| `tool_name: "read*"` | 100 | 1 condition |
| `tool_name: "read_file"` | 110 | 1 condition + exact match |
| `tool_name: "read*", extension: ".py"` | 200 | 2 conditions |
| `tool_name: "read*", path_pattern: "/a/b/c/**"` | 203 | 2 conditions + depth 3 |

**Tie-breaker:** If two rules have the same specificity score, the rule that appears first in the policy file wins (preserves predictability).

---

## Policy File Structure

**Location**: `<config_dir>/proxies/<name>/policy.json`

Each proxy has its own policy file. The path is determined by the manager configuration's `config_dir` setting (default: `~/.config/mcp-acp` on Linux/macOS). Use `mcp-acp proxy show <name>` to see the policy path for a specific proxy.

### Minimal Valid Policy

An empty object is a valid policy - all fields have defaults:

```json
{}
```

This is equivalent to:

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": []
}
```

With no rules, all operations are denied (Zero Trust default).

**Note:** HITL configuration (timeout, caching) is in `config.json`, not `policy.json`. See the [HITL Configuration](#hitl-configuration) section below.

### PolicyConfig Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `version` | No | `"1"` | Schema version for migrations |
| `default_action` | No | `"deny"` | What to do when no rule matches (always "deny", cannot be changed) |
| `rules` | No | `[]` | List of rules; all matches combined via HITL > DENY > ALLOW |

### Example Policy

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-reads",
      "description": "Allow all read operations without prompting",
      "effect": "allow",
      "conditions": { "operations": ["read"] }
    },
    {
      "id": "hitl-writes",
      "description": "Require approval for write operations",
      "effect": "hitl",
      "conditions": { "operations": ["write"] }
    }
  ]
}
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | No | Unique identifier (auto-generated if not provided) |
| `description` | No | Human-readable explanation of the rule's purpose |
| `effect` | Yes | Action when rule matches: `allow`, `deny`, `hitl` |
| `conditions` | Yes | Matching criteria (AND logic) |

---

## Rule Conditions

> **⚠️ At least one condition MUST be specified.** Empty conditions are rejected because they would match everything - a security risk. A rule like `{"effect": "allow", "conditions": {}}` is invalid.

All conditions in a rule use **AND logic** (all must match).
Most conditions support **list values with OR logic** - when a list is provided, the condition matches if ANY value matches.

| Condition | Description | Matching | List Support |
|-----------|-------------|----------|--------------|
| `tool_name` | Tool name pattern | glob (*, ?), case-insensitive | ✓ OR logic |
| `path_pattern` | File path pattern | glob (*, **, ?), case-sensitive | ✓ OR logic |
| `source_path` | Source path for move/copy operations | glob (*, **, ?), case-sensitive | ✓ OR logic |
| `dest_path` | Destination path for move/copy operations | glob (*, **, ?), case-sensitive | ✓ OR logic |
| `operations` | Operation types (heuristic) | exact: read/write/delete | (list only) |
| `extension` | File extension | exact, case-insensitive | ✓ OR logic |
| `scheme` | URL scheme | exact, case-insensitive | ✓ OR logic |
| `backend_id` | Server identifier | glob (*, ?), case-insensitive | ✓ OR logic |
| `resource_type` | Resource type | exact, case-insensitive | single only |
| `mcp_method` | MCP method name | glob (*, ?), case-sensitive | ✓ OR logic |
| `subject_id` | User identity | exact, case-sensitive | ✓ OR logic |
| `side_effects` | Side effect types | ANY match | (list only) |

### Path Pattern Matching

Path patterns support glob syntax:
- `*` matches any characters except `/`
- `**` matches any characters including `/`
- `?` matches a single character except `/`

**Important**: `/path/**` matches both the directory itself and everything under it:
- `/project/**` matches `/project`, `/project/file`, `/project/src/main.py`
- This is intuitive for policies - allowing access to `/project/**` includes the directory itself

### List Conditions (OR Logic)

Most conditions accept either a single value or a list of values. When a list is provided, the condition matches if ANY value in the list matches:

```json
{
  "id": "deny-dangerous-tools-on-etc",
  "description": "Block dangerous tools on /etc",
  "effect": "deny",
  "conditions": {
    "tool_name": ["bash", "rm", "mv", "cp", "chmod"],
    "path_pattern": "/etc/**"
  }
}
```

This matches: (tool is bash OR rm OR mv OR cp OR chmod) AND (path matches /etc/**)

```json
{
  "id": "allow-reads-from-safe-dirs",
  "description": "Allow reads from project or tmp directories",
  "effect": "allow",
  "conditions": {
    "tool_name": "read_*",
    "path_pattern": ["/project/**", "/tmp/**"]
  }
}
```

This matches: (tool matches read_*) AND (path matches /project/** OR /tmp/**)

**Empty lists** never match - a rule with `tool_name: []` will never apply.

### Source/Destination Path Conditions

For move/copy operations, you can control data flow with `source_path` and `dest_path`:

```json
{
  "id": "allow-copy-tmp-to-project",
  "description": "Allow copying from /tmp to /project",
  "effect": "allow",
  "conditions": {
    "tool_name": "copy_*",
    "source_path": "/tmp/**",
    "dest_path": "/project/**"
  }
}
```

```json
{
  "id": "deny-copy-to-secrets",
  "description": "Deny copying anything to /secrets",
  "effect": "deny",
  "conditions": {
    "dest_path": "/secrets/**"
  }
}
```

Supported argument names:
- **Source**: `source`, `src`, `from`, `from_path`, `source_path`, `origin`
- **Destination**: `destination`, `destination_path`, `dest`, `to`, `to_path`, `dest_path`, `target`, `target_path`

**Empty conditions are invalid** (rejected by validator - would match everything).

---

## Operation Inference

Operations (read/write/delete) are inferred from tool name patterns (`read_*`, `write_*`, etc.).

**This is a HEURISTIC, not a security guarantee** - tool names may lie.

- Unknown tools with operation conditions -> rule doesn't match (safe default)

---

## Side Effects System

The side effects system allows policies to match based on what a tool CAN DO rather than just its name.

### Available Side Effects

| Category | Side Effects |
|----------|--------------|
| Filesystem | `fs_read`, `fs_write` |
| Database | `db_read`, `db_write` |
| Network | `network_egress`, `network_ingress` |
| Execution | `code_exec`, `process_spawn`, `sudo_elevate` |
| Secrets | `secrets_read`, `env_read`, `keychain_read` |
| System | `clipboard_read`, `clipboard_write`, `browser_open` |
| Capture | `screen_capture`, `audio_capture`, `camera_capture` |
| Cloud | `cloud_api`, `container_exec` |
| Communication | `email_send` |

### Side Effects Matching

Uses **ANY logic**: matches if tool has ANY of the listed effects.

Unknown tools (not in mapping) won't match side_effect rules (conservative).

### How Side Effects Are Determined

Side effects are currently **manually mapped** per tool. Example mappings:

| Tool | Side Effects |
|------|--------------|
| `bash` | `code_exec`, `fs_write`, `fs_read`, `network_egress`, `process_spawn` |
| `read_file` | `fs_read` |
| `write_file` | `fs_write` |

### Important Limitations

| Limitation | Implication |
|------------|-------------|
| **Manual mapping** | Side effects are DECLARED, not detected or verified yet |
| **Tool names can lie** | A malicious tool named `read_file` could actually execute code |
| **Unknown tools have no effects** | Tools not in mapping won't match side_effect policy rules |
| **No runtime verification** | We don't analyze what a tool actually does |

### Trust Model

- We currently trust that tool names are honest (weak assumption)
- The mapping is based on common tool naming conventions
- Unknown tools fail-safe: they won't match allow rules with side_effect conditions

Possible future: Verified Tool Registry

---

## Discovery Bypass

Discovery methods skip policy evaluation entirely. These include connection setup (`initialize`, `ping`), capability discovery (`tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`), and async notifications.

See `DISCOVERY_METHODS` in `constants.py` for the complete list.

**`prompts/get` is NOT bypassed** - it returns actual content and needs policy evaluation.

Logged as `discovery_bypass` in decision logs for audit trail.

### Why Discovery Methods Bypass Policy

| Reason | Explanation |
|--------|-------------|
| **Protocol requirement** | MCP clients MUST call `initialize` and discovery methods to function. Denying these breaks the protocol entirely. |
| **No state mutation** | These methods don't change anything - they only return metadata about capabilities. |
| **No sensitive data** | Discovery returns tool names/descriptions, not actual content. |
| **Defense in depth** | Even if an attacker sees what tools exist, they can't USE them without policy approval. |
| **Audit trail preserved** | All discovery calls are logged with `final_rule: "discovery_bypass"`. |

**Exception: `prompts/get`** returns actual prompt content which could contain:
- Sensitive instructions
- API keys embedded in prompts
- Business logic that shouldn't be exposed

Therefore `prompts/get` requires policy evaluation like any other action.

---

## Example Policy

A practical policy allowing reads from a project directory, requiring approval for writes:

```json
{
  "version": "1",
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-read-project",
      "effect": "allow",
      "conditions": {
        "tool_name": "read*",
        "path_pattern": "/home/user/projects/**"
      }
    },
    {
      "id": "hitl-write-project",
      "effect": "hitl",
      "conditions": {
        "tool_name": "write*",
        "path_pattern": "/home/user/projects/**"
      }
    },
    {
      "id": "deny-secrets-dir",
      "effect": "deny",
      "conditions": {
        "path_pattern": "**/secrets/**"
      }
    },
    {
      "id": "deny-private-dir",
      "effect": "deny",
      "conditions": {
        "path_pattern": "**/private/**"
      }
    }
  ]
}
```

**How this works:**
- Reads from `/home/user/projects/**`: allowed
- Writes to `/home/user/projects/**`: HITL approval required
- Any access to `**/secrets/**` or `**/private/**`: denied (DENY beats ALLOW/HITL)
- Everything else: denied (default action)

---

## Human-in-the-Loop (HITL)

HITL is triggered **exclusively by policy rules** with `effect: "hitl"`. The system does not yet perform autonomous context analysis, heuristic-based triggering, or risk scoring.

### Platform Support

**Two HITL interfaces are available:**

1. **Web UI** (cross-platform): When the management UI is connected via SSE, approval requests are routed to the web interface. This works on all platforms.

2. **macOS native dialogs**: Falls back to `osascript` dialogs when web UI is not connected:
   - Audio notification (`Funk.aiff`) on first dialog
   - Queue indicator shows pending requests

**Linux/Windows without web UI**: Auto-deny with warning log.

### Dialog Content (osascript)

```
Tool: <tool_name>
Backend: <backend_id>
Path: <path>                    (truncated to 60 chars if needed)
Rule: <rule_that_triggered>     (why HITL was required)
Effects: <side_effects>         (e.g., fs_write, code_exec)
User: <subject_id>
Queue: #2 pending               (only shown if queue_position > 1)

Auto-deny in 60s
[Esc] Deny | Allow (Xm) | [Return] Allow once
```

**Button behavior (when caching enabled - 3 buttons):**
- **Deny** (Esc): Reject the operation
- **Allow (Xm)**: Approve and cache for X minutes (based on `approval_ttl_seconds`)
- **Allow once** (Return): Approve without caching

**Button behavior (when caching disabled - 2 buttons):**
- **Deny** (Esc): Reject the operation
- **Allow** (Return): Approve the operation

### HITL Configuration

HITL timeout and TTL settings are in `config.json`. Caching behavior is configured per-rule in `policy.json`.

**Config settings** (`config.json`):

| Field | Required | Default | Constraints | Description |
|-------|----------|---------|-------------|-------------|
| `timeout_seconds` | No | `60` | 5-300 | How long to wait for user response |
| `default_on_timeout` | No | `"deny"` | (fixed) | Always deny on timeout (Zero Trust, cannot be changed) |
| `approval_ttl_seconds` | No | `600` | 300-900 | How long cached approvals remain valid (5-15 min) |

**Per-rule caching** (`policy.json`):

Each HITL rule can specify `cache_side_effects` to control which side effects allow caching:

```json
{
  "id": "hitl-read-files",
  "effect": "hitl",
  "conditions": { "tool_name": "read*" },
  "cache_side_effects": ["fs_read"]
}
```

| Value | Behavior |
|-------|----------|
| `null` or omitted | Only cache tools with NO side effects |
| `["fs_read", "fs_write", ...]` | Cache tools with these specific side effects |
| (any value) | Tools with `code_exec` are **never cached** (security) |

**Note**: `cache_side_effects` is only valid on rules with `effect: "hitl"`. It will be rejected on allow/deny rules.

**Note**: MCP clients have their own request timeouts. Ensure client timeout > HITL timeout to allow user response time.

### Approval Caching

To reduce HITL dialog fatigue, approvals can be cached for repeated operations:

- **Cache key**: `(user, tool, path)` - approvals are path-specific
- **TTL**: Configurable via `approval_ttl_seconds` (default: 10 minutes)
- **Buttons**: "Allow (Xm)" caches the approval, "Allow once" does not
- **Clearing**: Cache is cleared on policy reload

**Security**: The cache key does not include tool arguments, so code execution tools (bash, etc.) cannot be safely cached - the same cache key would match different commands.

### Audit & Security

All HITL decisions are logged to `decisions.jsonl`. See [Logging](logging.md) for details and [Security](security.md) for HITL security design decisions.

---

## See Also

- [Configuration](configuration.md) for policy file location and HITL settings (in config.json)
- [Security](security.md) for fail-closed behavior
- [Logging](logging.md) for decision logging
