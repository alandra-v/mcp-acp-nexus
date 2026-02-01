# Roadmap

This document outlines planned improvements and future work for mcp-acp-nexus.

**Note:** Items within each category are not prioritized. Order does not indicate implementation sequence.

---

## Table of Contents

1. [Tool Registry](#1-tool-registry)
2. [Policy Engine Enhancements](#2-policy-engine-enhancements)
3. [Content Inspection](#3-content-inspection)
4. [Operations & Architecture](#4-operations--architecture)
5. [HTTP Client Support](#5-http-client-support)
6. [Authentication Enhancements](#6-authentication-enhancements)

---

## 1. Tool Registry

Features related to tool classification and metadata management.

### 1.1 External Tool Registry

Replace hardcoded `TOOL_SIDE_EFFECTS` in `constants.py` with user-editable registry file.

```json
{
  "version": "1",
  "tools": {
    "my_custom_tool": {
      "side_effects": ["fs_write", "network_egress"],
      "risk_tier": "high"
    },
    "filesystem:read_file": {
      "side_effects": ["fs_read"],
      "risk_tier": "low"
    }
  },
  "defaults": {
    "unknown_tool_side_effects": [],
    "treat_unknown_as_mutating": true
  }
}
```

**Why deferred**: Hardcoded mapping demonstrates the concept. External registry is a UX improvement.

### 1.2 Confidence Tracking

Add explicit confidence levels to side effect mappings:

| Confidence | Meaning | Source |
|------------|---------|--------|
| `verified` | Cryptographically signed by tool author | Signed tool manifests |
| `mapped` | Admin manually configured | Registry file or built-in map |
| `guessed` | Inferred from tool name | `infer_operation()` heuristics |
| `unknown` | No information available | Tool not in any mapping |

```python
class ToolInfo(BaseModel):
    name: str
    side_effects: frozenset[SideEffect] | None = None
    side_effects_confidence: Literal["verified", "mapped", "guessed", "unknown"] | None = None
```

### 1.3 Sandbox Verification

Verify claimed side effects by running tools in isolated sandbox:

1. Tool claims `side_effects: ["fs_read"]`
2. Sandbox runs tool with monitoring
3. If tool attempts `fs_write`, flag as untrusted
4. Update confidence to `verified` or `untrusted`

**Why deferred**: Complex infrastructure. Manual mapping + distrust is sufficient for PoC.

---

## 2. Policy Engine Enhancements

Features that extend policy matching and evaluation capabilities.

### 2.1 Confidence-Based Policies

Enable policies to condition on tool metadata confidence levels. This allows different handling based on how reliably a tool's side effects are known.

**Use cases**:
- Require HITL for tools with `unknown` confidence
- Auto-allow tools with `verified` side effects from signed manifests
- Ship default policies for common security patterns (e.g., always HITL for `code_exec`)

```json
{
  "rules": [
    {
      "conditions": {
        "side_effects_confidence": "unknown"
      },
      "effect": "hitl"
    },
    {
      "conditions": {
        "side_effects": ["code_exec"]
      },
      "effect": "hitl"
    }
  ]
}
```

### 2.2 Provenance-Aware Policies

Enable policies to require specific provenance levels:

```json
{
  "conditions": {
    "tool_name": "bash",
    "subject_provenance": "token"
  },
  "effect": "allow"
}
```

Sensitive operations only allowed when identity is cryptographically verified.

### 2.3 Tool Arguments in Policy

Make tool arguments available for fine-grained policy:

```json
{
  "conditions": {
    "tool_name": "http_request",
    "argument.method": "DELETE"
  },
  "effect": "deny"
}
```

**Why deferred**: Requires flattening arbitrary argument structures. Path extraction covers most cases.

### 2.4 Regex Support in Matchers

Add `path_regex` condition alongside glob patterns:

```json
{
  "conditions": {"path_regex": ".*\\.(key|pem|p12)$"},
  "effect": "deny"
}
```

**Why deferred**: Glob patterns cover 90% of use cases.

### 2.5 Resource Groups

Define reusable groups of values to reduce policy duplication:

```json
{
  "groups": {
    "sensitive_paths": [
      "/etc/passwd",
      "/etc/shadow",
      "~/.ssh/*",
      "**/*.key",
      "**/*.pem"
    ],
    "admin_tools": [
      "bash",
      "sh",
      "zsh",
      "exec_*"
    ]
  },
  "rules": [
    {
      "conditions": {
        "path_pattern": {"in_group": "sensitive_paths"}
      },
      "effect": "deny"
    },
    {
      "conditions": {
        "tool_name": {"in_group": "admin_tools"}
      },
      "effect": "hitl"
    }
  ]
}
```

**Benefits**:
- DRY: define common patterns once
- Maintainability: update group, all rules using it update
- Readability: semantic names instead of repeated patterns

**Why deferred**: Current flat rules are sufficient for PoC. Groups are a convenience feature that doesn't change the security model.

### 2.6 Approval-Aware Policy Conditions

Expose approval state as policy conditions for more flexible rules:

```json
{
  "rules": [
    {
      "conditions": {
        "tool_name": "bash",
        "approval_present": true
      },
      "effect": "allow"
    },
    {
      "conditions": {
        "tool_name": "bash"
      },
      "effect": "hitl"
    }
  ]
}
```

Available conditions:
- `approval_present: true/false` - Whether a cached approval exists
- `approval_age_seconds: "<600"` - How old the cached approval is

**Current behavior**: Approval caching is transparent (internal to HITL handler). Cached approvals automatically skip the HITL dialog without policy involvement.

**Why deferred**: Current transparent caching reduces dialog fatigue. Exposing approval state to policies adds complexity and requires careful design to avoid security pitfalls (e.g., attackers triggering approvals then changing context).

### 2.7 Policy Dry-Run / What-If Simulation

Test policy changes against historical audit data before applying. The user provides a candidate policy, and the system replays recent decisions from `decisions.jsonl`, reporting which outcomes would change.

**Example output**:
```
Dry-run against last 500 decisions:
  3 requests: ALLOW → DENY  (tools: bash, exec_command)
  1 request:  DENY  → HITL  (tool: filesystem:write_file)
  496 decisions unchanged
```

**API endpoint**: `POST /api/policy/dry-run` with candidate policy in request body. Returns per-rule diff with affected tool names and counts.

**UI integration**: "Test Changes" button in the policy editor. Shows a diff-style summary before the user commits the new policy.

**Benefits**:
- Reduces risk of policy misconfiguration (e.g., accidentally denying critical tools)
- Builds confidence before deploying restrictive policies
- Enables iterative policy refinement with immediate feedback

**Why deferred**: Requires audit log parsing and offline policy evaluation replay. Core policy enforcement works without simulation.

### 2.8 Auto-Suggest Policy Rules from HITL Patterns

Detect repeated HITL approvals for the same tool/resource pattern and suggest explicit allow rules to the user.

**Trigger**: After N approvals (configurable, default 5) for the same `(tool_name, path_pattern)` combination within a session, the UI displays a suggestion:

> "You've approved `filesystem:read_file` 12 times. Create an allow rule?"

**Suggestion includes**:
- Pre-filled rule with matched conditions
- One-click "Add Rule" button in the UI
- Option to scope the rule (e.g., add path constraint)

**Implementation**:
- Track approval frequency per `(tool_name, path_pattern)` in `ProxyState`
- Emit `rule_suggestion` SSE event when threshold is exceeded
- UI renders suggestion banner with pre-filled `RuleFormDialog`

```json
{
  "type": "rule_suggestion",
  "tool_name": "filesystem:read_file",
  "approval_count": 12,
  "suggested_rule": {
    "name": "auto-allow-filesystem-read",
    "conditions": {"tool_name": "filesystem:read_file"},
    "effect": "allow"
  }
}
```

**Benefits**:
- Turns HITL approval flow into a guided policy-building tool
- Reduces approval fatigue over time as policies mature
- Natural extension of existing approval caching mechanism

**Why deferred**: Requires frequency tracking infrastructure and suggestion UX. Current approval caching handles immediate fatigue.

### 2.9 Policy Templates / Presets

Ship built-in policy templates for common security postures, selectable during `proxy add` (CLI and UI).

| Template | Effect | Description |
|----------|--------|-------------|
| `strict` | HITL for all | Every non-discovery request requires human approval |
| `read-only` | Allow reads, deny writes | Allow `fs_read`, deny `fs_write`/`code_exec`/`network_egress` |
| `permissive` | Allow all, log all | No enforcement, full audit trail (audit-only mode) |
| `custom` | Empty rules | Start from scratch (current default) |

**CLI integration**:
```
$ mcp-acp proxy add
  ...
  Policy template:
  > strict (HITL for all non-discovery)
    read-only (allow reads, deny writes)
    permissive (allow all, log all)
    custom (start from scratch)
```

**UI integration**: Template selector in `AddProxyModal` with preview of generated rules.

**Storage**: Templates stored as JSON in `mcp_acp/policy/templates/` and written to per-proxy `policy.json` on selection.

**Benefits**:
- Lowers barrier to entry for new users
- Demonstrates flexibility of the ABAC policy engine with concrete examples
- Provides secure defaults (`strict` template) for first-time setup

**Why deferred**: Per-proxy policy files work. Templates are a UX convenience that doesn't change the security model.

---

## 3. Content Inspection

Features for inspecting request/response content for security issues.

### 3.1 Request Data Inspection

Inspect request arguments for sensitive content before forwarding to backend.

**Detection targets**:
- API keys, passwords, tokens in arguments
- PII (SSN, email, phone numbers)
- Private keys, certificates
- Internal hostnames/IPs being sent externally

**Why deferred**: Requires regex pattern library and false-positive tuning.

### 3.2 Response Inspection

Inspect responses from backend servers for:

- Secret leakage (API keys, passwords in responses)
- Prompt injection attempts
- Data exfiltration in error messages

**Why deferred**: Complex threat model. Requires careful design of what to block vs. warn.

### 3.3 Discovery Response Filtering

Filter `tools/list` responses to hide tools that would be denied:

- Agent never sees tools it can't use
- Prevents agent from attempting denied operations
- Reduces confusion and wasted tokens

**Why deferred**: Core policy enforcement works without it. This is a UX improvement.

---

## 4. Operations & Architecture

Features related to operational monitoring and policy architecture.

### 4.1 Heuristic HITL Triggers

Automatically trigger HITL based on risk scoring rather than explicit policy rules:
- Unknown tool + write operation
- First time accessing this resource
- High-value target (secrets, config files)

**Why deferred**: Requires risk scoring model.

### 4.2 Global + Per-Proxy Policy Inheritance

Reduce policy duplication with inheritance model:

```
~/.mcp-acp/
├── policy.json              # Global defaults (shared rules)
└── proxies/
    ├── filesystem/
    │   └── policy.json      # Inherits global + backend-specific overrides
    └── database/
        └── policy.json      # Inherits global + backend-specific overrides
```

**Benefits**:
- Common patterns defined once ("always HITL for destructive ops")
- Per-proxy rules for backend-specific needs
- Clear override semantics (per-proxy wins over global)

**Why deferred**: Per-proxy policy is sufficient. Different backends need different rules anyway.

### 4.3 Multi-Instance Policy Sync

For distributed deployments, sync policies across proxy instances:

```
┌─────────────┐     push/pull      ┌─────────────┐
│   Policy    │◀──────────────────▶│   Proxy A   │
│   Server    │◀──────────────────▶│   Proxy B   │
│             │◀──────────────────▶│   Proxy C   │
└─────────────┘                    └─────────────┘
```

Inspired by [permit.io/permit-fastmcp](https://github.com/permitio/permit-fastmcp).

**Why deferred**: Single-host deployment is current scope. Multi-host requires policy server infrastructure.

### 4.4 Third-Party Policy Engines

Integrate with external policy engines for complex authorization:

| Engine | Description |
|--------|-------------|
| [OPA](https://www.openpolicyagent.org/) | Open Policy Agent - Rego language, widely adopted |
| [Cedar](https://www.cedarpolicy.com/) | AWS Cedar - expressive, formally verified |
| [Permit.io](https://permit.io) | SaaS policy management with UI |
| [Cerbos](https://cerbos.dev/) | Self-hosted, GitOps-friendly |

**Benefits**:
- Battle-tested policy evaluation
- Rich policy languages
- Policy-as-code workflows
- Audit and compliance features

**Why deferred**: Custom policy engine is sufficient. External engines add deployment complexity.

### 4.5 Backend Health Monitoring

Continuous health checks for backend MCP servers (beyond startup validation).

**Features**:
- Periodic health checks (configurable interval)
- Health states: healthy, degraded, unhealthy, unknown
- Toast notifications on state transitions
- Health history tracking per backend
- Auto-recovery / restart on failure

**Value in future deployments**:

| Scenario | Value |
|----------|-------|
| Multi-user deployments | Admins need visibility into system health across all proxies |
| Long-running services | Proactive alerts before users encounter failures |
| Auto-recovery | Foundation for "restart backend on failure" automation |

**Why deferred**: For single-user local deployment, error handling on tool calls already tells you something's wrong. Health monitoring adds complexity without significant benefit in this context.

### 4.6 Policy Rule Hit Counters

Track and display how many times each policy rule has been triggered, broken down by decision outcome (allow/deny/hitl).

**Data source**: `decisions.jsonl` already logs `matched_rules` and `final_rule` per evaluation. Aggregation can be performed:
- **Live**: Counter in `ProxyState` incremented on each `record_decision()` call
- **Historical**: Parse `decisions.jsonl` on demand for cumulative counts

**API endpoint**: `GET /api/policy/stats` returns per-rule statistics:

```json
{
  "rules": [
    {
      "rule_id": "allow-reads",
      "hit_count": 347,
      "last_hit": "2025-01-28T14:30:00Z",
      "as_final_rule": 340,
      "outcomes": {"allow": 340, "deny": 0, "hitl": 7}
    }
  ],
  "unmatched_count": 12
}
```

**UI integration**: Display hit counts as badges next to each rule in `PolicyRulesList`. Highlight rules with zero hits (potential dead policy). Show `unmatched_count` as a warning if non-zero (requests falling through to default deny).

**Benefits**:
- Identify unused rules (dead policy that can be cleaned up)
- Understand which rules are most active for tuning
- Detect unmatched requests hitting default deny (policy gaps)

**Why deferred**: Audit logs already capture the underlying data. Aggregation and display are presentation features.

### 4.7 Export Audit Summary Report

Generate a downloadable summary of audit activity for a proxy over a configurable time range.

**Report contents**:
- Time range and proxy identification
- Total requests with decision breakdown (allow/deny/hitl)
- Top 10 triggered rules with hit counts
- Authentication events (logins, logouts, token refreshes)
- Integrity incidents (hash chain breaks, emergency events)
- Policy change history within the period

**Format options**:
- JSON (machine-readable, suitable for further analysis)
- Markdown (human-readable, suitable for stakeholder reports)

**API endpoint**: `GET /api/audit/report?from=2025-01-01&to=2025-01-31&format=markdown`

**CLI integration**: `mcp-acp audit report --proxy <name> [--from DATE] [--to DATE] [--format json|markdown]`

**Benefits**:
- Demonstrates compliance value of the audit trail
- Useful for periodic security reviews
- Makes audit data accessible to non-technical stakeholders

**Why deferred**: Raw audit logs and the log viewer provide access to the underlying data. Export is a presentation feature.

---

## 5. HTTP Client Support

Enable non-STDIO clients (ChatGPT, custom apps) to connect via HTTP.

See [design/http-client-support.md](http-client-support.md) for full design.

### Summary

HTTP client mode enables cloud-based AI assistants and web clients to connect through the manager instead of spawning proxies via STDIO.

**Key features**:
- Manager as reverse proxy with lazy worker spawn
- OIDC/mTLS/API key authentication for HTTP clients
- Idle timeout shutdown for resource management
- SSE streaming support

**Why deferred**: Introduces zero-trust challenges:
- Cannot verify device posture for remote clients
- Cannot verify human intent behind AI requests
- Requires internet exposure of manager endpoint
- HITL approval UX needs rethinking for async/remote scenarios

**Alternatives documented**: Local AI only, bastion host pattern, pre-approved action sets, async request queue.

---

## 6. Authentication Enhancements

Features related to credential and key management.

### 6.1 OIDC Confidential Client Support

Current implementation uses **public clients** with Device Flow (RFC 8628), which don't require a client secret. This is appropriate for CLI/desktop applications where secrets cannot be securely embedded in application binaries.

For server-to-server or confidential client scenarios:

- Add optional `client_secret_key` field to `OIDCConfig` (keychain reference, not the secret)
- Store actual secret in OS keychain: service=`mcp-acp`, key=`oauth:client_secret`
- Support appropriate grant types (client_credentials, authorization_code)

**Why deferred**: Device Flow covers current CLI/desktop use cases. Confidential clients require different grant types and deployment patterns (server-side applications).

### 6.2 mTLS Private Key Passphrase Storage

Support password-protected mTLS private keys by storing passphrases in OS keychain.

**Current behavior**: mTLS key files must be unencrypted.

**Enhancement**:
- `proxy add` detects encrypted key files and prompts for passphrase
- Passphrase stored in keychain: `proxy:{name}:mtls_passphrase`
- Loaded automatically when creating SSL context

**Why deferred**: Most users use unencrypted key files. Enterprise users with encrypted keys often have dedicated key management systems (HSMs, vault). Adds complexity for minority use case.

### 6.3 Audit Log HMAC Protection

Add HMAC-SHA256 signing to audit log entries using a secret key stored in OS keychain.

**Current limitation** (documented in `hash_chain.py`): The hash chain is self-attesting. An attacker with write access to both log files AND `.integrity_state` can truncate logs, recompute hashes, and update state to match - tampering goes undetected.

**Enhancement**: Store HMAC key in keychain. Entry hashes become `HMAC-SHA256(key, entry)` instead of `SHA256(entry)`. Attacker would need keychain access to forge valid hashes.

**Backward compatibility**: Existing logs have plain SHA-256 hashes (cannot be retroactively HMAC'd). State file would track `hmac_start_sequence` - verification uses SHA-256 for entries before that sequence, HMAC after.

**Existing mitigations** (without HMAC): Forward logs to remote syslog, use append-only filesystem attributes (`chattr +a`), or backup to immutable storage.

**Why deferred**: Current hash chain demonstrates tamper-evident logging. HMAC is production hardening for edge cases where attacker has write access to both logs and state file.

---

## Future Exploration

Ideas that require significant research or infrastructure before becoming actionable roadmap items.

### Deep Content Analysis

Beyond regex patterns, analyze request content semantically:
- Detect encoded secrets (base64, hex)
- Identify data that looks like credentials
- Flag unusual data volumes

Requires ML/heuristics research.

### Behavioral Analysis

Detect unusual patterns that may indicate compromise:
- Unusual request volume or timing
- Access to resources not typically accessed
- Session behavior changes

Requires behavioral baselines and statistical analysis.

---

## Summary

| Category | Features |
|----------|----------|
| Tool Registry | External registry, confidence tracking, sandbox verification |
| Policy Engine | Confidence policies, provenance, arguments, regex, resource groups, approval-aware, dry-run simulation, auto-suggest rules, policy templates |
| Content Inspection | Request/response inspection, discovery filtering |
| Operations & Architecture | Heuristic HITL triggers, policy inheritance/sync, third-party engines, health monitoring, rule hit counters, audit summary export |
| HTTP Client Support | Manager reverse proxy, OIDC/mTLS auth, lazy spawn, idle shutdown |
| Authentication Enhancements | OIDC confidential clients, mTLS key passphrases, audit HMAC protection |

All features are deferred because explicit policy rules and manual tool mapping are sufficient for the current scope.
