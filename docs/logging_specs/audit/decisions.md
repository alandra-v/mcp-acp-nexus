### ABAC decisions

The policy decision log schema records the outcome of attribute-based access control (ABAC) evaluations performed by the proxy for each Model Context Protocol request. Each entry captures the evaluated action, the identified subject and backend, the final rule responsible for the decision, and the set of matched rules that contributed to the outcome, providing transparency into why a request was allowed, denied, or escalated. For high-risk operations, the schema additionally supports synchronous human-in-the-loop (HITL) enforcement by logging the human approval or denial outcome and the associated response time. By correlating each decision with the corresponding session, request, and active policy version, the decision log enables auditability, policy analysis, and forensic reconstruction of authorization behavior in a zero-trust proxy environment.

**Log file**: `logs/audit/decisions.jsonl`

**Model**: `DecisionEvent` in `telemetry/models/decision.py`

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
sequence — monotonically increasing entry number (added by HashChainFormatter)
prev_hash — SHA-256 hash of previous entry, or "GENESIS" for first entry
entry_hash — SHA-256 hash of this entry (for chain verification)
event — fixed string "policy_decision"

## Decision outcome
decision — "allow" | "deny" | "hitl"
hitl_outcome — optional, "user_allowed" | "user_denied" | "timeout" (only when decision == "hitl")
hitl_cache_hit — optional, true if approval was from cache, false if user was prompted, null if not HITL
hitl_approver_id — optional, OIDC subject ID of user who approved/denied (null if timeout or cache hit)
matched_rules — list of matched rule objects with decision trace info:
  - id: rule identifier
  - effect: "allow" | "deny" | "hitl"
  - description: optional human-readable description
final_rule — rule ID that determined the outcome (or "default", "discovery_bypass")

## Context summary
mcp_method — MCP method ("tools/call", "resources/read", etc.)
tool_name — optional, only for tools/call
path — optional file path (from tool arguments)
source_path — optional source path for move/copy operations
dest_path — optional destination path for move/copy operations
uri — optional resource URI (from resources/read)
scheme — optional URI scheme (file, https, s3, etc.)
subject_id — optional, OIDC sub claim (optional until auth is fully implemented)
backend_id — backend server ID (always known from config)
side_effects — optional list of side-effect tags (e.g. "FS_WRITE", "CODE_EXEC")

## Policy
policy_version — active policy version at decision time

## Performance
policy_eval_ms — policy rule evaluation time in milliseconds (float)
policy_hitl_ms — optional, HITL wait time in milliseconds (float, only when decision == "hitl")
policy_total_ms — total evaluation time in milliseconds (float, eval + HITL, excludes context building)

## Correlation
request_id — JSON-RPC request ID (every decision has a request)
session_id — optional, MCP session ID (may not exist during initialize)
