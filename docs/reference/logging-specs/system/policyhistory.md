### Policy History

Policy history logs capture the full lifecycle of policy configuration, including creation, updates, loads, manual changes, and validation failures. The design mirrors config_history for consistency and follows the same security logging best practices (OWASP, NIST SP 800-92/800-128, CIS Control 8).

**Log file**: `logs/system/policy_history.jsonl`

**Model**: `PolicyHistoryEvent` in `telemetry/models/system.py`

### Fields

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
sequence — monotonically increasing entry number (added by HashChainFormatter, proxy context only)
prev_hash — SHA-256 hash of previous entry, or "GENESIS" for first entry (proxy context only)
entry_hash — SHA-256 hash of this entry (proxy context only)
event — "policy_created" | "policy_loaded" | "policy_updated" | "manual_change_detected" | "policy_validation_failed"
message — optional human-readable description

## Versioning
policy_version — version ID (e.g., "v1", "v2")
previous_version — optional, previous version ID
change_type — "initial_creation" | "startup_load" | "rule_update" | "manual_edit" | "validation_error"

## Source / component
component — optional, e.g. "cli", "proxy", "pep", "hitl"
policy_path — optional, path to policy.json on disk
source — optional, e.g. "cli_init", "proxy_startup", "hitl_handler"

## Integrity
checksum — e.g. "sha256:abcd1234..."

## Snapshot
snapshot_format — "json" (only JSON supported for policies)
snapshot — optional, full policy content (string)

## Rule details (for rule updates)
rule_id — optional, ID of added/removed rule
rule_effect — optional, "allow" | "deny" | "hitl"
rule_conditions — optional dict, conditions of added rule

## Error details (for validation failures)
error_type — optional, e.g. "JSONDecodeError", "ValidationError"
error_message — optional, human-readable error
