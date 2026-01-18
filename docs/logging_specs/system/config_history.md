### Configuration History

Config history logs follow general security logging and configuration-management best practices (OWASP, NIST SP 800-92/800-128, CIS Control 8) by recording when configuration versions are created or updated, their identifiers, source file, and a full snapshot sufficient to reconstruct the effective configuration during later incident analysis.

The configuration history log schema is designed in alignment with established security logging and configuration-management best practices. The OWASP Logging Cheat Sheet emphasizes that application logs should include security-relevant events such as configuration changes to assist in incident detection, auditing, and forensic analysis, and that logs should record sufficient information to answer the questions of 'who, what, when, and where'.
NIST Special Publication 800-128, Guide for Security-Focused Configuration Management of Information Systems, highlights the importance of managing and monitoring system configurations as part of a security-focused configuration management process, supporting effective control of changes and minimizing risk.
CIS Controls v8.1 (Control 8: Audit Log Management) similarly recommends collecting and retaining audit logs of security-relevant events, including configuration changes, that can help detect, understand, or recover from attacks.
Reflecting this guidance, the config_history log records each successful configuration load or update, including the version identifier, previous version, change type, source path, a checksum of the content, and a full snapshot of the configuration, enabling reconstruction of the effective configuration at any point in time for investigation or analysis.

**Log file**: `logs/system/config_history.jsonl`

**Model**: `ConfigHistoryEvent` in `telemetry/models/system.py`

### Fields

## Core
time — ISO 8601 timestamp (added by formatter during serialization)
sequence — monotonically increasing entry number (added by HashChainFormatter, proxy context only)
prev_hash — SHA-256 hash of previous entry, or "GENESIS" for first entry (proxy context only)
entry_hash — SHA-256 hash of this entry (proxy context only)
event — "config_created" | "config_updated" | "config_loaded" | "manual_change_detected" | "config_validation_failed"
message — optional human-readable description

## Versioning
config_version — version ID (e.g., "v1", "v2")
previous_version — optional, previous version ID
change_type — "initial_load" | "cli_update" | "manual_edit" | "startup_load" | "validation_error"

## Source / component
component — optional, e.g. "cli", "proxy", "config"
config_path — optional, path to the config file on disk
source — optional, e.g. "cli_init", "cli_update", "proxy_startup"

## Integrity
checksum — e.g. "sha256:abcd1234..."

## Snapshot
snapshot_format — "json" (only JSON supported)
snapshot — optional, full config content (string)

## Change details (for update events)
changes — optional dict: {"path": {"old": x, "new": y}}

## Error details (for validation failures)
error_type — optional, e.g. "JSONDecodeError", "ValidationError"
error_message — optional, human-readable error

### References
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://csrc.nist.gov/pubs/sp/800/128/upd1/final
- https://www.cisecurity.org/controls/v8-1
