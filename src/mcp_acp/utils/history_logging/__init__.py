"""History logging utilities for config and policy files.

This module provides utilities for logging configuration and policy
lifecycle events to JSONL history files for audit trail and compliance.

Features:
- Auto-increment versioning (v1, v2, v3...)
- SHA256 checksum for integrity verification
- Manual edit detection via checksum comparison
- Full audit trail of file lifecycle

Structure:
    config_logger.py  - Configuration history logging
    policy_logger.py  - Policy history logging

Shared utilities (VersionInfo, get_next_version, etc.) live in utils/file_helpers.py.

Note: Policy logging functions are NOT exported here to avoid circular imports.
Import them directly from mcp_acp.pdp or from policy_logger.py.
"""

from mcp_acp.utils.file_helpers import (
    VersionInfo,
    get_history_logger,
    get_last_version_info,
    get_next_version,
)
from mcp_acp.utils.history_logging.config_logger import (
    detect_config_changes,
    log_config_created,
    log_config_loaded,
    log_config_updated,
    log_config_validation_failed,
)

# Note: Policy functions not imported here to avoid circular imports with pdp
# Import directly: from mcp_acp.utils.history_logging.policy_logger import ...

__all__ = [
    # Base utilities
    "VersionInfo",
    "get_next_version",
    "get_last_version_info",
    "get_history_logger",
    # Config logging
    "detect_config_changes",
    "log_config_created",
    "log_config_loaded",
    "log_config_updated",
    "log_config_validation_failed",
]
