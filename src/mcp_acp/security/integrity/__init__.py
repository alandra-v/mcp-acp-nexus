"""Audit log integrity monitoring and emergency fallback.

This module provides security controls for audit log integrity:
- FailClosedAuditHandler: Handler that triggers shutdown on compromise
- AuditLogMonitor: Background monitoring for log tampering
- Emergency audit: Last-resort logging when primary logs fail

Fallback chain: primary audit → system.jsonl → emergency_audit.jsonl
"""

from mcp_acp.security.integrity.audit_handler import (
    FailClosedAuditHandler,
    verify_audit_writable,
)
from mcp_acp.security.integrity.audit_monitor import AuditHealthMonitor
from mcp_acp.security.integrity.emergency_audit import (
    get_emergency_audit_path,
    log_with_fallback,
    write_emergency_audit,
)

__all__ = [
    "FailClosedAuditHandler",
    "verify_audit_writable",
    "AuditHealthMonitor",
    "get_emergency_audit_path",
    "log_with_fallback",
    "write_emergency_audit",
]
