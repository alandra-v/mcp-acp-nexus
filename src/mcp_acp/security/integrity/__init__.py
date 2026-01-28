"""Audit log integrity monitoring, hash chains, and emergency fallback.

This module provides security controls for audit log integrity:
- FailClosedAuditHandler: Handler that triggers shutdown on compromise
- AuditHealthMonitor: Background monitoring for log tampering
- HashChainFormatter: Tamper-evident hash chain for log entries
- IntegrityStateManager: Between-run state persistence and verification
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
from mcp_acp.security.integrity.hash_chain import (
    HashChainFormatter,
    compute_entry_hash,
    verify_chain_from_lines,
    verify_chain_integrity,
    verify_file_integrity,
)
from mcp_acp.security.integrity.integrity_state import (
    FileIntegrityState,
    IntegrityStateManager,
    VerificationResult,
)

__all__ = [
    # Audit handler
    "FailClosedAuditHandler",
    "verify_audit_writable",
    # Audit monitor
    "AuditHealthMonitor",
    # Hash chain
    "HashChainFormatter",
    "compute_entry_hash",
    "verify_chain_from_lines",
    "verify_chain_integrity",
    "verify_file_integrity",
    # Integrity state
    "FileIntegrityState",
    "IntegrityStateManager",
    "VerificationResult",
    # Emergency audit
    "get_emergency_audit_path",
    "log_with_fallback",
    "write_emergency_audit",
]
