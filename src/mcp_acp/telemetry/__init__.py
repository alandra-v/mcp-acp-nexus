"""Telemetry domain: audit logging, debug wire logs, and system events.

This module contains FastMCP middleware implementations and logging utilities
for observability. The classes are named with "Middleware" suffix because they
ARE middleware - they extend FastMCP's Middleware/BaseLoggingMiddleware and
intercept the request/response flow.

Structure:
    audit/          Security audit logging (operations.jsonl)
                    - AuditLoggingMiddleware: Logs every MCP operation outcome
    debug/          Wire-level debug logs (client_wire.jsonl, backend_wire.jsonl)
                    - BidirectionalClientLoggingMiddleware: Client<->Proxy traffic
                    - LoggingProxyClient: Proxy<->Backend traffic
    models/         Pydantic models for all log event types
    system/         System operational logs (system.jsonl)
                    - Backend disconnect detection, startup events

Note: These are organized by domain (telemetry) rather than by pattern
(middleware) for clearer navigation. The middleware naming is intentional
and accurate - it describes what these components do at the implementation level.
"""

__all__: list[str] = []
