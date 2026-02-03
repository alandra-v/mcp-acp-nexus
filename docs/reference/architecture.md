# Architecture

## Project Overview

**mcp-acp** is a Zero Trust Access Control Proxy for the Model Context Protocol (MCP). It sits between MCP clients (like Claude Desktop) and MCP servers (like filesystem servers), providing comprehensive security, logging, and human oversight.

```
                                          ┌───────────┐
                                          │   PIPs    │
                                          │ (OIDC,    │
                                          │  Device)  │
                                          └───────────┘
                                                ▲
                                                │ 3. query
                                                │
┌──────────┐  1. request   ┌────────────────────┼───────────────┐  6. request   ┌──────────┐
│  Client  │──────────────▶│              Proxy │               │──────────────▶│  Server  │
│          │◀──────────────│                    │               │◀──────────────│          │
└──────────┘  6. response  │  ┌───────┐    ┌────┴──────┐        │  6. response  └──────────┘
                           │  │       │ 2. │           │        │
                           │  │  PEP  │───▶│    PDP    │        │
                           │  │       │◀───│  (Policy  │        │
                           │  │       │ 5. │   Engine) │        │
                           │  └───────┘    └───────────┘        │
                           │                                    │
                           │  ┌───────────┐    ┌───────────┐    │
                           │  │ Audit Log │    │System Log │    │
                           │  └───────────┘    └───────────┘    │
                           └────────────────────────────────────┘
```

**Architecture Pattern**: PEP/PDP separation (Policy Enforcement Point / Policy Decision Point)

**Philosophy**: Default-deny, explicit policies, audit everything, modular and extensible

---

## Request Flow

**Request processing steps:**

```
1. Client sends MCP request -> Proxy (STDIO)
2. DoS rate limiter: Check global request rate (10 req/s, 50 burst)
3. Context middleware: Set request_id, session_id, tool_context
4. Audit middleware: Log operation to operations.jsonl
5. ClientLogger: Debug logging (if enabled)
6. Enforcement middleware:
   a. Build DecisionContext (user, session, operation, resource)
   b. Check per-tool rate limits (triggers HITL if exceeded)
   c. Call PolicyEngine.evaluate(context) -> Decision
   d. If ALLOW: forward to backend
   e. If DENY: return error, log denial
   f. If HITL: prompt user -> ALLOW or DENY
7. Backend processes request
8. Response flows back through middleware (inner-to-outer)
9. Client receives response
```

### Middleware Stack

Middleware executes outer-to-inner on requests, inner-to-outer on responses. In FastMCP, **first-added middleware is outermost** (runs first on requests).

```
Request:  Client → DoS → Context → Audit → ClientLogger → Enforcement → Backend
Response: Client ← DoS ← Context ← Audit ← ClientLogger ← Enforcement ← Backend
```

| Middleware | Purpose |
|------------|---------|
| DoS (outermost) | Token bucket rate limiting (10 req/s, 50 burst) - catches flooding before any processing |
| Context | Sets request_id, session_id, tool_context for correlation |
| Audit | Logs all operations to `operations.jsonl` (always enabled) |
| ClientLogger | Debug wire logging to `client_wire.jsonl` (if debug enabled) |
| Enforcement (innermost) | Policy evaluation, HITL, per-tool rate limiting, blocks before backend |

**Two rate limiters:**
- **DoS rate limiter** (outermost): Global token bucket, catches flooding before any processing
- **Per-tool rate limiter** (in Enforcement): Per-session, per-tool tracking (30 calls/60s triggers HITL)

Policy decisions use ABAC (Attribute-Based Access Control) with subject, action, resource, and environment attributes. See [Policies](policies.md) for attribute details.

For detailed sequence diagrams, see [Request Flow Diagrams](request_flow_diagrams.md).

---

## Zero Trust Tenets (NIST SP 800-207)

The proxy implements Zero Trust Architecture based on the seven tenets defined in [NIST SP 800-207](https://doi.org/10.6028/NIST.SP.800-207):

| # | NIST Tenet | Status | Implementation | Gaps |
|---|------------|--------|----------------|------|
| 1 | "All data sources and computing services are considered resources." | Partial | MCP operations (tools/call, resources/read, prompts/get) require policy evaluation | Discovery methods (`tools/list`, `resources/list`, etc.) bypass policy entirely |
| 2 | "All communication is secured regardless of network location." | Partial | STDIO with binary attestation (hash, codesign, SLSA); Streamable HTTP with mTLS | Post-spawn process verification implemented but **not integrated** into transport |
| 3 | "Access to individual enterprise resources is granted on a per-session basis." | Partial | Policy evaluated for ACTION methods; identity validated per-request; session-scoped approvals | Discovery methods skip per-request authorization; HITL approvals cached (reduces re-auth frequency) |
| 4 | "Access to resources is determined by dynamic policy..." | Full | ABAC policy engine evaluates subject, action, resource, environment attributes per request | — |
| 5 | "The enterprise monitors and measures the integrity and security posture of all owned and associated assets." | POC | Audit log integrity (30s interval, fail-closed); device posture (5-min interval) | Device health is **POC only**: just FileVault/SIP on macOS, no MDM, endpoint agents, or cert attestation |
| 6 | "All resource authentication and authorization are dynamic and strictly enforced before access is allowed." | Partial | OIDC JWT validated per-request (mandatory); policy enforced before forwarding | Discovery methods bypass authorization entirely |
| 7 | "The enterprise collects as much information as possible..." | Full | Audit logging (operations, decisions, config/policy history) for forensics | — |

**Additional design principles:**
- **Fail-closed**: All errors result in DENY; audit/integrity failures trigger shutdown
- **Human oversight**: HITL for sensitive operations as policy-defined escalation
- **Least privilege**: Path-scoped policies, default-deny, protected directories

### Modularity

| Component | Mechanism | Status |
|-----------|-----------|--------|
| Identity | `IdentityProvider` protocol | Pluggable (OIDC implemented) |
| Token storage | `TokenStorage` ABC | Pluggable (keyring, encrypted file) |
| Transport | FastMCP transport abstraction | STDIO, streamable HTTP |
| Middleware | FastMCP middleware stack | Composable ordering |
| Configuration | Version field, Pydantic models | Schema evolution supported |
| Policy engine | `PolicyEngineProtocol` in pdp/ | Pluggable (built-in ABAC engine implemented) |
| Logging | Pydantic models, JSONL format | Extensible (SystemEvent allows extra fields) |


---

## Module Organization

The codebase is organized by domain with related responsibilities grouped together:

| Module | Purpose |
|--------|---------|
| `proxy.py` | Main entry point, lifecycle orchestration |
| `config.py` | Configuration models (Pydantic) |
| `api/` | Management API server (FastAPI), routes, schemas |
| `manager/` | Manager daemon, proxy coordination, registry, SSE events, state aggregation |
| `cli/` | Command-line interface (Click-based) |
| `context/` | ABAC context building (subject, action, resource, environment) |
| `pdp/` | Policy Decision Point (engine, matcher, rules) |
| `pep/` | Policy Enforcement Point (middleware, HITL, approval cache) |
| `pips/` | Policy Information Points (OIDC, session management) |
| `security/` | Security infrastructure (auth, posture, integrity, shutdown) |
| `telemetry/` | Logging (audit, debug, system) |
| `web/` | Static files for React UI |
| `utils/` | Helpers (transport, config, policy, logging, history logging, file ops) |

---

## Context vs PIP

**`context/`** builds decision context from **local information**:
- Request data (MCP method, arguments, tool name)
- Proxy configuration (server ID, protected directories)
- Tool side effects mapping

**`pips/`** queries **external attribute sources** at decision time:

| PIP | What it provides | Status |
|-----|------------------|--------|
| OIDC Identity Provider | User ID, scopes, token claims from JWT | Implemented |
| Device Posture | FileVault, SIP status | POC |
| Tool Registry | Verified side effects, risk tiers | Future |
| Threat Intel Feed | Known bad IPs, risk scores | Future |

Both modules contribute to the DecisionContext - `context/` provides locally-derived attributes, `pips/` provides externally-sourced attributes with higher trust (e.g., TOKEN provenance from IdP).

The `DecisionContext` flows through the system for policy evaluation, logging, and user interaction. See [Policies](policies.md) for attribute details.

**Design principle**: Context is used for **matching**, not autonomous decision-making. The PolicyEngine matches attributes against rules - it does not analyze context to infer intent.

### Why Device Posture lives in `security/posture/`, not `pips/`

Device health is conceptually a PIP in NIST 800-207 — it provides posture attributes that should feed into policy decisions. However, the current implementation lives in `security/posture/` because it does not yet behave like a PIP:

- **Current behavior is enforcement, not attribute-providing.** Device health is a hard startup gate (`check_device_health()`) and a background monitor (`DeviceHealthMonitor`) that triggers fail-closed shutdown on failure. This is PEP-like behavior — it enforces a binary pass/fail, not surfacing attributes for the PDP to evaluate in policy rules.
- **`security/` groups implementation primitives** (auth tokens, mTLS, integrity, posture) while `pips/` groups higher-level zero trust components that provide attributes to the PDP. The split reflects what the code actually does.
- **Migration trigger:** Move device posture to `pips/posture/` when it becomes a real attribute source for the PDP — i.e., when posture signals (e.g., `device.filevault == "enabled"`, `device.sip == "enabled"`) are exposed as policy conditions in `RuleConditions` and evaluated by the policy engine per-request, rather than acting as a binary startup/shutdown gate.

---

## State Management

The `manager/` module runs a daemon process that coordinates proxies, serves the web UI (port 8765), handles proxy registration via UDS, and provides state aggregation for the Management API.

**ProxyState** aggregates:
- Cached HITL approvals
- Active user sessions
- Pending approvals (requests waiting for UI decision)
- Request statistics (total/allowed/denied/HITL counts)
- Backend connection state (for reconnection detection)

**SSE Events** are broadcast to connected UI clients for real-time updates:
- **HITL lifecycle**: snapshot, pending_created, pending_resolved, pending_timeout, pending_not_found
- **Backend connection**: backend_connected, backend_disconnected, backend_reconnected, backend_timeout, backend_refused
- **TLS/mTLS**: tls_error, mtls_failed, cert_validation_failed
- **Authentication**: auth_login, auth_logout, auth_session_expiring, token_refresh_failed, token_validation_failed, auth_failure
- **Policy**: policy_reloaded, policy_reload_failed, policy_file_not_found, policy_rollback, config_change_detected
- **Rate limiting**: rate_limit_triggered, rate_limit_approved, rate_limit_denied
- **Cache**: cache_cleared, cache_entry_deleted, cached_snapshot
- **Request processing**: request_error, hitl_parse_failed, tool_sanitization_failed
- **Proxy lifecycle**: proxy_deleted
- **Live updates**: stats_updated, new_log_entries, incidents_updated
- **Critical events**: critical_shutdown, audit_init_failed, device_health_failed, session_hijacking, audit_tampering, audit_missing, audit_permission_denied, health_degraded, health_monitor_failed

See `manager/events.py` for the full `SSEEventType` enum.

---

## Future

### Evolution Stages

**Stage 1: Single Tenant Zero Trust Proxy**
- Single session, single backend server
- STDIO and Streamable HTTP transports

**Stage 2: Authentication & Authorization**
- OIDC authentication (Auth0 IdP)
- mTLS for proxy↔backend authentication
- User ID, email, scopes from JWT tokens
- Background health monitors with fail-closed shutdown
- Web UI for monitoring and HITL

**Stage 3 (Current): Multi-server**
- Multiple backend servers with per-proxy configs and policies
- Manager daemon for proxy coordination and web UI serving
- Per-proxy log directories, audit trails, and hash chain state
- Proxy registry with UDS-based registration

---

## See Also

- [API Reference](api_reference.md) for Management API endpoints
- [Security](../security/security.md) for security design decisions
- [Logging](../security/logging.md) for telemetry architecture
- [Policies](policies.md) for policy evaluation
- [Request Flow Diagrams](request_flow_diagrams.md) for detailed sequence diagrams of lifecycle and operation phases
