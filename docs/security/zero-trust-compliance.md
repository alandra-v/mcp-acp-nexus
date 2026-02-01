# Zero Trust Architecture Compliance

Evaluation of mcp-acp against NIST SP 800-207 Zero Trust Architecture (Section 2.1 — Seven Tenets).

---

## NIST SP 800-207 — Seven Tenets of Zero Trust

| # | Tenet |
|---|-------|
| 1 | All data sources and computing services are considered resources. |
| 2 | All communication is secured regardless of network location. |
| 3 | Access to individual enterprise resources is granted on a per-session basis. |
| 4 | Access to resources is determined by dynamic policy—including the observable state
of client identity, application/service, and the requesting asset—and may include
other behavioral and environmental attributes.  |
| 5 | The enterprise monitors and measures the integrity and security posture of all owned and associated assets. |
| 6 | All resource authentication and authorization are dynamic and strictly enforced before access is allowed. |
| 7 | The enterprise collects as much information as possible about the current state of
assets, network infrastructure and communications and uses it to improve its security posture. |

## NIST ZTA Logical Components Mapping

| NIST Component | mcp-acp Implementation |
|----------------|------------------------|
| **Policy Engine (PE)** | `pdp/engine.py` — ABAC policy engine with specificity-scored rule combining |
| **Policy Administrator (PA)** | `pep/middleware.py` — PolicyEnforcementMiddleware orchestrates context→evaluation→enforcement |
| **Policy Enforcement Point (PEP)** | Middleware chain: Context → Audit → ClientLogger → Enforcement (innermost) |
| **Policy Information Point (PIP)** | `pips/auth/oidc_provider.py` (identity), `context/context.py` (environment), `context/resource.py` (tool metadata) |
| **Subject** | Human user authenticated via OIDC; represented as `context/subject.py` with provenance-tagged claims |
| **Resource** | MCP tools, resources, prompts — each individually addressable in policy |

---

## Feature → Tenet Mapping

| Feature | Implementation | Tenets | Source |
|---------|---------------|--------|--------|
| **OIDC per-request validation** | JWT validated on every request; explicit no-caching design | 6 | `pips/auth/oidc_provider.py` |
| **ABAC policy engine** | Attribute-based rules with AND logic, deny-overrides combining, specificity scoring | 4 | `pdp/engine.py` |
| **Deny-by-default** | `default_action = "deny"` — no rules match → deny | 4, 6 | `pdp/policy.py` |
| **Per-tool policy rules** | Tools individually addressable via `tool_name`, `path_pattern`, `operations`, `side_effects`, etc. | 1, 4 | `pdp/policy.py` |
| **Side-effect classification** | 21 SideEffect categories (CODE_EXEC, FS_WRITE, NETWORK_EGRESS, etc.) for tool risk typing | 1, 4 | `context/resource.py` |
| **Session binding** | Format `<user_id>:<session_id>`, identity change → immediate shutdown | 3, 6 | `pips/auth/session.py` |
| **HITL approval** | Human-in-the-loop for sensitive operations with per-rule configuration | 4, 6 | `pep/middleware.py` |
| **HITL approval cache** | TTL-based cache (default 10 min); CODE_EXEC never cached; policy still re-evaluated | 4 | `pep/approval_store.py` |
| **Device health checks** | FileVault + SIP verification at startup and periodic (5-min intervals) | 5 | `constants.py` |
| **mTLS for HTTP backends** | Optional mutual TLS with certificate expiry monitoring | 2 | `security/mtls.py`, `utils/transport.py` |
| **Binary attestation (STDIO)** | SHA-256 hash of backend binary verified at startup | 2, 5 | `utils/transport.py` |
| **Fail-closed audit** | Inode/device checks before every write; shutdown on mismatch | 7 | `security/integrity/audit_handler.py` |
| **SHA-256 hash chain** | Audit log entries chained with SHA-256 hashes for tamper detection | 7 | `telemetry/audit/` |
| **Rate limiting** | Per-session, per-tool rate tracking (default 30/min); breach triggers HITL | 5, 7 | `security/rate_limiter.py` |
| **Tool description sanitization** | Strips prompt injection patterns from tool descriptions | 1, 5 | `security/tool_sanitizer.py` |
| **Protected config directory** | `PROTECTED_CONFIG_DIR` resolved with `os.path.realpath()` to prevent symlink bypass | 1 | `constants.py` |
| **Machine-bound token storage** | Tokens encrypted with machine-specific key in OS keychain | 3 | `security/auth/` |
| **Provenance tracking** | Context facts tagged with provenance (TOKEN, MTLS, MCP_REQUEST, CLIENT_HINT, etc.) | 7 | `context/provenance.py` |
| **Shutdown coordinator** | Exit codes 10-15 for specific security failures; crash breadcrumb for recovery | 5 | `security/shutdown.py` |
| **Manager API security** | Host validation (DNS rebinding), origin validation (CSRF), token/cookie auth, security headers | 2 | `api/security.py` |
| **UDS auth via OS permissions** | Socket at 0o600; OS file permissions = authentication (no token needed for CLI) | 2, 3 | `constants.py` (path), `proxy.py`, `manager/daemon/server.py` (permissions) |

---

## Per-Tenet Detailed Evaluation

### Tenet 1 — All data sources and computing services are considered resources.

> *"All data sources and computing services are considered resources. A network may be composed of multiple classes of devices... A zero trust architecture may also include additional items as resources, such as SaaS services, personally owned devices, or enterprise-owned assets."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| Tools as resources | Aligned | Each MCP tool is individually addressable in policy via `tool_name` condition |
| Resources as resources | Aligned | MCP `resources/read` has dedicated policy path with `path_pattern`, `extension`, `scheme` conditions |
| Prompts as resources | Aligned | `prompts/get` excluded from discovery bypass, requires policy evaluation |
| Backend servers | Aligned | `backend_id` condition allows per-server policy differentiation |
| Side-effect typing | Aligned | 21 SideEffect categories classify tool risk; used in policy conditions |
| Protected config dir | Aligned | Built-in immutable protection for policy/config/audit directories |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-001 | No formal resource registry/inventory | Medium | Implementation | Tenet 1 requires all resources to be identified and cataloged. Not met because tools are discovered dynamically from backends via `tools/list` with no persistent registry. There is no mapping of tool→risk tier, data classification, or ownership. `ToolInfo.risk_tier` field exists but is never populated. |
| GAP-002 | No data classification labels | Low | Implementation | Tenet 1 expects resources to be classified by sensitivity. Not met because resources lack sensitivity labels (e.g., PII, confidential, public). Policy rules approximate this via `path_pattern` and `extension`, but there is no formal data classification scheme. |

---

### Tenet 2 — All communication is secured regardless of network location.

> *"Network location alone does not imply trust. Access requests from assets located on enterprise-owned network infrastructure must meet the same security requirements as access requests from any other network."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| Backend HTTP: mTLS | Aligned | Optional mutual TLS with cert expiry monitoring (14-day warning, 7-day critical) |
| Backend STDIO: process isolation | Aligned | Local process pipe — no network involved; binary attestation at startup |
| Manager API: localhost binding | Aligned | HTTP on `127.0.0.1:8765` — not exposed to network |
| Manager API: host validation | Aligned | DNS rebinding protection — rejects requests with non-localhost Host headers |
| Manager API: CSRF protection | Aligned | Origin header validation for browser requests |
| UDS: OS permissions | Aligned | Socket at 0o600 — only owning user can connect; no token needed |
| Token storage | Aligned | Machine-bound encryption in OS keychain |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-003 | No TLS on manager HTTP API | Low | Implementation | See [GAP-003 detail](#gap-003-detail) below. |
| GAP-004 | No encryption on UDS transport | Low | Design constraint | Tenet 2 requires encrypted communication. Not met because Unix domain sockets do not support TLS. Mitigated by: OS file permissions (0o600, owner-only access) and kernel-mediated IPC (no network exposure). UDS is not a network protocol — data never leaves the kernel. |

#### GAP-003 detail: No TLS on manager HTTP API {#gap-003-detail}

**Tenet requirement:** Tenet 2 requires all communication to be secured regardless of network location.

**Why not met:** The manager HTTP server at `127.0.0.1:8765` uses plain HTTP. A strict ZTA reading considers unencrypted communication a gap even on loopback.

**Assessment: Low priority, high complexity, marginal benefit.**

**Current connection topology:**

```
┌─────────────────────────────────────────────────────────────────────┐
│  User's Machine (single-user desktop)                               │
│                                                                     │
│  ┌──────────┐     HTTP (plain)      ┌──────────────────────┐       │
│  │ Browser  │ ──────────────────────→│ Manager HTTP Server  │       │
│  │ (UI)     │    127.0.0.1:8765     │ (uvicorn)            │       │
│  └──────────┘                        │                      │       │
│                                      │ SecurityMiddleware:   │       │
│  ┌──────────┐     UDS (0o600)       │ • Host validation    │       │
│  │ CLI      │ ──────────────────────→│ • Origin validation  │       │
│  │ (mcp-acp)│    manager.sock       │ • Token/cookie auth  │       │
│  └──────────┘                        │ • Request size limit │       │
│                                      └──────────┬───────────┘       │
│                                                  │                  │
│                                        ┌─────────▼──────────┐      │
│                                        │  Proxy Instance(s)  │      │
│                                        │                     │      │
│  ┌──────────────┐   STDIO (pipe)      │  ┌───────────────┐  │      │
│  │ MCP Client   │ ───────────────────→│  │ PEP Middleware │  │      │
│  │ (Claude      │   (no network)      │  │ Chain          │  │      │
│  │  Desktop)    │                     │  └───────┬───────┘  │      │
│  └──────────────┘                     │          │          │      │
│                                        │  ┌───────▼───────┐  │      │
│                                        │  │ Backend       │  │      │
│                                        │  │ ┌─ STDIO ──┐  │  │      │
│                                        │  │ │ (pipe)    │  │  │      │
│                                        │  │ └──────────┘  │  │      │
│                                        │  │ ┌─ HTTP ───┐  │  │      │
│                                        │  │ │ (mTLS)   │  │  │      │
│                                        │  │ └──────────┘  │  │      │
│                                        │  └───────────────┘  │      │
│                                        └─────────────────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

**Where TLS exists today:**

| Connection | Transport | Encryption | Auth |
|------------|-----------|------------|------|
| Browser → Manager HTTP | TCP 127.0.0.1:8765 | **None (HTTP)** | Token (Bearer/cookie) + host/origin validation |
| CLI → Manager | UDS (manager.sock) | **None (kernel IPC)** | OS file permissions (0o600) |
| MCP Client → Proxy | STDIO pipe | **None (kernel IPC)** | Process parentage |
| Proxy → HTTP Backend | TCP (remote) | **mTLS** | Client certificate |
| Proxy → STDIO Backend | STDIO pipe | **None (kernel IPC)** | Binary attestation at startup |

**Existing mitigations (why severity is Low):**

- Bound to `127.0.0.1` only — loopback traffic never hits the network wire
- Host header validation blocks DNS rebinding attacks
- Origin header validation blocks CSRF from malicious websites
- 32-byte random token with constant-time comparison for authentication

**What TLS would protect against:**

- Local network sniffing — irrelevant, loopback traffic doesn't hit the wire
- Malicious local process intercepting traffic — would need root/admin, at which point all bets are off

**What TLS would cost:**

- Self-signed certificate generation and management (or an embedded CA)
- Browser trust warnings — self-signed certs trigger "Your connection is not private"
- Certificate rotation complexity for a desktop application
- Users would need to install a root CA or accept browser warnings on every session

**Recommendation:** Not worthwhile for a localhost-bound desktop application. The existing SecurityMiddleware provides equivalent protection for the actual threat model. If the API were ever network-exposed (e.g., HTTP client support), TLS becomes mandatory — the [http-client-support.md](../design/http-client-support.md) design already specifies TLS 1.3 as required.

---

### Tenet 3 — Access to individual enterprise resources is granted on a per-session basis.

> *"Trust in the requester is evaluated before the access is granted. Access should also be granted with the least privileges needed to complete the task. This could mean only 'just-in-time' and 'just enough' access."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| Per-session lifecycle | Aligned | Proxy runs per-MCP-session; sessions bound to authenticated identity |
| Session binding | Aligned | Format `<user_id>:<session_id>` — identity change triggers immediate shutdown |
| 8-hour session TTL | Aligned | Configurable maximum session duration |
| Machine-bound tokens | Aligned | Cannot be exfiltrated and used on another device |
| In-memory state | Aligned | Approval cache, rate counters, session state — all cleared on restart |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-005 | No granular scope narrowing within session | Medium | Implementation | Tenet 3 requires "just enough" and "just-in-time" access. Not met because all tools allowed by policy are available for the full session duration — there is no time-boxing, no scope narrowing after initial access, and no capability to grant access to a specific tool only for the next N requests. HITL partially addresses this (user can deny individual operations at runtime). |

---

### Tenet 4 — Access to resources is determined by dynamic policy—including the observable state of client identity, application/service, and the requesting asset—and may include other behavioral and environmental attributes.

> *"Resource access and action permission policies can vary based on the sensitivity of the resource/data. Least privilege principles are applied to restrict both visibility and accessibility."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| ABAC policy engine | Aligned | 12 condition types covering subject, action, resource, and environment |
| Dynamic context building | Aligned | `build_decision_context()` assembles fresh context per-request from live signals |
| Identity as input | Aligned | Subject ID from OIDC token feeds policy conditions via `subject_id` |
| Tool metadata as input | Aligned | Tool name, side effects, path, extension, scheme, backend — all policy-evaluable |
| Session context as input | Aligned | Request ID, session ID, client name/version, timestamp available in Environment |
| Combining algorithm | Aligned | HITL > DENY > ALLOW with specificity scoring within each level |
| Hot-reload | Aligned | Policy reloadable without restart via `reload_policy()` — approval cache cleared on reload |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-006 | No behavioral/historical attributes in policy | Medium | Implementation | Tenet 4 requires policy to incorporate "behavioral and environmental attributes." Not met because the policy engine evaluates only point-in-time attributes (identity, tool name, path, side effects). It has no access to historical patterns — e.g., "this user normally calls 5 tools/session but is now at 50" cannot influence a policy decision. Rate limiting detects volume anomalies but operates outside the policy engine (triggers HITL, not a policy condition). |
| GAP-007 | No risk scoring / trust algorithm | Medium | Implementation | Tenet 4 says policy "may include... a risk analysis." Not met because the proxy has no composite risk score. Signals like identity confidence, device health status, tool risk tier, and behavioral history are not aggregated into a graduated trust score that could drive policy (e.g., "if risk > threshold, escalate to HITL"). Decisions are binary per-rule matches, not scored. |
| GAP-017 | No client network location or device posture | Low | Transport constraint | See [GAP-017 detail](#gap-017-detail) below. |

#### GAP-017 detail: No client network location or device posture {#gap-017-detail}

**Tenet requirement:** Tenet 4 mentions "the requesting asset" and "environmental attributes" as policy inputs. Tenet 7 requires collecting "as much information as possible."

**Why not met:** The proxy has no client IP, geolocation, device fingerprint, or device posture information available for policy evaluation.

**What the proxy knows about the client:**

| Attribute | Source | Available | Used in Policy |
|-----------|--------|-----------|----------------|
| `mcp_client_name` | MCP `initialize` request `clientInfo.name` | Yes | No (Environment field only) |
| `mcp_client_version` | MCP `initialize` request `clientInfo.version` | Yes | No (Environment field only) |
| User identity (sub) | OIDC JWT token | Yes | Yes (`subject_id` condition) |
| User claims | OIDC JWT token | Yes | No (logged in audit) |
| Session ID | Generated per-session | Yes | Yes (rate limiting key) |
| Client IP address | — | **No** | N/A |
| Client geolocation | — | **No** | N/A |
| Client device info | — | **No** | N/A |

**Why no client IP — per transport:**

1. **STDIO transport** — The MCP client (e.g., Claude Desktop) communicates via stdin/stdout pipes. This is kernel-level IPC, not a network connection. There is no IP, no socket, no connection tuple. The "client" is the parent process that spawned the proxy.

2. **UDS transport** — Unix domain sockets are kernel-mediated IPC. The only "addressing" is the filesystem path of the socket. The kernel enforces file permissions, but there is no IP address.

3. **MCP protocol** — The MCP specification's `initialize` request only carries `clientInfo: { name, version }`. There is no field for client IP, device fingerprint, or network location.

**Feasibility of adding network location:**

| Transport | Feasibility | How |
|-----------|-------------|-----|
| STDIO | **Impossible** | No network connection exists. Process pipe has no addressing. |
| UDS | **Impossible** | No network connection exists. Kernel IPC only. |
| HTTP (future) | **Possible** | `request.client.host` from the ASGI server would provide client IP. |

**Device posture — architectural boundary:**

Real device posture assessment (EDR status, OS patch level, disk encryption, host-based firewall, TPM/Secure Enclave attestation) is not something the proxy should perform itself. In ZTA, these signals originate from external systems — MDM, CDM, EDR agents — and are consumed by the Policy Engine via Policy Information Points (PIPs). NIST SP 1800-35 describes this pattern: a PIP aggregates device health signals from enterprise infrastructure and exposes a boolean/score to the PE for policy decisions.

The proxy's current device health checks (FileVault, SIP) are **local self-assessment** — the proxy inspects its own host. This is useful but architecturally distinct from enterprise device posture, where an external authority (e.g., CrowdStrike, Jamf, Microsoft Intune) attests to the device's compliance state and the proxy consumes that attestation as a policy input.

**What consumption would look like:**

| Component | Role |
|-----------|------|
| MDM/CDM/EDR agent | Produces device posture signal (compliant/non-compliant, risk score) |
| PIP (new) | Fetches or receives posture signal from enterprise infrastructure |
| Policy Engine | Evaluates posture boolean/score as a policy condition |
| PEP | Enforces the decision (allow/deny/HITL based on posture) |

The proxy already has the PIP abstraction (`pips/auth/oidc_provider.py` for identity). A device posture PIP would follow the same pattern — fetch an external signal and make it available in the `DecisionContext` for policy evaluation.

**Resolution path:** When HTTP client transport is added (see [http-client-support.md](../design/http-client-support.md)), the `Environment` model should be extended with `client_ip`, `client_port`, and `device_posture` fields, and `RuleConditions` should gain corresponding policy conditions. The http-client-support design already specifies client authentication via OIDC Bearer tokens and mTLS, with the manager as the ingress point having full ASGI request context. Device posture integration would additionally require a PIP that consumes signals from enterprise MDM/CDM/EDR infrastructure.

---

### Tenet 5 — The enterprise monitors and measures the integrity and security posture of all owned and associated assets.

> *"No asset is inherently trusted. The enterprise evaluates the security posture of the asset when evaluating a resource request."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| Device health: FileVault | Aligned | Disk encryption verified at startup and every 5 minutes |
| Device health: SIP | Aligned | System Integrity Protection verified at startup and every 5 minutes |
| Fail-closed on health failure | Aligned | `DEFAULT_DEVICE_FAILURE_THRESHOLD = 1` — single failure triggers shutdown |
| Backend binary attestation | Aligned | SHA-256 hash of STDIO backend binary verified at startup |
| Audit log integrity | Aligned | Inode/device monitoring, fail-closed on compromise |
| Tool sanitization monitoring | Aligned | Prompt injection patterns detected and stripped |
| Crash recovery breadcrumbs | Aligned | `CRASH_BREADCRUMB_FILENAME` records failure context for post-incident analysis |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-008 | Device health: macOS only | Medium | Platform limitation | Tenet 5 requires evaluating security posture of all assets. Not met on Linux/Windows because FileVault and SIP checks are macOS-specific. `SKIP_DEVICE_HEALTH_CHECK = True` on non-macOS — no equivalent disk encryption or system integrity checks exist for those platforms. |
| GAP-018 | No external device posture integration | Medium | Scope limitation | Tenet 5 expects device security posture to be evaluated continuously. The current FileVault/SIP checks are **local self-assessment** — the proxy inspects its own host. ZTA architecturally expects device posture signals to come from external authorities (MDM/CDM/EDR) and be consumed via PIPs ([NIST SP 1800-35](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-35.pdf)). The proxy has no PIP for consuming external posture signals (e.g., EDR compliance status, OS patch level, host firewall state). See [GAP-017 detail](#gap-017-detail) for the architectural pattern. |
| GAP-009 | No continuous backend integrity monitoring | Low | Implementation | Tenet 5 says "no asset is inherently trusted." Partially not met because the STDIO backend binary hash is verified at startup only. If the binary is replaced while the proxy is running, the change goes undetected until restart. The process is still the original one (binary replacement doesn't affect a running process), but a restart would load the modified binary without re-verification until the next startup. |
| GAP-010 | No asset inventory or CMDB integration | Low | Scope limitation | Tenet 5 assumes an enterprise asset inventory. Not met because the proxy has no formal catalog of monitored assets, software versions, patch levels, or compliance status. The proxy operates on tools discovered at runtime, not from a managed inventory. |

---

### Tenet 6 — All resource authentication and authorization are dynamic and strictly enforced before access is allowed.

> *"This is a constant cycle of obtaining access, scanning and assessing threats, adapting, and continually re-evaluating trust in ongoing communication."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| Per-request auth | Aligned | JWT validated on every request. Explicit design comment: *"Zero Trust: Validates on every request. No caching."* |
| Per-request policy evaluation | Aligned | `self._engine.evaluate(decision_context)` called on every `on_message()` — including when HITL cache is used (cache skips dialog, not policy) |
| Auth is mandatory | Aligned | No unauthenticated fallback; `AuthenticationError` → deny |
| Session binding enforcement | Aligned | Identity change mid-session → immediate shutdown (exit code for session binding violation) |
| HITL for elevated access | Aligned | Human-in-the-loop for operations matching HITL rules |
| Fail-closed on errors | Aligned | Context build failure, policy evaluation error → deny |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-011 | Discovery methods bypass policy | Medium | Design trade-off | Tenet 6 requires authorization to be "strictly enforced before access is allowed." Not met for discovery methods because `tools/list`, `resources/list`, `initialize`, `ping`, and other `DISCOVERY_METHODS` skip policy evaluation entirely (engine returns ALLOW). This reveals available tool names and resource URIs to any authenticated user without policy consent. Rationale: MCP clients cannot function without discovering available tools; `prompts/get` (which returns content) is excluded from bypass. |
| GAP-012 | No step-up / re-authentication | Low | Implementation | Tenet 6 describes "a constant cycle of obtaining access, scanning and assessing threats, adapting." Not met because the proxy has no step-up authentication — there is no mechanism to force MFA or re-authentication for especially sensitive operations (e.g., CODE_EXEC tools). Token refresh re-validates with IdP, but this is automatic, not triggered by risk level. |
| GAP-013 | JWKS cache creates revocation delay | Low | Implementation | Tenet 6 requires dynamic enforcement. Partially not met because JWKS (JSON Web Key Set) is cached for 600 seconds (`JWKS_CACHE_TTL_SECONDS`). During this window, a revoked signing key could still validate tokens. Note: identity (JWT) validation itself is per-request and not cached — this gap is specifically about the signing key set, not the token. |

---

### Tenet 7 — The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture.

> *"An enterprise should collect as much information as possible about the current state of assets, network infrastructure, and communications and use it to improve its security posture."*

**Alignment:**

| Aspect | Status | Detail |
|--------|--------|--------|
| Structured audit logs | Aligned | OCSF-inspired events: `AuthEvent`, `OperationEvent`, `DecisionEvent` with structured fields |
| Decision trace logging | Aligned | Every policy decision logged with matched rules, final rule, eval timing |
| Fail-closed audit | Aligned | Operations blocked if audit log is compromised; inode monitoring |
| SHA-256 hash chain | Aligned | Tamper-evident audit trail |
| Provenance tracking | Aligned | Context facts tagged with source (TOKEN, MTLS, MCP_REQUEST, CLIENT_HINT) |
| Rate anomaly detection | Aligned | Per-session, per-tool rate tracking with configurable thresholds |
| Duration metrics | Aligned | `DurationInfo` tracks operation timing for performance/anomaly analysis |
| Response hashing | Aligned | `ResponseSummary` captures `size_bytes` and `body_hash` without storing content |

**Gaps:**

| ID | Gap | Severity | Category | Detail |
|----|-----|----------|----------|--------|
| GAP-014 | No behavioral analytics / feedback loop | Medium | Implementation | Tenet 7 says the enterprise "uses [collected information] to improve its security posture." Not met because telemetry is collected (structured audit logs, decision traces, rate counters) but never analyzed to improve policy or detect anomalies. There is no baseline profiling, no trend analysis, and no automated policy adjustment. The feedback loop from observation→improvement does not exist. |
| GAP-015 | Tool arguments never logged | Medium | Design trade-off | See [GAP-015 detail](#gap-015-detail) below. |
| GAP-016 | No centralized log aggregation | Low | Scope limitation | Tenet 7 assumes enterprise-wide collection and analysis. Not met because logs are local files only (`logs/audit/*.jsonl`). There is no syslog output, no log shipping, and no centralized analysis. Requires external SIEM infrastructure. |

#### GAP-015 detail: Tool arguments never logged {#gap-015-detail}

**Tenet requirement:** Tenet 7 requires collecting "as much information as possible" about communications to improve security posture.

**Why not met:** `ArgumentsSummary` records only `redacted=True`, `body_hash` (SHA-256), and `payload_length`. Tool argument keys, structure, and values are never logged — forensics cannot reconstruct what a tool was asked to do, only that it was called with a payload of a certain size and hash. This is an intentional privacy trade-off.

**What is currently logged for tool calls:**

| What's logged | How | Source |
|---------------|-----|--------|
| Tool name | Plaintext | `OperationEvent.tool_name` |
| File path(s) | Plaintext | `OperationEvent.file_path`, `source_path`, `dest_path` |
| File extension | Plaintext | `OperationEvent.file_extension` |
| Argument hash | SHA-256 | `ArgumentsSummary.body_hash` |
| Argument size | Bytes | `ArgumentsSummary.payload_length` |
| Response hash | SHA-256 | `ResponseSummary.body_hash` |
| Response size | Bytes | `ResponseSummary.size_bytes` |
| Decision + rules | Plaintext | `DecisionEvent` (matched rules, final rule) |
| Timing | Milliseconds | `DurationInfo.duration_ms` |

**Content logging tiers — risk/value trade-offs:**

**Tier 1 — Structural metadata (recommended, low risk):**
- Argument **key names** without values (e.g., `["path", "content", "language"]` for a write_file call)
- Argument count
- Resource URI scheme and authority (e.g., `file:///`, `postgres://host/`)
- MCP protocol-level fields (method, resource URI for resources/read)

Tier 1 significantly improves forensic capability without exposing sensitive values. You can tell the *shape* of a request (e.g., "this call had a `content` argument of 45KB") without storing the actual content.

**Tier 2 — Selective content (requires data classification):**
- File paths and URIs (already logged)
- Tool-specific "safe" arguments (e.g., `language` parameter for a code tool)
- Error messages from backend responses
- Configuration/flag arguments (non-sensitive by nature)

Tier 2 requires a data classification framework (see GAP-002). Without knowing which arguments are sensitive, selective logging risks leaking secrets.

**Tier 3 — Full content (high risk, specialized use cases):**
- Complete tool arguments (may contain PII, secrets, proprietary code)
- Complete response bodies (may contain sensitive data from backends)
- Raw MCP JSON-RPC messages

Tier 3 creates a high-value attack target (the log itself becomes the most sensitive file on disk). Should remain off by default. If needed: opt-in with encryption-at-rest and access controls on log files.

**Recommendation:** Implement Tier 1 (argument key names and counts). This is the best risk/value trade-off — meaningful forensic improvement with no sensitive data exposure.

---

## Gap Summary Matrix

| Gap ID | Tenet | Severity | Category | Short Description |
|--------|-------|----------|----------|-------------------|
| GAP-001 | 1 | Medium | Implementation | No formal resource registry/inventory |
| GAP-002 | 1 | Low | Implementation | No data classification labels |
| GAP-003 | 2 | Low | Implementation | No TLS on manager HTTP API |
| GAP-004 | 2 | Low | Design constraint | No encryption on UDS transport |
| GAP-005 | 3 | Medium | Implementation | No granular scope narrowing within session |
| GAP-006 | 4 | Medium | Implementation | No behavioral/historical attributes in policy |
| GAP-007 | 4 | Medium | Implementation | No risk scoring / trust algorithm |
| GAP-008 | 5 | Medium | Platform limitation | Device health: macOS only |
| GAP-009 | 5 | Low | Implementation | No continuous backend integrity monitoring |
| GAP-010 | 5 | Low | Scope limitation | No asset inventory or CMDB integration |
| GAP-011 | 6 | Medium | Design trade-off | Discovery methods bypass policy |
| GAP-012 | 6 | Low | Implementation | No step-up / re-authentication |
| GAP-013 | 6 | Low | Implementation | JWKS cache creates revocation delay |
| GAP-014 | 7 | Medium | Implementation | No behavioral analytics / feedback loop |
| GAP-015 | 7 | Medium | Design trade-off | Tool arguments never logged |
| GAP-016 | 7 | Low | Scope limitation | No centralized log aggregation |
| GAP-017 | 4, 7 | Low | Transport constraint | No client network location or device posture |
| GAP-018 | 5 | Medium | Scope limitation | No external device posture integration (MDM/CDM/EDR via PIP) |

### Gap categories explained

- **Implementation** — Could be implemented within the current architecture.
- **Design trade-off** — Intentional choice with documented rationale (security vs. functionality or privacy).
- **Platform limitation** — Depends on OS capabilities that don't exist cross-platform.
- **Scope limitation** — Beyond the proxy's architectural scope (requires external infrastructure).
- **Design constraint** — Fundamental protocol/transport limitation.
- **Transport constraint** — Limited by the transport layer (STDIO/UDS have no network addressing).

---

## Tenet Coverage Summary

| Tenet | Coverage | Key Strength | Primary Gap |
|-------|----------|--------------|-------------|
| 1 — Resources | Strong | Per-tool policy with side-effect classification | GAP-001: No resource registry |
| 2 — Secure Comms | Strong | mTLS for HTTP, binary attestation for STDIO, localhost binding | GAP-003: No TLS on local HTTP API |
| 3 — Per-Session | Strong | Session binding with identity-change shutdown | GAP-005: No scope narrowing within session |
| 4 — Dynamic Policy | Strong | ABAC with 12 condition types, hot-reload | GAP-006: No behavioral attributes |
| 5 — Asset Integrity | Moderate | Device health + audit integrity + binary attestation | GAP-008: macOS-only device checks |
| 6 — Dynamic AuthZ | Strong | Per-request auth + policy eval, no caching | GAP-011: Discovery bypass |
| 7 — Telemetry | Moderate | Structured OCSF-inspired logs, hash chain, provenance | GAP-014: No feedback loop |

---

## Corrected Claims

### "No least-privilege enforcement at the operation level" — INVALID GAP

This was flagged in an earlier evaluation but is **not a valid gap**. Here is why:

MCP protocol's `tools/call` method has **no operation type field**. There is no `read`/`write`/`delete` in the protocol — it is simply "call this tool with these arguments." The proxy cannot enforce operation-level least privilege because the protocol does not express operation intent.

What the proxy **does** implement:

1. **Side-effect classification** — 21 `SideEffect` categories (CODE_EXEC, FS_WRITE, FS_READ, NETWORK_EGRESS, etc.) map tools to their actual capabilities
2. **`operations` policy condition** — Derived from side-effect mapping, allows rules like `operations: [read]` to match tools classified as read-only
3. **Per-tool granularity** — Each tool is individually addressable in policy
4. **Path-level controls** — `path_pattern`, `source_path`, `dest_path`, `extension` conditions constrain where tools can operate

This is the maximum operation-level enforcement possible given MCP protocol constraints. The `operations` condition working through side-effects mapping is the correct architectural approach.

**Classification**: MCP protocol design constraint, not an implementation gap.

### "HITL approval cache bypasses policy re-evaluation" — INCORRECT

The HITL approval cache does **not** bypass policy re-evaluation. The actual flow (`pep/middleware.py`):

1. `on_message()` builds DecisionContext (includes per-request JWT validation)
2. `self._engine.evaluate(decision_context)` runs policy evaluation → returns `Decision.HITL`
3. `_handle_hitl_decision()` is called
4. **Inside** `_handle_hitl_decision`, approval cache is checked
5. If cached → skips the dialog, but policy was **already evaluated** in step 2

The cache reduces dialog fatigue, not policy enforcement. If policy changes (e.g., rule removed), the engine may return `Decision.ALLOW` or `Decision.DENY` instead of `Decision.HITL`, and the cache is never consulted. Additionally, `reload_policy()` explicitly clears the approval cache (`middleware.py`).

---

## Architectural Limitations (Not Gaps)

These are properties of the proxy's architecture and deployment model. They are not implementation gaps — they are intentional design boundaries.

### Desktop single-user architecture

The proxy runs as a desktop application for a single user, not as an enterprise service. This affects:

- **Control/data plane separation**: Logical separation exists in code (PE, PA, PEP are distinct modules), but physical separation (separate services/processes) adds deployment complexity inappropriate for desktop use.
- **IdP resilience**: Users configure one identity provider. Fallback IdP assumes multiple providers, which is uncommon for individual users.

### Per-session lifecycle

The proxy runs per-MCP-session (started by Claude Desktop, ends when session ends). This affects:

- **Dynamic policy updates**: Hot-reload is supported (`reload_policy()`), but the primary mechanism is session restart. This is acceptable for short sessions.
- **Continuous re-authentication**: Token refresh already re-validates with IdP. Additional re-auth during typical session durations provides marginal benefit.

### Proxy scope boundary

The proxy controls the client→backend path. Some ZTA concerns are outside this scope:

- **Network segmentation**: VLANs, firewalls, service mesh are infrastructure concerns.
- **Backend trust**: User configures which backend to use, establishing trust at configuration time. The proxy protects the backend from unauthorized clients, not vice versa.

### MCP protocol constraints

Certain ZTA capabilities are limited by the MCP protocol specification:

- **No operation-level intent** on `tools/call` — addressed via side-effect classification
- **No client device info** in `initialize` — only `name` and `version`
- **No client network location** — STDIO transport is kernel IPC, not network

---

## Deferred Work

Features deferred from Stage 3 PoC. See [roadmap.md](../design/roadmap.md) for details.

| Roadmap Item | Related Gap(s) | Tenet | Why Deferred |
|--------------|---------------|-------|--------------|
| Tool Registry | GAP-001 | 1, 5 | Hardcoded mapping demonstrates concept |
| Tool Arguments in Policy | — | 4 | Path extraction covers most cases |
| Approval-Aware Conditions | — | 4 | Current caching is sufficient |
| Content Inspection | GAP-015 | 7 | Core enforcement works without it |
| Behavioral Analysis | GAP-006, GAP-014 | 4, 5, 7 | Requires research and statistical infrastructure |
| Linux/Windows Device Health | GAP-008 | 5 | Needs platform-specific implementations |
| Risk Scoring Engine | GAP-007 | 4 | Requires design for signal aggregation |
| HTTP Client Transport | GAP-017 | 2, 4, 7 | Enables client IP/network location as policy input. See [http-client-support.md](../design/http-client-support.md) |

## Out of Scope

Beyond the proxy's architectural scope:

| Item | Related Gap(s) | Reason |
|------|---------------|--------|
| Network micro-segmentation | — | Infrastructure (VLANs, firewalls, service mesh) |
| ML behavioral analytics | GAP-014 | Requires ML pipelines, baselines, statistical analysis |
| Full disk encryption | — | OS-level (FileVault already required for device health) |
| Centralized SIEM | GAP-016 | Enterprise infrastructure requirement |
| Asset inventory / CMDB | GAP-010 | Enterprise infrastructure requirement |
| Device Posture PIP (MDM/CDM/EDR) | GAP-018 | Enterprise infrastructure; requires external posture signal source |

## References

- NIST SP 800-207: Zero Trust Architecture (Section 2.1 — Seven Tenets)
- [NIST SP 1800-35](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1800-35.pdf): Implementing a Zero Trust Architecture — Device posture integration via PIPs (addresses GAP-018)
- [roadmap.md](../design/roadmap.md) — Deferred improvements
- [ui-security.md](../design/ui-security.md) — API security design
- [http-client-support.md](../design/http-client-support.md) — Future HTTP client transport (addresses GAP-017)
