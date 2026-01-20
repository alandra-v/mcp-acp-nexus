# HTTP Client Support

> **Status**: Future work
>
> Stage 3 focuses on STDIO client mode where Claude Desktop spawns proxies and owns their lifecycle. This document describes a future mode where HTTP clients (ChatGPT, custom apps) connect through the manager.

---

## Overview

HTTP client support enables non-STDIO clients to connect to MCP backends through the proxy. Unlike STDIO mode where the client spawns the proxy, HTTP mode has the manager spawn and manage proxy workers.

**Use cases**:
- Cloud-based AI assistants (ChatGPT, Gemini, custom apps)
- Web-based MCP clients
- Multi-tenant deployments

```
STDIO Mode (Current):
  Claude Desktop ──STDIO──▶ Proxy ──▶ Backend
                              │
                              └──UDS──▶ Manager (observe)

HTTP Mode (Future):
  ChatGPT/Other ──HTTPS──▶ Manager ──▶ Proxy Worker ──▶ Backend
```

---

## Architecture

### Manager as Reverse Proxy

```
┌─────────────────────────────────────────────────────────────────┐
│                      Manager (daemon :8765)                      │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │   Web UI     │  │  Auth (OIDC) │  │   Reverse Proxy       │  │
│  │   Server     │  │  Validation  │  │   Router              │  │
│  └──────────────┘  └──────────────┘  └───────────┬───────────┘  │
│                                                   │              │
│                                      spawns/routes│              │
└───────────────────────────────────────────────────┼──────────────┘
                                                    │
                          ┌─────────────────────────┼─────────────────────────┐
                          │                         │                         │
                          ▼                         ▼                         ▼
                   ┌────────────┐           ┌────────────┐           ┌────────────┐
                   │  Worker A  │           │  Worker B  │           │  Worker C  │
                   │  (Proxy)   │           │  (Proxy)   │           │  (Proxy)   │
                   └─────┬──────┘           └─────┬──────┘           └─────┬──────┘
                         │                        │                        │
                         ▼                        ▼                        ▼
                   ┌───────────┐           ┌───────────┐           ┌───────────┐
                   │ Backend A │           │ Backend B │           │ Backend C │
                   └───────────┘           └───────────┘           └───────────┘
```

### Key Differences from STDIO Mode

| Aspect | STDIO Mode | HTTP Mode |
|--------|------------|-----------|
| Client example | Claude Desktop | ChatGPT, custom apps |
| Client→Proxy transport | STDIO | HTTPS |
| Who spawns proxy | Client | Manager |
| Lifecycle ownership | Client | Manager |
| Auth | Implicit (process tree) | Explicit (OIDC/mTLS) |
| On client disconnect | Proxy dies | Idle timeout → proxy dies |

---

## Client Authentication

HTTP clients must authenticate with the manager before accessing proxies.

### Auth Points

```
┌────────────┐         ┌────────────┐         ┌────────────┐         ┌────────────┐
│   Client   │────────►│  Manager   │────────►│   Proxy    │────────►│  Backend   │
│ (ChatGPT)  │         │            │         │  Worker    │         │(MCP Server)│
└────────────┘         └────────────┘         └────────────┘         └────────────┘
       │                     │                      │                      │
       │  Auth 1             │                      │  Auth 2              │
       │  Client identity    │                      │  Backend creds       │
       │  (OIDC Bearer)      │                      │  (API key, OAuth)    │
```

| Auth | Purpose | Credential | Who validates |
|------|---------|------------|---------------|
| Client → Manager | "Who is making this request?" | OIDC token (Bearer) | Manager |
| Proxy → Backend | "Does proxy have access to backend?" | API key, OAuth, mTLS | Backend |

**Initial approach**: Manager validates client auth (centralizes auth, simplifies workers).

**Future improvement**: Workers validate independently for defense in depth. Manager compromise shouldn't bypass auth. Each worker would have JWKS access and validate tokens itself - matches credential isolation philosophy where workers are self-contained security boundaries.

Backend credentials are per-proxy (see credential isolation in [multi.md](multi.md)).

### Auth Pattern Comparison: STDIO vs HTTP

**STDIO Mode (Current):**
```
┌──────────────────┐         ┌─────────────────────┐
│  Claude Desktop  │──STDIO──│       Proxy         │
│                  │         │  (OIDCIdentityProv) │
└──────────────────┘         └─────────────────────┘
                                      │
                                      ▼
                             Token from keychain
                             (user logged in via CLI)
```
- `OIDCIdentityProvider` loads token from OS keychain
- Token obtained via device flow (`mcp-acp auth login`)
- Same user identity for all requests in session

**HTTP Mode (Future):**
```
┌──────────┐  HTTP + Bearer   ┌──────────┐         ┌─────────────────────┐
│  Client  │─────────────────►│ Manager  │────────►│   Proxy Worker      │
│          │  Auth header     │(validates)│        │                     │
└──────────┘                  └──────────┘         └─────────────────────┘
                                   │
                                   ▼
                          Token from request header
                          (FastMCP get_access_token())
```
- Manager validates client OIDC token from `Authorization: Bearer <token>` header
- Same JWT validation logic as STDIO mode, different token source
- Manager owns lifecycle, so centralizing auth makes sense
- Per-request identity (could be different users)

### Auth Methods

| Method | How it works | Use case |
|--------|--------------|----------|
| **OIDC token** | Bearer token in Authorization header | Cloud clients (ChatGPT) |
| **mTLS** | Client presents certificate | Enterprise/custom clients |
| **API key** | Shared secret in header | Simple integrations |

### OIDC Token Flow

```
1. Client obtains OIDC token (device flow or other grant)
2. Client connects to Manager with Authorization: Bearer <token>
3. Manager validates token (same OIDC config as STDIO mode)
4. Manager routes authenticated request to proxy worker
5. Worker uses its own backend credentials to talk to backend
```

### mTLS Flow

```
1. Client configured with client certificate + key
2. Client connects to Manager via HTTPS with client cert
3. Manager validates client cert against CA
4. Manager extracts identity from cert subject
5. Manager routes authenticated request to proxy worker
6. Worker uses its own backend credentials to talk to backend
```

---

## Lazy Spawn

Proxies are spawned on-demand, not pre-started.

```
1. HTTP client connects to Manager
   │
   ▼
2. Manager authenticates client (OIDC/mTLS)
   │
   ▼
3. Client requests backend "filesystem"
   │
   ▼
4. Manager checks: Worker for "filesystem" running?
   │
   ├──No──▶ Load proxy config
   │        Spawn worker process
   │        Wait for ready signal
   │        │
   └──Yes─▶ Route request to worker
            │
            ▼
5. Worker handles request, returns response
   │
   ▼
6. Client continues sending requests
   │
   ▼
7. Client disconnects
   │
   ▼
8. Idle timer starts (30 min default)
   │
   ▼
9. No new connections → Worker stops
```

### Benefits

- No orphan processes (idle shutdown)
- No manual "start proxy" step
- Resources used only when needed
- Transparent to client (just connects)

---

## Idle Shutdown

Workers stop after period of inactivity.

### Configuration

```json
{
  "http_mode": {
    "idle_timeout_minutes": 30,
    "grace_period_seconds": 10
  }
}
```

### What Counts as Idle

- No active client connections
- Grace period after last disconnect (handles reconnects)

### Shutdown Sequence

```
1. Last client disconnects
2. Start idle timer (30 min)
3. Timer expires, no new connections
4. Worker receives stop signal from Manager
5. Worker performs clean shutdown:
   - Log to shutdowns.jsonl (reason: idle_timeout)
   - Close backend connection
   - Exit cleanly
6. Manager marks worker as stopped
```

---

## Manager Failure Handling

If manager dies while workers are running:

```
Manager (parent)
    │
    │ dies unexpectedly
    ▼
Worker (child) receives signal (if configured)
    │
    ▼
Worker shutdown sequence:
    1. Log "manager_died" to shutdowns.jsonl
    2. Log session_ended to auth.jsonl
    3. Write .last_crash breadcrumb
    4. Close backend connection
    5. Exit with code 13 (manager_failure)

Same ShutdownCoordinator pattern, different trigger.
```

**Note:** Child processes do not automatically receive signals when their parent dies. On Linux, the worker must call `prctl(PR_SET_PDEATHSIG, SIGHUP)` after fork to request parent-death notification. macOS has no direct equivalent; alternatives include heartbeat polling or using a dedicated supervision process.

### Exit Codes (extended)

| Code | Failure Type | Description |
|------|--------------|-------------|
| 10 | `audit_failure` | Audit log issue |
| 11 | `session_hijack` | Session hijacking detected |
| 12 | `auth_failure` | Authentication failure |
| 13 | `manager_failure` | Manager died (HTTP mode) |
| 14 | `idle_timeout` | Clean idle shutdown |

---

## Port Management

Workers need ports for internal communication with manager.

### Auto-Assignment

```python
class PortManager:
    def __init__(self, range_start: int = 9000, range_end: int = 9100):
        self._range = range(range_start, range_end)
        self._assigned: set[int] = set()

    def allocate(self) -> int:
        for port in self._range:
            if port not in self._assigned and self._is_available(port):
                self._assigned.add(port)
                return port
        raise PortExhaustedError("No available ports in range")

    def release(self, port: int) -> None:
        self._assigned.discard(port)
```

### Configuration

```json
{
  "http_mode": {
    "worker_port_range": [9000, 9100]
  }
}
```

---

## Routing

Manager routes client requests to appropriate workers.

### By Backend Name

```
Client request: POST /mcp/filesystem/tools/call
                      └────┬─────┘
                      backend name
                           │
                           ▼
Manager looks up worker for "filesystem"
                           │
                           ▼
Forward request to worker
```

### Request Flow

```
Client                    Manager                   Worker
   │                         │                         │
   │──POST /mcp/fs/call─────▶│                         │
   │                         │──validate auth──────────│
   │                         │                         │
   │                         │──lookup worker("fs")────│
   │                         │                         │
   │                         │──forward request───────▶│
   │                         │                         │──▶ Backend
   │                         │                         │◀── response
   │                         │◀──response──────────────│
   │◀──response──────────────│                         │
```

---

## MCP Protocol Considerations

MCP (as of spec version 2025-03-26) uses **Streamable HTTP** transport:
- HTTP POST for client-to-server messages (tool calls, resource reads)
- HTTP GET for opening server-to-client stream
- Server may optionally use SSE within the response for streaming multiple messages
- Session state (tools exchanged at init)

**Note:** The older HTTP+SSE transport (spec version 2024-11-05) is deprecated. Streamable HTTP is the current standard.

### Streaming Support

Manager must proxy Streamable HTTP responses:

```
Client ◀──HTTP──▶ Manager ◀──HTTP──▶ Worker ◀──▶ Backend
              (optional SSE within response)
```

### Session Binding

Each HTTP client gets own session:
- Session created on first request
- Bound to client identity (from auth)
- Session ID in response headers
- Client includes session ID in subsequent requests

---

## UI Changes for HTTP Mode

### Worker Status Indicators

```
┌─────────────────────────────────────────────────────────┐
│  Proxies                                                │
├─────────────────────────────────────────────────────────┤
│  STDIO Proxies (client-owned):                          │
│  ● filesystem     Claude Desktop    connected           │
│                                                         │
│  HTTP Proxies (manager-owned):                          │
│  ● github         ChatGPT           running (idle 5m)   │
│  ○ database       -                 stopped             │
└─────────────────────────────────────────────────────────┘
```

### No Start/Stop Buttons

Even in HTTP mode, no manual start/stop:
- Workers spawn on client connect (lazy)
- Workers stop on idle timeout
- Lifecycle is automatic

Could add "Force Stop" for stuck workers (future).

---

## CLI Commands (HTTP Mode)

```bash
# View HTTP worker status
mcp-acp proxy list --http

# View connected HTTP clients
mcp-acp clients list

# Force stop idle worker (emergency)
mcp-acp proxy stop <name> --force
```

---

## Configuration

### Manager Config Extension

```json
{
  "ui_port": 8765,
  "auth": { ... },
  "http_mode": {
    "enabled": true,
    "idle_timeout_minutes": 30,
    "worker_port_range": [9000, 9100],
    "allowed_auth_methods": ["oidc", "mtls"],
    "mtls": {
      "client_ca_path": "~/.mcp-acp/certs/client-ca.crt",
      "require_client_cert": true
    }
  }
}
```

### Proxy Config (unchanged)

HTTP mode uses same proxy configs as STDIO mode. The difference is how the proxy is started (by manager vs by client).

---

## Security Considerations

### Authentication Required

HTTP mode MUST require authentication:
- Localhost is not sufficient (other processes could connect)
- OIDC token or mTLS required
- API keys as fallback for simple setups

### Credential Isolation

Same as STDIO mode:
- Each worker has own backend credentials
- Manager injects keys at spawn time
- Manager forgets keys after spawn

### Audit Trail

HTTP-specific audit events:
- `http_client_connected`: Client authenticated
- `http_client_disconnected`: Client disconnected
- `worker_spawned`: Lazy spawn triggered
- `worker_idle_stopped`: Idle timeout
- `worker_manager_died`: Manager failure

---

## Zero-Trust Considerations

HTTP client support introduces challenges for the device-bound zero-trust model. These are documented as open problems to address before implementation.

### Current Trust Model (STDIO)

The current architecture relies on device-bound identity:

```
Zero Trust Principle: "Never trust, always verify"

Local client verification:
✓ Device posture (FileVault, SIP)
✓ User identity (OS authentication)
✓ Physical presence (local keyboard/screen)
✓ Network isolation (localhost only)
```

### Challenges with HTTP Clients

Remote HTTP clients (especially cloud-based AI assistants) cannot satisfy all device-bound checks:

| Current Mechanism | Challenge for HTTP Clients |
|-------------------|----------------------------|
| Unix socket permissions | Remote clients can't access local sockets |
| Localhost-only HTTP | Remote clients need internet-accessible endpoint |
| Device posture checks | Can't verify remote client's device |
| Browser cookie auth | Remote AI isn't using a browser |

### Identity Model Questions

With HTTP clients, the identity model becomes more complex:

- **Who is the "user"?** The human, the AI service, or both?
- **How do you verify the human behind the AI request?**
- **What identity appears in audit logs?**
- **Who can approve HITL requests?**

#### Possible Approaches

**A. AI Service as Delegated Agent**
```yaml
identity:
  type: delegated_agent
  service: openai
  service_account: user-registered-api-key
  human_identity: unverified  # Cannot verify who prompted the AI
```

**B. Pre-authenticated Session Token**
```yaml
identity:
  type: session_token
  issued_to: user@example.com  # Verified via OIDC before token issued
  issued_at: 2024-01-15T10:00:00Z
  expires_at: 2024-01-15T11:00:00Z
  scope: [read_files, search]  # Limited capabilities
```

**C. Per-Request Human Verification**
```yaml
identity:
  type: per_request_verified
  mechanism: push_notification  # Human approves each AI request
  human_identity: user@example.com
```

### Unverifiable Human Intent

With local clients, the human directly controls the AI:
```
Human → types prompt → Local AI Client → MCP request → Proxy
        ↑
        Human sees request, can intervene
```

With remote clients, there's an unverifiable gap:
```
Human → types prompt → Cloud AI → interprets → MCP request → Proxy
                            ↑
                            AI decides what tools to call
                            Human may not see actual request
```

The proxy cannot verify:
- What the human actually asked for
- Whether the AI's tool call matches human intent
- Whether a human is even present

### Attack Surface Expansion

| Attack Vector | Local Client | Remote Client |
|--------------|--------------|---------------|
| Network attacks | Not applicable (no network) | DDoS, MITM, injection |
| Credential theft | Requires device access | Can be stolen remotely |
| Session hijacking | Requires local access | Network-based attacks |
| Replay attacks | Not applicable | Must implement protection |
| Enumeration | Not possible | Endpoint discovery |

### HITL Implications

Current HITL assumes human is at the keyboard, looking at the same screen.

**Remote HITL options**:

| Mechanism | UX | Security |
|-----------|-----|----------|
| Web UI (existing) | Good if user has browser open | Session hijacking risk |
| Push notification | Good for mobile | Requires mobile app/integration |
| Email approval | Poor (slow) | Phishing risk |
| SMS/TOTP | Poor (out of band) | SIM swap risk |
| Synchronous timeout | Poor (blocks AI) | Secure but unusable |

### Compliance Considerations

Many zero-trust frameworks explicitly require device verification:

- **[NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final)**: "Access requests must be evaluated based on multiple factors, including user identity, device posture, and the sensitivity of the data being requested."

- **[Google BeyondCorp](https://cloud.google.com/beyondcorp)**: "All access to enterprise resources is fully authenticated, fully authorized, and fully encrypted based upon device state and user credentials."

- **[CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)**: The Device pillar requires "constant monitoring and validation of device security posture" and "continuous device posture assessments."

HTTP clients from cloud services cannot fully satisfy these requirements - there is no device to verify.

### Policy Differentiation

Remote/HTTP clients should have different (stricter) policies than local clients:

```yaml
# Example: Differentiated policy for remote clients
policies:
  - name: local-client-tools
    match:
      client_type: local
    tools:
      - pattern: "*"
        action: prompt  # HITL for sensitive, allow for safe

  - name: remote-client-tools
    match:
      client_type: remote
    tools:
      - pattern: "filesystem/*"
        action: deny  # No filesystem access from remote
      - pattern: "database/read"
        action: allow  # Read-only allowed
      - pattern: "database/write"
        action: deny  # No writes from remote
      - pattern: "*"
        action: deny  # Default deny for remote
```

### Required Authentication Stack

If HTTP client support is implemented, a robust authentication stack is needed:

```
┌─────────────────────────────────────────────────────────────┐
│ HTTP Client Authentication Middleware                        │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Transport Security                                  │
│   - TLS 1.3 required                                         │
│   - Certificate pinning for known clients                    │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Client Identity                                     │
│   - mTLS with client certificates, OR                        │
│   - OAuth2 bearer tokens with audience validation, OR        │
│   - API key + HMAC request signing                           │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Request Integrity                                   │
│   - Request signing (timestamp + nonce + HMAC)               │
│   - Replay protection (nonce cache)                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Session Binding                                     │
│   - Tie requests to authenticated identity                   │
│   - Rate limiting per identity                               │
│   - Session timeout enforcement                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Alternative Approaches

If full HTTP client support is not feasible due to zero-trust constraints, consider these alternatives:

### Option A: Local AI Only (Current Model)

Use AI clients that run locally:
- Claude Desktop
- Cursor
- VS Code with MCP extensions
- Local LLM interfaces (Ollama, LM Studio)

**Pros**: Full zero-trust compliance, device verification, HITL works.
**Cons**: Requires local compute, may not have latest models.

### Option B: Bastion/Jump Host Pattern

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│ Cloud AI    │────▶│ Bastion Host        │────▶│ Internal    │
│ (ChatGPT)   │     │ (cloud VM, locked   │     │ Resources   │
│             │     │  down, audited)     │     │             │
└─────────────┘     └─────────────────────┘     └─────────────┘
                              │
                              ▼
                    Human approval via
                    separate secure channel
```

The bastion host:
- Runs in a controlled cloud environment (your cloud, not OpenAI's)
- Has minimal attack surface
- Requires separate human approval channel
- Provides defense-in-depth

**Pros**: Isolates risk, maintains audit trail.
**Cons**: Complex setup, latency, still can't verify human intent.

### Option C: Pre-Approved Action Sets

Instead of real-time tool access, pre-approve specific actions:

```yaml
approved_actions:
  - id: daily-report
    description: "Generate daily sales report"
    tools_allowed:
      - database/query: "SELECT * FROM sales WHERE date = TODAY"
    valid_until: 2024-12-31
    max_executions_per_day: 1
```

The AI can only execute pre-defined, pre-approved action bundles.

**Pros**: Human reviews actions in advance, limited blast radius.
**Cons**: Inflexible, requires pre-planning.

### Option D: Async Request Queue

```
Cloud AI → Submit request to queue → Human reviews → Approved requests execute
```

All AI requests go to a queue. Humans review and approve asynchronously. Results are delivered when ready.

**Pros**: Full human review, audit trail.
**Cons**: Not real-time, poor UX for interactive AI usage.

---

## Implementation Phases

### Phase 1: Foundation
- [ ] Manager as reverse proxy (routing)
- [ ] OIDC token auth for HTTP clients
- [ ] Worker spawn/stop lifecycle

### Phase 2: Core Features
- [ ] Lazy spawn on first request
- [ ] Idle timeout shutdown
- [ ] Port management
- [ ] SSE proxying

### Phase 3: Polish
- [ ] mTLS client auth option
- [ ] UI for HTTP proxy status
- [ ] CLI commands
- [ ] Audit events

---

## Open Questions

1. **ChatGPT MCP support**: Does ChatGPT support custom auth headers when connecting to MCP servers? Need to verify.

2. **Session handoff**: If worker restarts, can client seamlessly reconnect? MCP sessions are stateful - likely needs re-init.

3. **Multiple clients per worker**: Should multiple HTTP clients share one worker (for same backend)? Current design: no, each client gets own worker.

4. **Internet exposure**: How to safely expose the manager to the internet? Reverse tunnel (ngrok, Cloudflare Tunnel) vs direct exposure?

5. **Zero-trust reconciliation**: Can HTTP client support be made compliant with device-bound zero-trust, or does it require accepting a different security model?

---

## Comparison with Similar Systems

| System | Remote Client Support | How They Handle It |
|--------|----------------------|-------------------|
| **Tailscale** | Yes | Device identity via WireGuard keys, no cloud AI support |
| **BeyondCorp** | Yes | Device certificates, continuous verification |
| **HashiCorp Boundary** | Yes | Identity-based access, session recording |
| **AWS IAM** | Yes | Service principals, assume-role, no device verification |

None of these systems are designed for AI agent access patterns. A purpose-built solution for "AI agent authorization" is an emerging space without established best practices.

---

## References

- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [Google BeyondCorp](https://cloud.google.com/beyondcorp)
- [CISA Zero Trust Maturity Model](https://www.cisa.gov/zero-trust-maturity-model)
- [MCP Specification: Transports](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)

---

## See Also

- [multi.md](multi.md) - Multi-proxy architecture (STDIO mode)
- [Architecture](../architecture.md) - Overall system design
