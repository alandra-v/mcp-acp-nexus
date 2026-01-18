# mcp-acp-nexus Implementation Progress

## Multi-Proxy Architecture

Multi-proxy architecture with manager daemon, credential isolation, and enhanced audit security.

**Scope**: STDIO client mode only. Claude Desktop spawns proxies and owns their lifecycle. Manager observes and coordinates but does not control proxy lifecycle.

---

## Phase 1: Audit Log Security

**Status: Complete**

Hash chain implementation and between-run protection for audit log integrity.

- [x] **Hash chain implementation**
  - Add `prev_hash`, `sequence`, `entry_hash` fields to audit entries
  - SHA-256 hash with deterministic JSON serialization
  - Detect deleted/inserted/reordered/modified entries via chain breaks
  - `HashChainFormatter` replaces `ISO8601Formatter` for protected logs

- [x] **Between-run protection**
  - `.integrity_state` file stores last_hash, last_sequence, last_inode, last_dev per file
  - Atomic save (temp file + rename) after each audit write
  - Startup verification detects file swap, hash mismatch, missing files, content tampering
  - Hard fail (exit code 10) if verification fails - manual repair required

- [x] **AuditHealthMonitor enhancement**
  - Verify last 10 entries in 30s health check loop
  - Uses `partial_chain=True` for tail verification
  - Triggers shutdown on chain break detection

- [x] **CLI commands**
  - `mcp-acp audit verify [--file <name>] [--verbose]` - verify integrity
  - `mcp-acp audit status` - show chain protection status
  - `mcp-acp audit repair [--file <name>] [--yes]` - manual state repair after crash
  - Exit codes: 0=passed, 1=tampering, 2=unable to verify

- [x] **Tests**
  - 48 tests covering hash chain logic, state persistence, tampering detection, manual repair

- [x] **Documentation**
  - Security limitations documented (self-attesting, no external attestation)
  - Mitigations documented (remote syslog, append-only filesystem, backups)
  - OS-level append-only instructions (Linux `chattr`, macOS `chflags`)

---

## Phase 2: Storage Backend Abstraction

**Status: Deferred (No Functional Gap)**

### Analysis

The `key_value.aio` library is already installed as a FastMCP dependency and provides:

```python
from key_value.aio.protocols.key_value import AsyncKeyValue  # Interface
from key_value.aio.stores.memory import MemoryStore          # In-memory
from key_value.aio.stores.disk import DiskStore              # File-based
from key_value.aio.stores.redis import RedisStore            # Distributed
# Also: dynamodb, mongodb, elasticsearch, memcached, rocksdb, valkey, vault
```

**Interface**: `get`, `get_many`, `put`, `put_many`, `delete`, `delete_many`, `ttl`, `ttl_many`

### Why This Phase Is Deferred

**ApprovalStore and SessionManager don't need persistence:**

| Component | Reset on Restart? | Reasoning |
|-----------|-------------------|-----------|
| ApprovalStore | ✅ Correct | Short TTL (minutes). Re-approval on restart is conservative security. |
| SessionManager | ✅ Correct | STDIO mode - connection resets anyway. Session state is moot. |

**Multi-proxy doesn't change this:**
- Approvals are per-proxy (different backends, different tools) - no sharing needed
- Sessions are per-proxy - no sharing needed
- Manager tracks registered proxies in-memory (proxies re-register on connect)
- OIDC tokens stored in OS keychain, not KV store

### When To Revisit

Introduce storage abstraction if:
1. **HTTP client mode** (out of scope) - Manager would own sessions for external HTTP clients
2. **Multi-host deployment** (out of scope) - Redis backend for distributed state
3. **UI session persistence** - Nice-to-have convenience, not security requirement

### If Implemented Later

The infrastructure already exists. Refactoring would be:

```python
class ApprovalStore:
    def __init__(self, store: AsyncKeyValue | None = None):
        self._store = store or MemoryStore()

    async def store(self, key, value):
        await self._store.put(key, value, ttl=self._ttl_seconds)
```

No new dependencies needed - just wire up existing library.

---

## Phase 3: Manager Introduction

**Status: Not Started**

Manager daemon that serves UI and observes STDIO proxies (does not own lifecycle).

### Architecture Overview

```
Browser ←─HTTP─→ Manager (serves UI, routes requests)
                    ↓ UDS
              ┌─────┴─────┐
           Proxy A     Proxy B
              ↓           ↓
          Backend A   Backend B
```

**Manager role**: Thin routing/aggregation layer. NOT a controller.

| Component | Responsibility |
|-----------|----------------|
| Manager | Serves UI, routes API requests, aggregates SSE events |
| Proxy | Policy enforcement, HITL handling, audit logging, backend connection (unchanged) |

### Tasks

- [ ] **Manager daemon architecture**
  - Separate daemon process
  - Serves web UI (UI available before any proxy starts)
  - Receives proxy registrations via UDS
  - Does NOT spawn or control proxy lifecycle (client-owned)

- [ ] **Manager startup modes**
  - Explicit: `mcp-acp manager start`
  - Auto-start: First proxy spawns manager if not running
  - File lock prevents race conditions on simultaneous starts
  - Manager runs as daemon (survives proxy restarts)

- [ ] **Manager configuration**
  - `manager.json` for manager-level settings
  - UI port, auth (shared OIDC)
  - Separate from per-proxy config

- [ ] **Proxy registration + SSE events**
  - Proxy connects to Manager via UDS on startup
  - Sends: proxy_id, proxy_name, instance_id, config summary
  - **Same UDS connection stays open for SSE events**
  - Proxy writes events to UDS → Manager forwards to browser
  - Manager detects disconnect when UDS closes

- [ ] **API structure**
  Manager-level endpoints (no routing):
  ```
  GET  /api/proxies              → list all proxies + status
  GET  /api/events               → aggregated SSE stream (all proxies)
  GET  /api/manager/status       → manager health
  ```

  Proxy-routed endpoints (Manager forwards via UDS):
  ```
  GET  /api/proxy/{name}/approvals
  POST /api/proxy/{name}/approvals/{id}/approve
  GET  /api/proxy/{name}/policy
  POST /api/proxy/{name}/policy/reload
  GET  /api/proxy/{name}/config
  GET  /api/proxy/{name}/incidents
  ```

- [ ] **SSE event format**
  ```json
  {
    "proxy_id": "filesystem",
    "event": "approval_requested",
    "data": { ... }
  }
  ```
  Single aggregated stream. UI filters by `proxy_id` client-side.

- [ ] **UI ownership transfer**
  - Manager serves web UI (not proxy)
  - UI survives proxy restart/crash
  - Proxy status shown in UI (observe only)
  - Config changes show "Restart client to apply" message

- [ ] **Manager CLI commands**
  - `mcp-acp manager start` - Start manager daemon
  - `mcp-acp manager stop` - Stop manager daemon
  - `mcp-acp manager status` - Show manager + all proxies status

- [ ] **Port conflict handling**
  - Clear error if UI port in use
  - Configurable via `ui_port` in manager.json
  - CLI override: `--port`

- [ ] **Tests**
  - Manager lifecycle tests
  - Proxy registration/deregistration tests
  - Auto-start tests
  - API routing tests
  - SSE aggregation tests

---

## Phase 4: Multi-Proxy Core

**Status: Not Started**

Multiple STDIO proxies registering with manager, with credential isolation.

- [ ] **Per-proxy directory structure**
  ```
  ~/.mcp-acp/
  ├── manager.json
  ├── proxies/
  │   ├── filesystem/
  │   │   ├── config.json
  │   │   └── policy.yaml
  │   └── github/
  │       ├── config.json
  │       └── policy.yaml
  └── logs/proxies/{name}/
  ```

- [ ] **Proxy identity**
  - `proxy_name`: User-facing, CLI/UI reference (e.g., "filesystem")
  - `proxy_id`: Stable internal identifier (e.g., "px_a1b2c3d4")
  - `instance_id`: Per-start ephemeral ID (e.g., "inst_x9y8z7")
  - Wire up `Environment.proxy_instance` in DecisionContext

- [ ] **Multiple proxy tracking**
  - Manager tracks all registered proxies
  - Per-proxy status (connected/disconnected)
  - Aggregate view across all proxies

- [ ] **Credential isolation**
  - Generate unique encryption key per backend
  - Store encrypted credentials in proxy config
  - Store encryption keys in OS keychain
  - Proxy decrypts own credentials on startup
  - Each proxy only has access to own backend credentials

- [ ] **Identity token handling**
  - Manager handles OIDC token refresh centrally
  - Proxies receive identity token on registration
  - Manager broadcasts token updates to connected proxies

- [ ] **Proxy CLI commands**
  - `mcp-acp proxy list` - List all configured proxies
  - `mcp-acp proxy add [--name, --backend]` - Add new proxy config
  - `mcp-acp proxy remove <name>` - Remove proxy config
  - `mcp-acp proxy show <name>` - Show proxy config
  - Note: No start/stop/restart commands (client owns lifecycle)

- [ ] **Per-proxy policy/config commands**
  - `mcp-acp proxy config <name> show`
  - `mcp-acp proxy policy <name> show`
  - `mcp-acp proxy policy <name> reload`

- [ ] **Login/logout flow updates**
  - Login: Manager handles OIDC, distributes tokens to proxies
  - Logout: Manager broadcasts logout, proxies zeroize credentials
  - Token refresh failure: Re-authentication required

- [ ] **Tests**
  - Multi-proxy registration tests
  - Credential isolation tests
  - Token distribution tests

---

## Phase 5: Multi-Proxy UI

**Status: Not Started**

UI enhancements for multi-proxy observation (no lifecycle control).

- [ ] **Proxy list view (new landing page)**
  - List all registered proxies
  - Show status indicator (connected/disconnected)
  - Show backend info
  - Show stats per proxy (requests count, median response time)
  - No start/stop buttons (client owns lifecycle)
  - "Add New" button (creates config, user must configure client)

- [ ] **Proxy detail view (enhanced)**
  - Back navigation to list
  - Status + connected clients count
  - No start/stop/restart buttons (observe only)
  - Tabs: Overview, Logs, Policy, Config, Incidents

- [ ] **Add proxy flow**
  - Name input
  - Backend type selection (STDIO command or HTTP URL)
  - Command/URL configuration
  - Creates config file
  - Shows instructions to add to Claude Desktop config

- [ ] **Manager settings page**
  - Authentication settings (OIDC, mTLS)
  - Storage backend settings
  - Warning: "Changes require client restart to apply"
  - Save/discard buttons

- [ ] **Global approval notifications**
  - Notification banner visible from any page
  - Shows proxy name + tool + args summary
  - Quick actions (Approve/Deny) or "View" for details
  - Badge in header with pending count across all proxies

- [ ] **Incidents aggregator**
  - Global `/incidents` page aggregates across all proxies
  - Filter by proxy name
  - Each incident shows which proxy it belongs to
  - Per-proxy Incidents tab in detail view

- [ ] **SSE updates for multi-proxy**
  - Proxy registration/deregistration events
  - Per-proxy event routing
  - Manager-level events

- [ ] **Tests**
  - UI component tests
  - SSE event handling tests

---

## Phase 6: Proxy Deletion

**Status: Not Started**

Proxy deletion with audit trail preservation and recovery support.

- [ ] **Soft delete (archive)**
  - Archive config + policy to `proxies/.deleted/{name}_{timestamp}/`
  - Archive audit + system logs to `logs/proxies/.deleted/{name}_{timestamp}/`
  - Delete debug logs immediately (no security value)
  - Remove encryption key from keychain
  - Write README.txt with deletion metadata and recovery instructions

- [ ] **Purge command**
  - `mcp-acp proxy purge <archive_name>` - Permanently delete archived data
  - Confirmation prompt before deletion
  - `mcp-acp proxy delete <name> --purge` - Direct hard delete

- [ ] **List deleted proxies**
  - `mcp-acp proxy list --deleted`

- [ ] **Delete safety checks**
  - Warn if proxy currently connected
  - Remind user to update client config (e.g., Claude Desktop)

- [ ] **UI delete flow**
  - Confirmation dialog showing what will be archived vs deleted
  - Recovery instructions in dialog
  - Client config reminder

- [ ] **Edge cases**
  - Timestamp in folder name prevents collisions
  - Fail-safe: don't delete original until archive succeeds
  - Restore blocked if proxy with same name exists

- [ ] **Tests**
  - Delete/archive tests
  - Purge tests
  - Edge case handling tests

---

## Phase 7: Stability & Polish

**Status: Not Started**

Toast notifications and crash handling.

- [ ] **Toast notification system**
  - Info (blue): Backend connected, proxy registered
  - Success (green): Reconnected, config saved, policy reloaded
  - Warning (orange): Reconnection timeout, certificate expiring
  - Error (red): Connection errors, TLS errors
  - Critical (red, persistent): Security shutdowns (audit tampering, session hijacking)

- [ ] **Critical toast behavior**
  - Does not auto-dismiss
  - Modal-like center display
  - Requires user acknowledgment
  - Links to logs for investigation

- [ ] **Proxy disconnect handling (UI survives)**
  - UI detects proxy deregistration/disconnect
  - Read `.last_crash` breadcrumb for failure details
  - Show crash reason in critical toast
  - Update proxy status to "disconnected"
  - Message: "Restart Claude Desktop to reconnect"

- [ ] **Manager crash detection**
  - Monitor for proxy disconnect events
  - Detect unexpected exits via breadcrumb files
  - Write to crashes.jsonl with proxy info
  - Read faulthandler crash dump if available

- [ ] **Tests**
  - Toast display tests
  - Crash detection tests

---

## Phase 8: Performance Metrics (POC)

**Status: Not Started**

Basic latency measurement for evaluation (extended testing out of scope).

- [ ] **LatencyTracker implementation**
  - Circular buffer for recent N samples (default 1000)
  - Record elapsed_ms after each request
  - Compute median on read (O(n) sort)
  - Thread-safe for async context

- [ ] **Middleware integration**
  - Create tracker at proxy startup
  - Record timing in outermost middleware
  - Measure total time through proxy (includes backend)

- [ ] **API endpoint**
  - `GET /api/stats` returns:
    ```json
    {
      "requests_total": 1234,
      "median_ms": 45.2
    }
    ```

- [ ] **UI display**
  - Show stats on each proxy card in list view
  - Requests count and median response time per proxy
  - `~` prefix indicates median (typical experience)
  - Example: "1,234 requests  ~45ms"
  - Disconnected proxies show stats from last session

- [ ] **Benchmark script for thesis**
  - Compare direct backend vs proxied latency
  - Calculate proxy overhead (median_proxied - median_direct)
  - Report: overhead_ms, overhead_pct, stdev
  - Document test methodology

- [ ] **Tests**
  - LatencyTracker unit tests
  - API endpoint tests

---

## Stage 3 Completion Criteria

- [x] Audit logs protected by hash chain with between-run verification
- [ ] Manager daemon serves UI and observes proxies
- [ ] Multiple STDIO proxies can register with manager
- [ ] Credential isolation per proxy
- [ ] CLI commands for proxy configuration (not lifecycle)
- [ ] UI updated for multi-proxy observation
- [ ] Proxy deletion with audit trail preservation
- [ ] Toast notifications for proxy events
- [ ] Crash detection with UI notification
- [ ] Basic performance metrics displayed in UI

---

## Out of Scope (Future Work)

### HTTP Client Mode

See [docs/design/http-client-mode.md](docs/design/http-client-mode.md) for:
- HTTP clients (ChatGPT, custom apps) connecting through manager
- Manager-owned proxy lifecycle (lazy spawn, idle shutdown)
- Manager as reverse proxy
- OIDC/mTLS authentication for HTTP clients

### Extended Performance Testing

See [docs/design/performance-testing-enhanced.md](docs/design/performance-testing-enhanced.md) for:
- Percentile tracking (p50, p95, p99)
- Segment-level timing breakdown
- Load testing / soak testing
- Coordinated omission-aware benchmarks
- Resource consumption metrics

### Distributed Deployment

See [docs/design/multi.md](docs/design/multi.md) "Storage Backends" section for:
- RedisStore for multi-host deployment
- DynamoDB / MongoDB backends
- Distributed approval coordination

Note: `key_value.aio` library (FastMCP dependency) already provides Redis, DynamoDB, MongoDB backends. No new dependencies needed - just configuration.
