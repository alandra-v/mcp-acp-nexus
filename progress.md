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
  - Startup verification:
    - Detects file swap (inode/dev mismatch), hash mismatch, missing files
    - Full chain verification detects tampering anywhere in file (not just last entry)
  - Hard fail (exit code 10) if verification fails - manual repair required

- [x] **AuditHealthMonitor enhancement**
  - Verify last 10 entries in 30s health check loop
  - Uses `partial_chain=True` for tail verification
  - Triggers shutdown on chain break detection

- [x] **CLI commands**
  - `mcp-acp audit verify [--file <name>]` - verify full chain integrity (always verbose)
  - `mcp-acp audit status` - show chain protection status (verifies integrity, shows BROKEN if corrupted)
  - `mcp-acp audit repair [--file <name>] [--yes]` - repair state or reset broken files
    - If chain is valid but state mismatch: syncs state to match log
    - If chain is internally broken: offers to backup file and create fresh one
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

**Status: In Progress (Implementation Complete, Tests + UI Polish Pending)**

Manager daemon that serves UI and observes STDIO proxies (does not own lifecycle).

See [docs/design/multi.md](docs/design/multi.md#phase-3-implementation-details) for architecture and implementation details.

### Step 3.1: Manager Daemon Skeleton — Complete

- [x] Manager process (daemon, PID file, graceful shutdown)
- [x] HTTP server (port 8765, static UI)
- [x] UDS server (manager.sock)
- [x] Auto-start logic (file lock, double-check)
- [x] Manager configuration (manager.json)
- [x] CLI commands (start/stop/status)
- [x] Manager logging (system.jsonl)
- [x] Tests (covered by routes tests: status endpoint, static serving)

### Step 3.2: Proxy Registration — Complete

- [x] Registration protocol (NDJSON over UDS)
- [x] Manager tracks proxies (in-memory dict)
- [x] Proxy graceful degradation (works without manager)
- [x] SSE events (proxy_registered, proxy_disconnected)
- [x] API endpoints (/api/proxies, /api/manager/proxies)
- [x] Tests (test_protocol.py, test_registry.py, test_client.py)

### Step 3.3: Event Forwarding — Complete

- [x] Event protocol (NDJSON, fire-and-forget)
- [x] Manager event aggregation (adds proxy_name, broadcasts)
- [x] Browser SSE endpoint (/api/events)
- [x] Proxy state snapshot on registration
- [x] Tests (test_registry.py: SSE broadcasting, test_client.py: push_event)

### Step 3.4: API Routing — Complete

- [x] Routing logic (httpx UDS transport)
- [x] Fallback routing (/api/* → default proxy)
- [x] Manager-level endpoints (/api/manager/*)
- [x] Error handling (404, 503, 504)
- [x] Tests (test_routes.py: routing errors, prefixes, path safety)

### Step 3.5: UI Polish

**Status: In Progress**

Final UI integration for manager-served UI.

- [x] **Browser auto-open**
  - Manager opens browser on `manager start` command
  - URL: `http://127.0.0.1:{port}`
  - macOS fallback: displays notification with URL if browser open fails

- [x] **UI SSE integration**
  - UI connects to `/api/events` (manager's aggregated endpoint)
  - Added `proxy_registered` / `proxy_disconnected` event handlers
  - Auto-refresh proxy list when proxies connect/disconnect
  - Added TypeScript types for new SSE events

- [x] **Pending approvals on reload**
  - Manager fetches initial snapshot on SSE connect
  - Properly sent before subscribing to live events

- [x] **Browser connectivity tracking**
  - Manager sends `ui_status` messages to proxies when browser connects/disconnects
  - Proxy tracks `browser_connected` state (accurate, not just manager registration)
  - `is_ui_connected` now reflects actual browser connectivity
  - HITL correctly falls back to osascript when no browser connected
  - HITL immediately falls back to osascript if manager disconnects mid-wait
  - Heartbeat mechanism (30s interval, 45s timeout) detects stale connections
  - Periodic reconnection (10s interval) after manager restart
  - System log events: `browser_status_changed`, `manager_connection_closed`, `manager_reconnected`
  - See [docs/demo-testing-guide/manager-ui-coupling-tests.md](docs/demo-testing-guide/manager-ui-coupling-tests.md)

- [ ] **UI updates**
  - [x] Basic proxy status indicator (running/inactive) in detail view
  - [ ] "No proxies connected" message when manager has no registrations
  - [ ] Enhanced proxy status indicators (connected/disconnected)
  - [ ] "Restart Claude Desktop to reconnect" message

- [ ] **Tests**
  - UI shows correct proxy states
  - Browser open logic

- **Known issue (deferred to Phase 4)**: Auth status in navbar doesn't update live on SSE reconnect—shows "not logged in" until page reload. Stats update correctly because they're stored directly in AppStateContext, but auth uses window events which have timing issues. This will be resolved naturally when auth moves to manager in Phase 4 (manager will own auth state and push updates natively).

---

## Phase 4: Multi-Proxy Core

**Status: Not Started**

Multiple STDIO proxies with per-proxy configuration, credential isolation, and centralized auth.

### Auth Migration

Move authentication from proxy to manager:
- Manager handles OIDC device flow (login)
- Manager stores tokens in keychain
- Manager handles token refresh
- Manager distributes identity tokens to proxies
- `auth.jsonl` moves from proxy logs to `logs/manager/auth.jsonl`

Proxies receive identity token from manager and validate per-request, but don't handle login/refresh.

### Tasks

- [ ] **Per-proxy directory structure**
  ```
  ~/.mcp-acp/
  ├── manager.json
  ├── proxies/
  │   ├── filesystem/
  │   │   ├── config.json
  │   │   └── policy.json
  │   └── github/
  │       ├── config.json
  │       └── policy.json
  └── logs/proxies/{name}/
  ```

- [ ] **Proxy identity**
  - `proxy_name`: User-facing, CLI/UI reference (e.g., "filesystem")
  - `proxy_id`: Stable internal identifier (e.g., "px_a1b2c3d4")
  - `instance_id`: Per-start ephemeral ID (e.g., "inst_x9y8z7")
  - Wire up `Environment.proxy_instance` in DecisionContext

- [ ] **Socket naming transition**
  - Switch from `api.sock` to `proxy_{name}.sock`
  - CLI commands use `--proxy` flag or default to single proxy
  - Manager routes to correct proxy socket by name

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
    - Validate name doesn't already exist
    - Validate backend name is unique across proxies
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

Latency measurement for UI display and thesis evaluation. Tracks three metrics:
1. **Policy decision latency** - Time added by per-request policy evaluation
2. **HITL overhead** - Additional delay when human approval is required
3. **Total proxy overhead** - End-to-end time through proxy (feasibility indicator)

### Step 8.1: LatencyTracker Implementation

- [ ] **LatencyTracker class** (in `manager/state.py` or separate file)
  - Circular buffer for recent N samples (`LATENCY_BUFFER_SIZE = 1000` in constants.py)
  - Compute median on read (O(n) sort acceptable for small N)
  - Thread-safe for async context (cooperative asyncio model)
  - Three tracker instances:
    - `proxy_latency`: Total request time through proxy (includes backend)
    - `policy_eval`: Policy evaluation time only
    - `hitl_wait`: HITL wait time only

- [ ] **Integration in ProxyState**
  - Add `LatencyTrackers` as field in `ProxyState.__init__()`
  - Keeps all stats together (request counts + latency)
  - API reads from single source
  - SSE emission handled consistently

- [ ] **Extend `record_decision()` signature**
  ```python
  def record_decision(
      self,
      decision: Decision,
      eval_ms: float | None = None,
      hitl_ms: float | None = None,
  ) -> None:
  ```
  - Records timing alongside decision (always called together)
  - `eval_ms`: Policy evaluation time (always provided for policy-evaluated requests)
  - `hitl_ms`: HITL wait time (only for HITL decisions)

- [ ] **Middleware updates**
  - Pass timing to `record_decision()` from each handler
  - `proxy_latency`: Measure total time in ContextMiddleware (outermost)
  - Timing data already captured: `eval_duration_ms`, `hitl_result.response_time_ms`

### Step 8.2: API and UI

- [ ] **Expanded `/api/stats` endpoint**
  ```json
  {
    "requests_total": 1234,
    "requests_allowed": 1100,
    "requests_denied": 50,
    "requests_hitl": 84,
    "latency": {
      "proxy_median_ms": 45.2,
      "policy_eval_median_ms": 2.1,
      "hitl_wait_median_ms": 8500.0,
      "sample_count": 1000
    }
  }
  ```

- [ ] **UI display**
  - Extend existing StatsSection with latency info
  - Show: "~45ms response" (total proxy median)
  - Tooltip or expandable detail: policy eval ~2ms, HITL ~8.5s
  - Multi-proxy list view: show median on each proxy card

### Step 8.3: Thesis Benchmark Script

Hybrid approach: log parsing for metrics already captured, live benchmark for proxy overhead comparison.

- [ ] **Log parser** (`scripts/parse_latency_logs.py`)
  - Parse audit logs for `policy_eval_ms` and `policy_hitl_ms`
  - Aggregate into median, std dev, sample count
  - Supports filtering by date range
  - **Why log parsing for these metrics:**
    - Data already exists from real usage
    - Reflects actual usage patterns, not synthetic tests
    - Historical analysis possible
    - No test infrastructure needed

- [ ] **Live benchmark** (`scripts/benchmark_overhead.py`)
  - Uses FastMCP Client (pytest fixtures) to send MCP requests programmatically
  - Tests both STDIO and HTTP proxy↔backend transport modes
  - **Why live benchmark for proxy overhead:**
    - Requires direct vs proxied comparison (can't get "direct" from logs)
    - Controlled, reproducible test conditions
    - Can isolate proxy overhead specifically

  - **Test setup**:
    ```
    Direct:   FastMCP Client ──STDIO/HTTP──▶ Backend
    Proxied:  FastMCP Client ──STDIO──▶ Proxy ──STDIO/HTTP──▶ Backend
    ```

  - **Warmup**: Discard first N requests (cold caches, lazy imports, policy parsing)
  - **Request mix**: Discovery (tools/list) + tool calls (representative workload)
  - **Transport modes**: Test proxy↔backend over both STDIO and HTTP

  - **Proxy overhead methodology**:
    ```
    Direct:  Client ──────────────────────▶ Backend
             median_direct = 30ms

    Proxied: Client ──▶ Proxy ──▶ Backend
             median_proxied = 45ms

    Proxy Overhead = median_proxied - median_direct = 15ms
    ```

- [ ] **Output report**:
  ```
  === Policy Decision Latency (from audit logs) ===
  Log file: ~/.mcp-acp/logs/audit/decisions.jsonl
  Samples: 1000
  Median: 2.1ms
  Std Dev: 0.8ms

  === HITL Overhead (from audit logs) ===
  Samples: 84 (HITL decisions only)
  Median: 8.5s
  Note: Human response time dominates

  === Proxy Overhead - STDIO backend (live benchmark) ===
  Warmup: 10 requests (discarded)
  Test requests: 100 x (tools/list + tool call)
  Direct median: 30.2ms
  Proxied median: 45.4ms
  Overhead: 15.2ms (+50.3%)
  Std Dev (direct): 5.1ms
  Std Dev (proxied): 6.3ms

  === Proxy Overhead - HTTP backend (live benchmark) ===
  Direct median: 28.1ms
  Proxied median: 42.8ms
  Overhead: 14.7ms (+52.3%)

  Note: Proxy overhead is a feasibility indicator only, not optimization data.
  ```

- [ ] **Tests**
  - LatencyTracker unit tests (buffer, median calculation, thread safety)
  - API endpoint tests (extended stats response)
  - Log parser tests (parsing, aggregation)
  - Benchmark script smoke test

---

## Stage 3 Completion Criteria

- [x] Audit logs protected by hash chain with between-run verification
- [x] Manager daemon serves UI and observes proxies (Phase 3 core complete)
- [ ] Multiple STDIO proxies can register with manager (Phase 4)
- [ ] Credential isolation per proxy (Phase 4)
- [ ] CLI commands for proxy configuration (not lifecycle) (Phase 4)
- [ ] UI updated for multi-proxy observation (Phase 5)
- [ ] Proxy deletion with audit trail preservation (Phase 6)
- [ ] Toast notifications for proxy events (Phase 7)
- [ ] Crash detection with UI notification (Phase 7)
- [ ] Basic performance metrics displayed in UI (Phase 8)

---

## Out of Scope (Future Work)

### HTTP Client Mode

See [docs/design/http-client-mode.md](docs/design/http-client-mode.md) for:
- HTTP clients (ChatGPT, custom apps) connecting through manager
- Manager-owned proxy lifecycle (lazy spawn, idle shutdown)
- Manager as reverse proxy
- OIDC/mTLS authentication for HTTP clients
