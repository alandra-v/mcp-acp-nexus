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

**Status: Complete**

Manager daemon that serves UI and observes STDIO proxies (does not own lifecycle).

### Step 3.1: Manager Daemon Skeleton

- [x] Manager process (daemon, PID file, graceful shutdown)
- [x] HTTP server (port 8765, static UI)
- [x] UDS server (manager.sock)
- [x] Auto-start logic (file lock, double-check)
- [x] Manager configuration (manager.json)
- [x] CLI commands (start/stop/status)
- [x] Manager logging (system.jsonl)
- [x] Tests (covered by routes tests: status endpoint, static serving)

### Step 3.2: Proxy Registration

- [x] Registration protocol (NDJSON over UDS)
- [x] Manager tracks proxies (in-memory dict)
- [x] Proxy graceful degradation (works without manager)
- [x] SSE events (proxy_registered, proxy_disconnected)
- [x] API endpoints (/api/proxies, /api/manager/proxies)
- [x] Tests (test_protocol.py, test_registry.py, test_client.py)

### Step 3.3: Event Forwarding

- [x] Event protocol (NDJSON, fire-and-forget)
- [x] Manager event aggregation (adds proxy_name, broadcasts)
- [x] Browser SSE endpoint (/api/events)
- [x] Proxy state snapshot on registration
- [x] Tests (test_registry.py: SSE broadcasting, test_client.py: push_event)

### Step 3.4: API Routing

- [x] Routing logic (httpx UDS transport)
- [x] Fallback routing (/api/* → default proxy)
- [x] Manager-level endpoints (/api/manager/*)
- [x] Error handling (404, 503, 504)
- [x] Tests (test_routes.py: routing errors, prefixes, path safety)

### Step 3.5: UI Polish

- [x] Browser auto-open (manager opens browser on start, macOS notification fallback)
- [x] UI SSE integration (connects to `/api/events`, handles proxy lifecycle events)
- [x] Pending approvals on reload (snapshot sent before live events)
- [x] Browser connectivity tracking (HITL fallback to osascript when no browser)
- [x] Proxy status indicator (running/inactive) in detail view

**Note**: Multi-proxy UI enhancements (proxy list view, "No proxies connected" message, enhanced status indicators) are in Phase 5.

---

## Phase 4: Multi-Proxy Core

**Status: Complete (CLI fully functional)**

Multi-proxy CLI support is complete. Users can configure multiple proxies and test them via CLI with `--headless`. The web UI still uses single-proxy patterns and will be updated in Phase 5.

### Step 4.1: Configuration Schema

**Status: Complete**

- [x] `PerProxyConfig` model (backend + hitl + proxy_id + mtls)
- [x] `ManagerConfig` model (auth + ui_port + log_dir + log_level)
- [x] `build_app_config_from_per_proxy()` helper
- [x] Per-proxy config paths (`get_proxy_config_dir()`, `get_proxy_config_path()`)
- [x] Config loading/saving functions
- [x] Removed legacy single-proxy config support (`mcp_acp_config.json`)

### Step 4.2: CLI Commands

**Status: Complete**

- [x] **`mcp-acp init`** (restructured)
  - Creates `manager.json` with OIDC auth config ONLY
  - No more backend/logging prompts (moved to `proxy add`)
  - Tells user to run `auth login` then `proxy add`

- [x] **`mcp-acp auth login/logout/status`**
  - Reads OIDC config from `manager.json`
  - Stores tokens in OS keychain
  - Works without running proxy

- [x] **`mcp-acp proxy add`**
  - Requires init first (manager.json exists)
  - Prompts for: proxy name, server name, connection type, command/URL
  - Supports mTLS configuration for HTTP backends
  - Generates `proxy_id` (e.g., "px_a1b2c3d4:filesystem-server")
  - Creates `proxies/{name}/config.json` and `policy.json`
  - Confirmation step with inline edit capability before saving
  - Shows Claude Desktop config snippet

- [x] **`mcp-acp proxy list`** - List all configured proxies + running status
- [x] **`mcp-acp proxy show <name>`** - Show proxy config details

- [x] **`mcp-acp start --proxy <name> [--headless]`** - Start specific proxy (required flag), `--headless` disables UI
- [x] **`mcp-acp status --proxy <name>`** - Per-proxy or all proxies summary
- [x] **`mcp-acp policy reload --proxy <name>`** - Requires proxy name
- [x] **`mcp-acp install mcp-json [--proxy <name>]`** - Generate Claude Desktop config

- [x] **`mcp-acp logs list/view/tail --proxy <name>`** - Per-proxy log access
- [x] **`mcp-acp audit verify/status/repair --proxy <name>`** - Per-proxy audit
- [x] **`mcp-acp config show --manager|--proxy <name>`** - Show manager or proxy config

- [x] **`api_client.py`** - Updated with `proxy_name` parameter, uses `get_proxy_socket_path()`

- [x] **CLI help updated** - Shows new multi-proxy flow (init → proxy add → start --proxy)

- [x] **Shared CLI helpers** - `require_proxy_name()`, `validate_proxy_if_provided()` in utils/cli/helpers.py

**Later Commands (Phase 7+):**

- [ ] **`mcp-acp proxy remove <name>`** - Remove proxy with archiving

### Step 4.3: Infrastructure Changes

**Status: Complete**

- [x] **Log path refactoring**
  - Changed `get_log_dir(config)` to `get_log_dir(proxy_name, log_dir=None)`
  - Updated all dependent log path functions
  - Updated all callers in proxy.py, init.py, CLI commands, tests

- [x] **Per-proxy log levels**
  - Each proxy can have independent log level (DEBUG or INFO)
  - Configured in per-proxy `config.json`
  - Allows verbose debugging for specific proxies without affecting others

- [x] **Socket path changes**
  - Replaced `SOCKET_PATH` constant with `get_proxy_socket_path(proxy_name)`
  - Updated all references in proxy.py
  - `api_client.py` accepts `proxy_name` parameter

- [x] **Manager routing**
  - Added `_get_default_proxy()` helper in routes.py
  - 0 proxies → 503 "No proxies connected"
  - 1 proxy → use it (backward compat for UI)
  - 2+ proxies → 400 error listing available proxies
  - SSE events include `proxy_name` and iterate all proxies

- [x] **Registration protocol**
  - Added `proxy_id` to registration message
  - Updated `ProxyConnection` dataclass with `proxy_id` field
  - Added `get_all_proxies()` method to registry

- [x] **Environment.proxy_instance**
  - Added `proxy_name` parameter through middleware chain
  - `build_decision_context()` accepts `proxy_name`
  - `Environment.proxy_instance` populated in policy context

- [x] **Crash breadcrumb path**
  - Uses per-proxy log_dir (already works)

- [x] **Token distribution protocol**
  - Message type documented: `{"type": "token_update", "access_token": "...", "expires_at": "..."}`
  - Stub handler in ManagerClient (logs receipt)

### Step 4.4: Auth Migration

**Status: Complete**

OIDC config moved to manager.json. CLI auth commands work. Manager owns token lifecycle and distributes to proxies.

- [x] **CLI reads OIDC from manager.json**
  - `auth login` triggers device flow, reads OIDC from manager.json
  - CLI stores tokens in OS keychain
  - CLI notifies manager to reload and broadcast tokens

- [x] **Manager handles token refresh**
  - `ManagerTokenService` loads tokens from keychain on startup
  - Monitors expiry, proactively refreshes (5 min before expiry)
  - Broadcasts updates to all connected proxies

- [x] **Token distribution implementation**
  - Proxies receive token from manager on registration
  - Manager broadcasts token updates to all connected proxies
  - `OIDCIdentityProvider` prefers manager-provided tokens

- [x] **Backend credentials in keychain**
  - `BackendCredentialStorage` for API keys/tokens
  - `credential_key` field in `HttpTransportConfig`
  - `proxy add` prompts for API key, stores in keychain

### Tests

- [x] Manager registry tests (with proxy_id)
- [x] Manager routes tests (updated error messages)
- [x] Policy reload CLI tests (with --proxy flag)
- [x] Context tests (proxy_name parameter)
- [x] CLI command tests (init, proxy add, auth, logs, audit)
- [x] Auth token distribution tests
- [x] Multi-proxy routing tests (fallback behavior with 0/1/2+ proxies)

---

## Phase 5: Multi-Proxy UI

**Status: Not Started**

UI enhancements for multi-proxy observation (no lifecycle control).

**Prerequisite cleanup from Phase 4:** ✅ Complete
- [x] Update `api/routes/config.py` to use per-proxy config paths
- [x] Update `api/deps.py` to load OIDC from manager.json
- [x] Remove `get_config_path()` returning legacy `mcp_acp_config.json`

**Already implemented (from Phase 3/4):**
- [x] Global approval notifications (header badge + PendingDrawer with `showProxyId`)
- [x] SSE multi-proxy events (`proxy_name` field, `proxy_registered`/`proxy_disconnected` handlers)
- [x] Manager settings page - **Not needed** (auth configured via CLI `mcp-acp init`)

**Backend work required:**
- [ ] Fix `get_log_base_path()` hardcoded "default" path in `utils/api/log_reader.py`
- [ ] Add `GET /api/manager/incidents` - aggregated incidents endpoint with `?proxy=` filter
- [ ] Enhance `GET /api/manager/proxies` - include config data (backend type, server_name, stats)
- [ ] Add `POST /api/manager/proxies` - proxy creation endpoint (mirrors CLI `proxy add`)

**UI work required:**
- [ ] **Proxy list view (new landing page at `/`)**
  - Grid of proxy cards with name, backend type, status, stats
  - "Add Proxy" button
  - Empty state for no proxies configured
  - Click card → `/proxy/:name`

- [ ] **Proxy detail view (route `/proxy/:name`)**
  - Back navigation to list
  - URL param selects proxy (not hardcoded `proxies[0]`)
  - Filter pending/cached/stats by proxy_id

- [ ] **Add proxy flow**
  - Form: name, server_name, connection type, command/URL, API key
  - POST to `/api/manager/proxies`
  - Show Claude Desktop snippet on success

- [ ] **Incidents proxy filtering**
  - Add proxy dropdown filter to existing IncidentsPage
  - Pass filter to aggregated incidents API

- [ ] **Tests**
  - Backend: incidents aggregation, proxy creation endpoint
  - Frontend: proxy list, detail routing, add flow

---

## Phase 6: Security Hardening (Credential Isolation)

**Status: Not Started**

Encrypt backend credentials per-proxy with spawn-time key injection. Each proxy can only decrypt its own backend credentials.

- [ ] **Per-proxy encryption keys**
  - Generate unique encryption key per proxy on `proxy add`
  - Store encryption keys in OS keychain (manager's keychain service)
  - Key ID stored in proxy config, references keychain entry

- [ ] **Backend credential encryption**
  - Backend credentials (API keys, tokens) encrypted in proxy config
  - `credentials.encrypted` blob in config.json
  - Only decryptable with proxy's specific key

- [ ] **Spawn-time key injection**
  - When proxy starts, manager injects decryption key via secure IPC
  - Proxy decrypts credentials on startup
  - Key held in memory only (not written to disk)
  - Manager forgets key after injection (zero-knowledge after spawn)

- [ ] **Security properties**
  - Compromised proxy A cannot decrypt proxy B's credentials
  - Stolen config files are useless without keychain access
  - Manager doesn't retain decryption keys after spawn

- [ ] **CLI updates**
  - `proxy add` prompts for backend credentials, encrypts them
  - `proxy credentials <name> update` - update encrypted credentials

- [ ] **Tests**
  - Credential encryption/decryption tests
  - Key injection tests
  - Isolation verification tests

---

## Phase 7: Proxy Deletion

**Status: Not Started**

Proxy deletion with audit trail preservation and recovery support.

- [ ] **Soft delete (archive)**
  - Archive config + policy to `proxies/.deleted/{name}_{timestamp}/`
  - Archive audit + system logs to `logs/proxies/.deleted/{name}_{timestamp}/`
  - Delete debug logs immediately (no security value)
  - Remove encryption key from keychain
  - Remove backend credential from keychain (`proxy:{name}:backend` key)
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

## Phase 8: Stability & Polish

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

## Phase 9: Performance Metrics (POC)

**Status: Not Started**

Latency measurement for UI display and thesis evaluation. Tracks three metrics:
1. **Policy decision latency** - Time added by per-request policy evaluation
2. **HITL overhead** - Additional delay when human approval is required
3. **Total proxy overhead** - End-to-end time through proxy (feasibility indicator)

### Step 9.1: LatencyTracker Implementation

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

### Step 9.2: API and UI

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

### Step 9.3: Thesis Benchmark Script

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

- [x] Audit logs protected by hash chain with between-run verification (Phase 1)
- [x] Manager daemon serves UI and observes proxies (Phase 3)
- [x] Multiple STDIO proxies can register with manager (Phase 4 Steps 1-3)
- [x] CLI commands for proxy configuration (Phase 4 Step 2)
- [x] CLI fully functional for multi-proxy testing (Phase 4 Complete)
- [x] Auth commands read OIDC from manager.json (Phase 4 Step 4 partial)
- [x] Full manager-owned auth lifecycle with token distribution (Phase 4 Step 4)
- [ ] UI updated for multi-proxy observation (Phase 5)
- [ ] Credential isolation per proxy (Phase 6 - Security Hardening)
- [ ] Proxy deletion with audit trail preservation (Phase 7)
- [ ] Toast notifications for proxy events (Phase 8)
- [ ] Crash detection with UI notification (Phase 8)
- [ ] Basic performance metrics displayed in UI (Phase 9)

---

## Out of Scope (Future Work)

### HTTP Client Mode

See [docs/design/http-client-mode.md](docs/design/http-client-mode.md) for:
- HTTP clients (ChatGPT, custom apps) connecting through manager
- Manager-owned proxy lifecycle (lazy spawn, idle shutdown)
- Manager as reverse proxy
- OIDC/mTLS authentication for HTTP clients
