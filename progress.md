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
  - `mcp-acp audit verify [--proxy <name>] [--file <name>]` - verify integrity and show status (combines verify + status)
  - `mcp-acp audit repair --proxy <name> [--file <name>] [--yes]` - repair state or reset broken files
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
- [x] `ManagerConfig` model (auth + ui_port + log_dir)
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

**Later Commands (Phase 7 — Complete):**

- [x] **`mcp-acp proxy delete <name>`** - Delete proxy with archiving
- [x] **`mcp-acp proxy purge <name>`** - Permanently delete archived proxy

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

**Status: Complete**

UI enhancements for multi-proxy observation (no lifecycle control).

**Prerequisite cleanup from Phase 4:**
- [x] Update `api/routes/config.py` to use per-proxy config paths
- [x] Update `api/deps.py` to load OIDC from manager.json
- [x] Remove `get_config_path()` returning legacy `mcp_acp_config.json`

**Already implemented (from Phase 3/4):**
- [x] Global approval notifications (header badge + PendingDrawer with `showProxyId`)
- [x] SSE multi-proxy events (`proxy_name` field, `proxy_registered`/`proxy_disconnected` handlers)
- [x] Manager settings page - **Not needed** (auth configured via CLI `mcp-acp init`)

**Backend work:**
- [x] Fix `get_log_base_path()` hardcoded "default" path in `utils/api/log_reader.py`
- [x] Add `GET /api/manager/incidents` - aggregated incidents endpoint with `?proxy=` filter
- [x] Enhance `GET /api/manager/proxies` - include config data (backend type, server_name, stats)
- [x] Add `POST /api/manager/proxies` - proxy creation endpoint (mirrors CLI `proxy add`)
- [x] Add `GET /api/manager/config-snippet` - Claude Desktop JSON (`?proxy=` for single, omit for all)

**UI work:**

- [x] **Proxy list view (new landing page at `/`)**
  - [x] Grid of proxy cards with name, backend type, status indicator
  - [x] Running proxies show stats; stopped proxies show "Not running"
  - [x] "Add Proxy" button opens modal
  - [x] "Export All" button - copies Claude Desktop JSON for all proxies
  - [x] Empty state for no proxies configured
  - [x] Click card → `/proxy/:name`
  - [x] Filter chips (All/Running/Stopped) with localStorage persistence

- [x] **Proxy detail view (route `/proxy/:name`)**
  - [x] Back navigation to list
  - [x] URL param selects proxy (not hardcoded `proxies[0]`)
  - [x] Filter pending/cached/stats by proxy_id
  - [x] Invalid proxy name → redirect to list
  - [x] Tabs: Overview, Logs, Policy, Config
  - [x] "Copy Config Snippet" button in header (per-proxy Claude Desktop JSON)
  - [x] Audit integrity section with verify/repair controls

- [x] **Add proxy modal**
  - [x] Form: name, server_name, connection type, command, args, URL, API key
  - [x] Advanced section (collapsible): mTLS cert paths, HTTP timeout
  - [x] Attestation options (SLSA owner, SHA256, require signature)
  - [x] HTTP backend health check validation
  - [x] On success: modal shows Claude Desktop snippet with copy button
  - [x] User clicks "Done" → modal closes → toast → stay on list

- [x] **Incidents proxy filtering**
  - [x] Single merged timeline (sorted by timestamp)
  - [x] Type and proxy filter dropdowns with localStorage persistence
  - [x] `useIncidents()` hook with server-side filtering
  - [x] Backend `/api/manager/incidents` aggregates from all proxies
  - [x] Proxy attribution: `proxy_id` and `proxy_name` on all incident entries
  - [x] Emergency audit fallback includes proxy attribution via `log_with_fallback`
  - [x] Per-proxy incident files: `bootstrap.jsonl` in proxy config dir, `shutdowns.jsonl` in proxy log dir
  - [x] Global `emergency_audit.jsonl` with embedded proxy info (survives log dir deletion)

**Tests:**
- [x] Backend: proxy list endpoint, proxy creation endpoint, incidents aggregation
- [x] Frontend: proxy list page, detail routing, add modal (pre-existing), incidents filtering, useIncidents hook

---

## Phase 5.5: Additional Features

**Status: Complete**

Additional features implemented after Phase 5 completion.

### Backend HTTP Authentication

- [x] **Keychain-based API key storage**
  - `BackendCredentialStorage` class in `security/credential_storage.py`
  - Stores API keys in OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Locker)
  - Key format: `mcp-acp:proxy:{proxy_name}:backend`
  - Fallback to encrypted file storage (Fernet AES-128-CBC)

- [x] **HTTP client factory with auth headers**
  - `create_httpx_client_factory()` in `utils/transport.py`
  - `_load_backend_credential()` retrieves API keys from keychain
  - Bearer token authentication for HTTP backend connections
  - Auth headers merged with User-Agent for all requests

### Auth Sessions Management

- [x] **CLI auth sessions command**
  - `mcp-acp auth sessions list --proxy <name>` - list active sessions
  - Shows session_id, user_id, timestamps
  - Refactored from standalone `sessions` command to `auth` subcommand

- [x] **Auth API endpoints** (proxy-level `/api/auth/*`)
  - `GET /api/auth/status` - check auth status with user info
  - `POST /api/auth/login` - start device flow authentication
  - `GET /api/auth/login/poll` - poll for device flow completion
  - `POST /api/auth/logout` - clear local keychain credentials
  - `POST /api/auth/logout-federated` - get Auth0 logout URL
  - `POST /api/auth/notify-login` - CLI notifies proxy of login
  - `GET /api/auth-sessions` - list active authentication sessions

- [x] **Manager auth endpoints** (`/api/manager/auth/*`)
  - `POST /api/manager/auth/reload` - reload tokens and broadcast to proxies
  - `POST /api/manager/auth/clear` - clear tokens and notify proxies
  - `GET /api/manager/auth/status` - get auth status from manager
  - `POST /api/manager/auth/login` - start device flow with SSE-driven completion (background poller)
  - `POST /api/manager/auth/logout` - clear tokens from storage and notify proxies
  - `POST /api/manager/auth/logout-federated` - clear tokens and return Auth0 logout URL

- [x] **Web UI auth migrated to manager endpoints**
  - Login/logout works without a running proxy (manager handles device flow)
  - SSE `auth_login` / `auth_login_failed` events replace client-side polling
  - `useDeviceFlow` hook listens for SSE custom events instead of polling `/auth/login/poll`
  - Identity provider wired to manager client for token distribution to proxies

### Audit Integrity UI

- [x] **Manager audit API endpoints** (`/api/manager/proxies/{proxy_id}/audit/*`)
  - `GET /{proxy_id}/audit/status` - get audit log file status
  - `GET /{proxy_id}/audit/verify` - verify hash chain integrity
  - `POST /{proxy_id}/audit/repair` - repair broken integrity state

- [x] **Web UI audit section** (`web/src/components/detail/AuditIntegritySection.tsx`)
  - Hash chain integrity section on proxy detail page
  - Visual status indicators: protected (green), unprotected (gray), broken (red)
  - File-by-file status display with entry counts
  - Verify button with spinner feedback
  - Repair button with confirmation dialog
  - Real-time updates on proxy connect/disconnect (SSE-driven)

- [x] **API schemas** (`api/schemas/audit.py`)
  - `AuditVerifyResponse`, `AuditFileResult` (unified status + verify)
  - `AuditRepairResponse`, `AuditRepairResult`

### Live Stats on Proxy Cards

- [x] **Real-time stats updates**
  - Proxy cards display live stats: requests total, proxy latency
  - SSE events include `proxy_id` for stable identification
  - Stats updated via `stats_updated` event

---

## Phase 6: Backend Credential Security

**Status: Complete**

Backend credentials (API keys for HTTP backends) are securely stored in OS keychain.

**Implemented:**
- [x] `BackendCredentialStorage` class stores credentials in OS keychain
- [x] Key format: `proxy:{proxy_name}:backend` (per-proxy isolation)
- [x] Config files store only a reference key (`credential_key`), never the actual secret
- [x] Runtime loads credential from keychain and adds `Authorization: Bearer` header
- [x] CLI commands: `proxy add --api-key`, `proxy auth set-key`, `proxy auth remove-key`

**Current limitations (documented in roadmap.md):**
- mTLS private keys must be unencrypted (passphrase support deferred)
- OIDC uses public clients only (confidential client support deferred)
- Audit log HMAC protection deferred (hash chain is self-attesting)

**Note:** Original Phase 6 design proposed per-proxy encryption keys and spawn-time key injection. This was superseded by direct keychain storage, which provides equivalent security with simpler architecture. Manager cannot inject keys at spawn time anyway (Claude Desktop owns proxy lifecycle in STDIO mode). Spawn-time key injection was designed for future HTTP client mode where manager owns proxy lifecycle. mTLS keys intentionally kept as file paths (not imported to keychain) because cert rotation would break and original files still exist on disk anyway .

---

## Phase 7: Proxy Deletion

**Status: Complete**

Proxy deletion with audit trail preservation, unified archive, and recovery support.

- [x] **Shared deletion module** (`manager/deletion.py`)
  - `DeleteResult` / `PurgeResult` frozen slotted dataclasses
  - `get_archive_dir()`, `get_archived_proxy_dir()`, `list_archived_proxies()`
  - `delete_proxy(name, purge, deleted_by)` — shared by CLI and API
  - `purge_archived_proxy(archive_name)` — permanent deletion
  - `format_size()` deduplicated to `utils/file_helpers.py` (shared by deletion, CLI logs, CLI proxy)

- [x] **Soft delete (archive)**
  - Callers check running status before calling (CLI checks socket, API checks registry)
  - Archive config dir → `archive/{name}_{ts}/config/`
  - Archive audit + system log subdirs → `archive/{name}_{ts}/logs/`
  - Archive log-dir root files: `.integrity_state`, `.last_crash`, `shutdowns.jsonl`
  - Delete debug logs (no security value), socket file
  - Remove backend credential from keychain (tracked in metadata; non-recoverable)
  - Write `metadata.json` (machine-readable manifest with actual state)
  - Write `README.txt` (conditional content listing actual archived files)
  - Config dir removal deferred until after metadata is safely written

- [x] **Purge command**
  - `mcp-acp proxy purge <name>` — accepts proxy name (disambiguation) or full archive name
  - Confirmation prompt before deletion
  - `mcp-acp proxy delete <name> --purge` — direct hard delete

- [x] **List deleted proxies**
  - `mcp-acp proxy list --deleted`

- [x] **Manager notification**
  - `PROXY_DELETED` added to `SSEEventType` enum
  - CLI notifies manager via HTTP POST to `/api/manager/proxies/notify-deleted` (fire-and-forget, matches `auth/notify-login` pattern)
  - API deletion broadcasts SSE directly (best-effort, wrapped in try/except)
  - Manager logs deletion at WARNING level (persists to `system.jsonl`)
  - UI proxy list removes card on `proxy_deleted` SSE event
  - UI proxy detail page navigates to `/` with toast if viewing deleted proxy (cross-tab safe)

- [x] **Delete safety checks**
  - CLI: socket connect check before deletion, `OSError` catch around deletion
  - API: registry check, returns 409 if running
  - Confirmation dialog reminds user to update client config

- [x] **UI delete flow**
  - Delete button on proxy detail header (disabled when running, tooltip explains why)
  - `DeleteProxyConfirmDialog` with archive vs delete summary + client config reminder
  - `DELETE /api/manager/proxies/{proxy_id}` endpoint (with `?purge=true` option)
  - Frontend `deleteProxy()` supports purge parameter
  - `ApiError` type narrowing surfaces server error messages
  - After deletion: success toast + navigate to proxy list

- [x] **CLI refactored to subpackage**
  - `cli/commands/proxy.py` split into `proxy/` subpackage: `__init__.py`, `add.py`, `auth.py`, `delete.py`, `list_cmd.py`, `purge.py`

- [x] **Edge cases**
  - Timestamp in folder name prevents collisions
  - Config dir removal deferred until metadata safely written
  - Manager not running during CLI delete: proceeds without SSE broadcast
  - SSE broadcast failure doesn't affect deletion success (API returns 200)

- [x] **Tests**
  - `test_deletion.py`: archive structure, metadata.json, purge, empty archive cleanup
  - `test_routes.py`: DELETE endpoint (200, 404, 409), POST notify-deleted (200, validation)
  - `test_proxy_commands.py`: updated for subpackage imports

---

## Phase 8: Stability & Polish

**Status: Complete**

Toast notifications, crash handling, and integration tests.

- [x] **Toast notification system**
  - Info (grey, 4s): Backend connected, proxy registered
  - Success (green, 3s): Reconnected, config saved, policy reloaded
  - Warning (orange, 6s): Reconnection timeout, certificate expiring
  - Error (red, 8s): Connection errors, TLS errors
  - Critical (red, 15s): Security shutdowns auto-dismiss after 15 seconds
  - Implementation: `web/src/components/ui/sonner.tsx` with automatic durations per type

- [x] **Error boundary**
  - React error boundary catches component rendering errors
  - Shows fallback UI with error details
  - Provides "Try Again" and "Reload Page" buttons
  - Implementation: `web/src/components/ErrorBoundary.tsx`

- [x] **Critical toast behavior**
  - [x] Auto-dismisses after 15 seconds (previously persistent)
  - [x] Plays error sound (triple beep 880Hz)
  - Only triggered by security shutdowns — modal display not needed

- [x] **Proxy identification in osascript popups**
  - HITL approval dialogs include proxy name for multi-proxy clarity
  - Security shutdown popups include proxy name
  - Implementation: `pep/hitl.py`, `security/shutdown.py`

- [x] **Policy reload CLI hardening**
  - Friendly warning when proxy is not running (instead of raw connection error)

- [x] **Pending approvals SSE-managed state**
  - Proxy detail page uses SSE-managed state for pending approvals (instead of REST polling)

- [x] **Proxy add next-steps snippet**
  - Resolves full executable path (consistent with `install mcp-json`)

- [x] **Proxy disconnect handling (UI survives)**
  - [x] UI detects proxy deregistration/disconnect
  - [x] Update proxy status to "disconnected"
  - [x] Manager enriches disconnect event with crash reason from `shutdowns.jsonl`
    - `_read_recent_shutdown()` reads last entry, checks if within 30s
    - `deregister()` includes `disconnect_reason` in SSE event payload
    - Implementation: `src/mcp_acp/manager/registry.py`
  - [x] UI shows contextual toast based on disconnect reason
    - Crash: error toast with reason + error sound
    - Normal: info toast with proxy name
    - Implementation: `web/src/context/AppStateContext.tsx`

- [x] **Tests**
  - [x] Frontend: proxy list, detail routing, add modal flow, incidents filtering (Phase 5)
  - [x] Frontend: disconnect enrichment toast mapping (Phase 8)
    - tests: crash toast, normal toast, error sound, fallback message, window events
    - Implementation: `web/src/__tests__/context/AppStateDisconnect.test.tsx`
  - [x] Backend: disconnect enrichment (Phase 8)
    - tests: `_read_last_line`, `_read_recent_shutdown` (recent/old/missing/malformed/empty), `deregister()` enrichment
    - Implementation: `tests/manager/test_disconnect.py`
  - [x] Integration: FastMCP Client end-to-end proxy tests
    - 10 test scenarios covering: discovery, allow, deny, zero-trust default, deny-overrides, path-based deny, selective allow, audit operations, audit denials
    - Implementation: `tests/integration/test_proxy_e2e.py`

---

## Phase 9: Performance Metrics (POC)

**Status: Complete**

Feasibility measurement for UI display and thesis evaluation. Tracks three metrics:
1. **Policy decision latency** - Time added by per-request policy evaluation
2. **HITL overhead** - Additional delay when human approval is required
3. **Total proxy overhead** - End-to-end time through proxy (feasibility indicator)

### Step 9.1: LatencyTracker Implementation

- [x] **LatencyTracker class** (`manager/latency.py`)
  - Circular buffer for recent N samples (`LATENCY_BUFFER_SIZE = 1000` in constants.py)
  - Compute median on read (O(n log n) sort acceptable for small N and low MCP request rates)
  - Thread-safe for async context (cooperative asyncio model)
  - Three tracker instances:
    - `proxy_latency`: Total request time through proxy (includes backend)
    - `policy_eval`: Policy evaluation time only
    - `hitl_wait`: HITL wait time only

- [x] **Integration in ProxyState**
  - Add `LatencyTrackers` as field in `ProxyState.__init__()`
  - Keeps all stats together (request counts + latency)
  - API reads from single source
  - SSE emission handled consistently

- [x] **Extend `record_decision()` signature**
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

- [x] **Middleware updates**
  - Pass timing to `record_decision()` from each handler
  - `proxy_latency`: Measure total time in ContextMiddleware via `set_proxy_state()`
    - Established pattern: enforcement, shutdown_coordinator, identity_provider, policy_reloader all use it
    - ProxyState created after middleware (chicken-and-egg) so setter injection is required
    - Wire at proxy.py alongside existing `enforcement_middleware.set_proxy_state(proxy_state)`
  - Rate limiter (outermost) is excluded from timing — adds ~0ms for non-throttled requests,
    and throttle delay is intentional, not proxy overhead
  - Timing data already captured: `eval_duration_ms`, `hitl_result.response_time_ms`

- [x] **Latency filtering decisions** (what gets recorded):
  - **Exclude denied requests** from `proxy_latency`: denials never reach the backend,
    so their timing doesn't represent "overhead added to a proxied request." Including
    them would lower the median with fast-path denials that don't reflect real overhead.
    Policy eval time for denials is still recorded in `policy_eval` tracker.
  - **Exclude discovery requests** from `proxy_latency`: discovery (`tools/list`) bypasses
    the policy engine entirely, so it has a fundamentally different overhead profile.
    The benchmark script measures discovery overhead separately.
  - **Exclude backend errors/timeouts**: skew median with values unrelated to proxy overhead.
  - **Exclude HITL-approved requests** from `proxy_latency`: human wait time (seconds) would
    dominate the metric. HITL wait is tracked separately in `hitl_wait`. Uses ContextVar flag
    (`_hitl_resolved_var`) set by enforcement middleware, read by ContextMiddleware.

- [x] **Create `/api/stats` endpoint** (fixes existing bug)
  - Manager's `listing.py:82` already calls `GET /api/stats` on each proxy via UDS,
    but no such route exists — the call 404s silently and stats show as `-` on proxy cards.
  - Create lightweight endpoint returning stats + latency data.

- [x] **Log parser** (`scripts/parse_latency_logs.py`)
  - Parse audit logs for `policy_eval_ms`, `policy_hitl_ms`, `policy_total_ms`
  - Aggregate into median, std dev, min, max, sample count
  - Supports filtering by date prefix (`--date 2025-01-15`)
  - JSON output (`--output results.json`)

### Step 9.2: API and UI

- [x] **`/api/stats` response schema**
  ```json
  {
    "requests_total": 1234,
    "requests_allowed": 1100,
    "requests_denied": 50,
    "requests_hitl": 84,
    "latency": {
      "proxy_latency_ms": 45.2,
      "policy_eval_ms": 2.1,
      "hitl_wait_ms": 8500.0
    }
  }
  ```

- [x] **UI display**
  - Proxy list cards show median proxy latency ("~14ms" or "–" when no samples)
  - Proxy cards streamlined to 2 stats: Requests count + Latency
  - `proxy_latency_ms` field added to `ProxyStats` model (backend + TypeScript)
  - Manager forwards latency from proxy `/api/stats` via `_parse_proxy_stats()` helper (DRY)
  - `StatsResponse` schema updated to include `proxy_latency_ms` (fixes SSE snapshot path)
  - `get_stats()` uses `LatencyTracker.median()` directly (not `to_dict()["median_ms"]`)

### Step 9.3: Thesis Measurement Scripts

Standalone measurement script for proxy overhead comparison.
This is **feasibility measurement**, not performance benchmarking — proving the proxy doesn't add unacceptable latency.

- [x] **Echo backend** (`scripts/echo_server.py`)
  - Minimal FastMCP server with single echo tool
  - Supports STDIO (default) and HTTP mode (`--http --port 8765`)

- [x] **Measurement script** (`scripts/measure_overhead.py`)
  - Completely standalone — not part of proxy, not in test suite
  - Uses FastMCP `Client` with `StdioTransport` (subprocess-based, reflects real deployment)
  - Supports both STDIO (`--backend-cmd`) and HTTP (`--backend-url`) backend scenarios
  - Measures discovery and tool calls separately (different code paths)
  - External client-side stopwatch: `time.perf_counter()` around `call_tool()` / `list_tools()`
  - Warmup phase (default: 10 requests), configurable runs (default: 100)
  - JSON output (`--output results.json`)
  - Full measurement plan: `docs/performance/performance-measurement-plan.md`

- [x] **Standalone measurement results** (6 tests, documented in `docs/performance/`)
  - Echo STDIO (allow-all): ~15ms tool call overhead
  - Echo HTTP (allow-all): ~111ms tool call overhead
  - Filesystem STDIO (allow-all): ~12ms tool call overhead
  - Filesystem STDIO (4-rule restrictive): ~16ms tool call overhead
  - Filesystem HTTP (allow-all): ~138ms tool call overhead
  - Filesystem HTTP (4-rule restrictive): ~127ms tool call overhead
  - Filesystem STDIO (50-rule mixed): ~11ms tool call overhead (policy scaling test)
  - Results: `scripts/results/results_*.json`
  - Documentation: `docs/performance/measurement-results.md`, `docs/performance/performance-documentation.md`
  - Limitation documented: only allowed paths measured; denied/HITL paths are future work

- [x] **Tests** (unit + API)
  - **Unit tests** (CI, deterministic):
    - `tests/manager/test_latency.py`: 14 LatencyTracker tests — buffer, median, edge cases (empty, single, wrapping), min/max, to_dict serialization
    - `tests/manager/test_stats.py`: 8 ProxyState latency integration tests — record_decision with eval_ms/hitl_ms, record_proxy_latency, get_latency response shape
  - **API tests** (CI, deterministic):
    - `tests/api/test_stats.py`: 6 endpoint tests — 200 OK, counter fields, latency fields, null latency when no samples, response shape, 503 when ProxyState unavailable
  - **Measurement script** (`scripts/measure_overhead.py`, manual run):
    - Uses `StdioTransport` for real subprocess-based measurement
    - Run manually, not CI
    - Produces thesis feasibility numbers

---

## Stage 3 Completion Criteria

- [x] Audit logs protected by hash chain with between-run verification (Phase 1)
- [x] Manager daemon serves UI and observes proxies (Phase 3)
- [x] Multiple STDIO proxies can register with manager (Phase 4 Steps 1-3)
- [x] CLI commands for proxy configuration (Phase 4 Step 2)
- [x] CLI fully functional for multi-proxy testing (Phase 4 Complete)
- [x] Auth commands read OIDC from manager.json (Phase 4 Step 4 partial)
- [x] Full manager-owned auth lifecycle with token distribution (Phase 4 Step 4)
- [x] UI updated for multi-proxy observation (Phase 5)
- [x] Backend credential security via OS keychain (Phase 6)
- [x] Proxy deletion with audit trail preservation (Phase 7)
- [x] Toast notifications for proxy events (Phase 8)
- [x] Proxy disconnect crash reason in UI (Phase 8)
- [x] Frontend test coverage: proxy list, detail, incidents, hooks (Phase 5)
- [x] Disconnect enrichment test coverage: backend (16 tests) + frontend (7 tests) (Phase 8)
- [x] Integration tests: FastMCP Client end-to-end proxy tests (Phase 8)
- [x] Basic performance metrics displayed in UI (Phase 9)

---

## Out of Scope (Future Work)

### HTTP Client Mode

See [docs/design/http-client-mode.md](docs/design/http-client-mode.md) for:
- HTTP clients (ChatGPT, custom apps) connecting through manager
- Manager-owned proxy lifecycle (lazy spawn, idle shutdown)
- Manager as reverse proxy
- OIDC/mTLS authentication for HTTP clients
