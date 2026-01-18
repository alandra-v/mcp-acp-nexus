# mcp-acp-nexus Implementation Progress

## Stage 3: Multi-Proxy Architecture

Multi-proxy architecture with manager daemon, credential isolation, and enhanced audit security.

**Scope**: STDIO client mode only. Claude Desktop spawns proxies and owns their lifecycle. Manager observes and coordinates but does not control proxy lifecycle.

**Design Document:** [docs/design/multi.md](docs/design/multi.md)

---

## Phase 1: Audit Log Security

**Status: Not Started**

Hash chain implementation and between-run protection for audit log integrity.

- [ ] **Hash chain implementation**
  - Add `prev_hash` and `sequence` fields to audit entries
  - Compute SHA-256 hash of each entry for next entry to reference
  - Detect deleted/inserted/reordered entries via chain breaks

- [ ] **Between-run protection**
  - Create `.audit_state` file storing last_hash, last_sequence, last_inode
  - Save state after each audit write
  - Verify state on proxy startup (detect file swap between runs)
  - Critical shutdown if verification fails

- [ ] **AuditHealthMonitor enhancement**
  - Add hash chain verification to existing 30s health check loop
  - Trigger shutdown on chain break detection

- [ ] **Verification CLI command**
  - `mcp-acp-nexus audit verify [--proxy <name>]`
  - Validate hash chain integrity
  - Check sequence monotonicity
  - Verify time ordering
  - Report any breaks or anomalies

- [ ] **Tests**
  - Unit tests for hash chain logic
  - Tests for between-run state persistence
  - Tests for tampering detection

---

## Phase 2: Storage Backend Abstraction

**Status: Not Started**

Abstract storage for persistence and future multi-host support using py-key-value-aio.

- [ ] **KeyValueStore interface**
  - Define async interface matching py-key-value-aio
  - `get()`, `set()`, `delete()` with TTL support
  - Key serialization helpers

- [ ] **Refactor ApprovalStore**
  - Accept `KeyValueStore` in constructor
  - Replace in-memory dict with store calls
  - Maintain TTL-based expiration via store TTL

- [ ] **Refactor SessionManager**
  - Accept `KeyValueStore` in constructor
  - Replace in-memory dict with store calls
  - Session serialization/deserialization

- [ ] **MemoryStore implementation**
  - In-memory backend (current behavior)
  - Used for development and single-proxy

- [ ] **DiskStore implementation**
  - File-based persistent storage
  - Survives proxy restarts
  - Used for single-host multi-proxy

- [ ] **Backend selection configuration**
  - Add `storage.backend` to config (memory, disk)
  - Add `storage.path` for disk backend
  - Factory function to create appropriate store

- [ ] **Tests**
  - Unit tests for each store implementation

---

## Phase 3: Manager Introduction

**Status: Not Started**

Manager daemon that serves UI and observes STDIO proxies (does not own lifecycle).

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
  - UI port, auth (shared OIDC), storage backend
  - Separate from per-proxy config

- [ ] **Proxy registration**
  - Proxy connects to manager via UDS on startup
  - Sends: proxy_id, proxy_name, instance_id, config summary
  - Manager tracks registered proxies
  - Proxy deregisters on shutdown (or manager detects disconnect)

- [ ] **UI ownership transfer**
  - Manager serves web UI (not proxy)
  - UI survives proxy restart/crash
  - Proxy status shown in UI (observe only)
  - Config changes show "Restart client to apply" message

- [ ] **Manager CLI commands**
  - `mcp-acp-nexus manager start` - Start manager daemon
  - `mcp-acp-nexus manager stop` - Stop manager daemon
  - `mcp-acp-nexus manager status` - Show manager + all proxies status

- [ ] **Port conflict handling**
  - Clear error if UI port in use
  - Configurable via `ui_port` in manager.json
  - CLI override: `--port`

- [ ] **Tests**
  - Manager lifecycle tests
  - Proxy registration/deregistration tests
  - Auto-start tests

---

## Phase 4: Multi-Proxy Core

**Status: Not Started**

Multiple STDIO proxies registering with manager, with credential isolation.

- [ ] **Per-proxy directory structure**
  ```
  ~/.mcp-acp-nexus/
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
  - `mcp-acp-nexus proxy list` - List all configured proxies
  - `mcp-acp-nexus proxy add [--name, --backend]` - Add new proxy config
  - `mcp-acp-nexus proxy remove <name>` - Remove proxy config
  - `mcp-acp-nexus proxy show <name>` - Show proxy config
  - Note: No start/stop/restart commands (client owns lifecycle)

- [ ] **Per-proxy policy/config commands**
  - `mcp-acp-nexus proxy config <name> show`
  - `mcp-acp-nexus proxy policy <name> show`
  - `mcp-acp-nexus proxy policy <name> reload`

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
  - `mcp-acp-nexus proxy purge <archive_name>` - Permanently delete archived data
  - Confirmation prompt before deletion
  - `mcp-acp-nexus proxy delete <name> --purge` - Direct hard delete

- [ ] **List deleted proxies**
  - `mcp-acp-nexus proxy list --deleted`

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

- [ ] **UI display (StatsSection)**
  - Show requests count and median response time
  - `~` prefix indicates median (typical experience)
  - Example: "Requests: 1,234  Response: ~45ms"

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

- [ ] Audit logs protected by hash chain with between-run verification
- [ ] Storage backends abstracted (memory, disk)
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
