// TypeScript types matching backend Pydantic models

export interface ProxyStats {
  requests_total: number
  requests_allowed: number
  requests_denied: number
  requests_hitl: number
}

/** Transport type for proxy configuration */
export type TransportType = 'stdio' | 'streamablehttp' | 'auto'

/** Proxy info from manager's /api/manager/proxies endpoint */
export interface Proxy {
  proxy_name: string
  proxy_id: string
  status: 'running' | 'inactive'
  instance_id: string | null
  server_name: string
  transport: TransportType
  command: string | null
  args: string[] | null
  url: string | null
  created_at: string
  /** Actual backend transport in use (resolved from 'auto' if needed) */
  backend_transport: 'stdio' | 'streamablehttp'
  /** Whether mTLS is enabled for backend connection */
  mtls_enabled: boolean
  stats: ProxyStats | null
}

/** Full proxy detail from GET /api/manager/proxies/{proxy_id} */
export interface ProxyDetailResponse extends Proxy {
  client_id: string | null
  pending_approvals: PendingApproval[] | null
  cached_approvals: CachedApproval[] | null
}

/** Request to create a new proxy via POST /api/manager/proxies */
export interface CreateProxyRequest {
  name: string
  server_name: string
  transport: TransportType
  // STDIO options
  command?: string
  args?: string[]
  // STDIO attestation
  attestation_slsa_owner?: string
  attestation_sha256?: string
  attestation_require_signature?: boolean
  // HTTP options
  url?: string
  timeout?: number
  api_key?: string
  // mTLS options
  mtls_cert?: string
  mtls_key?: string
  mtls_ca?: string
  // Health check override
  skip_health_check?: boolean
}

/** Response from POST /api/manager/proxies */
export interface CreateProxyResponse {
  ok: boolean
  proxy_name: string
  proxy_id: string | null
  config_path: string | null
  policy_path: string | null
  claude_desktop_snippet: Record<string, { command: string; args: string[] }> | null
  message: string
}

/** Response from DELETE /api/manager/proxies/{proxy_id} */
export interface ProxyDeleteResponse {
  archived: string[]
  deleted: string[]
  archive_name: string | null
  archived_size: number
  deleted_size: number
}

/** Response from GET /api/manager/config-snippet */
export interface ConfigSnippetResponse {
  mcpServers: Record<string, { command: string; args: string[] }>
  executable_path: string
}

/** Aggregated incidents response from GET /api/manager/incidents */
export interface AggregatedIncidentsResponse {
  entries: IncidentEntry[]
  total_returned: number
  has_more: boolean
  filters_applied: {
    time_range: string
    proxy?: string
    incident_type?: string
  }
}

/** Single incident entry with type annotation */
export interface IncidentEntry {
  time: string
  incident_type: 'shutdown' | 'bootstrap' | 'emergency'
  proxy_name?: string
  proxy_id?: string
  message?: string
  event?: string
  [key: string]: unknown
}

export interface PendingApproval {
  id: string
  proxy_id: string
  tool_name: string
  path: string | null
  subject_id: string
  created_at: string
  timeout_seconds: number
  request_id: string
  can_cache: boolean
  cache_ttl_seconds: number | null
}

export interface CachedApproval {
  subject_id: string
  tool_name: string
  path: string | null
  request_id: string
  age_seconds: number
  ttl_seconds: number
  expires_in_seconds: number
}

export interface ProxyStatus {
  running: boolean
  uptime_seconds: number
  policy_version: string | null
  policy_rules_count: number
  last_reload_at: string | null
  reload_count: number
}

export interface LogEntry {
  time?: string
  timestamp?: string
  [key: string]: unknown
}

export interface LogsResponse {
  entries: LogEntry[]
  total_returned: number
  total_scanned: number
  log_file: string
  has_more: boolean
  filters_applied: Record<string, unknown>
}

export interface BackupFileInfo {
  filename: string
  path: string
  size_bytes: number
  timestamp: string
}

export interface LogFileInfo {
  name: string
  path: string
  exists: boolean
  size_bytes: number | null
  backups: BackupFileInfo[]
}

export interface LogFolderInfo {
  name: string
  files: LogFileInfo[]
}

export interface LogsMetadataResponse {
  folders: LogFolderInfo[]
  debug_enabled: boolean
  available_policy_versions: string[]
  available_config_versions: string[]
}

// Severity levels for toast styling
export type EventSeverity = 'success' | 'warning' | 'error' | 'critical' | 'info'

// Base fields for system events
interface SSESystemEventBase {
  severity?: EventSeverity
  message?: string
  details?: string
  proxy_id?: string
  timestamp?: string
  error_type?: string
}

// HITL Approval Events (discriminated union)
export interface SSESnapshotEvent {
  type: 'snapshot'
  approvals: PendingApproval[]
  proxy_id?: string
  proxy_name?: string
}

export interface SSEPendingCreatedEvent {
  type: 'pending_created'
  approval: PendingApproval
}

export interface SSEPendingResolvedEvent {
  type: 'pending_resolved'
  approval_id: string
  decision: 'allow' | 'deny'
}

export interface SSEPendingTimeoutEvent {
  type: 'pending_timeout'
  approval_id: string
}

export interface SSEPendingNotFoundEvent extends SSESystemEventBase {
  type: 'pending_not_found'
  approval_id?: string
}

// Policy Events
export interface SSEPolicyReloadedEvent extends SSESystemEventBase {
  type: 'policy_reloaded'
  old_rules_count?: number
  new_rules_count?: number
  approvals_cleared?: number
  policy_version?: string
}

export interface SSEPolicyRollbackEvent extends SSESystemEventBase {
  type: 'policy_rollback'
}

export interface SSEPolicyErrorEvent extends SSESystemEventBase {
  type: 'policy_reload_failed' | 'policy_file_not_found' | 'config_change_detected'
}

// Rate Limiting Events
export interface SSERateLimitEvent extends SSESystemEventBase {
  type: 'rate_limit_triggered' | 'rate_limit_approved' | 'rate_limit_denied'
  tool_name?: string
  count?: number
  threshold?: number
}

// Cache Events
export interface SSECacheEvent extends SSESystemEventBase {
  type: 'cache_cleared' | 'cache_entry_deleted'
  count?: number
}

// Cached approvals snapshot (full state update via SSE)
export interface SSECachedSnapshotEvent {
  type: 'cached_snapshot'
  approvals: CachedApproval[]
  ttl_seconds: number
  count?: number
  proxy_id?: string
  proxy_name?: string
}

// Backend Connection Events
export interface SSEBackendEvent extends SSESystemEventBase {
  type: 'backend_connected' | 'backend_reconnected' | 'backend_disconnected' | 'backend_timeout' | 'backend_refused'
  method?: string
}

// TLS Events
export interface SSETLSEvent extends SSESystemEventBase {
  type: 'tls_error' | 'mtls_failed' | 'cert_validation_failed'
}

// Auth Events
export interface SSEAuthEvent extends SSESystemEventBase {
  type: 'auth_login' | 'auth_logout' | 'auth_login_failed' | 'auth_session_expiring' | 'token_refresh_failed' | 'token_validation_failed' | 'auth_failure'
  reason?: string  // for auth_login_failed: 'expired', 'denied', 'error'
}

// Request Processing Events
export interface SSERequestEvent extends SSESystemEventBase {
  type: 'request_error' | 'hitl_parse_failed' | 'tool_sanitization_failed'
}

// Critical Events
export interface SSECriticalEvent extends SSESystemEventBase {
  type: 'critical_shutdown' | 'audit_init_failed' | 'device_health_failed' | 'session_hijacking' | 'audit_tampering' | 'audit_missing' | 'audit_permission_denied' | 'health_degraded' | 'health_monitor_failed'
}

// Live Update Events
export interface SSEStatsUpdatedEvent extends SSESystemEventBase {
  type: 'stats_updated'
  stats: ProxyStats
  proxy_id?: string
  proxy_name?: string  // Added by manager when forwarding proxy events
}

export interface SSENewLogEntriesEvent extends SSESystemEventBase {
  type: 'new_log_entries'
  count?: number
}

export interface SSEIncidentsUpdatedEvent extends SSESystemEventBase {
  type: 'incidents_updated'
  trigger_event?: string
}

// Proxy Registration Events (from manager)
export interface SSEProxyRegisteredEvent extends SSESystemEventBase {
  type: 'proxy_registered'
  proxy_name?: string
  proxy_id?: string
  instance_id?: string
}

export interface SSEProxyDisconnectedEvent extends SSESystemEventBase {
  type: 'proxy_disconnected'
  proxy_name?: string
  proxy_id?: string
  instance_id?: string
}

export interface SSEProxyDeletedEvent extends SSESystemEventBase {
  type: 'proxy_deleted'
  proxy_name?: string
  proxy_id?: string
  archive_name?: string
}

// System events (extend SSESystemEventBase, have severity/message)
export type SSESystemEvent =
  | SSEPendingNotFoundEvent
  | SSEPolicyReloadedEvent
  | SSEPolicyRollbackEvent
  | SSEPolicyErrorEvent
  | SSERateLimitEvent
  | SSECacheEvent
  | SSEBackendEvent
  | SSETLSEvent
  | SSEAuthEvent
  | SSERequestEvent
  | SSECriticalEvent
  | SSEStatsUpdatedEvent
  | SSENewLogEntriesEvent
  | SSEIncidentsUpdatedEvent
  | SSEProxyRegisteredEvent
  | SSEProxyDisconnectedEvent
  | SSEProxyDeletedEvent

// Discriminated union of all SSE event types
export type SSEEvent =
  | SSESnapshotEvent
  | SSECachedSnapshotEvent
  | SSEPendingCreatedEvent
  | SSEPendingResolvedEvent
  | SSEPendingTimeoutEvent
  | SSESystemEvent

// Type helper to extract event type strings
export type SSEEventType = SSEEvent['type']

// Error codes for programmatic handling (matching backend ErrorCode enum)
export const ErrorCode = {
  // Authentication (401, 403)
  AUTH_REQUIRED: 'AUTH_REQUIRED',
  AUTH_FORBIDDEN: 'AUTH_FORBIDDEN',
  AUTH_PROVIDER_UNAVAILABLE: 'AUTH_PROVIDER_UNAVAILABLE',
  AUTH_DEVICE_FLOW_FAILED: 'AUTH_DEVICE_FLOW_FAILED',
  AUTH_DEVICE_FLOW_LIMIT: 'AUTH_DEVICE_FLOW_LIMIT',

  // Approvals (403, 404)
  APPROVAL_NOT_FOUND: 'APPROVAL_NOT_FOUND',
  APPROVAL_UNAUTHORIZED: 'APPROVAL_UNAUTHORIZED',
  CACHED_APPROVAL_NOT_FOUND: 'CACHED_APPROVAL_NOT_FOUND',

  // Policy (400, 404, 409, 500)
  POLICY_NOT_FOUND: 'POLICY_NOT_FOUND',
  POLICY_INVALID: 'POLICY_INVALID',
  POLICY_RULE_NOT_FOUND: 'POLICY_RULE_NOT_FOUND',
  POLICY_RULE_DUPLICATE: 'POLICY_RULE_DUPLICATE',
  POLICY_RELOAD_FAILED: 'POLICY_RELOAD_FAILED',

  // Config (400, 404, 500)
  CONFIG_NOT_FOUND: 'CONFIG_NOT_FOUND',
  CONFIG_INVALID: 'CONFIG_INVALID',
  CONFIG_SAVE_FAILED: 'CONFIG_SAVE_FAILED',

  // Resources (404)
  PROXY_NOT_FOUND: 'PROXY_NOT_FOUND',
  LOG_NOT_AVAILABLE: 'LOG_NOT_AVAILABLE',
  NOT_FOUND: 'NOT_FOUND', // Generic 404

  // Conflict (409)
  CONFLICT: 'CONFLICT', // Generic 409
  PROXY_EXISTS: 'PROXY_EXISTS', // Proxy already exists
  PROXY_RUNNING: 'PROXY_RUNNING', // Proxy is running, cannot delete

  // Proxy creation (400, 500)
  PROXY_INVALID: 'PROXY_INVALID', // Invalid proxy configuration
  BACKEND_UNREACHABLE: 'BACKEND_UNREACHABLE', // Backend not reachable (non-fatal)
  PROXY_CREATION_FAILED: 'PROXY_CREATION_FAILED', // Failed to create proxy

  // Validation (400, 422)
  VALIDATION_ERROR: 'VALIDATION_ERROR',

  // Internal (500, 501, 502, 503)
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  NOT_IMPLEMENTED: 'NOT_IMPLEMENTED',
  UPSTREAM_ERROR: 'UPSTREAM_ERROR',
  SERVICE_UNAVAILABLE: 'SERVICE_UNAVAILABLE',
} as const

export type ErrorCodeType = (typeof ErrorCode)[keyof typeof ErrorCode]

// Validation error item from Pydantic
export interface ValidationErrorItem {
  loc: (string | number)[]
  msg: string
  type: string
}

// Structured error detail from backend
export interface ErrorDetail {
  code: string
  message: string
  details?: Record<string, unknown>
  validation_errors?: ValidationErrorItem[]
}

// API Error with structured error support
export class ApiError extends Error {
  /** Error code for programmatic handling (e.g., 'APPROVAL_NOT_FOUND') */
  public code: string | null = null
  /** Contextual details from the error response */
  public details: Record<string, unknown> | null = null
  /** Validation errors for 422 responses */
  public validationErrors: ValidationErrorItem[] | null = null

  constructor(
    public status: number,
    public statusText: string,
    message?: string,
    errorDetail?: ErrorDetail
  ) {
    super(message || `API Error: ${status} ${statusText}`)
    this.name = 'ApiError'

    if (errorDetail) {
      this.code = errorDetail.code
      this.details = errorDetail.details ?? null
      this.validationErrors = errorDetail.validation_errors ?? null
    }
  }

  /** Check if this error has a specific error code */
  hasCode(code: ErrorCodeType): boolean {
    return this.code === code
  }

  /** Get detail value by key */
  getDetail<T>(key: string): T | undefined {
    return this.details?.[key] as T | undefined
  }
}

// Policy types

/** Effect type for policy rules */
export type PolicyEffect = 'allow' | 'deny' | 'hitl'

/** Resource type for matching */
export type PolicyResourceType = 'tool' | 'resource' | 'prompt' | 'server'

/** Operations that can be matched */
export type PolicyOperation = 'read' | 'write' | 'delete' | 'execute' | 'create' | 'update' | 'list' | 'invoke'

/** Side effects that can be used in policy conditions and cache settings */
export type PolicySideEffect =
  | 'fs_read'
  | 'fs_write'
  | 'db_read'
  | 'db_write'
  | 'network_egress'
  | 'network_ingress'
  | 'code_exec'
  | 'process_spawn'
  | 'sudo_elevate'
  | 'secrets_read'
  | 'env_read'
  | 'keychain_read'
  | 'clipboard_read'
  | 'clipboard_write'
  | 'browser_open'
  | 'screen_capture'
  | 'audio_capture'
  | 'camera_capture'
  | 'cloud_api'
  | 'container_exec'
  | 'email_send'

/** Conditions for matching a policy rule */
export interface PolicyRuleConditions {
  tool_name?: string | string[]
  path_pattern?: string | string[]
  source_path?: string | string[]
  dest_path?: string | string[]
  extension?: string | string[]
  scheme?: string | string[]
  backend_id?: string | string[]
  resource_type?: PolicyResourceType
  mcp_method?: string | string[]
  subject_id?: string | string[]
  operations?: string[]
  side_effects?: PolicySideEffect[]
}

/** HITL configuration
 * Note: cache_side_effects has moved to per-rule policy configuration.
 */
export interface HITLConfig {
  timeout_seconds: number
  default_on_timeout: 'deny'
  approval_ttl_seconds: number
}

/** Policy rule from API response */
export interface PolicyRuleResponse {
  id: string | null
  effect: PolicyEffect
  conditions: PolicyRuleConditions
  description: string | null
  /** Side effects that allow approval caching (HITL rules only) */
  cache_side_effects?: PolicySideEffect[] | null
}

/** Policy rule for create/update requests */
export interface PolicyRuleCreate {
  id?: string
  description?: string
  effect: PolicyEffect
  conditions: PolicyRuleConditions
  /** Side effects that allow approval caching (HITL rules only) */
  cache_side_effects?: PolicySideEffect[] | null
}

/** Full policy response from GET /api/policy
 * Note: HITL configuration is in ConfigResponse (GET /api/config), not here.
 */
export interface PolicyResponse {
  version: string
  default_action: 'deny'
  rules_count: number
  rules: PolicyRuleResponse[]
  policy_version: string | null
  policy_path: string
}

/** Response after creating/updating a rule */
export interface PolicyRuleMutationResponse {
  rule: PolicyRuleResponse
  policy_version: string | null
  rules_count: number
}

/** Policy schema with valid field values */
export interface PolicySchemaResponse {
  operations: string[]
}

/** Full policy update request for PUT /api/policy
 * Note: HITL configuration is managed via /api/config, not here.
 */
export interface PolicyFullUpdate {
  version?: string
  default_action?: 'deny'
  rules: PolicyRuleCreate[]
}
