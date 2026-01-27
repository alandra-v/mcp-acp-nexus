import { apiGet, apiPut, type RequestOptions } from './client'

// =============================================================================
// Response Types
// =============================================================================

export interface StdioTransportConfig {
  command: string
  args: string[]
}

export interface HttpTransportConfig {
  url: string
  timeout: number
  /** Keychain reference for API key (if configured). The actual key is never exposed. */
  credential_key: string | null
}

export type TransportType = 'stdio' | 'streamablehttp' | 'auto'

export interface BackendConfig {
  server_name: string
  transport: TransportType | null
  stdio: StdioTransportConfig | null
  http: HttpTransportConfig | null
}

export interface LoggingConfig {
  log_dir: string
  log_level: string
  include_payloads: boolean
}

export interface OIDCConfig {
  issuer: string
  client_id: string
  audience: string
  scopes: string[]
}

export interface MTLSConfig {
  client_cert_path: string
  client_key_path: string
  ca_bundle_path: string
}

export interface AuthConfig {
  oidc: OIDCConfig | null
  mtls: MTLSConfig | null
}

export interface ProxyConfig {
  name: string
}

/** HITL configuration (cache_side_effects moved to per-rule policy) */
export interface HITLConfig {
  timeout_seconds: number
  default_on_timeout: string
  approval_ttl_seconds: number
}

export interface ConfigResponse {
  backend: BackendConfig
  logging: LoggingConfig
  auth: AuthConfig | null
  proxy: ProxyConfig
  hitl: HITLConfig
  config_path: string
  requires_restart_for_changes: boolean
}

export interface ConfigUpdateResponse {
  config: ConfigResponse
  message: string
}

// =============================================================================
// Comparison Types
// =============================================================================

export interface ConfigChange {
  field: string
  running_value: string | number | boolean | string[] | null
  saved_value: string | number | boolean | string[] | null
}

export interface ConfigComparisonResponse {
  running_config: ConfigResponse
  saved_config: ConfigResponse
  has_changes: boolean
  changes: ConfigChange[]
  message: string
}

// =============================================================================
// Update Request Types
// =============================================================================

export interface StdioTransportUpdate {
  command?: string
  args?: string[]
}

export interface HttpTransportUpdate {
  url?: string
  timeout?: number
}

export interface BackendConfigUpdate {
  server_name?: string
  transport?: TransportType
  stdio?: StdioTransportUpdate
  http?: HttpTransportUpdate
}

export interface LoggingConfigUpdate {
  log_dir?: string
  log_level?: string
  include_payloads?: boolean
}

export interface OIDCConfigUpdate {
  issuer?: string
  client_id?: string
  audience?: string
  scopes?: string[]
}

export interface MTLSConfigUpdate {
  client_cert_path?: string
  client_key_path?: string
  ca_bundle_path?: string
}

export interface AuthConfigUpdate {
  oidc?: OIDCConfigUpdate
  mtls?: MTLSConfigUpdate
}

export interface ProxyConfigUpdate {
  name?: string
}

/** HITL update (cache_side_effects moved to per-rule policy) */
export interface HITLConfigUpdate {
  timeout_seconds?: number
  approval_ttl_seconds?: number
}

export interface ConfigUpdateRequest {
  logging?: LoggingConfigUpdate
  backend?: BackendConfigUpdate
  proxy?: ProxyConfigUpdate
  auth?: AuthConfigUpdate
  hitl?: HITLConfigUpdate
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Get current configuration.
 */
export async function getConfig(): Promise<ConfigResponse> {
  return apiGet<ConfigResponse>('/config')
}

/**
 * Update configuration.
 * Only specified fields will be updated.
 * Changes take effect on proxy restart.
 */
export async function updateConfig(
  updates: ConfigUpdateRequest
): Promise<ConfigUpdateResponse> {
  return apiPut<ConfigUpdateResponse>('/config', updates)
}

/**
 * Compare running (in-memory) config with saved (file) config.
 * Returns both configs and a list of differences.
 */
export async function compareConfig(): Promise<ConfigComparisonResponse> {
  return apiGet<ConfigComparisonResponse>('/config/compare')
}

// =============================================================================
// Manager-Level Config API (for accessing config when proxy is not running)
// =============================================================================

/**
 * Get configuration for a specific proxy via manager endpoint.
 * Works regardless of whether the proxy is running.
 *
 * @param proxyId - Stable proxy identifier
 * @param options - Request options with optional abort signal
 * @returns Configuration from disk
 */
export async function getProxyConfig(
  proxyId: string,
  options?: RequestOptions
): Promise<ConfigResponse> {
  return apiGet<ConfigResponse>(`/manager/proxies/${encodeURIComponent(proxyId)}/config`, options)
}

/**
 * Update configuration for a specific proxy via manager endpoint.
 * Saves to disk. Changes take effect on proxy restart.
 *
 * Note: Config comparison is not available at manager level
 * (requires running proxy's in-memory state).
 *
 * @param proxyId - Stable proxy identifier
 * @param updates - Configuration updates to apply
 * @param options - Request options with optional abort signal
 * @returns Updated configuration with message
 */
export async function updateProxyConfig(
  proxyId: string,
  updates: ConfigUpdateRequest,
  options?: RequestOptions
): Promise<ConfigUpdateResponse> {
  return apiPut<ConfigUpdateResponse>(
    `/manager/proxies/${encodeURIComponent(proxyId)}/config`,
    updates,
    options
  )
}
