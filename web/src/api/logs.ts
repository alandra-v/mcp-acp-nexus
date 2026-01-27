import { apiGet } from './client'
import type { LogsResponse } from '@/types/api'

/** All available log types */
export type LogType =
  | 'decisions'
  | 'operations'
  | 'auth'
  | 'system'
  | 'config_history'
  | 'policy_history'
  | 'client_wire'
  | 'backend_wire'

/** Time range filter options */
export type TimeRange = '5m' | '1h' | '24h' | 'all'

/** Filter parameters for log queries */
export interface LogFilters {
  time_range?: TimeRange
  limit?: number
  before?: string // ISO timestamp for cursor pagination
  session_id?: string
  bound_session_id?: string
  request_id?: string
  decision?: string // comma-separated: allow,deny,hitl
  hitl_outcome?: string // comma-separated: allowed,denied,timeout
  policy_version?: string
  config_version?: string
  level?: string // comma-separated: INFO,WARNING,ERROR
  event_type?: string // comma-separated event types
}

/**
 * Build URL search params from filters, excluding undefined/empty values.
 */
function buildParams(filters: LogFilters): URLSearchParams {
  const params = new URLSearchParams()

  if (filters.time_range) params.set('time_range', filters.time_range)
  if (filters.limit) params.set('limit', filters.limit.toString())
  if (filters.before) params.set('before', filters.before)
  if (filters.session_id) params.set('session_id', filters.session_id)
  if (filters.bound_session_id) params.set('bound_session_id', filters.bound_session_id)
  if (filters.request_id) params.set('request_id', filters.request_id)
  if (filters.decision) params.set('decision', filters.decision)
  if (filters.hitl_outcome) params.set('hitl_outcome', filters.hitl_outcome)
  if (filters.policy_version) params.set('policy_version', filters.policy_version)
  if (filters.config_version) params.set('config_version', filters.config_version)
  if (filters.level) params.set('level', filters.level)
  if (filters.event_type) params.set('event_type', filters.event_type)

  return params
}

/**
 * Fetch logs of a specific type with optional filters.
 *
 * Uses proxy-level endpoint (requires running proxy).
 *
 * @param type - Log type to fetch
 * @param filters - Filter parameters
 */
export async function getLogs(
  type: LogType,
  filters: LogFilters = {}
): Promise<LogsResponse> {
  const params = buildParams(filters)
  const query = params.toString()
  const path = query ? `/logs/${type}?${query}` : `/logs/${type}`
  return apiGet<LogsResponse>(path)
}

/**
 * Fetch logs for a specific proxy via manager endpoint.
 *
 * Reads from disk, works regardless of proxy running state.
 *
 * @param proxyId - Stable proxy identifier
 * @param type - Log type to fetch
 * @param filters - Filter parameters
 */
export async function getProxyLogs(
  proxyId: string,
  type: LogType,
  filters: LogFilters = {}
): Promise<LogsResponse> {
  const params = buildParams(filters)
  const query = params.toString()
  const encodedProxyId = encodeURIComponent(proxyId)
  const path = query
    ? `/manager/proxies/${encodedProxyId}/logs/${type}?${query}`
    : `/manager/proxies/${encodedProxyId}/logs/${type}`
  return apiGet<LogsResponse>(path)
}
