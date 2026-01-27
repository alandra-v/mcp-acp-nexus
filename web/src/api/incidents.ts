/**
 * Incidents API client.
 *
 * Provides access to incident history:
 * - Shutdowns: Intentional security shutdowns (audit failure, session hijacking)
 * - Bootstrap: Startup validation errors (config/policy issues)
 * - Emergency: Audit fallback entries when normal audit fails
 *
 * Two levels of API:
 * - Manager level: /api/manager/incidents - aggregated from all proxies
 * - Proxy level: /incidents/* - from a specific proxy (legacy)
 */

import { apiGet, type RequestOptions } from './client'
import { DEFAULT_INCIDENT_LIMIT } from '@/constants'
import type { LogsResponse, AggregatedIncidentsResponse } from '@/types/api'

// =============================================================================
// Types
// =============================================================================

export interface IncidentsSummary {
  shutdowns_count: number
  emergency_count: number
  bootstrap_count: number
  latest_critical_timestamp: string | null
  shutdowns_path: string | null
  emergency_path: string | null
  bootstrap_path: string | null
}

export type IncidentType = 'shutdown' | 'bootstrap' | 'emergency'

// =============================================================================
// Manager-level API (aggregated from all proxies)
// =============================================================================

export interface AggregatedIncidentsParams {
  proxy?: string
  incident_type?: IncidentType
  time_range?: string
  limit?: number
  before?: string
}

/**
 * Get aggregated incidents from all proxies.
 * Combines shutdowns (per-proxy) with bootstrap and emergency (global).
 * Each entry includes 'incident_type' and 'proxy_name' (for shutdowns).
 */
export async function getAggregatedIncidents(
  params: AggregatedIncidentsParams = {},
  options?: RequestOptions
): Promise<AggregatedIncidentsResponse> {
  const searchParams = new URLSearchParams()
  if (params.proxy) searchParams.set('proxy', params.proxy)
  if (params.incident_type) searchParams.set('incident_type', params.incident_type)
  if (params.time_range) searchParams.set('time_range', params.time_range)
  if (params.limit) searchParams.set('limit', String(params.limit))
  if (params.before) searchParams.set('before', params.before)

  const query = searchParams.toString()
  const url = query ? `/api/manager/incidents?${query}` : '/api/manager/incidents'
  return apiGet<AggregatedIncidentsResponse>(url, options)
}

// =============================================================================
// Helpers
// =============================================================================

/** @internal Build URLSearchParams for incident log queries. */
function _buildParams(timeRange: string, limit: number, before?: string): URLSearchParams {
  const params = new URLSearchParams({ time_range: timeRange, limit: String(limit) })
  if (before) params.set('before', before)
  return params
}

// =============================================================================
// Proxy-level API (legacy, single proxy)
// =============================================================================

/**
 * Get security shutdown logs.
 * Returns entries from shutdowns.jsonl.
 * These are INTENTIONAL security shutdowns (audit failure, session hijacking, etc.)
 */
export async function getShutdowns(
  timeRange: string = 'all',
  limit: number = DEFAULT_INCIDENT_LIMIT,
  before?: string,
  options?: RequestOptions
): Promise<LogsResponse> {
  return apiGet<LogsResponse>(
    `/incidents/shutdowns?${_buildParams(timeRange, limit, before)}`,
    options
  )
}

/**
 * Get bootstrap/startup error logs.
 * Returns entries from bootstrap.jsonl.
 */
export async function getBootstrapLogs(
  timeRange: string = 'all',
  limit: number = DEFAULT_INCIDENT_LIMIT,
  before?: string,
  options?: RequestOptions
): Promise<LogsResponse> {
  return apiGet<LogsResponse>(
    `/incidents/bootstrap?${_buildParams(timeRange, limit, before)}`,
    options
  )
}

/**
 * Get emergency audit logs.
 * Returns entries from emergency_audit.jsonl.
 */
export async function getEmergencyLogs(
  timeRange: string = 'all',
  limit: number = DEFAULT_INCIDENT_LIMIT,
  before?: string,
  options?: RequestOptions
): Promise<LogsResponse> {
  return apiGet<LogsResponse>(
    `/incidents/emergency?${_buildParams(timeRange, limit, before)}`,
    options
  )
}

/**
 * Get incidents summary with counts and latest timestamp.
 * Used for badge state calculation.
 */
export async function getIncidentsSummary(options?: RequestOptions): Promise<IncidentsSummary> {
  return apiGet<IncidentsSummary>('/incidents/summary', options)
}
