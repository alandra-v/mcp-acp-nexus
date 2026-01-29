/**
 * Incidents API client.
 *
 * Provides access to incident history:
 * - Shutdowns: Intentional security shutdowns (audit failure, session hijacking)
 * - Bootstrap: Startup validation errors (config/policy issues)
 * - Emergency: Audit fallback entries when normal audit fails
 *
 * Uses manager-level API: /api/manager/incidents - aggregated from all proxies
 */

import { apiGet, type RequestOptions } from './client'
import type { AggregatedIncidentsResponse } from '@/types/api'

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
  const url = query ? `/manager/incidents?${query}` : '/manager/incidents'
  return apiGet<AggregatedIncidentsResponse>(url, options)
}

/**
 * Get incidents summary with counts and latest timestamp.
 * Used for badge state calculation.
 *
 * Uses manager-level endpoint to aggregate from all proxies.
 *
 * @param params.since - Only count entries after this ISO timestamp (for unread badge).
 */
export async function getIncidentsSummary(
  params?: { since?: string },
  options?: RequestOptions,
): Promise<IncidentsSummary> {
  const searchParams = new URLSearchParams()
  if (params?.since) searchParams.set('since', params.since)
  const query = searchParams.toString()
  const url = query ? `/manager/incidents/summary?${query}` : '/manager/incidents/summary'
  return apiGet<IncidentsSummary>(url, options)
}
