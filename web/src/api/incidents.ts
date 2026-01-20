/**
 * Incidents API client.
 *
 * Provides access to incident history:
 * - Shutdowns: Intentional security shutdowns (audit failure, session hijacking)
 * - Bootstrap: Startup validation errors (config/policy issues)
 * - Emergency: Audit fallback entries when normal audit fails
 */

import { apiGet, type RequestOptions } from './client'
import type { LogsResponse } from '@/types/api'

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
// Helpers
// =============================================================================

/** Build URLSearchParams for incident log queries. */
function buildParams(timeRange: string, limit: number, before?: string): URLSearchParams {
  const params = new URLSearchParams({ time_range: timeRange, limit: String(limit) })
  if (before) params.set('before', before)
  return params
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Get security shutdown logs.
 * Returns entries from shutdowns.jsonl.
 * These are INTENTIONAL security shutdowns (audit failure, session hijacking, etc.)
 */
export async function getShutdowns(
  timeRange: string = 'all',
  limit: number = 100,
  before?: string
): Promise<LogsResponse> {
  return apiGet<LogsResponse>(`/incidents/shutdowns?${buildParams(timeRange, limit, before)}`)
}

/**
 * Get bootstrap/startup error logs.
 * Returns entries from bootstrap.jsonl.
 */
export async function getBootstrapLogs(
  timeRange: string = 'all',
  limit: number = 100,
  before?: string
): Promise<LogsResponse> {
  return apiGet<LogsResponse>(`/incidents/bootstrap?${buildParams(timeRange, limit, before)}`)
}

/**
 * Get emergency audit logs.
 * Returns entries from emergency_audit.jsonl.
 */
export async function getEmergencyLogs(
  timeRange: string = 'all',
  limit: number = 100,
  before?: string
): Promise<LogsResponse> {
  return apiGet<LogsResponse>(`/incidents/emergency?${buildParams(timeRange, limit, before)}`)
}

/**
 * Get incidents summary with counts and latest timestamp.
 * Used for badge state calculation.
 */
export async function getIncidentsSummary(options?: RequestOptions): Promise<IncidentsSummary> {
  return apiGet<IncidentsSummary>('/incidents/summary', options)
}
