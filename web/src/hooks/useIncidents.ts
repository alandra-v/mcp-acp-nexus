/**
 * Hook for fetching and managing incident logs.
 *
 * Uses the aggregated /api/manager/incidents endpoint which combines:
 * - Shutdowns: Intentional security shutdowns (per-proxy)
 * - Bootstrap: Startup validation errors (global)
 * - Emergency: Audit fallback entries (global)
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  getAggregatedIncidents,
  type IncidentType,
} from '@/api/incidents'
import { notifyError } from '@/hooks/useErrorSound'
import { DEFAULT_INCIDENT_LIMIT } from '@/constants'
import type { IncidentEntry } from '@/types/api'

export interface UseIncidentsOptions {
  /** Filter by proxy name */
  proxy?: string
  /** Filter by incident type */
  incidentType?: IncidentType
  /** Time range filter */
  timeRange?: string
}

export interface UseIncidentsResult {
  /** All incidents sorted by time (newest first) */
  incidents: IncidentEntry[]
  /** Loading state */
  loading: boolean
  /** Error if fetch failed */
  error: Error | null
  /** Whether there are more entries to load */
  hasMore: boolean
  /** Load more entries */
  loadMore: () => void
  /** Refresh all data */
  refresh: () => void
}

/**
 * Hook for fetching incident logs from the aggregated endpoint.
 *
 * Supports filtering by proxy name and incident type.
 */
export function useIncidents(options: UseIncidentsOptions = {}): UseIncidentsResult {
  const { proxy, incidentType, timeRange = 'all' } = options

  const [incidents, setIncidents] = useState<IncidentEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const [hasMore, setHasMore] = useState(false)

  // Track cursor for pagination (oldest timestamp seen)
  const cursorRef = useRef<string | undefined>(undefined)
  const hasShownErrorRef = useRef(false)
  const mountedRef = useRef(true)

  const fetchIncidents = useCallback(async (reset = false, signal?: AbortSignal) => {
    setLoading(true)
    setError(null)

    if (reset) {
      cursorRef.current = undefined
    }

    try {
      const response = await getAggregatedIncidents(
        {
          proxy,
          incident_type: incidentType,
          time_range: timeRange,
          limit: DEFAULT_INCIDENT_LIMIT,
          before: reset ? undefined : cursorRef.current,
        },
        { signal }
      )

      if (!mountedRef.current) return

      // Update cursor based on oldest entry
      if (response.entries.length > 0) {
        const oldest = response.entries[response.entries.length - 1]
        cursorRef.current = oldest.time
      }

      setHasMore(response.has_more)

      if (reset) {
        setIncidents(response.entries)
      } else {
        setIncidents((prev) => [...prev, ...response.entries])
      }

      hasShownErrorRef.current = false
    } catch (err) {
      // Ignore abort errors
      if (err instanceof DOMException && err.name === 'AbortError') return

      if (mountedRef.current) {
        const error = err instanceof Error ? err : new Error('Failed to load incidents')
        setError(error)
        if (!hasShownErrorRef.current) {
          notifyError('Failed to load incidents')
          hasShownErrorRef.current = true
        }
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
  }, [proxy, incidentType, timeRange])

  // Initial fetch and refetch when filters change
  useEffect(() => {
    mountedRef.current = true
    const controller = new AbortController()
    fetchIncidents(true, controller.signal)
    return () => {
      mountedRef.current = false
      controller.abort()
    }
  }, [fetchIncidents])

  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      fetchIncidents(false)
    }
  }, [loading, hasMore, fetchIncidents])

  const refresh = useCallback(() => {
    fetchIncidents(true)
  }, [fetchIncidents])

  return {
    incidents,
    loading,
    error,
    hasMore,
    loadMore,
    refresh,
  }
}
