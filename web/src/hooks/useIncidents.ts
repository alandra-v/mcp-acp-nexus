/**
 * Hook for fetching and managing incident logs.
 *
 * Fetches all incident types and merges them into a unified timeline:
 * - Shutdowns: Intentional security shutdowns
 * - Bootstrap: Startup validation errors
 * - Emergency: Audit fallback entries
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import {
  getShutdowns,
  getBootstrapLogs,
  getEmergencyLogs,
  type IncidentType,
} from '@/api/incidents'
import { notifyError } from '@/hooks/useErrorSound'
import type { LogEntry } from '@/types/api'

export interface IncidentEntry extends LogEntry {
  /** Type of incident for styling */
  incident_type: IncidentType
}

export interface UseIncidentsResult {
  /** All incidents merged and sorted by time (newest first) */
  incidents: IncidentEntry[]
  /** Loading state */
  loading: boolean
  /** Whether there are more entries to load */
  hasMore: boolean
  /** Load more entries */
  loadMore: () => void
  /** Refresh all data */
  refresh: () => void
}

const PAGE_SIZE = 50

/**
 * Hook for fetching incident logs from all sources.
 *
 * Merges shutdowns, bootstrap errors, and emergency audit logs into
 * a single timeline sorted by timestamp (newest first).
 */
export function useIncidents(): UseIncidentsResult {
  const [shutdowns, setShutdowns] = useState<LogEntry[]>([])
  const [bootstrap, setBootstrap] = useState<LogEntry[]>([])
  const [emergency, setEmergency] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)

  // Track cursors for pagination (oldest timestamp seen for each type)
  const shutdownsCursor = useRef<string | undefined>(undefined)
  const bootstrapCursor = useRef<string | undefined>(undefined)
  const emergencyCursor = useRef<string | undefined>(undefined)

  // Track if there are more entries for each type
  const [shutdownsHasMore, setShutdownsHasMore] = useState(true)
  const [bootstrapHasMore, setBootstrapHasMore] = useState(true)
  const [emergencyHasMore, setEmergencyHasMore] = useState(true)

  const fetchAll = useCallback(async (reset = false) => {
    setLoading(true)

    if (reset) {
      shutdownsCursor.current = undefined
      bootstrapCursor.current = undefined
      emergencyCursor.current = undefined
      setShutdownsHasMore(true)
      setBootstrapHasMore(true)
      setEmergencyHasMore(true)
    }

    try {
      const [shutdownsRes, bootstrapRes, emergencyRes] = await Promise.all([
        getShutdowns('all', PAGE_SIZE, reset ? undefined : shutdownsCursor.current),
        getBootstrapLogs('all', PAGE_SIZE, reset ? undefined : bootstrapCursor.current),
        getEmergencyLogs('all', PAGE_SIZE, reset ? undefined : emergencyCursor.current),
      ])

      // Update cursors based on oldest entry in each response
      if (shutdownsRes.entries.length > 0) {
        const oldest = shutdownsRes.entries[shutdownsRes.entries.length - 1]
        shutdownsCursor.current = oldest.time
      }
      if (bootstrapRes.entries.length > 0) {
        const oldest = bootstrapRes.entries[bootstrapRes.entries.length - 1]
        bootstrapCursor.current = oldest.time
      }
      if (emergencyRes.entries.length > 0) {
        const oldest = emergencyRes.entries[emergencyRes.entries.length - 1]
        emergencyCursor.current = oldest.time
      }

      // Update has_more flags
      setShutdownsHasMore(shutdownsRes.has_more)
      setBootstrapHasMore(bootstrapRes.has_more)
      setEmergencyHasMore(emergencyRes.has_more)

      // Update state
      if (reset) {
        setShutdowns(shutdownsRes.entries)
        setBootstrap(bootstrapRes.entries)
        setEmergency(emergencyRes.entries)
      } else {
        setShutdowns((prev) => [...prev, ...shutdownsRes.entries])
        setBootstrap((prev) => [...prev, ...bootstrapRes.entries])
        setEmergency((prev) => [...prev, ...emergencyRes.entries])
      }
    } catch {
      notifyError('Failed to load incidents')
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    fetchAll(true)
  }, [fetchAll])

  // Merge and sort all incidents
  const incidents = useMemo<IncidentEntry[]>(() => {
    const all: IncidentEntry[] = [
      ...shutdowns.map((e) => ({ ...e, incident_type: 'shutdown' as const })),
      ...bootstrap.map((e) => ({ ...e, incident_type: 'bootstrap' as const })),
      ...emergency.map((e) => ({ ...e, incident_type: 'emergency' as const })),
    ]

    // Sort by time descending (newest first)
    return all.sort((a, b) => {
      const timeA = a.time || ''
      const timeB = b.time || ''
      return timeB.localeCompare(timeA)
    })
  }, [shutdowns, bootstrap, emergency])

  const hasMore = shutdownsHasMore || bootstrapHasMore || emergencyHasMore

  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      fetchAll(false)
    }
  }, [loading, hasMore, fetchAll])

  const refresh = useCallback(() => {
    fetchAll(true)
  }, [fetchAll])

  return {
    incidents,
    loading,
    hasMore,
    loadMore,
    refresh,
  }
}
