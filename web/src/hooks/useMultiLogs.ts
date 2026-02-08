import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { getLogs, getProxyLogs, type LogType, type LogFilters } from '@/api/logs'
import { notifyError } from '@/hooks/useErrorSound'
import { useAppStore } from '@/store/appStore'
import type { LogEntry } from '@/types/api'

/** Result interface for useMultiLogs hook */
export interface UseMultiLogsResult {
  logs: LogEntry[]
  loading: boolean
  hasMore: boolean
  totalScanned: number
  logFile: string | null
  loadMore: () => void
  refresh: () => void
}

/** Options for useMultiLogs hook */
export interface UseMultiLogsOptions {
  /**
   * When provided, uses manager-level endpoints to access logs
   * regardless of whether the proxy is running.
   * When undefined, uses the default proxy-level endpoints.
   */
  proxyId?: string
}

/**
 * Hook for fetching and merging logs from multiple log types.
 * Used for "All Files" view within a folder.
 * Entries are sorted by timestamp (newest first).
 *
 * @param types - Array of log types to fetch
 * @param filters - Filter parameters (excluding before/limit)
 * @param pageSize - Number of entries per page per log type
 * @param options - Optional configuration including proxyId for manager-level access
 */
export function useMultiLogs(
  types: LogType[],
  filters: Omit<LogFilters, 'before' | 'limit'> = {},
  pageSize = 50,
  options?: UseMultiLogsOptions
): UseMultiLogsResult {
  const proxyId = options?.proxyId
  const [logsByType, setLogsByType] = useState<Record<string, LogEntry[]>>({})
  const [loading, setLoading] = useState(true)
  const [hasMoreByType, setHasMoreByType] = useState<Record<string, boolean>>({})
  const [totalScanned, setTotalScanned] = useState(0)

  // Track cursors per log type
  const cursorsRef = useRef<Record<string, string | undefined>>({})

  // Serialize for dependency comparison
  const typesKey = JSON.stringify(types)
  const filtersKey = JSON.stringify(filters)

  // Subscribe to store signal counter
  const logEntriesVersion = useAppStore((s) => s.logEntriesVersion)

  // Track mount-time version to skip initial effect run
  const mountVersionRef = useRef(logEntriesVersion)

  // Merged and sorted logs
  const logs = useMemo(() => {
    const allLogs: (LogEntry & { _source?: string })[] = []
    for (const [type, entries] of Object.entries(logsByType)) {
      for (const entry of entries) {
        allLogs.push({ ...entry, _source: type })
      }
    }
    // Sort by time descending (newest first)
    return allLogs.sort((a, b) => {
      const timeA = a.time || a.timestamp || ''
      const timeB = b.time || b.timestamp || ''
      return timeB.localeCompare(timeA)
    })
  }, [logsByType])

  // Overall hasMore if any type has more
  const hasMore = useMemo(
    () => Object.values(hasMoreByType).some(Boolean),
    [hasMoreByType]
  )

  const fetchLogs = useCallback(async (reset = false) => {
    if (types.length === 0) {
      setLogsByType({})
      setLoading(false)
      return
    }

    try {
      setLoading(true)

      // Fetch all types in parallel
      const results = await Promise.all(
        types.map(async (type) => {
          const before = reset ? undefined : cursorsRef.current[type]
          const filterParams = {
            ...filters,
            limit: pageSize,
            before,
          }

          // Use manager endpoint when proxyId is provided
          const data = proxyId
            ? await getProxyLogs(proxyId, type, filterParams)
            : await getLogs(type, filterParams)

          return { type, data }
        })
      )

      // Update state for each type
      const newLogsByType: Record<string, LogEntry[]> = reset ? {} : { ...logsByType }
      const newHasMore: Record<string, boolean> = {}
      let scanned = 0

      for (const { type, data } of results) {
        if (reset) {
          newLogsByType[type] = data.entries
        } else {
          newLogsByType[type] = [...(newLogsByType[type] || []), ...data.entries]
        }

        // Update cursor
        if (data.entries.length > 0) {
          const oldestEntry = data.entries[data.entries.length - 1]
          cursorsRef.current[type] = oldestEntry.time || oldestEntry.timestamp
        }

        newHasMore[type] = data.has_more
        scanned += data.total_scanned
      }

      setLogsByType(newLogsByType)
      setHasMoreByType(newHasMore)
      setTotalScanned((prev) => reset ? scanned : prev + scanned)
    } catch {
      notifyError('Failed to load logs')
    } finally {
      setLoading(false)
    }
  }, [types, filtersKey, pageSize, proxyId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Reset and fetch when types or filters change
  useEffect(() => {
    // Clear all state immediately when types change
    cursorsRef.current = {}
    setLogsByType({})
    setHasMoreByType({})
    setTotalScanned(0)
    fetchLogs(true)
  }, [typesKey, filtersKey, fetchLogs])

  // Refetch when logEntriesVersion changes (skip mount-time value)
  useEffect(() => {
    if (logEntriesVersion === mountVersionRef.current) return
    cursorsRef.current = {}
    fetchLogs(true)
  }, [logEntriesVersion, fetchLogs])

  const loadMore = useCallback(() => {
    if (!loading && hasMore) {
      fetchLogs(false)
    }
  }, [loading, hasMore, fetchLogs])

  const refresh = useCallback(() => {
    cursorsRef.current = {}
    setTotalScanned(0)
    fetchLogs(true)
  }, [fetchLogs])

  // Multi-type view doesn't have a single log file path
  return { logs, loading, hasMore, totalScanned, logFile: null, loadMore, refresh }
}
