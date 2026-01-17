import { useState, useEffect, useCallback, useRef } from 'react'
import { getLogs, type LogType, type LogFilters } from '@/api/logs'
import { toast } from '@/components/ui/sonner'
import { notifyError } from '@/hooks/useErrorSound'
import { ApiError, type LogEntry } from '@/types/api'

export interface UseLogsResult {
  logs: LogEntry[]
  loading: boolean
  hasMore: boolean
  totalScanned: number
  loadMore: () => void
  refresh: () => void
}

/**
 * Hook for fetching and paginating logs with filtering support.
 * Uses cursor-based pagination with the `before` parameter.
 *
 * @param type - Log type to fetch
 * @param filters - Filter parameters (excluding before/limit)
 * @param pageSize - Number of entries per page
 * @param enabled - Whether to fetch (false skips all API calls)
 */
export function useLogs(
  type: LogType,
  filters: Omit<LogFilters, 'before' | 'limit'> = {},
  pageSize = 50,
  enabled = true
): UseLogsResult {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(enabled)
  const [hasMore, setHasMore] = useState(false)
  const [totalScanned, setTotalScanned] = useState(0)

  // Track the oldest timestamp for cursor pagination
  const cursorRef = useRef<string | undefined>(undefined)

  // Serialize filters for dependency comparison
  const filtersKey = JSON.stringify(filters)

  const fetchLogs = useCallback(async (reset = false) => {
    if (!enabled) return

    try {
      setLoading(true)

      const before = reset ? undefined : cursorRef.current
      const data = await getLogs(type, {
        ...filters,
        limit: pageSize,
        before,
      })

      if (reset) {
        setLogs(data.entries)
      } else {
        setLogs((prev) => [...prev, ...data.entries])
      }

      // Update cursor to oldest entry's timestamp for next page
      if (data.entries.length > 0) {
        const oldestEntry = data.entries[data.entries.length - 1]
        cursorRef.current = oldestEntry.time || oldestEntry.timestamp
      }

      setHasMore(data.has_more)
      setTotalScanned((prev) => reset ? data.total_scanned : prev + data.total_scanned)
    } catch (e) {
      // Check for 404 on debug logs (not available unless DEBUG level)
      const isDebugLog = type === 'client_wire' || type === 'backend_wire'
      const is404 = e instanceof ApiError && e.status === 404

      if (isDebugLog && is404) {
        toast.warning('Debug logs not available. Set log_level to DEBUG in config.')
      } else {
        notifyError('Failed to load logs')
      }
    } finally {
      setLoading(false)
    }
  }, [type, filtersKey, pageSize, enabled]) // eslint-disable-line react-hooks/exhaustive-deps

  // Reset and fetch when type or filters change (only if enabled)
  useEffect(() => {
    if (!enabled) {
      setLogs([])
      setLoading(false)
      setHasMore(false)
      setTotalScanned(0)
      cursorRef.current = undefined
      return
    }
    cursorRef.current = undefined
    setTotalScanned(0)
    fetchLogs(true)
  }, [type, filtersKey, fetchLogs, enabled]) // eslint-disable-line react-hooks/exhaustive-deps

  // Listen for SSE new-log-entries event to auto-refresh (only if enabled)
  useEffect(() => {
    if (!enabled) return

    const handleNewLogEntries = () => {
      cursorRef.current = undefined
      fetchLogs(true)
    }
    window.addEventListener('new-log-entries', handleNewLogEntries)
    return () => {
      window.removeEventListener('new-log-entries', handleNewLogEntries)
    }
  }, [fetchLogs, enabled])

  const loadMore = useCallback(() => {
    if (!loading && hasMore && enabled) {
      fetchLogs(false)
    }
  }, [loading, hasMore, fetchLogs, enabled])

  const refresh = useCallback(() => {
    if (!enabled) return
    cursorRef.current = undefined
    setTotalScanned(0)
    fetchLogs(true)
  }, [fetchLogs, enabled])

  return { logs, loading, hasMore, totalScanned, loadMore, refresh }
}
