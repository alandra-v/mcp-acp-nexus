/**
 * Incidents context for badge state management.
 *
 * Shows unread count badge when there are new incidents since last viewed.
 * Resets when user views the incidents page.
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from 'react'
import { getIncidentsSummary, type IncidentsSummary } from '@/api/incidents'

const LAST_SEEN_TOTAL_KEY = 'mcp-acp-incidents-last-seen-total'
const LAST_SEEN_TIMESTAMP_KEY = 'mcp-acp-incidents-last-seen-timestamp'

interface IncidentsContextValue {
  /** Count of unread incidents */
  unreadCount: number
  /** Timestamp when incidents were last marked as read (for glow on new items) */
  lastSeenTimestamp: string | null
  /** Summary data from API */
  summary: IncidentsSummary | null
  /** Mark all incidents as read */
  markAsRead: () => void
  /** Refresh summary from API */
  refresh: () => Promise<void>
}

const IncidentsContext = createContext<IncidentsContextValue | null>(null)

interface IncidentsProviderProps {
  children: ReactNode
}

/** Calculate total incident count from summary. */
function getTotalCount(summary: IncidentsSummary | null): number {
  if (!summary) return 0
  return summary.shutdowns_count + summary.emergency_count + summary.bootstrap_count
}

export function IncidentsProvider({ children }: IncidentsProviderProps) {
  const [summary, setSummary] = useState<IncidentsSummary | null>(null)
  const [lastSeenTotal, setLastSeenTotal] = useState<number>(() => {
    const stored = localStorage.getItem(LAST_SEEN_TOTAL_KEY)
    return stored ? parseInt(stored, 10) || 0 : 0
  })
  const [lastSeenTimestamp, setLastSeenTimestamp] = useState<string | null>(() => {
    return localStorage.getItem(LAST_SEEN_TIMESTAMP_KEY)
  })

  // Track active fetch for cleanup
  const abortControllerRef = useRef<AbortController | null>(null)

  const fetchSummary = useCallback(async () => {
    // Cancel any in-flight request
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller

    try {
      const data = await getIncidentsSummary({ signal: controller.signal })
      setSummary(data)
    } catch (error) {
      // Ignore abort errors (expected on cleanup)
      // Other errors (network, server) are logged by fetchWithRetry in client.ts
      if (error instanceof DOMException && error.name === 'AbortError') {
        return
      }
    }
  }, [])

  useEffect(() => {
    fetchSummary()

    // Listen for incidents_updated SSE events (dispatched by AppStateContext)
    const handleIncidentsUpdated = () => {
      fetchSummary()
    }
    window.addEventListener('incidents-updated', handleIncidentsUpdated)

    return () => {
      abortControllerRef.current?.abort()
      window.removeEventListener('incidents-updated', handleIncidentsUpdated)
    }
  }, [fetchSummary])

  const totalCount = getTotalCount(summary)
  const unreadCount = Math.max(0, totalCount - lastSeenTotal)

  const markAsRead = useCallback(() => {
    const total = getTotalCount(summary)
    if (total > 0) {
      const now = new Date().toISOString()
      localStorage.setItem(LAST_SEEN_TOTAL_KEY, String(total))
      localStorage.setItem(LAST_SEEN_TIMESTAMP_KEY, now)
      setLastSeenTotal(total)
      setLastSeenTimestamp(now)
    }
  }, [summary])

  const value: IncidentsContextValue = {
    unreadCount,
    lastSeenTimestamp,
    summary,
    markAsRead,
    refresh: fetchSummary,
  }

  return (
    <IncidentsContext.Provider value={value}>
      {children}
    </IncidentsContext.Provider>
  )
}

export function useIncidentsContext(): IncidentsContextValue {
  const context = useContext(IncidentsContext)
  if (!context) {
    throw new Error('useIncidentsContext must be used within IncidentsProvider')
  }
  return context
}
