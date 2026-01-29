/**
 * Incidents context for badge state management.
 *
 * Shows unread count badge when there are new incidents since last viewed.
 * Resets when user views the incidents page.
 *
 * Uses timestamp-based tracking: the summary endpoint is called with
 * `since=lastSeenTimestamp` so the returned counts ARE the unread counts.
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
import { INCIDENTS_STORAGE_KEYS, SSE_EVENTS } from '@/constants'

interface IncidentsContextValue {
  /** Count of unread incidents */
  unreadCount: number
  /** Timestamp when incidents were last marked as read (for glow on new items) */
  lastSeenTimestamp: string | null
  /** Summary data from API (filtered by since — counts reflect unread only) */
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
  const [lastSeenTimestamp, setLastSeenTimestamp] = useState<string | null>(() => {
    return localStorage.getItem(INCIDENTS_STORAGE_KEYS.LAST_SEEN_TIMESTAMP)
  })

  // Track active fetch for cleanup
  const abortControllerRef = useRef<AbortController | null>(null)
  // Ref to avoid stale closure in fetchSummary (event handlers capture the
  // initial callback; using a ref lets them always read the latest value
  // without re-subscribing to SSE events on every timestamp change).
  const lastSeenRef = useRef(lastSeenTimestamp)
  lastSeenRef.current = lastSeenTimestamp

  const fetchSummary = useCallback(async () => {
    // Cancel any in-flight request
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller

    try {
      const since = lastSeenRef.current ?? undefined
      const data = await getIncidentsSummary(
        since ? { since } : undefined,
        { signal: controller.signal },
      )
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

    const handleRefetch = () => {
      fetchSummary()
    }

    // Listen for incidents_updated SSE events (dispatched by AppStateContext)
    window.addEventListener(SSE_EVENTS.INCIDENTS_UPDATED, handleRefetch)

    // Also refetch when a proxy registers/disconnects
    window.addEventListener(SSE_EVENTS.PROXY_REGISTERED, handleRefetch)
    window.addEventListener(SSE_EVENTS.PROXY_DISCONNECTED, handleRefetch)

    // Refetch when the tab regains visibility
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        fetchSummary()
      }
    }
    document.addEventListener('visibilitychange', handleVisibility)

    return () => {
      abortControllerRef.current?.abort()
      window.removeEventListener(SSE_EVENTS.INCIDENTS_UPDATED, handleRefetch)
      window.removeEventListener(SSE_EVENTS.PROXY_REGISTERED, handleRefetch)
      window.removeEventListener(SSE_EVENTS.PROXY_DISCONNECTED, handleRefetch)
      document.removeEventListener('visibilitychange', handleVisibility)
    }
  }, [fetchSummary])

  // The summary is already filtered by `since` — counts ARE the unread counts
  const unreadCount = getTotalCount(summary)

  const markAsRead = useCallback(() => {
    const now = new Date().toISOString()
    localStorage.setItem(INCIDENTS_STORAGE_KEYS.LAST_SEEN_TIMESTAMP, now)
    setLastSeenTimestamp(now)
    // Update ref eagerly so fetchSummary reads the new value immediately
    // (state update hasn't triggered a re-render yet at this point)
    lastSeenRef.current = now
    // Optimistically clear badge — the next fetch will confirm 0 counts
    setSummary(null)
    // Re-fetch with the new timestamp to confirm
    fetchSummary()
    // Notify other components (e.g., ProxyGrid) that incidents were marked as read
    window.dispatchEvent(new CustomEvent(SSE_EVENTS.INCIDENTS_MARKED_READ))
  }, [fetchSummary])

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
