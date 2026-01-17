/**
 * Incidents context for badge state management.
 *
 * Tracks whether there are unread incidents by comparing the latest
 * critical timestamp (shutdowns + emergency) against a localStorage timestamp.
 */

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react'
import { getIncidentsSummary, type IncidentsSummary } from '@/api/incidents'

const LAST_SEEN_KEY = 'mcp-acp-incidents-last-seen'

interface IncidentsContextValue {
  /** Whether there are unread incidents (shutdowns or emergency) */
  hasUnread: boolean
  /** Total count of all incidents (shutdowns + emergency + bootstrap) */
  totalCount: number
  /** Summary data from API */
  summary: IncidentsSummary | null
  /** Mark all incidents as read (update localStorage) */
  markAsRead: () => void
  /** Refresh summary from API */
  refresh: () => Promise<void>
}

const IncidentsContext = createContext<IncidentsContextValue | null>(null)

interface IncidentsProviderProps {
  children: ReactNode
}

export function IncidentsProvider({ children }: IncidentsProviderProps) {
  const [summary, setSummary] = useState<IncidentsSummary | null>(null)
  const [lastSeen, setLastSeen] = useState<string | null>(() => {
    return localStorage.getItem(LAST_SEEN_KEY)
  })

  const fetchSummary = useCallback(async () => {
    try {
      const data = await getIncidentsSummary()
      setSummary(data)
    } catch {
      // Silent fail - badge just won't show
    }
  }, [])

  // Fetch on mount
  useEffect(() => {
    fetchSummary()
  }, [fetchSummary])

  // Calculate hasUnread: latest_critical_timestamp > lastSeen
  const hasUnread = Boolean(
    summary?.latest_critical_timestamp &&
      (!lastSeen || summary.latest_critical_timestamp > lastSeen)
  )

  const totalCount =
    (summary?.shutdowns_count ?? 0) +
    (summary?.emergency_count ?? 0) +
    (summary?.bootstrap_count ?? 0)

  const markAsRead = useCallback(() => {
    if (summary?.latest_critical_timestamp) {
      localStorage.setItem(LAST_SEEN_KEY, summary.latest_critical_timestamp)
      setLastSeen(summary.latest_critical_timestamp)
    }
  }, [summary])

  const value: IncidentsContextValue = {
    hasUnread,
    totalCount,
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
