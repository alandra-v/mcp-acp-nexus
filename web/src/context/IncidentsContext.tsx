/**
 * Incidents context for badge state management.
 *
 * Badge visibility is determined by critical incidents (shutdowns + emergency).
 * Badge count shows ALL new incidents since last viewed (including bootstrap).
 *
 * This design alerts users to critical security events while showing
 * the full picture of all new incidents in the count.
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
const LAST_SEEN_COUNTS_KEY = 'mcp-acp-incidents-last-seen-counts'

interface LastSeenCounts {
  shutdowns: number
  emergency: number
  bootstrap: number
}

/** Parse and validate LastSeenCounts from localStorage. Returns null if invalid. */
function parseLastSeenCounts(json: string | null): LastSeenCounts | null {
  if (!json) return null
  try {
    const parsed: unknown = JSON.parse(json)
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      typeof (parsed as LastSeenCounts).shutdowns === 'number' &&
      typeof (parsed as LastSeenCounts).emergency === 'number' &&
      typeof (parsed as LastSeenCounts).bootstrap === 'number'
    ) {
      return parsed as LastSeenCounts
    }
    return null
  } catch {
    return null
  }
}

interface IncidentsContextValue {
  /** Whether there are unread incidents (shutdowns or emergency) */
  hasUnread: boolean
  /** Count of NEW incidents since last marked as read */
  unreadCount: number
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
  const [lastSeenCounts, setLastSeenCounts] = useState<LastSeenCounts | null>(() => {
    return parseLastSeenCounts(localStorage.getItem(LAST_SEEN_COUNTS_KEY))
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

  // Calculate unread count as delta from last seen counts.
  // Includes all incident types (not just critical) to show full picture.
  // Math.max(0, ...) handles log rotation/deletion gracefully.
  const unreadCount = lastSeenCounts
    ? Math.max(0, (summary?.shutdowns_count ?? 0) - lastSeenCounts.shutdowns) +
      Math.max(0, (summary?.emergency_count ?? 0) - lastSeenCounts.emergency) +
      Math.max(0, (summary?.bootstrap_count ?? 0) - lastSeenCounts.bootstrap)
    : totalCount // If never marked as read, all are unread

  const markAsRead = useCallback(() => {
    if (summary?.latest_critical_timestamp) {
      localStorage.setItem(LAST_SEEN_KEY, summary.latest_critical_timestamp)
      setLastSeen(summary.latest_critical_timestamp)
    }
    // Store current counts when marking as read
    if (summary) {
      const counts: LastSeenCounts = {
        shutdowns: summary.shutdowns_count,
        emergency: summary.emergency_count,
        bootstrap: summary.bootstrap_count,
      }
      localStorage.setItem(LAST_SEEN_COUNTS_KEY, JSON.stringify(counts))
      setLastSeenCounts(counts)
    }
  }, [summary])

  const value: IncidentsContextValue = {
    hasUnread,
    unreadCount,
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
