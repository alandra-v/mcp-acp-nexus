/**
 * Incidents page - displays security shutdowns, startup errors, and emergency audit fallbacks.
 *
 * Features:
 * - Type filter chips (All/Shutdowns/Startup/Emergency)
 * - Proxy dropdown filter (All Proxies + configured proxy names)
 * - Timeline view with IncidentCards showing proxy attribution
 */

import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, ShieldAlert, ChevronDown } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { Button } from '@/components/ui/button'
import { IncidentCard } from '@/components/incidents/IncidentCard'
import { useIncidents } from '@/hooks/useIncidents'
import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useIncidentsContext } from '@/context/IncidentsContext'
import { cn } from '@/lib/utils'
import { INCIDENTS_MARK_READ_DELAY_MS } from '@/constants'
import type { IncidentType } from '@/api/incidents'

type FilterType = 'all' | IncidentType

const TYPE_FILTER_STORAGE_KEY = 'incidentsTypeFilter'
const PROXY_FILTER_STORAGE_KEY = 'incidentsProxyFilter'

const TYPE_FILTER_OPTIONS: { value: FilterType; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'shutdown', label: 'Shutdowns' },
  { value: 'bootstrap', label: 'Startup' },
  { value: 'emergency', label: 'Emergency Audit' },
]

export function IncidentsPage() {
  const navigate = useNavigate()
  const { markAsRead, lastSeenTimestamp } = useIncidentsContext()
  const { proxies } = useManagerProxies()

  // Filter state (persisted to localStorage)
  const [typeFilter, setTypeFilter] = useState<FilterType>(() => {
    const stored = localStorage.getItem(TYPE_FILTER_STORAGE_KEY)
    if (stored === 'shutdown' || stored === 'bootstrap' || stored === 'emergency') {
      return stored
    }
    return 'all'
  })
  const [proxyFilter, setProxyFilter] = useState<string>(() => {
    return localStorage.getItem(PROXY_FILTER_STORAGE_KEY) || 'all'
  })

  // Persist filters to localStorage
  useEffect(() => {
    localStorage.setItem(TYPE_FILTER_STORAGE_KEY, typeFilter)
  }, [typeFilter])

  useEffect(() => {
    localStorage.setItem(PROXY_FILTER_STORAGE_KEY, proxyFilter)
  }, [proxyFilter])

  // Reset proxy filter if stored proxy no longer exists
  useEffect(() => {
    if (proxyFilter !== 'all' && proxies.length > 0) {
      const proxyExists = proxies.some((p) => p.proxy_name === proxyFilter)
      if (!proxyExists) {
        setProxyFilter('all')
      }
    }
  }, [proxies, proxyFilter])

  // Fetch incidents with filters (server-side filtering)
  const { incidents, loading, hasMore, loadMore, refresh } = useIncidents({
    proxy: proxyFilter === 'all' ? undefined : proxyFilter,
    incidentType: typeFilter === 'all' ? undefined : typeFilter,
  })

  // Capture lastSeenTimestamp on mount (before markAsRead updates it)
  const initialLastSeenRef = useRef<string | null>(lastSeenTimestamp)

  // Build proxy options from configured proxies (memoized to prevent recalc on every render)
  const proxyOptions = useMemo(() => [
    { value: 'all', label: 'All Proxies' },
    ...proxies.map((p) => ({ value: p.proxy_name, label: p.proxy_name })),
  ], [proxies])

  const handleBack = useCallback(() => {
    navigate('/')
  }, [navigate])

  // Mark incidents as read when page is viewed
  useEffect(() => {
    // Small delay to ensure summary is loaded
    const timer = setTimeout(markAsRead, INCIDENTS_MARK_READ_DELAY_MS)
    return () => clearTimeout(timer)
  }, [markAsRead])

  /** Check if an incident is new (after the last time user viewed incidents) */
  const isIncidentNew = useCallback((incidentTime: string | undefined): boolean => {
    if (!incidentTime) return false // No timestamp = can't determine, treat as old
    if (!initialLastSeenRef.current) return true // Never viewed = all are new
    return incidentTime > initialLastSeenRef.current
  }, [])

  return (
    <Layout showFooter={false}>
      <div className="max-w-[900px] mx-auto px-8 py-8">
        {/* Header */}
        <div className="flex items-center gap-6 pb-6 border-b border-[var(--border-subtle)] mb-6">
          <button
            onClick={handleBack}
            className="inline-flex items-center gap-2 px-4 py-2 bg-transparent border border-[var(--border-subtle)] rounded-lg text-muted-foreground text-sm hover:bg-base-900 hover:text-foreground transition-smooth"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>
          <h1 className="font-display text-xl font-semibold">Incidents</h1>
        </div>

        {/* Subheader with filters and refresh */}
        <div className="flex items-center justify-between mb-6">
          <p className="text-muted-foreground text-sm">
            Security shutdowns, startup errors, and emergency audit fallbacks
          </p>

          <div className="flex items-center gap-3">
            {/* Proxy filter dropdown */}
            {proxies.length > 0 && (
              <div className="relative">
                <select
                  value={proxyFilter}
                  onChange={(e) => setProxyFilter(e.target.value)}
                  className="appearance-none bg-base-900 border border-base-700 rounded-lg px-3 py-1.5 pr-8 text-xs font-medium text-foreground cursor-pointer hover:border-base-600 focus:outline-none focus:ring-1 focus:ring-primary"
                  aria-label="Filter by proxy"
                >
                  {proxyOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
              </div>
            )}

            {/* Type filter dropdown */}
            <div className="relative">
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value as FilterType)}
                className="appearance-none bg-base-900 border border-base-700 rounded-lg px-3 py-1.5 pr-8 text-xs font-medium text-foreground cursor-pointer hover:border-base-600 focus:outline-none focus:ring-1 focus:ring-primary"
                aria-label="Filter by incident type"
              >
                {TYPE_FILTER_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={refresh}
              disabled={loading}
            >
              <RefreshCw className={cn('w-4 h-4 mr-2', loading && 'animate-spin')} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Content */}
        {loading && incidents.length === 0 ? (
          <div className="text-center py-16 text-muted-foreground">
            Loading incidents...
          </div>
        ) : incidents.length === 0 ? (
          <EmptyState typeFilter={typeFilter} proxyFilter={proxyFilter} />
        ) : (
          <div>
            {incidents.map((incident, index) => (
              <IncidentCard
                key={`${incident.incident_type}-${incident.time}-${index}`}
                incident={incident}
                isLast={index === incidents.length - 1 && !hasMore}
                isNew={isIncidentNew(incident.time)}
              />
            ))}

            {/* Load More */}
            {hasMore && (
              <div className="flex justify-center py-4">
                <Button
                  variant="outline"
                  onClick={loadMore}
                  disabled={loading}
                >
                  {loading ? 'Loading...' : 'Load More'}
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </Layout>
  )
}

interface EmptyStateProps {
  typeFilter: FilterType
  proxyFilter: string
}

function EmptyState({ typeFilter, proxyFilter }: EmptyStateProps) {
  // Build contextual message based on active filters
  const hasFilters = typeFilter !== 'all' || proxyFilter !== 'all'

  const typeLabel = typeFilter === 'shutdown'
    ? 'shutdowns'
    : typeFilter === 'bootstrap'
      ? 'startup errors'
      : typeFilter === 'emergency'
        ? 'emergency audit fallbacks'
        : 'incidents'

  const message = hasFilters
    ? `No ${typeLabel}${proxyFilter !== 'all' ? ` for ${proxyFilter}` : ''} recorded`
    : 'No incidents recorded'

  const description = hasFilters
    ? 'Try adjusting your filters or check back later.'
    : 'When security shutdowns, startup errors, or emergency audit fallbacks occur, they will appear here.'

  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-full bg-base-800 flex items-center justify-center mb-4">
        <ShieldAlert className="w-8 h-8 text-muted-foreground" />
      </div>
      <h2 className="text-lg font-medium mb-2">{message}</h2>
      <p className="text-sm text-muted-foreground max-w-md">
        {description}
      </p>
    </div>
  )
}
