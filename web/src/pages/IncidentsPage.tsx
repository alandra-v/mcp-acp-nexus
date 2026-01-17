/**
 * Incidents page - displays security shutdowns, startup errors, and emergency audit fallbacks.
 */

import { useEffect, useState, useMemo, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ArrowLeft, RefreshCw, ShieldAlert } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { Button } from '@/components/ui/button'
import { IncidentCard } from '@/components/incidents/IncidentCard'
import { useIncidents, type IncidentEntry } from '@/hooks/useIncidents'
import { useIncidentsContext } from '@/context/IncidentsContext'
import { cn } from '@/lib/utils'
import type { IncidentType } from '@/api/incidents'

type FilterType = 'all' | IncidentType

const FILTER_OPTIONS: { value: FilterType; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'shutdown', label: 'Shutdowns' },
  { value: 'bootstrap', label: 'Startup' },
  { value: 'emergency', label: 'Emergency Audit' },
]

export function IncidentsPage() {
  const navigate = useNavigate()
  const { incidents, loading, hasMore, loadMore, refresh } = useIncidents()
  const { markAsRead } = useIncidentsContext()
  const [filter, setFilter] = useState<FilterType>('all')

  const handleBack = useCallback(() => {
    navigate('/')
  }, [navigate])

  // Mark incidents as read when page is viewed
  useEffect(() => {
    // Small delay to ensure summary is loaded
    const timer = setTimeout(markAsRead, 500)
    return () => clearTimeout(timer)
  }, [markAsRead])

  // Filter incidents
  const filteredIncidents = useMemo<IncidentEntry[]>(() => {
    if (filter === 'all') return incidents
    return incidents.filter((i) => i.incident_type === filter)
  }, [incidents, filter])

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

        {/* Subheader with filter and refresh */}
        <div className="flex items-center justify-between mb-6">
          <p className="text-muted-foreground text-sm">
            Security shutdowns, startup errors, and emergency audit fallbacks
          </p>

          <div className="flex items-center gap-3">
            {/* Filter chips */}
            <div
              role="tablist"
              aria-label="Filter incidents"
              className="flex items-center gap-1 bg-base-900 rounded-lg p-1"
            >
              {FILTER_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  role="tab"
                  aria-selected={filter === option.value}
                  onClick={() => setFilter(option.value)}
                  className={cn(
                    'px-3 py-1 text-xs font-medium rounded-md transition-colors',
                    filter === option.value
                      ? 'bg-base-700 text-foreground'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  {option.label}
                </button>
              ))}
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
          <EmptyState />
        ) : filteredIncidents.length === 0 ? (
          <div className="text-center py-16 text-muted-foreground">
            No {filter === 'shutdown' ? 'shutdowns' : filter === 'bootstrap' ? 'startup errors' : 'emergency audit fallbacks'} recorded
          </div>
        ) : (
          <div>
            {filteredIncidents.map((incident, index) => (
              <IncidentCard
                key={`${incident.incident_type}-${incident.time}-${index}`}
                incident={incident}
                isLast={index === filteredIncidents.length - 1 && !hasMore}
              />
            ))}

            {/* Load More */}
            {hasMore && filter === 'all' && (
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

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-full bg-base-800 flex items-center justify-center mb-4">
        <ShieldAlert className="w-8 h-8 text-muted-foreground" />
      </div>
      <h2 className="text-lg font-medium mb-2">No incidents recorded</h2>
      <p className="text-sm text-muted-foreground max-w-md">
        When security shutdowns, startup errors, or emergency audit fallbacks occur, they will appear here.
      </p>
    </div>
  )
}
