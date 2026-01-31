/**
 * Proxy list page - landing page showing all configured proxies.
 *
 * Features:
 * - Filter chips (All, Running, Inactive)
 * - Grid of proxy cards with name, server, cmd/url, status, stats
 * - "Add Proxy" button opens modal
 * - "Export All" button copies Claude Desktop JSON config
 * - Empty state for no proxies configured
 */

import { useState, useEffect, useMemo, useCallback } from 'react'
import { Plus, Copy, Check, Server } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { Button } from '@/components/ui/button'
import { ProxyGrid } from '@/components/proxies/ProxyGrid'
import { ProxyGridSkeleton } from '@/components/proxies/ProxyCardSkeleton'
import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useAppState } from '@/context/AppStateContext'
import { getConfigSnippet } from '@/api/proxies'
import { AddProxyModal } from '@/components/proxy/AddProxyModal'
import { notifyError } from '@/hooks/useErrorSound'
import { COPY_FEEDBACK_DURATION_MS } from '@/constants'
import { cn } from '@/lib/utils'

type FilterType = 'all' | 'active' | 'inactive'

const FILTER_STORAGE_KEY = 'proxyListFilter'

function EmptyState({ onAddProxy }: { onAddProxy: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-full bg-base-800 flex items-center justify-center mb-4">
        <Server className="w-8 h-8 text-muted-foreground" />
      </div>
      <h2 className="text-lg font-medium mb-2">No proxies configured</h2>
      <p className="text-muted-foreground mb-6 max-w-md">
        Add your first proxy to start managing MCP server connections with human-in-the-loop approval.
      </p>
      <Button onClick={onAddProxy}>
        <Plus className="w-4 h-4 mr-2" />
        Add Proxy
      </Button>
    </div>
  )
}

export function ProxyListPage() {
  const { proxies: rawProxies, loading: proxiesLoading, refetch } = useManagerProxies()
  const { stats: sseStats } = useAppState()

  // Merge SSE-maintained stats as fallback when API returns null stats.
  // AppStateContext persists across SPA navigation and always has the latest
  // stats from SSE events, covering the case where the backend UDS stats
  // fetch times out or fails on the initial API call after navigation.
  const proxies = useMemo(() =>
    rawProxies.map(p => {
      if (p.stats) return p
      const fallback = sseStats[p.proxy_id]
      return fallback ? { ...p, stats: fallback } : p
    }),
    [rawProxies, sseStats]
  )

  const [filter, setFilter] = useState<FilterType>(() => {
    const stored = localStorage.getItem(FILTER_STORAGE_KEY)
    return stored === 'active' || stored === 'inactive' ? stored : 'all'
  })
  const [addModalOpen, setAddModalOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  // Persist filter to localStorage
  useEffect(() => {
    localStorage.setItem(FILTER_STORAGE_KEY, filter)
  }, [filter])

  // Calculate counts
  const counts = useMemo(() => {
    const active = proxies.filter((p) => p.status === 'running').length
    const inactive = proxies.filter((p) => p.status !== 'running').length
    return { total: proxies.length, active, inactive }
  }, [proxies])

  // Filter proxies
  const filteredProxies = useMemo(() => {
    switch (filter) {
      case 'active':
        return proxies.filter((p) => p.status === 'running')
      case 'inactive':
        return proxies.filter((p) => p.status !== 'running')
      default:
        return proxies
    }
  }, [proxies, filter])

  const filterOptions: { value: FilterType; label: string; count: number }[] = [
    { value: 'all', label: 'All', count: counts.total },
    { value: 'active', label: 'Running', count: counts.active },
    { value: 'inactive', label: 'Inactive', count: counts.inactive },
  ]

  const handleCopyAll = useCallback(async () => {
    if (proxies.length === 0) return

    try {
      const response = await getConfigSnippet()
      await navigator.clipboard.writeText(JSON.stringify({ mcpServers: response.mcpServers }, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), COPY_FEEDBACK_DURATION_MS)
    } catch {
      notifyError('Failed to copy config')
    }
  }, [proxies.length])

  const handleProxyCreated = useCallback(() => {
    refetch()
  }, [refetch])

  return (
    <Layout>
      <div className="max-w-[1200px] mx-auto px-8 py-12">
        {/* Page header */}
        <div className="flex items-start justify-between mb-10">
          <div>
            <h1 className="font-display text-3xl font-semibold tracking-tight mb-2">
              Proxies
            </h1>
            <p className="text-muted-foreground text-base">
              Manage your MCP proxy connections
            </p>
          </div>
          <div className="flex items-center gap-2">
            {proxies.length > 0 && (
              <Button variant="outline" onClick={handleCopyAll}>
                {copied ? (
                  <>
                    <Check className="w-4 h-4 mr-2" />
                    Copied!
                  </>
                ) : (
                  <>
                    <Copy className="w-4 h-4 mr-2" />
                    Export All Client Configs
                  </>
                )}
              </Button>
            )}
            <Button onClick={() => setAddModalOpen(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Add Proxy
            </Button>
          </div>
        </div>

        {proxiesLoading ? (
          <ProxyGridSkeleton count={3} />
        ) : proxies.length === 0 ? (
          <EmptyState onAddProxy={() => setAddModalOpen(true)} />
        ) : (
          <>
            {/* Filter chips */}
            <div className="flex items-center gap-4 mb-8">
              <div
                role="tablist"
                aria-label="Filter proxies"
                className="flex items-center gap-1 bg-base-900 rounded-lg p-1"
              >
                {filterOptions.map((option) => (
                  <button
                    key={option.value}
                    role="tab"
                    aria-selected={filter === option.value}
                    onClick={() => setFilter(option.value)}
                    className={cn(
                      'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                      filter === option.value
                        ? 'bg-base-700 text-foreground'
                        : 'text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {option.label}
                    <span className="ml-1.5 text-xs opacity-60">({option.count})</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Proxy grid */}
            <ProxyGrid proxies={filteredProxies} />

            {/* Hint */}
            <div className="text-center mt-12 text-base-600 text-sm">
              Click a proxy to view details, logs, and configuration
            </div>
          </>
        )}
      </div>

      {/* Add proxy modal */}
      <AddProxyModal
        open={addModalOpen}
        onOpenChange={setAddModalOpen}
        onCreated={handleProxyCreated}
      />
    </Layout>
  )
}
