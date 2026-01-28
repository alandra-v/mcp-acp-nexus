import { useState, useEffect, useCallback, useRef } from 'react'
import { ProxyCard } from './ProxyCard'
import { getAggregatedIncidents } from '@/api/incidents'
import type { Proxy } from '@/types/api'

interface ProxyGridProps {
  proxies: Proxy[]
}

export function ProxyGrid({ proxies }: ProxyGridProps) {
  const [proxiesWithIssues, setProxiesWithIssues] = useState<Set<string>>(new Set())
  const abortControllerRef = useRef<AbortController | null>(null)

  const fetchIncidents = useCallback(async () => {
    abortControllerRef.current?.abort()
    const controller = new AbortController()
    abortControllerRef.current = controller

    try {
      const response = await getAggregatedIncidents(
        { time_range: '7d', limit: 100 },
        { signal: controller.signal }
      )
      // Extract proxy names from shutdown incidents
      const names = new Set<string>()
      for (const entry of response.entries) {
        if (entry.proxy_name) {
          names.add(entry.proxy_name)
        }
      }
      setProxiesWithIssues(names)
    } catch (error) {
      // Ignore abort errors
      if (error instanceof DOMException && error.name === 'AbortError') {
        return
      }
    }
  }, [])

  useEffect(() => {
    fetchIncidents()

    // Listen for incidents updates
    const handleIncidentsUpdated = () => {
      fetchIncidents()
    }
    window.addEventListener('incidents-updated', handleIncidentsUpdated)

    return () => {
      abortControllerRef.current?.abort()
      window.removeEventListener('incidents-updated', handleIncidentsUpdated)
    }
  }, [fetchIncidents])

  if (proxies.length === 0) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        No proxies found
      </div>
    )
  }

  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] gap-5">
      {proxies.map((proxy) => (
        <ProxyCard
          key={proxy.proxy_id}
          proxy={proxy}
          hasIssues={proxiesWithIssues.has(proxy.proxy_name)}
        />
      ))}
    </div>
  )
}
