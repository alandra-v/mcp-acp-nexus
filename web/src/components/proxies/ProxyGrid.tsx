import { useState, useEffect, useCallback, useRef } from 'react'
import { ProxyCard } from './ProxyCard'
import { getAggregatedIncidents } from '@/api/incidents'
import { verifyAuditLogs } from '@/api/audit'
import {
  DEFAULT_INCIDENT_LIMIT,
  INCIDENTS_STORAGE_KEYS,
  SSE_EVENTS,
} from '@/constants'
import type { Proxy } from '@/types/api'

interface ProxyGridProps {
  proxies: Proxy[]
}

export function ProxyGrid({ proxies }: ProxyGridProps) {
  const [proxiesWithIncidents, setProxiesWithIncidents] = useState<Set<string>>(new Set())
  const [proxiesWithAuditIssues, setProxiesWithAuditIssues] = useState<Set<string>>(new Set())
  const incidentAbortRef = useRef<AbortController | null>(null)
  const auditAbortRef = useRef<AbortController | null>(null)

  const fetchIncidents = useCallback(async () => {
    incidentAbortRef.current?.abort()
    const controller = new AbortController()
    incidentAbortRef.current = controller

    try {
      const response = await getAggregatedIncidents(
        { limit: DEFAULT_INCIDENT_LIMIT },
        { signal: controller.signal }
      )

      // Get last seen timestamp to filter for unread incidents only
      const lastSeenTimestamp = localStorage.getItem(INCIDENTS_STORAGE_KEYS.LAST_SEEN_TIMESTAMP)
      const lastSeenDate = lastSeenTimestamp ? new Date(lastSeenTimestamp) : null

      // Extract proxy identifiers from unread incidents only
      const ids = new Set<string>()
      for (const entry of response.entries) {
        const proxyKey = entry.proxy_id ?? entry.proxy_name
        if (proxyKey) {
          // Only mark as issue if incident is newer than last seen
          const entryTime = new Date(entry.time)
          if (!lastSeenDate || entryTime > lastSeenDate) {
            ids.add(proxyKey)
          }
        }
      }
      setProxiesWithIncidents(ids)
    } catch (error) {
      // Ignore abort errors
      if (error instanceof DOMException && error.name === 'AbortError') {
        return
      }
    }
  }, [])

  // Fetch audit status for all proxies
  const fetchAuditStatus = useCallback(async (proxyList: Proxy[]) => {
    auditAbortRef.current?.abort()
    const controller = new AbortController()
    auditAbortRef.current = controller

    const auditIssues = new Set<string>()

    // Check audit status for each proxy in parallel
    const results = await Promise.allSettled(
      proxyList.map(async (proxy) => {
        try {
          const status = await verifyAuditLogs(proxy.proxy_id, {
            signal: controller.signal,
          })
          if (status.total_broken > 0) {
            return proxy.proxy_id
          }
        } catch (error) {
          // Ignore abort and other errors - audit status is non-critical
          if (error instanceof DOMException && error.name === 'AbortError') {
            return null
          }
        }
        return null
      })
    )

    // Don't update state if aborted
    if (controller.signal.aborted) {
      return
    }

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        auditIssues.add(result.value)
      }
    }

    setProxiesWithAuditIssues(auditIssues)
  }, [])

  useEffect(() => {
    fetchIncidents()

    // Listen for incidents updates (new incidents)
    const handleIncidentsUpdated = () => {
      fetchIncidents()
    }
    window.addEventListener(SSE_EVENTS.INCIDENTS_UPDATED, handleIncidentsUpdated)

    // Listen for when user marks incidents as read (same tab)
    const handleMarkedRead = () => {
      fetchIncidents()
    }
    window.addEventListener(SSE_EVENTS.INCIDENTS_MARKED_READ, handleMarkedRead)

    // Listen for cross-tab localStorage changes
    const handleStorage = (e: StorageEvent) => {
      if (e.key === INCIDENTS_STORAGE_KEYS.LAST_SEEN_TIMESTAMP) {
        fetchIncidents()
      }
    }
    window.addEventListener('storage', handleStorage)

    return () => {
      incidentAbortRef.current?.abort()
      window.removeEventListener(SSE_EVENTS.INCIDENTS_UPDATED, handleIncidentsUpdated)
      window.removeEventListener(SSE_EVENTS.INCIDENTS_MARKED_READ, handleMarkedRead)
      window.removeEventListener('storage', handleStorage)
    }
  }, [fetchIncidents])

  // Fetch audit status when proxies change
  useEffect(() => {
    if (proxies.length > 0) {
      fetchAuditStatus(proxies)
    }

    // Re-fetch audit status when proxy connects/disconnects
    const handleProxyChange = () => {
      if (proxies.length > 0) {
        fetchAuditStatus(proxies)
      }
    }
    window.addEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)

    return () => {
      auditAbortRef.current?.abort()
      window.removeEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)
    }
  }, [proxies, fetchAuditStatus])

  if (proxies.length === 0) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        No proxies found
      </div>
    )
  }

  // Combine incidents and audit issues (keyed by proxy_id)
  const hasIssues = (proxyId: string) =>
    proxiesWithIncidents.has(proxyId) || proxiesWithAuditIssues.has(proxyId)

  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] gap-5">
      {proxies.map((proxy) => (
        <ProxyCard
          key={proxy.proxy_id}
          proxy={proxy}
          hasIssues={hasIssues(proxy.proxy_id)}
        />
      ))}
    </div>
  )
}
