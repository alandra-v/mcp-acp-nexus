import { useState, useEffect, useCallback, useRef } from 'react'
import { ProxyCard } from './ProxyCard'
import { getAggregatedIncidents } from '@/api/incidents'
import { verifyAuditLogs } from '@/api/audit'
import { DEFAULT_INCIDENT_LIMIT, INCIDENTS_STORAGE_KEYS } from '@/constants'
import { useAppStore } from '@/store/appStore'
import type { Proxy } from '@/types/api'

interface ProxyGridProps {
  proxies: Proxy[]
}

export function ProxyGrid({ proxies }: ProxyGridProps) {
  const [proxiesWithIncidents, setProxiesWithIncidents] = useState<Set<string>>(new Set())
  const [proxiesWithAuditIssues, setProxiesWithAuditIssues] = useState<Set<string>>(new Set())
  const incidentAbortRef = useRef<AbortController | null>(null)
  const auditAbortRef = useRef<AbortController | null>(null)

  // Subscribe to store signal counters
  const incidentsVersion = useAppStore((s) => s.incidentsVersion)
  const incidentsMarkedReadVersion = useAppStore((s) => s.incidentsMarkedReadVersion)
  const proxyListVersion = useAppStore((s) => s.proxyListVersion)

  // Track mount-time versions to skip initial effect run
  const mountIncidentsVersionRef = useRef(incidentsVersion)
  const mountIncidentsMarkedReadVersionRef = useRef(incidentsMarkedReadVersion)
  const mountProxyListVersionRef = useRef(proxyListVersion)

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

  // Initial fetch and cross-tab localStorage sync
  useEffect(() => {
    fetchIncidents()

    // Listen for cross-tab localStorage changes
    const handleStorage = (e: StorageEvent) => {
      if (e.key === INCIDENTS_STORAGE_KEYS.LAST_SEEN_TIMESTAMP) {
        fetchIncidents()
      }
    }
    window.addEventListener('storage', handleStorage)

    return () => {
      incidentAbortRef.current?.abort()
      window.removeEventListener('storage', handleStorage)
    }
  }, [fetchIncidents])

  // Refetch incidents when incidentsVersion changes (skip mount-time value)
  useEffect(() => {
    if (incidentsVersion === mountIncidentsVersionRef.current) return
    fetchIncidents()
  }, [incidentsVersion, fetchIncidents])

  // Refetch incidents when incidentsMarkedReadVersion changes (skip mount-time value)
  useEffect(() => {
    if (incidentsMarkedReadVersion === mountIncidentsMarkedReadVersionRef.current) return
    fetchIncidents()
  }, [incidentsMarkedReadVersion, fetchIncidents])

  // Fetch audit status when proxies change
  useEffect(() => {
    if (proxies.length > 0) {
      fetchAuditStatus(proxies)
    }

    return () => {
      auditAbortRef.current?.abort()
    }
  }, [proxies, fetchAuditStatus])

  // Refetch audit status when proxyListVersion changes (skip mount-time value)
  useEffect(() => {
    if (proxyListVersion === mountProxyListVersionRef.current) return
    if (proxies.length > 0) {
      fetchAuditStatus(proxies)
    }
  }, [proxyListVersion, proxies, fetchAuditStatus])

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
