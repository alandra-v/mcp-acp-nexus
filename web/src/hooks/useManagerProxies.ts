/**
 * Hook for fetching all configured proxies from the manager.
 *
 * Uses /api/manager/proxies which returns all configured proxies
 * (not just running ones) with config + runtime data.
 *
 * Subscribes to Zustand store for SSE-driven updates instead of window events.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { getManagerProxies } from '@/api/proxies'
import { notifyError } from '@/hooks/useErrorSound'
import { useAppStore } from '@/store/appStore'
import type { Proxy } from '@/types/api'

export interface UseManagerProxiesResult {
  proxies: Proxy[]
  loading: boolean
  error: Error | null
  refetch: () => Promise<void>
}

export function useManagerProxies(): UseManagerProxiesResult {
  const [proxies, setProxies] = useState<Proxy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const hasShownErrorRef = useRef(false)
  const mountedRef = useRef(true)

  // Subscribe to store signal counters and stats
  const proxyListVersion = useAppStore((s) => s.proxyListVersion)
  const storeStats = useAppStore((s) => s.stats)

  // Shared controller ref: any new fetch (initial or SSE-triggered) aborts the
  // previous in-flight request.  This prevents a slow initial fetch from
  // overwriting a fresher SSE-triggered refetch with stale data.
  const controllerRef = useRef<AbortController | null>(null)

  // Track mount-time version to skip initial effect run
  const mountVersionRef = useRef(proxyListVersion)

  const fetchProxies = useCallback(async (signal?: AbortSignal) => {
    try {
      setLoading(true)
      setError(null)
      const data = await getManagerProxies({ signal })
      if (mountedRef.current) {
        setProxies(data)
        hasShownErrorRef.current = false
      }
    } catch (err) {
      // Ignore abort errors
      if (err instanceof DOMException && err.name === 'AbortError') return

      if (mountedRef.current) {
        const error = err instanceof Error ? err : new Error('Failed to connect to manager')
        setError(error)
        if (!hasShownErrorRef.current) {
          notifyError('Failed to connect to manager')
          hasShownErrorRef.current = true
        }
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }
  }, [])

  // Initial fetch — abort on unmount or when an SSE-triggered fetch supersedes
  useEffect(() => {
    mountedRef.current = true
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    fetchProxies(controller.signal)
    return () => {
      mountedRef.current = false
      controller.abort()
    }
  }, [fetchProxies])

  // Refetch when proxyListVersion changes (skip mount-time value)
  useEffect(() => {
    // Skip if this is the mount-time value
    if (proxyListVersion === mountVersionRef.current) return

    // Abort any in-flight fetch (initial or previous SSE-triggered)
    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    fetchProxies(controller.signal)

    return () => {
      controller.abort()
    }
  }, [proxyListVersion, fetchProxies])

  // Update proxy stats from store (no refetch needed)
  useEffect(() => {
    setProxies((prev) => {
      // Skip no-op on mount when proxies haven't loaded yet
      if (prev.length === 0) return prev
      return prev.map((p) => {
        const updated = storeStats[p.proxy_id]
        return updated ? { ...p, stats: updated } : p
      })
    })
  }, [storeStats])

  const refetch = useCallback(async () => {
    await fetchProxies()
  }, [fetchProxies])

  return { proxies, loading, error, refetch }
}
