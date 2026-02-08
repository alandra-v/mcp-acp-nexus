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

  // Initial fetch with AbortController cleanup
  useEffect(() => {
    mountedRef.current = true
    const controller = new AbortController()
    fetchProxies(controller.signal)
    return () => {
      mountedRef.current = false
      controller.abort()
    }
  }, [fetchProxies])

  // Refetch when proxyListVersion changes (skip mount-time value)
  const sseControllerRef = useRef<AbortController | null>(null)

  useEffect(() => {
    // Skip if this is the mount-time value
    if (proxyListVersion === mountVersionRef.current) return

    // Abort any in-flight SSE-triggered fetch
    sseControllerRef.current?.abort()
    const controller = new AbortController()
    sseControllerRef.current = controller
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
