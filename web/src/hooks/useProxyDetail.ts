/**
 * Hook for fetching full proxy detail by proxy_id.
 *
 * Uses /api/manager/proxies/{proxy_id} which returns config + runtime data
 * including pending and cached approvals.
 *
 * Subscribes to Zustand store for SSE-driven updates instead of window events.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { getProxyDetail } from '@/api/proxies'
import { useAppStore } from '@/store/appStore'
import type { ProxyDetailResponse } from '@/types/api'

export interface UseProxyDetailResult {
  proxy: ProxyDetailResponse | null
  loading: boolean
  error: Error | null
  refetch: () => Promise<void>
}

export function useProxyDetail(proxyId: string | undefined): UseProxyDetailResult {
  const [proxy, setProxy] = useState<ProxyDetailResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  // Subscribe to store signal counter
  const proxyListVersion = useAppStore((s) => s.proxyListVersion)

  // Track mount-time version to skip initial effect run
  const mountVersionRef = useRef(proxyListVersion)

  const fetchProxy = useCallback(async (signal?: AbortSignal) => {
    if (!proxyId) {
      setLoading(false)
      return
    }
    try {
      setLoading(true)
      setError(null)
      const data = await getProxyDetail(proxyId, { signal })
      setProxy(data)
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      setError(err instanceof Error ? err : new Error('Failed to load proxy'))
    } finally {
      setLoading(false)
    }
  }, [proxyId])

  // Initial fetch with cleanup
  useEffect(() => {
    const controller = new AbortController()
    controllerRef.current = controller
    fetchProxy(controller.signal)
    return () => controller.abort()
  }, [fetchProxy])

  // Refetch when proxyListVersion changes (skip mount-time value)
  useEffect(() => {
    // Skip if this is the mount-time value
    if (proxyListVersion === mountVersionRef.current) return

    controllerRef.current?.abort()
    const controller = new AbortController()
    controllerRef.current = controller
    fetchProxy(controller.signal)

    return () => {
      controller.abort()
    }
  }, [proxyListVersion, fetchProxy])

  const refetch = useCallback(async () => {
    await fetchProxy()
  }, [fetchProxy])

  return { proxy, loading, error, refetch }
}
