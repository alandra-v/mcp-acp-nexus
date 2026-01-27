/**
 * Hook for fetching full proxy detail by proxy_id.
 *
 * Uses /api/manager/proxies/{proxy_id} which returns config + runtime data
 * including pending and cached approvals.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { getProxyDetail } from '@/api/proxies'
import { SSE_EVENTS } from '@/constants'
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

  // SSE event listeners for auto-refresh
  useEffect(() => {
    const handleRefresh = () => {
      controllerRef.current?.abort()
      const controller = new AbortController()
      controllerRef.current = controller
      fetchProxy(controller.signal)
    }

    window.addEventListener(SSE_EVENTS.PROXY_REGISTERED, handleRefresh)
    window.addEventListener(SSE_EVENTS.PROXY_DISCONNECTED, handleRefresh)
    return () => {
      controllerRef.current?.abort()
      window.removeEventListener(SSE_EVENTS.PROXY_REGISTERED, handleRefresh)
      window.removeEventListener(SSE_EVENTS.PROXY_DISCONNECTED, handleRefresh)
    }
  }, [fetchProxy])

  const refetch = useCallback(async () => {
    await fetchProxy()
  }, [fetchProxy])

  return { proxy, loading, error, refetch }
}
