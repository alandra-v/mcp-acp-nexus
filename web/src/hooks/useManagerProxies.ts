/**
 * Hook for fetching all configured proxies from the manager.
 *
 * Uses /api/manager/proxies which returns all configured proxies
 * (not just running ones) with config + runtime data.
 */

import { useState, useEffect, useCallback, useRef } from 'react'
import { getManagerProxies } from '@/api/proxies'
import { notifyError } from '@/hooks/useErrorSound'
import { SSE_EVENTS } from '@/constants'
import type { EnhancedProxy } from '@/types/api'

export interface UseManagerProxiesResult {
  proxies: EnhancedProxy[]
  loading: boolean
  error: Error | null
  refetch: () => Promise<void>
}

export function useManagerProxies(): UseManagerProxiesResult {
  const [proxies, setProxies] = useState<EnhancedProxy[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const hasShownErrorRef = useRef(false)
  const mountedRef = useRef(true)

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

  // Listen for proxy_registered and proxy_disconnected SSE events to refetch
  // Track controller to abort in-flight requests when new events arrive
  const sseControllerRef = useRef<AbortController | null>(null)

  useEffect(() => {
    const handleProxyChange = () => {
      // Abort any in-flight SSE-triggered fetch
      sseControllerRef.current?.abort()
      const controller = new AbortController()
      sseControllerRef.current = controller
      fetchProxies(controller.signal)
    }

    window.addEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)
    window.addEventListener(SSE_EVENTS.PROXY_DISCONNECTED, handleProxyChange)
    return () => {
      // Abort any in-flight fetch on cleanup
      sseControllerRef.current?.abort()
      window.removeEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)
      window.removeEventListener(SSE_EVENTS.PROXY_DISCONNECTED, handleProxyChange)
    }
  }, [fetchProxies])

  const refetch = useCallback(async () => {
    await fetchProxies()
  }, [fetchProxies])

  return { proxies, loading, error, refetch }
}
