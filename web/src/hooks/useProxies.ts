import { useState, useEffect, useCallback, useRef } from 'react'
import { getProxies } from '@/api/proxies'
import { notifyError } from '@/hooks/useErrorSound'
import type { Proxy } from '@/types/api'

export interface UseProxiesResult {
  proxies: Proxy[]
  loading: boolean
  refetch: () => Promise<void>
}

export function useProxies(): UseProxiesResult {
  const [proxies, setProxies] = useState<Proxy[]>([])
  const [loading, setLoading] = useState(true)
  const hasShownErrorRef = useRef(false)

  const fetchProxies = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getProxies()
      setProxies(data)
      hasShownErrorRef.current = false
    } catch {
      if (!hasShownErrorRef.current) {
        notifyError('Failed to load proxies')
        hasShownErrorRef.current = true
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchProxies()
  }, [fetchProxies])

  // Listen for proxy_registered SSE event to refetch
  useEffect(() => {
    const handleProxyRegistered = () => {
      fetchProxies()
    }

    window.addEventListener('proxy-registered', handleProxyRegistered)
    return () => window.removeEventListener('proxy-registered', handleProxyRegistered)
  }, [fetchProxies])

  return { proxies, loading, refetch: fetchProxies }
}
