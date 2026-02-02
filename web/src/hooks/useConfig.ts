import { useState, useEffect, useCallback, useRef } from 'react'
import {
  getConfig,
  updateConfig,
  compareConfig,
  compareProxyConfig,
  getProxyConfig,
  updateProxyConfig,
  ConfigResponse,
  ConfigUpdateRequest,
  ConfigChange,
} from '@/api/config'
import { toast } from '@/components/ui/sonner'
import { notifyError } from '@/hooks/useErrorSound'

export interface UseConfigResult {
  config: ConfigResponse | null
  loading: boolean
  saving: boolean
  error: string | null
  /** Changes between running and saved config (from file) */
  pendingChanges: ConfigChange[]
  /** True if saved config differs from running config */
  hasPendingChanges: boolean
  save: (updates: ConfigUpdateRequest) => Promise<boolean>
  refresh: () => Promise<void>
  /** Update config state locally without a server round-trip */
  setConfig: React.Dispatch<React.SetStateAction<ConfigResponse | null>>
}

/** Options for useConfig hook */
export interface UseConfigOptions {
  /**
   * When provided, uses manager-level endpoints to access config
   * regardless of whether the proxy is running.
   * When undefined, uses the default proxy-level endpoints.
   *
   * When the proxy is running, the manager returns the in-memory
   * (running) config and comparison is available via UDS forwarding.
   */
  proxyId?: string
}

/**
 * Hook for fetching and updating proxy configuration.
 *
 * Returns:
 * - config: The current configuration (null while loading)
 * - loading: True while fetching config
 * - saving: True while saving updates
 * - error: Error message if fetch failed
 * - pendingChanges: List of changes between running and saved config
 * - hasPendingChanges: True if saved config differs from running
 * - save: Function to save updates (returns true on success)
 * - refresh: Function to re-fetch config
 *
 * @param options - Optional configuration including proxyId for manager-level access
 */
export function useConfig(options?: UseConfigOptions): UseConfigResult {
  const proxyId = options?.proxyId
  const [config, setConfig] = useState<ConfigResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pendingChanges, setPendingChanges] = useState<ConfigChange[]>([])
  const [hasPendingChanges, setHasPendingChanges] = useState(false)
  const mountedRef = useRef(true)

  const fetchComparison = useCallback(async () => {
    try {
      const comparison = proxyId
        ? await compareProxyConfig(proxyId)
        : await compareConfig()
      if (mountedRef.current) {
        setPendingChanges(comparison.changes)
        setHasPendingChanges(comparison.has_changes)
      }
    } catch {
      // Comparison failed - that's OK, just don't show pending changes
      if (mountedRef.current) {
        setPendingChanges([])
        setHasPendingChanges(false)
      }
    }
  }, [proxyId])

  const fetchConfig = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      // Fetch config (use manager endpoint if proxyId provided)
      const configData = proxyId
        ? await getProxyConfig(proxyId)
        : await getConfig()
      if (mountedRef.current) {
        setConfig(configData)
      }
    } catch (e) {
      if (mountedRef.current) {
        const msg = e instanceof Error ? e.message : 'Failed to load config'
        setError(msg)
        notifyError(msg)
      }
    } finally {
      if (mountedRef.current) {
        setLoading(false)
      }
    }

    // Fetch comparison non-blocking (after loading is done)
    fetchComparison()
  }, [proxyId, fetchComparison])

  const save = useCallback(async (updates: ConfigUpdateRequest): Promise<boolean> => {
    setSaving(true)
    try {
      const result = proxyId
        ? await updateProxyConfig(proxyId, updates)
        : await updateConfig(updates)
      if (mountedRef.current) {
        setConfig(result.config)
        toast.success(result.message)
        // Re-fetch comparison after save so pending changes table updates
        fetchComparison()
      }
      return true
    } catch (e) {
      if (mountedRef.current) {
        // Try to extract error detail from API response
        let msg = 'Failed to save config'
        if (e instanceof Error) {
          // API errors include the detail in the message
          msg = e.message
        }
        notifyError(msg)
      }
      return false
    } finally {
      if (mountedRef.current) {
        setSaving(false)
      }
    }
  }, [proxyId, fetchComparison])

  useEffect(() => {
    mountedRef.current = true
    fetchConfig()
    return () => {
      mountedRef.current = false
    }
  }, [fetchConfig])

  return {
    config,
    loading,
    saving,
    error,
    pendingChanges,
    hasPendingChanges,
    save,
    refresh: fetchConfig,
    setConfig,
  }
}
