import { useState, useEffect, useCallback, useRef } from 'react'
import {
  getAuthStatus,
  logout as apiLogout,
  logoutFederated as apiLogoutFederated,
  type AuthStatus,
} from '@/api/auth'
import { notifyError } from '@/hooks/useErrorSound'
import { useAppStore } from '@/store/appStore'

interface UseAuthReturn {
  status: AuthStatus | null
  loading: boolean
  loggingOut: boolean
  logout: () => Promise<void>
  logoutFederated: () => Promise<void>
  refresh: () => Promise<void>
  popupBlockedUrl: string | null
  clearPopupBlockedUrl: () => void
}

export function useAuth(): UseAuthReturn {
  const [status, setStatus] = useState<AuthStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [loggingOut, setLoggingOut] = useState(false)
  const [popupBlockedUrl, setPopupBlockedUrl] = useState<string | null>(null)

  // Subscribe to store signal counter
  const authVersion = useAppStore((s) => s.authVersion)

  // Track mount-time version to skip initial effect run
  const mountVersionRef = useRef(authVersion)

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true)
      const data = await getAuthStatus()
      setStatus(data)
    } catch {
      // Set not configured on error (can't reach manager)
      setStatus({
        configured: false,
        authenticated: false,
        subject_id: null,
        email: null,
        name: null,
        provider: null,
        client_id: null,
        audience: null,
        scopes: null,
        token_expires_in_hours: null,
        has_refresh_token: null,
        storage_backend: null,
      })
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    fetchStatus()
  }, [fetchStatus])

  // Refetch when authVersion changes (skip mount-time value)
  useEffect(() => {
    if (authVersion === mountVersionRef.current) return
    fetchStatus()
  }, [authVersion, fetchStatus])

  const logout = useCallback(async () => {
    try {
      setLoggingOut(true)
      await apiLogout()
      await fetchStatus()
      // Success toast handled by SSE auth_logout event
    } catch {
      notifyError('Logout failed')
    } finally {
      setLoggingOut(false)
    }
  }, [fetchStatus])

  const logoutFederated = useCallback(async () => {
    try {
      setLoggingOut(true)
      setPopupBlockedUrl(null)
      const response = await apiLogoutFederated()
      // Open logout URL in new window/tab
      const popup = window.open(response.logout_url, '_blank')
      if (!popup) {
        setPopupBlockedUrl(response.logout_url)
      }
      await fetchStatus()
      // Success toast handled by SSE auth_logout event
    } catch {
      notifyError('Logout failed')
    } finally {
      setLoggingOut(false)
    }
  }, [fetchStatus])

  const clearPopupBlockedUrl = useCallback(() => {
    setPopupBlockedUrl(null)
  }, [])

  return {
    status,
    loading,
    loggingOut,
    logout,
    logoutFederated,
    refresh: fetchStatus,
    popupBlockedUrl,
    clearPopupBlockedUrl,
  }
}
