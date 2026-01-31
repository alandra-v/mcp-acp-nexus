import { createContext, useContext, useState, useEffect, useCallback, useRef, type ReactNode } from 'react'
import { subscribeToPendingApprovals, approveRequest, approveOnceRequest, denyRequest, fetchCachedApprovals, clearCachedApprovals, deleteCachedApproval } from '@/api/approvals'
import { toast } from '@/components/ui/sonner'
import { playApprovalChime } from '@/hooks/useNotificationSound'
import { playErrorSound, notifyError } from '@/hooks/useErrorSound'
import { requestNotificationPermission, showApprovalNotification } from '@/lib/notifications'
import { ApiError, type CachedApproval, type PendingApproval, type ProxyStats, type SSEEvent, type SSEEventType, type SSEProxyDisconnectedEvent, type SSESystemEvent } from '@/types/api'

const ORIGINAL_TITLE = 'MCP ACP'
const SHUTDOWN_TOAST_ID = 'proxy-shutdown'

// Default messages for system events
const DEFAULT_MESSAGES: Partial<Record<SSEEventType, string>> = {
  // Backend connection
  backend_connected: 'Backend connected',
  backend_reconnected: 'Backend reconnected',
  backend_disconnected: 'Backend connection lost',
  backend_timeout: 'Backend connection timeout',
  backend_refused: 'Backend connection refused',
  // TLS/mTLS
  tls_error: 'SSL/TLS certificate error',
  mtls_failed: 'mTLS handshake failed',
  cert_validation_failed: 'Server certificate validation failed',
  // Authentication
  auth_login: 'Logged in',
  auth_logout: 'Logged out',
  auth_login_failed: 'Login failed',
  auth_session_expiring: 'Session expiring soon',
  token_refresh_failed: 'Session expired - please log in again',
  token_validation_failed: 'Token validation failed',
  auth_failure: 'Authentication failed',
  // Policy
  policy_reloaded: 'Policy reloaded',
  policy_reload_failed: 'Policy reload failed - using last known good',
  policy_file_not_found: 'Policy file not found - using last known good',
  policy_rollback: 'Policy rolled back',
  config_change_detected: 'Config change detected',
  // Rate limiting
  rate_limit_triggered: 'Rate limit exceeded',
  rate_limit_approved: 'Rate limit breach approved',
  rate_limit_denied: 'Rate limit breach denied',
  // Cache
  cache_cleared: 'Approval cache cleared',
  cache_entry_deleted: 'Cached approval deleted',
  // Request processing
  request_error: 'Request processing error',
  hitl_parse_failed: 'HITL request parse failed',
  tool_sanitization_failed: 'Tool sanitization failed',
  pending_not_found: 'Approval not found (may have timed out)',
  // Critical events
  critical_shutdown: 'Proxy shutting down',
  audit_init_failed: 'Audit log initialization failed',
  device_health_failed: 'Device health check failed',
  session_hijacking: 'Session binding violation detected',
  audit_tampering: 'Audit log tampering detected',
  audit_missing: 'Audit log file missing',
  audit_permission_denied: 'Audit log permission denied',
  health_degraded: 'Device health degraded',
  health_monitor_failed: 'Health monitor failed',
}

// Auth event types that should trigger auth state refresh
const AUTH_CHANGE_EVENTS = new Set([
  'auth_login',
  'auth_logout',
  'auth_login_failed',
  'token_refresh_failed',
])

function showSystemToast(event: SSESystemEvent) {
  const message = event.message || DEFAULT_MESSAGES[event.type] || event.type
  const severity = event.severity || 'info'

  switch (severity) {
    case 'success':
      toast.success(message)
      break
    case 'warning':
      toast.warning(message)
      break
    case 'error':
      notifyError(message)
      break
    case 'critical':
      // Critical events stay longer than normal errors but still auto-dismiss
      toast.error(message, { duration: 15_000 })
      playErrorSound()
      break
    case 'info':
    default:
      toast.info(message)
  }

  // Dispatch custom event for auth state changes
  if (AUTH_CHANGE_EVENTS.has(event.type)) {
    window.dispatchEvent(new CustomEvent('auth-state-changed', { detail: event.type }))
  }
}

export type ConnectionStatus = 'connected' | 'reconnecting' | 'disconnected'

interface AppStateContextValue {
  pending: PendingApproval[]
  cached: CachedApproval[]
  cachedTtlSeconds: number
  stats: ProxyStats | null
  connected: boolean
  connectionStatus: ConnectionStatus
  approve: (id: string) => Promise<void>
  approveOnce: (id: string) => Promise<void>
  deny: (id: string) => Promise<void>
  clearCached: () => Promise<void>
  deleteCached: (subjectId: string, toolName: string, path: string | null) => Promise<void>
}

const AppStateContext = createContext<AppStateContextValue | null>(null)

// Max errors before showing "disconnected" instead of "reconnecting"
const MAX_RECONNECT_ERRORS = 5

export function AppStateProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingApproval[]>([])
  const [cached, setCached] = useState<CachedApproval[]>([])
  const [cachedTtlSeconds, setCachedTtlSeconds] = useState(0)
  const [stats, setStats] = useState<ProxyStats | null>(null)
  const [connected, setConnected] = useState(false)
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('reconnecting')

  // Track connection errors to avoid spamming toasts on repeated reconnect failures
  const errorCountRef = useRef(0)
  const isShutdownRef = useRef(false)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Update document title when pending count changes
  useEffect(() => {
    if (pending.length > 0) {
      document.title = `🔴 (${pending.length}) ${ORIGINAL_TITLE}`
    } else {
      document.title = ORIGINAL_TITLE
    }
  }, [pending.length])

  useEffect(() => {
    const handleEvent = (event: SSEEvent) => {
      switch (event.type) {
        // HITL-specific events
        case 'snapshot': {
          const snapshotApprovals = (event.approvals || []).map((a) =>
            event.proxy_name ? { ...a, proxy_name: event.proxy_name } : a
          )
          setPending(snapshotApprovals)
          setConnected(true)
          setConnectionStatus('connected')
          // Reset error count on successful reconnect
          errorCountRef.current = 0
          // Dismiss shutdown toast if proxy was restarted
          if (isShutdownRef.current) {
            toast.dismiss(SHUTDOWN_TOAST_ID)
            isShutdownRef.current = false
          }
          break
        }
        case 'pending_created':
          if (event.approval) {
            const created = event.proxy_name
              ? { ...event.approval, proxy_name: event.proxy_name }
              : event.approval
            setPending((prev) => [...prev, created])
            playApprovalChime()
            // Request notification permission on first approval, then show notification
            requestNotificationPermission()
              .then(() => showApprovalNotification(created))
              .catch(() => {}) // Notification errors are non-critical
          }
          break
        case 'pending_resolved':
          if (event.approval_id) {
            setPending((prev) => prev.filter((p) => p.id !== event.approval_id))
          }
          break
        case 'pending_timeout':
          if (event.approval_id) {
            setPending((prev) => prev.filter((p) => p.id !== event.approval_id))
            toast.warning('Approval request timed out')
          }
          break

        // Cached approvals snapshot (full state from SSE, per-proxy)
        case 'cached_snapshot': {
          const eventProxyId = event.proxy_id
          const tagged = (event.approvals || []).map((a) =>
            eventProxyId ? { ...a, proxy_id: eventProxyId } : a
          )
          if (eventProxyId) {
            // Merge: replace this proxy's entries, keep others
            setCached((prev) => [
              ...prev.filter((c) => c.proxy_id !== eventProxyId),
              ...tagged,
            ])
          } else {
            setCached(tagged)
          }
          if (event.ttl_seconds !== undefined) {
            setCachedTtlSeconds(event.ttl_seconds)
          }
          break
        }

        // Live stats update
        case 'stats_updated':
          if (event.stats) {
            setStats(event.stats)
            // Dispatch event for proxy list to update individual proxy stats
            window.dispatchEvent(new CustomEvent('stats-updated', {
              detail: { proxy_id: event.proxy_id, stats: event.stats }
            }))
          }
          break

        // New log entries available - dispatch event for log viewers
        case 'new_log_entries':
          window.dispatchEvent(new CustomEvent('new-log-entries', { detail: event.count }))
          break

        // Proxy registered/disconnected - trigger refetch of proxy data
        case 'proxy_registered':
          window.dispatchEvent(new CustomEvent('proxy-registered'))
          break
        case 'proxy_disconnected': {
          // Dispatch both events: proxy-registered for components that only
          // listen to that, and proxy-disconnected for dedicated listeners
          window.dispatchEvent(new CustomEvent('proxy-registered'))
          window.dispatchEvent(new CustomEvent('proxy-disconnected'))
          const disconnectEvent = event as SSEProxyDisconnectedEvent
          if (disconnectEvent.disconnect_reason) {
            const reason = disconnectEvent.disconnect_reason.reason || 'Unknown error'
            toast.error(`Proxy '${disconnectEvent.proxy_name}' stopped: ${reason}`)
            playErrorSound()
          } else if (disconnectEvent.proxy_name) {
            toast.info(`Proxy '${disconnectEvent.proxy_name}' disconnected`)
          }
          break
        }
        case 'proxy_deleted':
          window.dispatchEvent(new CustomEvent('proxy-deleted', { detail: event }))
          break

        // Incidents updated - trigger refetch of incidents summary
        case 'incidents_updated':
          window.dispatchEvent(new CustomEvent('incidents-updated'))
          break

        // Critical shutdown - show long-lived toast but DON'T change connection status
        // The manager connection is still fine, only the proxy shut down
        case 'critical_shutdown':
          isShutdownRef.current = true
          toast.error(event.message || 'Proxy shut down', { id: SHUTDOWN_TOAST_ID, duration: 15_000 })
          playErrorSound()
          break

        // System events with severity - show toast
        default:
          if ('severity' in event && event.severity) {
            showSystemToast(event as SSESystemEvent)
          }
          // Dispatch custom event for device flow SSE listener
          if (event.type === 'auth_login' || event.type === 'auth_login_failed') {
            window.dispatchEvent(new CustomEvent('auth-login-result', { detail: event }))
          }
          break
      }
    }

    const handleError = () => {
      // Don't spam toasts if proxy shut down
      if (isShutdownRef.current) return

      setConnected(false)
      errorCountRef.current++

      // Update connection status based on error count
      if (errorCountRef.current >= MAX_RECONNECT_ERRORS) {
        setConnectionStatus('disconnected')
        // Only play error sound when transitioning to disconnected
        if (errorCountRef.current === MAX_RECONNECT_ERRORS) {
          playErrorSound()
        }
      } else {
        setConnectionStatus('reconnecting')
      }
    }

    // Track if effect was cleaned up before async completes
    let cancelled = false

    const connect = async () => {
      try {
        const es = await subscribeToPendingApprovals(handleEvent, handleError)
        if (cancelled) {
          es.close()
          return
        }
        eventSourceRef.current = es
      } catch {
        // Token fetch or connection failed - trigger error handler
        // This can happen if the API server is unreachable
        if (!cancelled) {
          handleError()
        }
      }
    }

    connect()

    return () => {
      cancelled = true
      eventSourceRef.current?.close()
    }
  }, [])

  // Refetch cached approvals from the REST API.
  // Used after actions that modify the cache to guarantee the UI updates
  // even if the SSE cached_snapshot event doesn't arrive.
  const refetchCached = useCallback(async () => {
    try {
      const res = await fetchCachedApprovals()
      setCached(res.approvals)
      if (res.ttl_seconds !== undefined) {
        setCachedTtlSeconds(res.ttl_seconds)
      }
    } catch {
      // Non-critical — SSE may still deliver the update
    }
  }, [])

  const approve = useCallback(async (id: string) => {
    try {
      await approveRequest(id)
      toast.success('Request approved')
      // Approval may have been cached — refetch after a short delay to let
      // the middleware store the approval before we query for it
      void setTimeout(() => void refetchCached(), 500)
    } catch (e) {
      // 404 errors emit SSE pending_not_found event with toast
      // 401/403 show specific authentication/authorization messages
      if (e instanceof ApiError) {
        if (e.status === 401) {
          notifyError('Login required to approve requests')
        } else if (e.status === 403) {
          notifyError(e.message || 'Not authorized to approve this request')
        } else if (e.status !== 404) {
          notifyError('Failed to approve request')
        }
      } else if (e instanceof Error) {
        notifyError('Failed to approve request')
      }
    }
  }, [refetchCached])

  const approveOnce = useCallback(async (id: string) => {
    try {
      await approveOnceRequest(id)
      toast.success('Request approved (once)')
    } catch (e) {
      // 404 errors emit SSE pending_not_found event with toast
      // 401/403 show specific authentication/authorization messages
      if (e instanceof ApiError) {
        if (e.status === 401) {
          notifyError('Login required to approve requests')
        } else if (e.status === 403) {
          notifyError(e.message || 'Not authorized to approve this request')
        } else if (e.status !== 404) {
          notifyError('Failed to approve request')
        }
      } else if (e instanceof Error) {
        notifyError('Failed to approve request')
      }
    }
  }, [])

  const deny = useCallback(async (id: string) => {
    try {
      await denyRequest(id)
      toast.success('Request denied')
    } catch (e) {
      // 404 errors emit SSE pending_not_found event with toast
      // 401/403 show specific authentication/authorization messages
      if (e instanceof ApiError) {
        if (e.status === 401) {
          notifyError('Login required to deny requests')
        } else if (e.status === 403) {
          notifyError(e.message || 'Not authorized to deny this request')
        } else if (e.status !== 404) {
          notifyError('Failed to deny request')
        }
      } else if (e instanceof Error) {
        notifyError('Failed to deny request')
      }
    }
  }, [])

  const clearCached = useCallback(async () => {
    try {
      await clearCachedApprovals()
      setCached([])
    } catch {
      notifyError('Failed to clear cache')
    }
  }, [])

  const deleteCached = useCallback(async (subjectId: string, toolName: string, path: string | null) => {
    try {
      await deleteCachedApproval(subjectId, toolName, path)
      setCached((prev) => prev.filter(
        (c) => !(c.subject_id === subjectId && c.tool_name === toolName && c.path === path)
      ))
    } catch {
      notifyError('Failed to delete cached approval')
    }
  }, [])

  return (
    <AppStateContext.Provider value={{ pending, cached, cachedTtlSeconds, stats, connected, connectionStatus, approve, approveOnce, deny, clearCached, deleteCached }}>
      {children}
    </AppStateContext.Provider>
  )
}

export function useAppState() {
  const context = useContext(AppStateContext)
  if (!context) {
    throw new Error('useAppState must be used within AppStateProvider')
  }
  return context
}
