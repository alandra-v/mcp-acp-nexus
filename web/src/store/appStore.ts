/**
 * Zustand store for SSE-driven application state.
 *
 * Centralizes all state from AppStateContext and replaces window.dispatchEvent
 * side-channels with signal counters that consumer hooks can subscribe to.
 */

import { create } from 'zustand'
import { useShallow } from 'zustand/react/shallow'
import {
  approveProxyRequest,
  approveOnceProxyRequest,
  denyProxyRequest,
  clearProxyCachedApprovals,
  deleteProxyCachedApproval,
} from '@/api/approvals'
import { toast } from '@/components/ui/sonner'
import { playApprovalChime } from '@/hooks/useNotificationSound'
import { playErrorSound, notifyError } from '@/hooks/useErrorSound'
import { requestNotificationPermission, showApprovalNotification } from '@/lib/notifications'
import {
  ApiError,
  type CachedApproval,
  type PendingApproval,
  type ProxyStats,
  type SSEEvent,
  type SSEEventType,
  type SSEProxyDisconnectedEvent,
  type SSEProxyDeletedEvent,
  type SSESystemEvent,
  type SSEAuthEvent,
} from '@/types/api'

const ORIGINAL_TITLE = 'MCP ACP'
const SHUTDOWN_TOAST_ID = 'proxy-shutdown'

// Max errors before showing "disconnected" instead of "reconnecting"
const MAX_RECONNECT_ERRORS = 5

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

export type ConnectionStatus = 'connected' | 'reconnecting' | 'disconnected'

/** Auth login result from SSE for device flow */
export interface AuthLoginResult {
  type: string
  reason?: string
  message?: string
}

interface AppState {
  // Core state
  pending: PendingApproval[]
  cached: CachedApproval[]
  cachedTtlSeconds: number
  stats: Record<string, ProxyStats>
  connected: boolean
  connectionStatus: ConnectionStatus

  // Signal counters (increment to trigger consumer refetches)
  proxyListVersion: number
  logEntriesVersion: number
  incidentsVersion: number
  incidentsMarkedReadVersion: number
  authVersion: number

  // Event payloads for consumers that need event details
  lastAuthLoginResult: AuthLoginResult | null
  lastProxyDeleted: SSEProxyDeletedEvent | null

  // Internal tracking
  _errorCount: number
  _isShutdown: boolean
}

interface AppActions {
  // SSE handlers
  handleSSEEvent: (event: SSEEvent) => void
  handleSSEError: () => void

  // Approval actions
  approve: (id: string) => Promise<void>
  approveOnce: (id: string) => Promise<void>
  deny: (id: string) => Promise<void>
  clearCached: (proxyName?: string, proxyId?: string) => Promise<void>
  deleteCached: (
    subjectId: string,
    toolName: string,
    path: string | null,
    proxyName?: string,
    proxyId?: string
  ) => Promise<void>

  // Incidents action
  markIncidentsRead: () => void
}

type AppStore = AppState & AppActions

const initialState: AppState = {
  pending: [],
  cached: [],
  cachedTtlSeconds: 0,
  stats: {},
  connected: false,
  connectionStatus: 'reconnecting',
  proxyListVersion: 0,
  logEntriesVersion: 0,
  incidentsVersion: 0,
  incidentsMarkedReadVersion: 0,
  authVersion: 0,
  lastAuthLoginResult: null,
  lastProxyDeleted: null,
  _errorCount: 0,
  _isShutdown: false,
}

/** Show toast for system events and increment authVersion if auth-related */
function showSystemToast(event: SSESystemEvent, incrementAuthVersion: () => void) {
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
      toast.error(message, { duration: 15_000 })
      playErrorSound()
      break
    case 'info':
    default:
      toast.info(message)
  }

  // Increment authVersion for auth state changes
  if (AUTH_CHANGE_EVENTS.has(event.type)) {
    incrementAuthVersion()
  }
}

/** Update document title based on pending count */
function updateDocumentTitle(pendingCount: number) {
  if (pendingCount > 0) {
    document.title = `\uD83D\uDD34 (${pendingCount}) ${ORIGINAL_TITLE}`
  } else {
    document.title = ORIGINAL_TITLE
  }
}

/** Handle approval action errors with consistent messaging */
function handleApprovalError(e: unknown, action: 'approve' | 'deny') {
  if (e instanceof ApiError) {
    if (e.status === 401) {
      notifyError(`Login required to ${action} requests`)
    } else if (e.status === 403) {
      notifyError(e.message || `Not authorized to ${action} this request`)
    } else if (e.status !== 404) {
      // 404 is expected when approval was already resolved
      notifyError(`Failed to ${action} request`)
    }
  } else if (e instanceof Error) {
    notifyError(`Failed to ${action} request`)
  }
}

export const useAppStore = create<AppStore>((set, get) => ({
  ...initialState,

  handleSSEEvent: (event: SSEEvent) => {
    switch (event.type) {
      // HITL-specific events
      case 'snapshot': {
        const eventProxyId = event.proxy_id
        const snapshotApprovals = (event.approvals || []).map((a) =>
          event.proxy_name ? { ...a, proxy_name: event.proxy_name } : a
        )

        const wasDisconnected = !get().connected

        if (eventProxyId) {
          // Merge: replace this proxy's entries, keep others
          set((state) => {
            const newPending = [
              ...state.pending.filter((p) => p.proxy_id !== eventProxyId),
              ...snapshotApprovals,
            ]
            updateDocumentTitle(newPending.length)
            return {
              pending: newPending,
              connected: true,
              connectionStatus: 'connected',
              _errorCount: 0,
            }
          })
        } else {
          set(() => {
            updateDocumentTitle(snapshotApprovals.length)
            return {
              pending: snapshotApprovals,
              connected: true,
              connectionStatus: 'connected',
              _errorCount: 0,
            }
          })
        }

        // Dismiss shutdown toast if proxy was restarted
        if (get()._isShutdown) {
          toast.dismiss(SHUTDOWN_TOAST_ID)
          set({ _isShutdown: false })
        }

        // On disconnected→connected transition, refresh auth and proxy list.
        // Proxy list refresh catches any proxy_registered events missed while
        // the SSE connection was being established (or during a reconnection gap).
        if (wasDisconnected) {
          set((state) => ({
            authVersion: state.authVersion + 1,
            proxyListVersion: state.proxyListVersion + 1,
          }))
        }
        break
      }

      case 'pending_created':
        if (event.approval) {
          const created = event.proxy_name
            ? { ...event.approval, proxy_name: event.proxy_name }
            : event.approval
          set((state) => {
            const newPending = [...state.pending, created]
            updateDocumentTitle(newPending.length)
            return { pending: newPending }
          })
          playApprovalChime()
          requestNotificationPermission()
            .then(() => showApprovalNotification(created))
            .catch(() => {}) // Notification errors are non-critical
        }
        break

      case 'pending_resolved':
        if (event.approval_id) {
          set((state) => {
            const newPending = state.pending.filter((p) => p.id !== event.approval_id)
            updateDocumentTitle(newPending.length)
            return { pending: newPending }
          })
        }
        break

      case 'pending_timeout':
        if (event.approval_id) {
          set((state) => {
            const newPending = state.pending.filter((p) => p.id !== event.approval_id)
            updateDocumentTitle(newPending.length)
            return { pending: newPending }
          })
          toast.warning('Approval request timed out')
        }
        break

      // Cached approvals snapshot (full state from SSE, per-proxy)
      case 'cached_snapshot': {
        const eventProxyId = event.proxy_id
        const now = Date.now()
        const tagged = (event.approvals || []).map((a) => ({
          ...a,
          ...(eventProxyId ? { proxy_id: eventProxyId } : {}),
          expires_at: new Date(now + (a.expires_in_seconds ?? 0) * 1000).toISOString(),
        }))
        if (eventProxyId) {
          set((state) => ({
            cached: [
              ...state.cached.filter((c) => c.proxy_id !== eventProxyId),
              ...tagged,
            ],
          }))
        } else {
          set({ cached: tagged })
        }
        if (event.ttl_seconds !== undefined) {
          set({ cachedTtlSeconds: event.ttl_seconds })
        }
        break
      }

      // Live stats update
      case 'stats_updated': {
        const statsProxyId = event.proxy_id
        if (event.stats && statsProxyId) {
          set((state) => ({
            stats: { ...state.stats, [statsProxyId]: event.stats },
          }))
        }
        break
      }

      // New log entries available
      case 'new_log_entries':
        set((state) => ({ logEntriesVersion: state.logEntriesVersion + 1 }))
        break

      // Proxy registered/disconnected - trigger refetch via proxyListVersion
      case 'proxy_registered':
        set((state) => ({ proxyListVersion: state.proxyListVersion + 1 }))
        break

      case 'proxy_disconnected': {
        set((state) => ({ proxyListVersion: state.proxyListVersion + 1 }))
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
        set((state) => ({
          proxyListVersion: state.proxyListVersion + 1,
          lastProxyDeleted: event as SSEProxyDeletedEvent,
        }))
        break

      // Incidents updated
      case 'incidents_updated':
        set((state) => ({ incidentsVersion: state.incidentsVersion + 1 }))
        break

      // Critical shutdown
      case 'critical_shutdown':
        set({ _isShutdown: true })
        toast.error(event.message || 'Proxy shut down', {
          id: SHUTDOWN_TOAST_ID,
          duration: 15_000,
        })
        playErrorSound()
        break

      // System events with severity - show toast
      default:
        if ('severity' in event && event.severity) {
          showSystemToast(event as SSESystemEvent, () => {
            set((state) => ({ authVersion: state.authVersion + 1 }))
          })
        }
        // Set lastAuthLoginResult for device flow
        if (event.type === 'auth_login' || event.type === 'auth_login_failed') {
          const authEvent = event as SSEAuthEvent
          set({
            lastAuthLoginResult: {
              type: authEvent.type,
              reason: authEvent.reason,
              message: authEvent.message,
            },
          })
        }
        break
    }
  },

  handleSSEError: () => {
    const state = get()
    // Don't spam if proxy shut down
    if (state._isShutdown) return

    const newErrorCount = state._errorCount + 1

    if (newErrorCount >= MAX_RECONNECT_ERRORS) {
      set({
        connected: false,
        connectionStatus: 'disconnected',
        _errorCount: newErrorCount,
      })
      // Only play error sound when transitioning to disconnected
      if (newErrorCount === MAX_RECONNECT_ERRORS) {
        playErrorSound()
      }
    } else {
      set({
        connected: false,
        connectionStatus: 'reconnecting',
        _errorCount: newErrorCount,
      })
    }
  },

  approve: async (id: string) => {
    const approval = get().pending.find((p) => p.id === id)
    if (!approval) return
    const proxyName = approval.proxy_name
    if (!proxyName) {
      notifyError('Cannot resolve proxy for this approval')
      return
    }
    try {
      await approveProxyRequest(proxyName, id)
      toast.success('Request approved')
    } catch (e) {
      handleApprovalError(e, 'approve')
    }
  },

  approveOnce: async (id: string) => {
    const approval = get().pending.find((p) => p.id === id)
    if (!approval) return
    const proxyName = approval.proxy_name
    if (!proxyName) {
      notifyError('Cannot resolve proxy for this approval')
      return
    }
    try {
      await approveOnceProxyRequest(proxyName, id)
      toast.success('Request approved (once)')
    } catch (e) {
      handleApprovalError(e, 'approve')
    }
  },

  deny: async (id: string) => {
    const approval = get().pending.find((p) => p.id === id)
    if (!approval) return
    const proxyName = approval.proxy_name
    if (!proxyName) {
      notifyError('Cannot resolve proxy for this approval')
      return
    }
    try {
      await denyProxyRequest(proxyName, id)
      toast.success('Request denied')
    } catch (e) {
      handleApprovalError(e, 'deny')
    }
  },

  clearCached: async (proxyName?: string, proxyId?: string) => {
    if (!proxyName) return
    try {
      await clearProxyCachedApprovals(proxyName)
      if (proxyId) {
        set((state) => ({
          cached: state.cached.filter((c) => c.proxy_id !== proxyId),
        }))
      }
    } catch {
      notifyError('Failed to clear cache')
    }
  },

  deleteCached: async (
    subjectId: string,
    toolName: string,
    path: string | null,
    proxyName?: string,
    proxyId?: string
  ) => {
    if (!proxyName) return
    try {
      await deleteProxyCachedApproval(proxyName, subjectId, toolName, path)
      set((state) => ({
        cached: state.cached.filter(
          (c) =>
            !(
              c.subject_id === subjectId &&
              c.tool_name === toolName &&
              c.path === path &&
              (!proxyId || c.proxy_id === proxyId)
            )
        ),
      }))
    } catch {
      notifyError('Failed to delete cached approval')
    }
  },

  markIncidentsRead: () => {
    set((state) => ({ incidentsMarkedReadVersion: state.incidentsMarkedReadVersion + 1 }))
  },
}))

/** Get initial state for test resets */
export const getInitialState = (): AppState => ({ ...initialState })

/** Return type for useAppState hook */
export interface UseAppStateResult {
  pending: PendingApproval[]
  cached: CachedApproval[]
  cachedTtlSeconds: number
  stats: Record<string, ProxyStats>
  connected: boolean
  connectionStatus: ConnectionStatus
  approve: (id: string) => Promise<void>
  approveOnce: (id: string) => Promise<void>
  deny: (id: string) => Promise<void>
  clearCached: (proxyName?: string, proxyId?: string) => Promise<void>
  deleteCached: (
    subjectId: string,
    toolName: string,
    path: string | null,
    proxyName?: string,
    proxyId?: string
  ) => Promise<void>
}

/**
 * Convenience hook that provides the same interface as the old useAppState context.
 * Uses useShallow for stable object identity on each selector property.
 */
export function useAppState(): UseAppStateResult {
  return useAppStore(
    useShallow((state) => ({
      pending: state.pending,
      cached: state.cached,
      cachedTtlSeconds: state.cachedTtlSeconds,
      stats: state.stats,
      connected: state.connected,
      connectionStatus: state.connectionStatus,
      approve: state.approve,
      approveOnce: state.approveOnce,
      deny: state.deny,
      clearCached: state.clearCached,
      deleteCached: state.deleteCached,
    }))
  )
}
