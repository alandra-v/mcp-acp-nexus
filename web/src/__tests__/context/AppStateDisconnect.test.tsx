/**
 * Tests for proxy disconnect enrichment in appStore.
 *
 * Verifies that proxy_disconnected SSE events show the correct toast
 * based on whether disconnect_reason is present.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act } from '@testing-library/react'
import { useAppStore, getInitialState } from '@/store/appStore'
import type { SSEEvent } from '@/types/api'

// Hoisted mocks (accessible inside vi.mock factories)
const {
  mockToast,
  mockPlayErrorSound,
  mockNotifyError,
  mockPlayApprovalChime,
} = vi.hoisted(() => ({
  mockToast: {
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
    dismiss: vi.fn(),
  },
  mockPlayErrorSound: vi.fn(),
  mockNotifyError: vi.fn(),
  mockPlayApprovalChime: vi.fn(),
}))

vi.mock('@/api/approvals', () => ({
  subscribeToPendingApprovals: vi.fn(),
  approveProxyRequest: vi.fn(),
  approveOnceProxyRequest: vi.fn(),
  denyProxyRequest: vi.fn(),
  clearProxyCachedApprovals: vi.fn(),
  deleteProxyCachedApproval: vi.fn(),
}))

vi.mock('@/components/ui/sonner', () => ({
  toast: mockToast,
}))

vi.mock('@/hooks/useErrorSound', () => ({
  playErrorSound: mockPlayErrorSound,
  notifyError: mockNotifyError,
}))

vi.mock('@/hooks/useNotificationSound', () => ({
  playApprovalChime: mockPlayApprovalChime,
}))

vi.mock('@/lib/notifications', () => ({
  requestNotificationPermission: vi.fn().mockResolvedValue(undefined),
  showApprovalNotification: vi.fn(),
}))

describe('appStore disconnect enrichment', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset store to initial state
    useAppStore.setState(getInitialState())
  })

  /** Send an SSE event through the store handler */
  function sendEvent(event: SSEEvent) {
    act(() => {
      useAppStore.getState().handleSSEEvent(event)
    })
  }

  describe('proxy_disconnected with disconnect_reason', () => {
    it('shows error toast with crash reason', () => {
      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'my-proxy',
        proxy_id: 'px_abc:my-proxy',
        instance_id: 'inst_123',
        disconnect_reason: {
          failure_type: 'audit_failure',
          reason: 'Audit log write failed',
          exit_code: 10,
          time: '2026-01-30T12:00:00Z',
        },
      } as SSEEvent)

      expect(mockToast.error).toHaveBeenCalledWith(
        "Proxy 'my-proxy' stopped: Audit log write failed"
      )
    })

    it('plays error sound on crash disconnect', () => {
      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'crash-proxy',
        disconnect_reason: {
          failure_type: 'session_binding_violation',
          reason: 'Session hijacking detected',
          exit_code: 12,
          time: '2026-01-30T12:00:00Z',
        },
      } as SSEEvent)

      expect(mockPlayErrorSound).toHaveBeenCalled()
    })

    it('uses fallback message when reason is empty', () => {
      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'bad-proxy',
        disconnect_reason: {
          failure_type: 'audit_failure',
          reason: '',
          exit_code: 10,
          time: '2026-01-30T12:00:00Z',
        },
      } as SSEEvent)

      expect(mockToast.error).toHaveBeenCalledWith(
        "Proxy 'bad-proxy' stopped: Unknown error"
      )
    })
  })

  describe('proxy_disconnected without disconnect_reason', () => {
    it('shows info toast for normal disconnect', () => {
      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'clean-proxy',
        proxy_id: 'px_clean:clean-proxy',
        instance_id: 'inst_456',
      } as SSEEvent)

      expect(mockToast.info).toHaveBeenCalledWith(
        "Proxy 'clean-proxy' disconnected"
      )
    })

    it('does not play error sound for normal disconnect', () => {
      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'clean-proxy',
      } as SSEEvent)

      expect(mockPlayErrorSound).not.toHaveBeenCalled()
    })

    it('does not show toast when proxy_name is missing', () => {
      sendEvent({
        type: 'proxy_disconnected',
      } as SSEEvent)

      expect(mockToast.info).not.toHaveBeenCalled()
      expect(mockToast.error).not.toHaveBeenCalled()
    })
  })

  describe('proxyListVersion counter', () => {
    it('increments proxyListVersion on proxy_disconnected', () => {
      const initialVersion = useAppStore.getState().proxyListVersion

      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'test-proxy',
      } as SSEEvent)

      expect(useAppStore.getState().proxyListVersion).toBe(initialVersion + 1)
    })

    it('increments proxyListVersion on proxy_registered', () => {
      const initialVersion = useAppStore.getState().proxyListVersion

      sendEvent({
        type: 'proxy_registered',
        proxy_name: 'test-proxy',
      } as SSEEvent)

      expect(useAppStore.getState().proxyListVersion).toBe(initialVersion + 1)
    })
  })
})
