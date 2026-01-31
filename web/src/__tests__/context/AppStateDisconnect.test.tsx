/**
 * Tests for proxy disconnect enrichment in AppStateContext.
 *
 * Verifies that proxy_disconnected SSE events show the correct toast
 * based on whether disconnect_reason is present.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, act } from '@testing-library/react'
import type { SSEEvent } from '@/types/api'

// Hoisted mocks (accessible inside vi.mock factories)
const {
  mockToast,
  mockPlayErrorSound,
  mockNotifyError,
  mockPlayApprovalChime,
  mockSubscribe,
  mockEventSource,
} = vi.hoisted(() => ({
  mockToast: {
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
    info: vi.fn(),
  },
  mockPlayErrorSound: vi.fn(),
  mockNotifyError: vi.fn(),
  mockPlayApprovalChime: vi.fn(),
  mockSubscribe: vi.fn(),
  mockEventSource: { close: vi.fn() },
}))

vi.mock('@/api/approvals', () => ({
  subscribeToPendingApprovals: mockSubscribe,
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

// Capture the onEvent callback
let capturedOnEvent: ((event: SSEEvent) => void) | null = null

describe('AppStateContext disconnect enrichment', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let windowDispatchSpy: any

  beforeEach(() => {
    vi.clearAllMocks()
    capturedOnEvent = null
    windowDispatchSpy = vi.spyOn(window, 'dispatchEvent')

    // Configure subscribe mock to capture the event handler
    mockSubscribe.mockImplementation(
      async (onEvent: (event: SSEEvent) => void) => {
        capturedOnEvent = onEvent
        return mockEventSource
      }
    )
  })

  afterEach(() => {
    windowDispatchSpy.mockRestore()
  })

  /** Render the provider and wait for SSE subscription to be set up */
  async function renderProvider() {
    // Dynamic import to ensure mocks are in place
    const { AppStateProvider } = await import('@/context/AppStateContext')

    await act(async () => {
      render(
        <AppStateProvider>
          <div>child</div>
        </AppStateProvider>
      )
    })
    expect(capturedOnEvent).not.toBeNull()
  }

  /** Send an SSE event through the captured handler */
  function sendEvent(event: SSEEvent) {
    act(() => {
      capturedOnEvent!(event)
    })
  }

  describe('proxy_disconnected with disconnect_reason', () => {
    it('shows error toast with crash reason', async () => {
      await renderProvider()

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

    it('plays error sound on crash disconnect', async () => {
      await renderProvider()

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

    it('uses fallback message when reason is empty', async () => {
      await renderProvider()

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
    it('shows info toast for normal disconnect', async () => {
      await renderProvider()

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

    it('does not play error sound for normal disconnect', async () => {
      await renderProvider()

      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'clean-proxy',
      } as SSEEvent)

      expect(mockPlayErrorSound).not.toHaveBeenCalled()
    })

    it('does not show toast when proxy_name is missing', async () => {
      await renderProvider()

      sendEvent({
        type: 'proxy_disconnected',
      } as SSEEvent)

      expect(mockToast.info).not.toHaveBeenCalled()
      expect(mockToast.error).not.toHaveBeenCalled()
    })
  })

  describe('window events', () => {
    it('dispatches both proxy-registered and proxy-disconnected events', async () => {
      await renderProvider()

      sendEvent({
        type: 'proxy_disconnected',
        proxy_name: 'test-proxy',
      } as SSEEvent)

      const eventTypes = windowDispatchSpy.mock.calls
        .map(([event]: [Event]) => (event as CustomEvent).type)

      expect(eventTypes).toContain('proxy-registered')
      expect(eventTypes).toContain('proxy-disconnected')
    })
  })
})
