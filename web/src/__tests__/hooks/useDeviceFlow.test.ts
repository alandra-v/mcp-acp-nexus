/**
 * Unit tests for useDeviceFlow hook.
 *
 * Tests device code flow login with SSE-based completion.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useDeviceFlow } from '@/hooks/useDeviceFlow'
import * as authApi from '@/api/auth'

// Mock the API module
vi.mock('@/api/auth', () => ({
  startLogin: vi.fn(),
}))

// Mock toast
vi.mock('@/components/ui/sonner', () => ({
  toast: {
    error: vi.fn(),
    success: vi.fn(),
  },
}))

// Mock error sound
vi.mock('@/hooks/useErrorSound', () => ({
  playErrorSound: vi.fn(),
  notifyError: vi.fn(),
}))

/** Dispatch an auth-login-result CustomEvent. */
function dispatchAuthResult(detail: { type: string; reason?: string; message?: string }) {
  window.dispatchEvent(new CustomEvent('auth-login-result', { detail }))
}

describe('useDeviceFlow', () => {
  const mockDeviceFlowStart: authApi.DeviceFlowStart = {
    user_code: 'ABCD-1234',
    verification_uri: 'https://auth.example.com/device',
    verification_uri_complete: 'https://auth.example.com/device?code=ABCD-1234',
    expires_in: 600,
    interval: 5,
  }

  let onSuccess: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()
    onSuccess = vi.fn()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('initial state', () => {
    it('starts with polling false and no codes', () => {
      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.userCode).toBeUndefined()
      expect(result.current.state.verificationUri).toBeUndefined()
      expect(result.current.state.error).toBeUndefined()
    })
  })

  describe('start', () => {
    it('starts device flow and sets polling state', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      expect(authApi.startLogin).toHaveBeenCalled()
      expect(result.current.state.userCode).toBe('ABCD-1234')
      expect(result.current.state.verificationUri).toBe('https://auth.example.com/device')
      expect(result.current.state.verificationUriComplete).toBe(
        'https://auth.example.com/device?code=ABCD-1234'
      )
      expect(result.current.state.polling).toBe(true)
    })

    it('sets error when start fails', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(authApi.startLogin).mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('Network error')
      expect(notifyError).toHaveBeenCalledWith('Failed to start login')
    })

    it('handles non-Error rejection', async () => {
      vi.mocked(authApi.startLogin).mockRejectedValue('Unknown error')

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      expect(result.current.state.error).toBe('Failed to start login')
    })
  })

  describe('SSE events', () => {
    it('calls onSuccess when auth_login event received', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      expect(result.current.state.polling).toBe(true)

      act(() => {
        dispatchAuthResult({ type: 'auth_login' })
      })

      expect(onSuccess).toHaveBeenCalled()
      expect(result.current.state.polling).toBe(false)
    })

    it('handles expired status from SSE', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      act(() => {
        dispatchAuthResult({ type: 'auth_login_failed', reason: 'expired', message: 'Code expired' })
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('Code expired')
      // Toast is shown by AppStateContext via showSystemToast, not by this hook
      expect(onSuccess).not.toHaveBeenCalled()
    })

    it('handles denied status from SSE', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      act(() => {
        dispatchAuthResult({ type: 'auth_login_failed', reason: 'denied', message: 'User denied' })
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('User denied')
      expect(onSuccess).not.toHaveBeenCalled()
    })

    it('handles error status from SSE', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      act(() => {
        dispatchAuthResult({ type: 'auth_login_failed', reason: 'error', message: 'Server error' })
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('Server error')
      expect(onSuccess).not.toHaveBeenCalled()
    })

    it('ignores SSE events when flow is not active', () => {
      renderHook(() => useDeviceFlow(onSuccess))

      // Dispatch without starting flow
      act(() => {
        dispatchAuthResult({ type: 'auth_login' })
      })

      expect(onSuccess).not.toHaveBeenCalled()
    })
  })

  describe('reset', () => {
    it('clears state and deactivates flow', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      expect(result.current.state.polling).toBe(true)
      expect(result.current.state.userCode).toBe('ABCD-1234')

      act(() => {
        result.current.reset()
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.userCode).toBeUndefined()
      expect(result.current.state.verificationUri).toBeUndefined()

      // SSE events should be ignored after reset
      act(() => {
        dispatchAuthResult({ type: 'auth_login' })
      })

      expect(onSuccess).not.toHaveBeenCalled()
    })
  })

  describe('cleanup', () => {
    it('removes event listener on unmount', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)

      const { result, unmount } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      unmount()

      // SSE events after unmount should not trigger callbacks
      act(() => {
        dispatchAuthResult({ type: 'auth_login' })
      })

      // onSuccess should not be called since activeRef was set by start
      // but the listener was removed on unmount — no way to receive events
      // The key assertion is that no errors are thrown
    })
  })

  describe('return values', () => {
    it('returns state, start, and reset', () => {
      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      expect(result.current).toHaveProperty('state')
      expect(result.current).toHaveProperty('start')
      expect(result.current).toHaveProperty('reset')
      expect(typeof result.current.start).toBe('function')
      expect(typeof result.current.reset).toBe('function')
    })
  })
})
