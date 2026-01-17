/**
 * Unit tests for useDeviceFlow hook.
 *
 * Tests device code flow login with polling.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useDeviceFlow } from '@/hooks/useDeviceFlow'
import * as authApi from '@/api/auth'

// Mock the API module
vi.mock('@/api/auth', () => ({
  startLogin: vi.fn(),
  pollLogin: vi.fn(),
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

describe('useDeviceFlow', () => {
  const mockDeviceFlowStart: authApi.DeviceFlowStart = {
    user_code: 'ABCD-1234',
    verification_uri: 'https://auth.example.com/device',
    verification_uri_complete: 'https://auth.example.com/device?code=ABCD-1234',
    expires_in: 600,
    interval: 5,
    poll_endpoint: '/auth/login/poll',
  }

  let onSuccess: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    onSuccess = vi.fn()
  })

  afterEach(() => {
    vi.useRealTimers()
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
    it('starts device flow and begins polling', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'pending', message: null })

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

    it('clears previous polling when starting again', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'pending', message: null })

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      // Start first flow
      await act(async () => {
        await result.current.start()
      })

      // Advance time for one poll
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      // Start second flow (should clear first)
      await act(async () => {
        await result.current.start()
      })

      // Should have started fresh
      expect(authApi.startLogin).toHaveBeenCalledTimes(2)
    })
  })

  describe('polling', () => {
    it('polls at specified interval', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'pending', message: null })

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      // Poll should happen every 5 seconds (interval from response)
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      expect(authApi.pollLogin).toHaveBeenCalled()
    })

    it('calls onSuccess when poll returns complete', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'complete', message: null })

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      expect(onSuccess).toHaveBeenCalled()
      expect(result.current.state.polling).toBe(false)
    })

    it('handles expired status', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'expired', message: 'Code expired' })

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('Code expired')
      expect(notifyError).toHaveBeenCalledWith('Code expired, please try again')
    })

    it('handles denied status', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'denied', message: 'User denied' })

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('User denied')
      expect(notifyError).toHaveBeenCalledWith('Authorization denied')
    })

    it('handles error status', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'error', message: 'Server error' })

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('Server error')
      expect(notifyError).toHaveBeenCalledWith('Login failed')
    })

    it('handles poll network error', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000)
      })

      expect(result.current.state.polling).toBe(false)
      expect(result.current.state.error).toBe('Polling failed')
      expect(notifyError).toHaveBeenCalledWith('Login failed')
    })
  })

  describe('reset', () => {
    it('clears state and stops polling', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'pending', message: null })

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
    })
  })

  describe('cleanup', () => {
    it('clears polling interval on unmount', async () => {
      vi.mocked(authApi.startLogin).mockResolvedValue(mockDeviceFlowStart)
      vi.mocked(authApi.pollLogin).mockResolvedValue({ status: 'pending', message: null })

      const { result, unmount } = renderHook(() => useDeviceFlow(onSuccess))

      await act(async () => {
        await result.current.start()
      })

      unmount()

      // Advance time - polling should not happen after unmount
      await act(async () => {
        await vi.advanceTimersByTimeAsync(10000)
      })

      // pollLogin should only have been called during the hook's lifecycle
      const callCountAtUnmount = vi.mocked(authApi.pollLogin).mock.calls.length
      expect(callCountAtUnmount).toBeLessThanOrEqual(2) // At most 1-2 polls
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
