/**
 * Unit tests for useManagerProxies hook.
 *
 * Tests proxy list fetching, store-driven refresh, error handling, and abort on unmount.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useAppStore, getInitialState } from '@/store/appStore'
import * as proxiesApi from '@/api/proxies'
import type { Proxy } from '@/types/api'

// Mock the API module
vi.mock('@/api/proxies', () => ({
  getManagerProxies: vi.fn(),
}))

// Mock error sound
vi.mock('@/hooks/useErrorSound', () => ({
  playErrorSound: vi.fn(),
  notifyError: vi.fn(),
}))

describe('useManagerProxies', () => {
  const mockProxies: Proxy[] = [
    {
      proxy_name: 'test-proxy-1',
      proxy_id: 'proxy-123',
      status: 'running',
      instance_id: 'instance-abc',
      server_name: 'Test Server 1',
      transport: 'stdio',
      command: 'node',
      args: ['server.js'],
      url: null,
      created_at: '2024-01-01T00:00:00Z',
      backend_transport: 'stdio',
      mtls_enabled: false,
      stats: {
        requests_total: 100,
        requests_allowed: 90,
        requests_denied: 5,
        requests_hitl: 5,
        proxy_latency_ms: null,
      },
    },
    {
      proxy_name: 'test-proxy-2',
      proxy_id: 'proxy-456',
      status: 'inactive',
      instance_id: null,
      server_name: 'Test Server 2',
      transport: 'streamablehttp',
      command: null,
      args: null,
      url: 'http://localhost:3000',
      created_at: '2024-01-02T00:00:00Z',
      backend_transport: 'streamablehttp',
      mtls_enabled: true,
      stats: null,
    },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    // Reset store to initial state
    useAppStore.setState(getInitialState())
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('initial fetch', () => {
    it('fetches proxies on mount', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockResolvedValue(mockProxies)

      const { result } = renderHook(() => useManagerProxies())

      expect(result.current.loading).toBe(true)

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(proxiesApi.getManagerProxies).toHaveBeenCalledTimes(1)
      expect(result.current.proxies).toEqual(mockProxies)
      expect(result.current.error).toBeNull()
    })

    it('sets error on fetch failure', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')
      vi.mocked(proxiesApi.getManagerProxies).mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.error).toBeInstanceOf(Error)
      expect(result.current.proxies).toEqual([])
      expect(notifyError).toHaveBeenCalledWith('Failed to connect to manager')
    })

    it('only shows error notification once for repeated failures', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')
      vi.mocked(proxiesApi.getManagerProxies).mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      // Trigger refetch
      await act(async () => {
        await result.current.refetch()
      })

      // Should only notify once
      expect(notifyError).toHaveBeenCalledTimes(1)
    })

    it('handles non-Error rejection', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockRejectedValue('Unknown error')

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.error?.message).toBe('Failed to connect to manager')
    })
  })

  describe('store-driven refresh', () => {
    it('refetches when proxyListVersion increments', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockResolvedValue(mockProxies)

      renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(proxiesApi.getManagerProxies).toHaveBeenCalledTimes(1)
      })

      // Increment proxyListVersion in store
      act(() => {
        useAppStore.setState((s) => ({ proxyListVersion: s.proxyListVersion + 1 }))
      })

      await waitFor(() => {
        expect(proxiesApi.getManagerProxies).toHaveBeenCalledTimes(2)
      })
    })

    it('updates proxy stats from store directly', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockResolvedValue(mockProxies)

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      // Verify initial stats for proxy-123
      expect(result.current.proxies[0].stats?.requests_total).toBe(100)

      // Update stats in store
      const newStats = {
        requests_total: 150,
        requests_allowed: 140,
        requests_denied: 5,
        requests_hitl: 5,
        proxy_latency_ms: null,
      }

      act(() => {
        useAppStore.setState((s) => ({
          stats: { ...s.stats, 'proxy-123': newStats },
        }))
      })

      // Stats should be updated without refetch
      await waitFor(() => {
        expect(result.current.proxies[0].stats?.requests_total).toBe(150)
      })

      // Should NOT have triggered a refetch
      expect(proxiesApi.getManagerProxies).toHaveBeenCalledTimes(1)

      // Other proxy stats should remain unchanged
      expect(result.current.proxies[1].stats).toBeNull()
    })

    it('ignores stats for unknown proxy_id', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockResolvedValue(mockProxies)

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      const originalStats = result.current.proxies[0].stats

      // Update stats for unknown proxy in store
      act(() => {
        useAppStore.setState((s) => ({
          stats: {
            ...s.stats,
            'unknown-proxy': {
              requests_total: 999,
              requests_allowed: 999,
              requests_denied: 0,
              requests_hitl: 0,
              proxy_latency_ms: null,
            },
          },
        }))
      })

      // Stats should remain unchanged
      expect(result.current.proxies[0].stats).toEqual(originalStats)
    })
  })

  describe('abort on unmount', () => {
    it('aborts fetch on unmount', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockImplementation(
        (options) =>
          new Promise((resolve, reject) => {
            const timeout = setTimeout(() => resolve(mockProxies), 100)
            options?.signal?.addEventListener('abort', () => {
              clearTimeout(timeout)
              reject(new DOMException('Aborted', 'AbortError'))
            })
          })
      )

      const { unmount } = renderHook(() => useManagerProxies())

      // Unmount immediately
      unmount()

      // Should not throw and should not update state after unmount
      await new Promise((resolve) => setTimeout(resolve, 150))
    })
  })

  describe('refetch', () => {
    it('refetches when refetch is called', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockResolvedValue(mockProxies)

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(proxiesApi.getManagerProxies).toHaveBeenCalledTimes(1)

      await act(async () => {
        await result.current.refetch()
      })

      expect(proxiesApi.getManagerProxies).toHaveBeenCalledTimes(2)
    })

    it('resets error flag on successful refetch after failure', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(proxiesApi.getManagerProxies)
        .mockRejectedValueOnce(new Error('First error'))
        .mockResolvedValueOnce(mockProxies)

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.error).not.toBeNull()
      })

      expect(notifyError).toHaveBeenCalledTimes(1)

      // Refetch successfully
      await act(async () => {
        await result.current.refetch()
      })

      expect(result.current.error).toBeNull()
      expect(result.current.proxies).toEqual(mockProxies)

      // Trigger another failure - should show error again
      vi.mocked(proxiesApi.getManagerProxies).mockRejectedValueOnce(new Error('Second error'))

      await act(async () => {
        await result.current.refetch()
      })

      expect(notifyError).toHaveBeenCalledTimes(2)
    })
  })

  describe('return values', () => {
    it('returns all expected properties', async () => {
      vi.mocked(proxiesApi.getManagerProxies).mockResolvedValue(mockProxies)

      const { result } = renderHook(() => useManagerProxies())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current).toHaveProperty('proxies')
      expect(result.current).toHaveProperty('loading')
      expect(result.current).toHaveProperty('error')
      expect(result.current).toHaveProperty('refetch')
    })
  })
})
