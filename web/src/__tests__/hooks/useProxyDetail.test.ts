/**
 * Unit tests for useProxyDetail hook.
 *
 * Tests proxy detail fetching, SSE refresh, and abort on unmount.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useProxyDetail } from '@/hooks/useProxyDetail'
import * as proxiesApi from '@/api/proxies'
import { SSE_EVENTS } from '@/constants'
import type { ProxyDetailResponse } from '@/types/api'

// Mock the API module
vi.mock('@/api/proxies', () => ({
  getProxyDetail: vi.fn(),
}))

// Mock error sound
vi.mock('@/hooks/useErrorSound', () => ({
  playErrorSound: vi.fn(),
  notifyError: vi.fn(),
}))

describe('useProxyDetail', () => {
  const mockProxyDetail: ProxyDetailResponse = {
    proxy_name: 'test-proxy',
    proxy_id: 'proxy-123',
    status: 'running',
    instance_id: 'instance-abc',
    server_name: 'Test Server',
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
    client_id: 'claude-ai',
    pending_approvals: [],
    cached_approvals: [],
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('initial fetch', () => {
    it('fetches proxy detail on mount when proxyId is provided', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      const { result } = renderHook(() => useProxyDetail('proxy-123'))

      expect(result.current.loading).toBe(true)

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(1)
      expect(proxiesApi.getProxyDetail).toHaveBeenCalledWith('proxy-123', expect.any(Object))
      expect(result.current.proxy).toEqual(mockProxyDetail)
      expect(result.current.error).toBeNull()
    })

    it('does not fetch when proxyId is undefined', async () => {
      const { result } = renderHook(() => useProxyDetail(undefined))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(proxiesApi.getProxyDetail).not.toHaveBeenCalled()
      expect(result.current.proxy).toBeNull()
    })

    it('sets error on fetch failure', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockRejectedValue(new Error('Network error'))

      const { result } = renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.error).toBeInstanceOf(Error)
      expect(result.current.error?.message).toBe('Network error')
      expect(result.current.proxy).toBeNull()
    })

    it('handles non-Error rejection', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockRejectedValue('Unknown error')

      const { result } = renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.error?.message).toBe('Failed to load proxy')
    })
  })

  describe('SSE refresh', () => {
    it('refetches on proxy_registered event', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(1)
      })

      // Dispatch SSE event
      act(() => {
        window.dispatchEvent(new Event(SSE_EVENTS.PROXY_REGISTERED))
      })

      await waitFor(() => {
        expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(2)
      })
    })

    it('refetches on proxy_disconnected event', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(1)
      })

      // Dispatch SSE event
      act(() => {
        window.dispatchEvent(new Event(SSE_EVENTS.PROXY_DISCONNECTED))
      })

      await waitFor(() => {
        expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(2)
      })
    })
  })

  describe('abort on unmount', () => {
    it('aborts fetch on unmount', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockImplementation(
        (_proxyId, options) =>
          new Promise((resolve, reject) => {
            const timeout = setTimeout(() => resolve(mockProxyDetail), 100)
            options?.signal?.addEventListener('abort', () => {
              clearTimeout(timeout)
              reject(new DOMException('Aborted', 'AbortError'))
            })
          })
      )

      const { unmount } = renderHook(() => useProxyDetail('proxy-123'))

      // Unmount immediately
      unmount()

      // Should not throw and should not update state after unmount
      await new Promise((resolve) => setTimeout(resolve, 150))
    })

    it('removes event listeners on unmount', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      const removeEventListenerSpy = vi.spyOn(window, 'removeEventListener')

      const { unmount } = renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(proxiesApi.getProxyDetail).toHaveBeenCalled()
      })

      unmount()

      expect(removeEventListenerSpy).toHaveBeenCalledWith(
        SSE_EVENTS.PROXY_REGISTERED,
        expect.any(Function)
      )
      expect(removeEventListenerSpy).toHaveBeenCalledWith(
        SSE_EVENTS.PROXY_DISCONNECTED,
        expect.any(Function)
      )
    })
  })

  describe('refetch', () => {
    it('refetches when refetch is called', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      const { result } = renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(1)

      await act(async () => {
        await result.current.refetch()
      })

      expect(proxiesApi.getProxyDetail).toHaveBeenCalledTimes(2)
    })
  })

  describe('proxyId change', () => {
    it('refetches when proxyId changes', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      const { result, rerender } = renderHook(
        ({ proxyId }) => useProxyDetail(proxyId),
        { initialProps: { proxyId: 'proxy-123' } }
      )

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(proxiesApi.getProxyDetail).toHaveBeenCalledWith('proxy-123', expect.any(Object))

      // Change proxyId
      rerender({ proxyId: 'proxy-456' })

      await waitFor(() => {
        expect(proxiesApi.getProxyDetail).toHaveBeenCalledWith('proxy-456', expect.any(Object))
      })
    })
  })

  describe('return values', () => {
    it('returns all expected properties', async () => {
      vi.mocked(proxiesApi.getProxyDetail).mockResolvedValue(mockProxyDetail)

      const { result } = renderHook(() => useProxyDetail('proxy-123'))

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current).toHaveProperty('proxy')
      expect(result.current).toHaveProperty('loading')
      expect(result.current).toHaveProperty('error')
      expect(result.current).toHaveProperty('refetch')
    })
  })
})
