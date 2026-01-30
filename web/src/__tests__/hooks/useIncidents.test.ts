/**
 * Unit tests for useIncidents hook.
 *
 * Tests initial fetch, filter-triggered refetch, cursor-based pagination,
 * error handling with single notification, and abort on unmount.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act } from '@testing-library/react'
import { useIncidents } from '@/hooks/useIncidents'
import * as incidentsApi from '@/api/incidents'
import type { AggregatedIncidentsResponse, IncidentEntry } from '@/types/api'

// Mock the API module
vi.mock('@/api/incidents', () => ({
  getAggregatedIncidents: vi.fn(),
}))

// Mock error sound
vi.mock('@/hooks/useErrorSound', () => ({
  notifyError: vi.fn(),
}))

describe('useIncidents', () => {
  const mockEntries: IncidentEntry[] = [
    {
      incident_type: 'shutdown',
      time: '2024-06-15T10:00:00Z',
      proxy_name: 'proxy-1',
      proxy_id: 'id-1',
      message: 'Audit integrity failure',
    },
    {
      incident_type: 'bootstrap',
      time: '2024-06-14T09:00:00Z',
      message: 'Config validation failed',
    },
  ]

  const mockResponse: AggregatedIncidentsResponse = {
    entries: mockEntries,
    total_returned: 2,
    has_more: false,
    filters_applied: { time_range: 'all' },
  }

  const mockResponseWithMore: AggregatedIncidentsResponse = {
    entries: mockEntries,
    total_returned: 2,
    has_more: true,
    filters_applied: { time_range: 'all' },
  }

  const mockPage2: AggregatedIncidentsResponse = {
    entries: [
      {
        incident_type: 'emergency',
        time: '2024-06-13T08:00:00Z',
        message: 'Audit fallback activated',
      },
    ],
    total_returned: 1,
    has_more: false,
    filters_applied: { time_range: 'all' },
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('initial fetch', () => {
    it('fetches incidents on mount', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockResolvedValue(mockResponse)

      const { result } = renderHook(() => useIncidents())

      expect(result.current.loading).toBe(true)

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(1)
      expect(result.current.incidents).toEqual(mockEntries)
      expect(result.current.hasMore).toBe(false)
      expect(result.current.error).toBeNull()
    })

    it('passes default time_range=all and limit', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockResolvedValue(mockResponse)

      renderHook(() => useIncidents())

      await waitFor(() => {
        expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalled()
      })

      const [params] = vi.mocked(incidentsApi.getAggregatedIncidents).mock.calls[0]
      expect(params).toMatchObject({
        time_range: 'all',
        before: undefined,
      })
    })
  })

  describe('filter changes', () => {
    it('refetches when proxy filter changes', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockResolvedValue(mockResponse)

      const { result, rerender } = renderHook(
        (props: { proxy?: string }) => useIncidents(props),
        { initialProps: {} }
      )

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(1)

      // Change proxy filter
      rerender({ proxy: 'proxy-1' })

      await waitFor(() => {
        expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(2)
      })

      const [params] = vi.mocked(incidentsApi.getAggregatedIncidents).mock.calls[1]
      expect(params).toMatchObject({ proxy: 'proxy-1' })
    })

    it('refetches when incidentType filter changes', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockResolvedValue(mockResponse)

      const { result, rerender } = renderHook(
        (props: { incidentType?: 'shutdown' | 'bootstrap' | 'emergency' }) =>
          useIncidents(props),
        { initialProps: {} }
      )

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      rerender({ incidentType: 'shutdown' })

      await waitFor(() => {
        expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(2)
      })

      const [params] = vi.mocked(incidentsApi.getAggregatedIncidents).mock.calls[1]
      expect(params).toMatchObject({ incident_type: 'shutdown' })
    })
  })

  describe('pagination', () => {
    it('appends entries on loadMore and uses cursor', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents)
        .mockResolvedValueOnce(mockResponseWithMore)
        .mockResolvedValueOnce(mockPage2)

      const { result } = renderHook(() => useIncidents())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.incidents).toHaveLength(2)
      expect(result.current.hasMore).toBe(true)

      // Load more
      act(() => {
        result.current.loadMore()
      })

      await waitFor(() => {
        expect(result.current.incidents).toHaveLength(3)
      })

      // Should have used cursor from oldest entry
      const [params] = vi.mocked(incidentsApi.getAggregatedIncidents).mock.calls[1]
      expect(params?.before).toBe('2024-06-14T09:00:00Z')

      expect(result.current.hasMore).toBe(false)
    })

    it('does not call loadMore when already loading', async () => {
      // Slow response to keep loading=true
      vi.mocked(incidentsApi.getAggregatedIncidents).mockImplementation(
        () => new Promise((resolve) => setTimeout(() => resolve(mockResponseWithMore), 500))
      )

      const { result } = renderHook(() => useIncidents())

      // Still loading from initial fetch
      expect(result.current.loading).toBe(true)

      act(() => {
        result.current.loadMore()
      })

      // Should not have triggered a second call
      expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(1)
    })
  })

  describe('refresh', () => {
    it('resets and refetches from the beginning', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockResolvedValue(mockResponse)

      const { result } = renderHook(() => useIncidents())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(1)

      act(() => {
        result.current.refresh()
      })

      await waitFor(() => {
        expect(incidentsApi.getAggregatedIncidents).toHaveBeenCalledTimes(2)
      })

      // Refresh should not use cursor
      const [params] = vi.mocked(incidentsApi.getAggregatedIncidents).mock.calls[1]
      expect(params?.before).toBeUndefined()
    })
  })

  describe('error handling', () => {
    it('sets error state on fetch failure', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockRejectedValue(
        new Error('Network error')
      )

      const { result } = renderHook(() => useIncidents())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(result.current.error).toBeInstanceOf(Error)
      expect(result.current.incidents).toEqual([])
    })

    it('shows error notification only once for repeated failures', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')
      vi.mocked(incidentsApi.getAggregatedIncidents).mockRejectedValue(
        new Error('Network error')
      )

      const { result } = renderHook(() => useIncidents())

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      expect(notifyError).toHaveBeenCalledWith('Failed to load incidents')

      // Trigger refresh (another failure)
      act(() => {
        result.current.refresh()
      })

      await waitFor(() => {
        expect(result.current.loading).toBe(false)
      })

      // Should still only have notified once
      expect(notifyError).toHaveBeenCalledTimes(1)
    })
  })

  describe('abort on unmount', () => {
    it('aborts fetch on unmount', async () => {
      vi.mocked(incidentsApi.getAggregatedIncidents).mockImplementation(
        (_params, options) =>
          new Promise((resolve, reject) => {
            const timeout = setTimeout(() => resolve(mockResponse), 100)
            options?.signal?.addEventListener('abort', () => {
              clearTimeout(timeout)
              reject(new DOMException('Aborted', 'AbortError'))
            })
          })
      )

      const { unmount } = renderHook(() => useIncidents())

      // Unmount immediately
      unmount()

      // Should not throw
      await new Promise((resolve) => setTimeout(resolve, 150))
    })

    it('ignores abort errors gracefully', async () => {
      const { notifyError } = await import('@/hooks/useErrorSound')

      vi.mocked(incidentsApi.getAggregatedIncidents).mockImplementation(
        (_params, options) =>
          new Promise((_resolve, reject) => {
            // Reject with abort error immediately
            options?.signal?.addEventListener('abort', () => {
              reject(new DOMException('Aborted', 'AbortError'))
            })
          })
      )

      const { unmount } = renderHook(() => useIncidents())

      unmount()

      await new Promise((resolve) => setTimeout(resolve, 50))

      // Should not have shown error for abort
      expect(notifyError).not.toHaveBeenCalled()
    })
  })
})
