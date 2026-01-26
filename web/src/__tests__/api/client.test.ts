/**
 * Unit tests for API client.
 *
 * Tests the HTTP client with retry logic, auth handling, and SSE creation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { ApiError } from '@/types/api'

// We need to mock fetch before importing the client
const mockFetch = vi.fn()
vi.stubGlobal('fetch', mockFetch)

// Import after mocking
import { apiGet, apiPost, apiPut, apiDelete, createSSEConnection } from '@/api/client'

describe('API Client', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // Helper to create mock Response with headers
  const mockResponse = (opts: {
    ok?: boolean
    status?: number
    statusText?: string
    json?: () => Promise<unknown>
    text?: () => Promise<string>
  }) => ({
    ok: opts.ok ?? true,
    status: opts.status ?? 200,
    statusText: opts.statusText ?? 'OK',
    headers: new Headers({ 'content-type': 'application/json' }),
    json: opts.json ?? (() => Promise.resolve({})),
    text: opts.text ?? (() => Promise.resolve('')),
  })

  describe('apiGet', () => {
    it('makes GET request with auth header', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        json: () => Promise.resolve({ data: 'test' }),
      }))

      const result = await apiGet('/test')

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/test',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            Authorization: expect.stringContaining('Bearer'),
          }),
        })
      )
      expect(result).toEqual({ data: 'test' })
    })

    it('throws ApiError on non-ok response', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        text: () => Promise.resolve('Resource not found'),
      }))

      await expect(apiGet('/missing')).rejects.toThrow(ApiError)
    })

    it('throws ApiError with invalid JSON response', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        json: () => Promise.reject(new Error('Invalid JSON')),
      }))

      await expect(apiGet('/test')).rejects.toThrow(ApiError)
    })

    it('respects abort signal', async () => {
      const controller = new AbortController()
      controller.abort()

      await expect(apiGet('/test', { signal: controller.signal })).rejects.toThrow()
    })
  })

  describe('apiPost', () => {
    it('makes POST request with JSON body', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        json: () => Promise.resolve({ created: true }),
      }))

      const result = await apiPost('/create', { name: 'test' })

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/create',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({ name: 'test' }),
        })
      )
      expect(result).toEqual({ created: true })
    })

    it('makes POST request without body', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        json: () => Promise.resolve({ status: 'ok' }),
      }))

      await apiPost('/action')

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/action',
        expect.objectContaining({
          method: 'POST',
          body: undefined,
        })
      )
    })
  })

  describe('apiPut', () => {
    it('makes PUT request with JSON body', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        json: () => Promise.resolve({ updated: true }),
      }))

      await apiPut('/update/1', { name: 'updated' })

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/update/1',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify({ name: 'updated' }),
        })
      )
    })
  })

  describe('apiDelete', () => {
    it('makes DELETE request', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        json: () => Promise.resolve({}),
      }))

      await apiDelete('/item/1')

      expect(mockFetch).toHaveBeenCalledWith(
        '/api/item/1',
        expect.objectContaining({
          method: 'DELETE',
        })
      )
    })
  })

  describe('retry logic', () => {
    it('retries on network error with exponential backoff', async () => {
      // First two calls fail, third succeeds
      mockFetch
        .mockRejectedValueOnce(new TypeError('Network error'))
        .mockRejectedValueOnce(new TypeError('Network error'))
        .mockResolvedValueOnce(mockResponse({
          json: () => Promise.resolve({ data: 'success' }),
        }))

      const promise = apiGet('/test')

      // Advance through retries
      await vi.advanceTimersByTimeAsync(1000) // First retry delay
      await vi.advanceTimersByTimeAsync(2000) // Second retry delay

      const result = await promise
      expect(result).toEqual({ data: 'success' })
      expect(mockFetch).toHaveBeenCalledTimes(3)
    })

    it('retries on 5xx server error', async () => {
      mockFetch
        .mockResolvedValueOnce(mockResponse({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          text: () => Promise.resolve('Server overloaded'),
        }))
        .mockResolvedValueOnce(mockResponse({
          json: () => Promise.resolve({ data: 'recovered' }),
        }))

      const promise = apiGet('/test')

      await vi.advanceTimersByTimeAsync(1000) // First retry delay

      const result = await promise
      expect(result).toEqual({ data: 'recovered' })
    })

    it('does not retry on 4xx client error', async () => {
      mockFetch.mockResolvedValueOnce(mockResponse({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        text: () => Promise.resolve('Invalid input'),
      }))

      await expect(apiGet('/test')).rejects.toThrow(ApiError)
      expect(mockFetch).toHaveBeenCalledTimes(1)
    })

    it('does not retry on abort', async () => {
      const controller = new AbortController()

      mockFetch.mockRejectedValueOnce(new DOMException('Aborted', 'AbortError'))

      await expect(apiGet('/test', { signal: controller.signal })).rejects.toThrow('Aborted')
      expect(mockFetch).toHaveBeenCalledTimes(1)
    })

    it('throws after max retries exceeded', async () => {
      mockFetch
        .mockRejectedValueOnce(new TypeError('Network error'))
        .mockRejectedValueOnce(new TypeError('Network error'))
        .mockRejectedValueOnce(new TypeError('Network error'))

      // Start the request and catch/track the promise
      let caughtError: Error | null = null
      const promise = apiGet('/test').catch((e) => {
        caughtError = e
      })

      // Advance through all retries
      await vi.advanceTimersByTimeAsync(1000)
      await vi.advanceTimersByTimeAsync(2000)
      await vi.advanceTimersByTimeAsync(4000)

      await promise
      expect(caughtError).toBeTruthy()
      expect(mockFetch).toHaveBeenCalledTimes(3)
    })
  })

  describe('createSSEConnection', () => {
    it('creates EventSource with correct URL', async () => {
      const onMessage = vi.fn()
      const es = await createSSEConnection('/approvals/pending', onMessage)

      expect(es.url).toContain('/api/approvals/pending')
    })

    it('includes token in URL when available', async () => {
      const onMessage = vi.fn()
      const es = await createSSEConnection('/approvals/pending', onMessage)

      // Token should be included as query param
      expect(es.url).toContain('token=')
    })

    it('parses JSON messages and calls handler', async () => {
      const onMessage = vi.fn()
      const es = await createSSEConnection('/approvals/pending', onMessage)

      // Simulate message event
      const mockEvent = new MessageEvent('message', {
        data: JSON.stringify({ type: 'snapshot', approvals: [] }),
      })
      es.onmessage?.(mockEvent)

      expect(onMessage).toHaveBeenCalledWith({ type: 'snapshot', approvals: [] })
    })

    it('calls error handler on SSE error', async () => {
      const onMessage = vi.fn()
      const onError = vi.fn()
      const es = await createSSEConnection('/approvals/pending', onMessage, onError)

      // Simulate error event
      const mockEvent = new Event('error')
      es.onerror?.(mockEvent)

      expect(onError).toHaveBeenCalledWith(mockEvent)
    })

    it('handles malformed JSON gracefully', async () => {
      const onMessage = vi.fn()
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const es = await createSSEConnection('/approvals/pending', onMessage)

      // Simulate malformed message
      const mockEvent = new MessageEvent('message', {
        data: 'not valid json',
      })
      es.onmessage?.(mockEvent)

      expect(onMessage).not.toHaveBeenCalled()
      expect(consoleSpy).toHaveBeenCalled()

      consoleSpy.mockRestore()
    })

    it('returns closeable EventSource', async () => {
      const onMessage = vi.fn()
      const es = await createSSEConnection('/approvals/pending', onMessage)

      es.close()

      expect(es.close).toHaveBeenCalled()
    })
  })
})

describe('ApiError', () => {
  it('includes status and message', () => {
    const error = new ApiError(404, 'Not Found', 'Resource not found')

    expect(error.status).toBe(404)
    expect(error.statusText).toBe('Not Found')
    expect(error.message).toBe('Resource not found')
  })

  it('has default message when not provided', () => {
    const error = new ApiError(500, 'Internal Server Error')

    expect(error.message).toContain('500')
    expect(error.message).toContain('Internal Server Error')
  })

  it('is instance of Error', () => {
    const error = new ApiError(400, 'Bad Request')

    expect(error).toBeInstanceOf(Error)
    expect(error.name).toBe('ApiError')
  })
})
