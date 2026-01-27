import { ApiError, type ErrorDetail } from '@/types/api'

const API_BASE = '/api'

// Retry configuration
const MAX_RETRIES = 3
const INITIAL_DELAY_MS = 1000

// Authentication:
// - Production (same-origin): Uses HttpOnly cookie (set by server, auto-sent)
// - Dev mode (cross-origin): Token fetched from /api/auth/dev-token endpoint
//
// In dev mode, Vite runs on :3000 while API runs on :8765 (cross-origin).
// Cookies with SameSite=Strict won't be sent cross-origin, so we fall back
// to token fetch + Authorization header for dev mode.

// Token storage - fetched from dev-token endpoint in dev mode
let API_TOKEN: string | null = null
let tokenPromise: Promise<void> | null = null

/**
 * Set the API token directly (for tests only).
 */
export function setApiToken(token: string | null): void {
  API_TOKEN = token
  tokenPromise = null
}

/**
 * Ensure the API token is available (for dev mode).
 * In production, cookies handle auth so this is a no-op.
 * In dev mode, fetches token from /api/auth/dev-token if not already present.
 */
async function ensureToken(): Promise<void> {
  // Token already available (from window injection, test, or previous fetch)
  if (API_TOKEN) return

  // Already fetching - wait for that
  if (tokenPromise) {
    await tokenPromise
    return
  }

  // Try to fetch dev token (only works in dev mode)
  tokenPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/dev-token`, {
        credentials: 'same-origin',
      })
      if (res.ok) {
        const data = await res.json()
        API_TOKEN = data.token
      }
      // 404 means production mode - that's fine, cookies will be used
    } catch (e) {
      // Network error (TypeError) or other issue - continue without token
      // In production, cookies will handle auth
      // Log only if it's an unexpected error type
      // if (!(e instanceof TypeError)) {
      //   console.warn('Unexpected error fetching dev token:', e)
      // }
      void e // silence unused variable
    }
  })()

  await tokenPromise
}

function getAuthHeaders(): HeadersInit {
  const headers: HeadersInit = {}
  if (API_TOKEN) {
    headers['Authorization'] = `Bearer ${API_TOKEN}`
  }
  return headers
}

/**
 * Sleep for the specified number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Parse error response from backend.
 *
 * Response formats:
 * - Structured: {"detail": {"code": "...", "message": "...", "details": {...}}}
 * - String: {"detail": "message"}
 * - Pydantic validation: {"detail": [{loc: [...], msg: "..."}]}
 */
async function parseErrorResponse(res: Response): Promise<ApiError> {
  const text = await res.text()

  try {
    const json = JSON.parse(text)

    // Structured format: {"detail": {"code": "...", "message": "...", ...}}
    if (json.detail && typeof json.detail === 'object' && 'code' in json.detail) {
      const errorDetail = json.detail as ErrorDetail
      return new ApiError(res.status, res.statusText, errorDetail.message, errorDetail)
    }

    // String format: {"detail": "string message"}
    if (typeof json.detail === 'string') {
      return new ApiError(res.status, res.statusText, json.detail)
    }

    // Pydantic validation error format: {"detail": [{msg: "..."}]}
    if (Array.isArray(json.detail)) {
      const messages = json.detail.map((e: { msg?: string }) => e.msg || JSON.stringify(e)).join(', ')
      return new ApiError(res.status, res.statusText, messages)
    }

    return new ApiError(res.status, res.statusText, text)
  } catch {
    return new ApiError(res.status, res.statusText, text)
  }
}

/**
 * Check if an error is retryable (network error or 5xx server error).
 */
function isRetryable(error: unknown): boolean {
  // Network errors (fetch throws)
  if (error instanceof TypeError) return true
  // Server errors (5xx)
  if (error instanceof ApiError && error.status >= 500) return true
  return false
}

/**
 * Options for API requests with optional abort signal.
 */
export interface RequestOptions {
  /** AbortSignal to cancel the request */
  signal?: AbortSignal
}

/**
 * Fetch with exponential backoff retry for transient failures.
 * Only retries on network errors and 5xx server errors.
 * Respects AbortSignal to cancel requests.
 */
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  retries = MAX_RETRIES
): Promise<Response> {
  let lastError: unknown

  for (let attempt = 0; attempt < retries; attempt++) {
    // Check if request was aborted before attempting
    if (options.signal?.aborted) {
      throw new DOMException('Request aborted', 'AbortError')
    }

    try {
      const res = await fetch(url, options)

      // Don't retry client errors (4xx)
      if (res.ok || (res.status >= 400 && res.status < 500)) {
        return res
      }

      // Server error (5xx) - will retry
      const error = await parseErrorResponse(res)
      lastError = error

      if (attempt < retries - 1 && isRetryable(error)) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt)
        // console.warn(`Request failed (${res.status}), retrying in ${delay}ms...`)
        await sleep(delay)
        continue
      }

      throw error
    } catch (error) {
      // Don't retry if request was aborted
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw error
      }

      lastError = error

      // Network error - retry with backoff
      if (attempt < retries - 1 && isRetryable(error)) {
        const delay = INITIAL_DELAY_MS * Math.pow(2, attempt)
        // console.warn(`Network error, retrying in ${delay}ms...`)
        await sleep(delay)
        continue
      }

      throw error
    }
  }

  throw lastError
}

/**
 * Generic API request handler that eliminates duplication across HTTP methods.
 * Handles authentication, error handling, and JSON parsing.
 */
async function apiRequest<T>(
  path: string,
  method: string,
  body?: unknown,
  options?: RequestOptions
): Promise<T> {
  // Ensure token is available (dev mode fetches from /api/auth/dev-token)
  await ensureToken()

  const headers: HeadersInit = {
    ...getAuthHeaders(),
    ...(body ? { 'Content-Type': 'application/json' } : {}),
  }

  const res = await fetchWithRetry(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    signal: options?.signal,
    credentials: 'same-origin', // Send cookies for same-origin requests (production)
  })

  if (!res.ok) {
    throw await parseErrorResponse(res)
  }

  // Handle 204 No Content (e.g., DELETE responses)
  if (res.status === 204 || res.headers.get('content-length') === '0') {
    return undefined as T
  }

  try {
    return await res.json()
  } catch {
    throw new ApiError(res.status, 'Invalid JSON', 'Server returned invalid JSON response')
  }
}

export function apiGet<T>(path: string, options?: RequestOptions): Promise<T> {
  return apiRequest<T>(path, 'GET', undefined, options)
}

export function apiPost<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
  return apiRequest<T>(path, 'POST', body, options)
}

export function apiPut<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
  return apiRequest<T>(path, 'PUT', body, options)
}

export function apiDelete<T>(path: string, options?: RequestOptions): Promise<T> {
  return apiRequest<T>(path, 'DELETE', undefined, options)
}

// SSE connection for pending approvals
// - Production: Cookie is sent automatically with EventSource (withCredentials: true)
// - Dev mode: Token passed as query param (EventSource can't send custom headers)
export async function createSSEConnection<T = unknown>(
  path: string,
  onMessage: (data: T) => void,
  onError?: (error: Event) => void
): Promise<EventSource> {
  // Ensure token is available (dev mode fetches from /api/auth/dev-token)
  await ensureToken()

  let url = `${API_BASE}${path}`

  // Add token as query param for cross-origin dev mode
  // The security middleware accepts ?token= for SSE endpoints
  if (API_TOKEN) {
    const separator = url.includes('?') ? '&' : '?'
    url = `${url}${separator}token=${encodeURIComponent(API_TOKEN)}`
  }

  // withCredentials sends cookies for same-origin requests (production)
  // In dev mode (cross-origin), cookies won't be sent but token query param is used
  const es = new EventSource(url, { withCredentials: true })

  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data)
      onMessage(data)
    } catch {
      // console.error('Failed to parse SSE message:', e)
    }
  }

  es.onerror = (error) => {
    // console.error('SSE error:', error)
    onError?.(error)
  }

  return es
}
