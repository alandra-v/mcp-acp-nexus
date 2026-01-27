import '@testing-library/jest-dom'
import { vi } from 'vitest'
import { setApiToken } from '@/api/client'

// Set API token for tests
setApiToken('test-token-1234567890abcdef1234567890abcdef1234567890abcdef')

// Mock pointer capture methods for Radix UI components (not available in jsdom)
Element.prototype.hasPointerCapture = vi.fn(() => false)
Element.prototype.setPointerCapture = vi.fn()
Element.prototype.releasePointerCapture = vi.fn()
Element.prototype.scrollIntoView = vi.fn()

// Mock ResizeObserver (not available in jsdom)
class MockResizeObserver {
  observe = vi.fn()
  unobserve = vi.fn()
  disconnect = vi.fn()
}
global.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver

// Mock clipboard API (configurable so userEvent can override)
Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: vi.fn().mockResolvedValue(undefined),
    readText: vi.fn().mockResolvedValue(''),
  },
  writable: true,
  configurable: true,
})

// Mock window.open
vi.stubGlobal('open', vi.fn())

// Mock Audio for notification sounds
vi.stubGlobal(
  'Audio',
  vi.fn().mockImplementation(() => ({
    play: vi.fn().mockResolvedValue(undefined),
    pause: vi.fn(),
    load: vi.fn(),
  }))
)

// Mock EventSource for SSE
class MockEventSource {
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  onopen: ((event: Event) => void) | null = null
  readyState = 1
  url: string
  withCredentials = false

  constructor(url: string) {
    this.url = url
  }

  close = vi.fn()
  addEventListener = vi.fn()
  removeEventListener = vi.fn()
  dispatchEvent = vi.fn(() => true)
}

vi.stubGlobal('EventSource', MockEventSource)
