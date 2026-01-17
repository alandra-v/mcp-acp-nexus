import '@testing-library/jest-dom'
import { vi } from 'vitest'

// Mock window.__API_TOKEN__
Object.defineProperty(window, '__API_TOKEN__', {
  value: 'test-token-1234567890abcdef1234567890abcdef1234567890abcdef',
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
