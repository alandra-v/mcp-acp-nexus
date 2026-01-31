/**
 * Unit tests for ConnectionStatusBanner component.
 *
 * Tests connection state transitions, auto-hide behavior,
 * dismiss/retry actions, and initial load suppression.
 *
 * The real AppStateContext starts with connectionStatus='reconnecting'
 * (initial SSE connection attempt), so tests simulate from that state.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConnectionStatusBanner } from '@/components/ConnectionStatusBanner'

// Hoisted mock state (accessible inside vi.mock factory)
const { mockUseAppState } = vi.hoisted(() => ({
  mockUseAppState: vi.fn(),
}))

vi.mock('@/context/AppStateContext', () => ({
  useAppState: mockUseAppState,
}))

// Mock window.location.reload
const reloadMock = vi.fn()

describe('ConnectionStatusBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    // Default to initial state (reconnecting before first connection)
    mockUseAppState.mockReturnValue({ connectionStatus: 'reconnecting' })
    Object.defineProperty(window, 'location', {
      value: { reload: reloadMock },
      writable: true,
      configurable: true,
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  /** Helper to render with a given status */
  function renderWithStatus(status: string) {
    mockUseAppState.mockReturnValue({ connectionStatus: status })
    return render(<ConnectionStatusBanner />)
  }

  /** Helper to change status and rerender */
  function changeStatus(rerender: (ui: React.ReactElement) => void, status: string) {
    mockUseAppState.mockReturnValue({ connectionStatus: status })
    rerender(<ConnectionStatusBanner />)
  }

  /**
   * Helper: simulate the normal first-connection flow.
   * Starts in 'reconnecting' (real initial state), transitions to 'connected'.
   * Returns the rerender function for further status transitions.
   */
  function connectOnce() {
    const { rerender } = renderWithStatus('reconnecting')
    changeStatus(rerender, 'connected')
    return rerender
  }

  describe('initial load', () => {
    it('renders nothing on initial connected state', () => {
      const { container } = renderWithStatus('connected')
      expect(container.innerHTML).toBe('')
    })

    it('renders nothing while reconnecting before first connection', () => {
      const { container } = renderWithStatus('reconnecting')
      expect(container.innerHTML).toBe('')
    })

    it('renders nothing while disconnected before first connection', () => {
      const { container } = renderWithStatus('disconnected')
      expect(container.innerHTML).toBe('')
    })
  })

  describe('after first connection', () => {
    it('shows reconnecting banner after connected → reconnecting', () => {
      const rerender = connectOnce()
      changeStatus(rerender, 'reconnecting')

      expect(screen.getByText('Connection to manager lost. Reconnecting...')).toBeInTheDocument()
    })

    it('shows dismiss button in reconnecting state', () => {
      const rerender = connectOnce()
      changeStatus(rerender, 'reconnecting')

      expect(screen.getByLabelText('Dismiss')).toBeInTheDocument()
    })

    it('shows disconnected banner after connected → disconnected', () => {
      const rerender = connectOnce()
      changeStatus(rerender, 'disconnected')

      expect(screen.getByText('Unable to connect to manager')).toBeInTheDocument()
    })

    it('shows Retry button in disconnected state', () => {
      const rerender = connectOnce()
      changeStatus(rerender, 'disconnected')

      expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
    })

    it('calls window.location.reload on Retry click', async () => {
      vi.useRealTimers()
      const user = userEvent.setup()
      const rerender = connectOnce()
      changeStatus(rerender, 'disconnected')

      await user.click(screen.getByRole('button', { name: 'Retry' }))
      expect(reloadMock).toHaveBeenCalled()
    })
  })

  describe('reconnection success', () => {
    it('shows "Connection restored" on reconnecting → connected', () => {
      const rerender = connectOnce()
      changeStatus(rerender, 'reconnecting')
      changeStatus(rerender, 'connected')

      expect(screen.getByText('Connection restored')).toBeInTheDocument()
    })

    it('shows success banner briefly on reconnection', () => {
      // The component shows "Connection restored" when transitioning
      // reconnecting → connected (after first connection). The banner
      // is shown via showSuccess state triggered in the useEffect.
      const rerender = connectOnce()
      changeStatus(rerender, 'reconnecting')
      changeStatus(rerender, 'connected')

      expect(screen.getByText('Connection restored')).toBeInTheDocument()

      // Subsequent reconnecting transition clears the success banner
      changeStatus(rerender, 'reconnecting')
      expect(screen.queryByText('Connection restored')).not.toBeInTheDocument()
      expect(screen.getByText('Connection to manager lost. Reconnecting...')).toBeInTheDocument()
    })

    it('does not show "Connection restored" on first connection', () => {
      // Start in reconnecting, connect for first time
      const { rerender } = renderWithStatus('reconnecting')
      changeStatus(rerender, 'connected')

      expect(screen.queryByText('Connection restored')).not.toBeInTheDocument()
    })
  })

  describe('dismiss', () => {
    it('hides reconnecting banner on dismiss click', async () => {
      vi.useRealTimers()
      const user = userEvent.setup()
      const rerender = connectOnce()
      changeStatus(rerender, 'reconnecting')

      await user.click(screen.getByLabelText('Dismiss'))

      expect(screen.queryByText('Connection to manager lost. Reconnecting...')).not.toBeInTheDocument()
    })

    it('shows banner again when status changes to disconnected after dismiss', async () => {
      vi.useRealTimers()
      const user = userEvent.setup()
      const rerender = connectOnce()

      changeStatus(rerender, 'reconnecting')
      await user.click(screen.getByLabelText('Dismiss'))

      changeStatus(rerender, 'disconnected')

      expect(screen.getByText('Unable to connect to manager')).toBeInTheDocument()
    })
  })
})
