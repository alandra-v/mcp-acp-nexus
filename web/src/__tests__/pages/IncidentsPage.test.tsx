/**
 * Unit tests for IncidentsPage component.
 *
 * Tests loading state, empty states (with/without filters), incident card
 * rendering, type/proxy filter dropdowns, filter persistence in localStorage,
 * proxy filter reset, load more, refresh, and mark as read on mount.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { IncidentsPage } from '@/pages/IncidentsPage'
import type { Proxy, IncidentEntry } from '@/types/api'
import type { UseIncidentsResult } from '@/hooks/useIncidents'

// Mock hooks
vi.mock('@/hooks/useIncidents', () => ({
  useIncidents: vi.fn(),
}))

vi.mock('@/hooks/useManagerProxies', () => ({
  useManagerProxies: vi.fn(),
}))

vi.mock('@/context/IncidentsContext', () => ({
  useIncidentsContext: vi.fn(),
}))

// Mock child components
vi.mock('@/components/layout/Layout', () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))

vi.mock('@/components/ui/BackButton', () => ({
  BackButton: () => <button aria-label="Go back">Back</button>,
}))

vi.mock('@/components/incidents/IncidentCard', () => ({
  IncidentCard: ({
    incident,
    isNew,
  }: {
    incident: IncidentEntry
    isNew: boolean
    isLast: boolean
  }) => (
    <div data-testid={`incident-card-${incident.incident_type}-${incident.time}`}>
      <span>{incident.incident_type}</span>
      {isNew && <span data-testid="new-badge">New</span>}
    </div>
  ),
}))

import { useIncidents } from '@/hooks/useIncidents'
import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useIncidentsContext } from '@/context/IncidentsContext'

const mockUseIncidents = vi.mocked(useIncidents)
const mockUseManagerProxies = vi.mocked(useManagerProxies)
const mockUseIncidentsContext = vi.mocked(useIncidentsContext)

const mockProxies: Proxy[] = [
  {
    proxy_name: 'proxy-1',
    proxy_id: 'id-1',
    status: 'running',
    instance_id: 'inst-1',
    server_name: 'Server 1',
    transport: 'stdio',
    command: 'node',
    args: ['server.js'],
    url: null,
    created_at: '2024-01-01T00:00:00Z',
    backend_transport: 'stdio',
    mtls_enabled: false,
    stats: null,
  },
  {
    proxy_name: 'proxy-2',
    proxy_id: 'id-2',
    status: 'inactive',
    instance_id: null,
    server_name: 'Server 2',
    transport: 'streamablehttp',
    command: null,
    args: null,
    url: 'http://localhost:3000',
    created_at: '2024-01-02T00:00:00Z',
    backend_transport: 'streamablehttp',
    mtls_enabled: false,
    stats: null,
  },
]

const mockIncidents: IncidentEntry[] = [
  {
    incident_type: 'shutdown',
    time: '2024-06-15T10:00:00Z',
    proxy_name: 'proxy-1',
    proxy_id: 'id-1',
    message: 'Audit integrity failure detected',
  },
  {
    incident_type: 'bootstrap',
    time: '2024-06-14T09:00:00Z',
    message: 'Config validation failed',
  },
  {
    incident_type: 'emergency',
    time: '2024-06-13T08:00:00Z',
    message: 'Audit fallback activated',
  },
]

const mockMarkAsRead = vi.fn()
const mockLoadMore = vi.fn()
const mockRefresh = vi.fn()

function defaultIncidentsReturn(overrides: Partial<UseIncidentsResult> = {}): UseIncidentsResult {
  return {
    incidents: [],
    loading: false,
    error: null,
    hasMore: false,
    loadMore: mockLoadMore,
    refresh: mockRefresh,
    ...overrides,
  }
}

function setupDefaultMocks(overrides: {
  incidents?: Partial<UseIncidentsResult>
  proxies?: Proxy[]
  lastSeenTimestamp?: string | null
} = {}) {
  mockUseIncidents.mockReturnValue(defaultIncidentsReturn(overrides.incidents))
  mockUseManagerProxies.mockReturnValue({
    proxies: overrides.proxies ?? mockProxies,
    loading: false,
    error: null,
    refetch: vi.fn(),
  })
  mockUseIncidentsContext.mockReturnValue({
    unreadCount: 0,
    lastSeenTimestamp: overrides.lastSeenTimestamp ?? null,
    summary: null,
    markAsRead: mockMarkAsRead,
    refresh: vi.fn(),
  })
}

function renderPage() {
  return render(
    <MemoryRouter>
      <IncidentsPage />
    </MemoryRouter>
  )
}

describe('IncidentsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('loading state', () => {
    it('shows "Loading incidents..." when loading with no data', () => {
      setupDefaultMocks({ incidents: { loading: true, incidents: [] } })

      renderPage()

      expect(screen.getByText('Loading incidents...')).toBeInTheDocument()
    })
  })

  describe('empty state', () => {
    it('shows "No incidents recorded" when no filters active', () => {
      setupDefaultMocks()

      renderPage()

      expect(screen.getByText('No incidents recorded')).toBeInTheDocument()
    })

    it('shows contextual message with type filter active', () => {
      setupDefaultMocks()

      renderPage()

      // Change type filter to "shutdown" using fireEvent (native select)
      const typeSelect = screen.getByLabelText('Filter by incident type')
      fireEvent.change(typeSelect, { target: { value: 'shutdown' } })

      expect(screen.getByText('No shutdowns recorded')).toBeInTheDocument()
    })

    it('shows contextual message with proxy filter active', () => {
      setupDefaultMocks()

      renderPage()

      // Change proxy filter
      const proxySelect = screen.getByLabelText('Filter by proxy')
      fireEvent.change(proxySelect, { target: { value: 'proxy-1' } })

      expect(screen.getByText('No incidents for proxy-1 recorded')).toBeInTheDocument()
    })
  })

  describe('incident cards', () => {
    it('renders incident cards for each incident', () => {
      setupDefaultMocks({ incidents: { incidents: mockIncidents } })

      renderPage()

      expect(screen.getByTestId('incident-card-shutdown-2024-06-15T10:00:00Z')).toBeInTheDocument()
      expect(screen.getByTestId('incident-card-bootstrap-2024-06-14T09:00:00Z')).toBeInTheDocument()
      expect(screen.getByTestId('incident-card-emergency-2024-06-13T08:00:00Z')).toBeInTheDocument()
    })

    it('marks incidents as new when after lastSeenTimestamp', () => {
      setupDefaultMocks({
        incidents: { incidents: mockIncidents },
        lastSeenTimestamp: '2024-06-14T12:00:00Z',
      })

      renderPage()

      // The shutdown at 10:00 on the 15th is after the 14th — should be new
      const shutdownCard = screen.getByTestId('incident-card-shutdown-2024-06-15T10:00:00Z')
      expect(shutdownCard.querySelector('[data-testid="new-badge"]')).toBeInTheDocument()

      // The bootstrap at 09:00 on the 14th is before — not new
      const bootstrapCard = screen.getByTestId('incident-card-bootstrap-2024-06-14T09:00:00Z')
      expect(bootstrapCard.querySelector('[data-testid="new-badge"]')).not.toBeInTheDocument()
    })
  })

  describe('type filter dropdown', () => {
    it('changes filter when selecting a type', () => {
      setupDefaultMocks({ incidents: { incidents: mockIncidents } })

      renderPage()

      const typeSelect = screen.getByLabelText('Filter by incident type')
      fireEvent.change(typeSelect, { target: { value: 'shutdown' } })

      // The hook should have been called with the new filter
      expect(mockUseIncidents).toHaveBeenCalledWith(
        expect.objectContaining({ incidentType: 'shutdown' })
      )
    })
  })

  describe('proxy filter dropdown', () => {
    it('shows proxy names when proxies exist', () => {
      setupDefaultMocks()

      renderPage()

      const proxySelect = screen.getByLabelText('Filter by proxy')
      expect(proxySelect).toBeInTheDocument()

      // Check options
      const options = proxySelect.querySelectorAll('option')
      expect(options).toHaveLength(3) // All Proxies + proxy-1 + proxy-2
      expect(options[0]).toHaveTextContent('All Proxies')
      expect(options[1]).toHaveTextContent('proxy-1')
      expect(options[2]).toHaveTextContent('proxy-2')
    })

    it('is hidden when no proxies exist', () => {
      setupDefaultMocks({ proxies: [] })

      renderPage()

      expect(screen.queryByLabelText('Filter by proxy')).not.toBeInTheDocument()
    })
  })

  describe('filter persistence', () => {
    it('reads type filter from localStorage', () => {
      localStorage.setItem('incidentsTypeFilter', 'shutdown')
      setupDefaultMocks()

      renderPage()

      expect(mockUseIncidents).toHaveBeenCalledWith(
        expect.objectContaining({ incidentType: 'shutdown' })
      )
    })

    it('reads proxy filter from localStorage', () => {
      localStorage.setItem('incidentsProxyFilter', 'proxy-1')
      setupDefaultMocks()

      renderPage()

      expect(mockUseIncidents).toHaveBeenCalledWith(
        expect.objectContaining({ proxy: 'proxy-1' })
      )
    })

    it('writes type filter to localStorage on change', () => {
      setupDefaultMocks()

      renderPage()

      const typeSelect = screen.getByLabelText('Filter by incident type')
      fireEvent.change(typeSelect, { target: { value: 'emergency' } })

      expect(localStorage.getItem('incidentsTypeFilter')).toBe('emergency')
    })
  })

  describe('proxy filter reset', () => {
    it('resets to "all" if stored proxy no longer exists', () => {
      localStorage.setItem('incidentsProxyFilter', 'deleted-proxy')
      setupDefaultMocks()

      renderPage()

      // The hook should eventually be called with proxy: undefined (all)
      const lastCall = mockUseIncidents.mock.calls[mockUseIncidents.mock.calls.length - 1]
      expect(lastCall[0]).toHaveProperty('proxy', undefined)
    })
  })

  describe('Load More button', () => {
    it('is visible when hasMore is true', () => {
      setupDefaultMocks({
        incidents: { incidents: mockIncidents, hasMore: true },
      })

      renderPage()

      expect(screen.getByRole('button', { name: /load more/i })).toBeInTheDocument()
    })

    it('is not visible when hasMore is false', () => {
      setupDefaultMocks({ incidents: { incidents: mockIncidents, hasMore: false } })

      renderPage()

      expect(screen.queryByRole('button', { name: /load more/i })).not.toBeInTheDocument()
    })

    it('calls loadMore when clicked', async () => {
      const user = userEvent.setup()
      setupDefaultMocks({
        incidents: { incidents: mockIncidents, hasMore: true },
      })

      renderPage()

      const loadMoreBtn = screen.getByRole('button', { name: /load more/i })
      await user.click(loadMoreBtn)

      expect(mockLoadMore).toHaveBeenCalledOnce()
    })
  })

  describe('Refresh button', () => {
    it('calls refresh when clicked', async () => {
      const user = userEvent.setup()
      setupDefaultMocks({ incidents: { incidents: mockIncidents } })

      renderPage()

      const refreshBtn = screen.getByRole('button', { name: /refresh/i })
      await user.click(refreshBtn)

      expect(mockRefresh).toHaveBeenCalledOnce()
    })
  })

  describe('mark as read', () => {
    it('calls markAsRead on mount after delay', () => {
      vi.useFakeTimers()
      setupDefaultMocks()

      renderPage()

      expect(mockMarkAsRead).not.toHaveBeenCalled()

      // Advance past the INCIDENTS_MARK_READ_DELAY_MS (500ms)
      act(() => {
        vi.advanceTimersByTime(500)
      })

      expect(mockMarkAsRead).toHaveBeenCalledOnce()
      vi.useRealTimers()
    })
  })
})
