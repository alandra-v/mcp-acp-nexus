/**
 * Unit tests for ProxyListPage component.
 *
 * Tests loading state, empty state, proxy grid rendering,
 * filter chips with counts, filter persistence in localStorage,
 * export all button, and add proxy button.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { ProxyListPage } from '@/pages/ProxyListPage'
import * as proxiesApi from '@/api/proxies'
import type { Proxy } from '@/types/api'

// Mock hooks and API
vi.mock('@/hooks/useManagerProxies', () => ({
  useManagerProxies: vi.fn(),
}))

vi.mock('@/api/proxies', () => ({
  getConfigSnippet: vi.fn(),
}))

vi.mock('@/hooks/useErrorSound', () => ({
  notifyError: vi.fn(),
}))

vi.mock('@/context/AppStateContext', () => ({
  useAppState: vi.fn(),
}))

// Mock child components to isolate page logic
vi.mock('@/components/proxies/ProxyGrid', () => ({
  ProxyGrid: ({ proxies }: { proxies: Proxy[] }) => (
    <div data-testid="proxy-grid">
      {proxies.map((p) => (
        <div key={p.proxy_id} data-testid={`proxy-card-${p.proxy_id}`}>
          {p.proxy_name}
        </div>
      ))}
    </div>
  ),
}))

vi.mock('@/components/proxies/ProxyCardSkeleton', () => ({
  ProxyGridSkeleton: () => <div data-testid="proxy-grid-skeleton">Loading...</div>,
}))

vi.mock('@/components/proxy/AddProxyModal', () => ({
  AddProxyModal: ({
    open,
    onOpenChange,
  }: {
    open: boolean
    onOpenChange: (open: boolean) => void
  }) =>
    open ? (
      <div data-testid="add-proxy-modal">
        <button onClick={() => onOpenChange(false)}>Close</button>
      </div>
    ) : null,
}))

vi.mock('@/components/layout/Layout', () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))

import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useAppState } from '@/context/AppStateContext'

const mockUseManagerProxies = vi.mocked(useManagerProxies)
const mockUseAppState = vi.mocked(useAppState)

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

function renderPage() {
  return render(
    <MemoryRouter>
      <ProxyListPage />
    </MemoryRouter>
  )
}

describe('ProxyListPage', () => {
  let clipboardWriteText: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()

    // Re-establish useAppState mock after clearAllMocks
    mockUseAppState.mockReturnValue({
      pending: [],
      cached: [],
      cachedTtlSeconds: 0,
      stats: {},
      connected: false,
      connectionStatus: 'reconnecting',
      approve: vi.fn(),
      approveOnce: vi.fn(),
      deny: vi.fn(),
      clearCached: vi.fn(),
      deleteCached: vi.fn(),
    } as ReturnType<typeof useAppState>)

    // Re-establish clipboard mock after clearAllMocks
    clipboardWriteText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: clipboardWriteText, readText: vi.fn().mockResolvedValue('') },
      writable: true,
      configurable: true,
    })
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('loading state', () => {
    it('shows skeleton when loading', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [],
        loading: true,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      expect(screen.getByTestId('proxy-grid-skeleton')).toBeInTheDocument()
    })
  })

  describe('empty state', () => {
    it('shows "No proxies configured" with Add Proxy button when no proxies', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      expect(screen.getByText('No proxies configured')).toBeInTheDocument()
      // Both header and empty state have Add Proxy buttons
      const addButtons = screen.getAllByRole('button', { name: /add proxy/i })
      expect(addButtons.length).toBeGreaterThanOrEqual(1)
    })
  })

  describe('proxy grid', () => {
    it('renders proxy cards when proxies exist', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      expect(screen.getByTestId('proxy-grid')).toBeInTheDocument()
      expect(screen.getByTestId('proxy-card-proxy-123')).toBeInTheDocument()
      expect(screen.getByTestId('proxy-card-proxy-456')).toBeInTheDocument()
    })
  })

  describe('filter chips', () => {
    it('shows All/Running/Inactive tabs with correct counts', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      const tablist = screen.getByRole('tablist', { name: /filter proxies/i })
      const tabs = within(tablist).getAllByRole('tab')

      expect(tabs).toHaveLength(3)
      expect(tabs[0]).toHaveTextContent('All')
      expect(tabs[0]).toHaveTextContent('(2)')
      expect(tabs[1]).toHaveTextContent('Running')
      expect(tabs[1]).toHaveTextContent('(1)')
      expect(tabs[2]).toHaveTextContent('Inactive')
      expect(tabs[2]).toHaveTextContent('(1)')
    })

    it('filters proxies when clicking a tab', async () => {
      const user = userEvent.setup()
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      // Click "Running" tab
      const runningTab = screen.getByRole('tab', { name: /running/i })
      await user.click(runningTab)

      // Only running proxy should appear
      expect(screen.getByTestId('proxy-card-proxy-123')).toBeInTheDocument()
      expect(screen.queryByTestId('proxy-card-proxy-456')).not.toBeInTheDocument()
    })

    it('shows "All" tab as selected by default', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      const allTab = screen.getByRole('tab', { name: /^all/i })
      expect(allTab).toHaveAttribute('aria-selected', 'true')
    })
  })

  describe('filter persistence', () => {
    it('reads initial filter from localStorage', () => {
      localStorage.setItem('proxyListFilter', 'active')

      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      const runningTab = screen.getByRole('tab', { name: /running/i })
      expect(runningTab).toHaveAttribute('aria-selected', 'true')
    })

    it('writes filter to localStorage on change', async () => {
      const user = userEvent.setup()
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      const inactiveTab = screen.getByRole('tab', { name: /inactive/i })
      await user.click(inactiveTab)

      expect(localStorage.getItem('proxyListFilter')).toBe('inactive')
    })
  })

  describe('Export All button', () => {
    it('is hidden when no proxies exist', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      expect(screen.queryByRole('button', { name: /export all/i })).not.toBeInTheDocument()
    })

    it('calls getConfigSnippet and copies to clipboard', async () => {
      const mockSnippet = {
        mcpServers: { 'test-proxy-1': { command: 'mcp-acp', args: ['start'] } },
        executable_path: '/usr/bin/mcp-acp',
      }
      vi.mocked(proxiesApi.getConfigSnippet).mockResolvedValue(mockSnippet)

      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      const exportBtn = screen.getByRole('button', { name: /export all client configs/i })
      // Use fireEvent for click since we don't need full user interaction simulation
      // and userEvent.setup() replaces the clipboard API internally
      fireEvent.click(exportBtn)

      await waitFor(() => {
        expect(proxiesApi.getConfigSnippet).toHaveBeenCalledOnce()
        expect(clipboardWriteText).toHaveBeenCalledWith(
          JSON.stringify({ mcpServers: mockSnippet.mcpServers }, null, 2)
        )
      })
    })
  })

  describe('Add Proxy button', () => {
    it('is visible in header when proxies exist', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      expect(screen.getByRole('button', { name: /add proxy/i })).toBeInTheDocument()
    })

    it('opens modal on click', async () => {
      const user = userEvent.setup()
      mockUseManagerProxies.mockReturnValue({
        proxies: mockProxies,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage()

      expect(screen.queryByTestId('add-proxy-modal')).not.toBeInTheDocument()

      const addBtn = screen.getByRole('button', { name: /add proxy/i })
      await user.click(addBtn)

      expect(screen.getByTestId('add-proxy-modal')).toBeInTheDocument()
    })
  })
})
