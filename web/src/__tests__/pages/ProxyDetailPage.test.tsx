/**
 * Unit tests for ProxyDetailPage component.
 *
 * Tests loading state, proxy not found, connecting state, header rendering,
 * tab routing via search params, delete button state, copy config, and
 * SSE proxy_deleted navigation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { ProxyDetailPage } from '@/pages/ProxyDetailPage'
import * as proxiesApi from '@/api/proxies'
import { SSE_EVENTS } from '@/constants'
import type { Proxy, ProxyDetailResponse } from '@/types/api'

// Track navigate calls
const mockNavigate = vi.fn()

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

vi.mock('@/hooks/useManagerProxies', () => ({
  useManagerProxies: vi.fn(),
}))

vi.mock('@/hooks/useProxyDetail', () => ({
  useProxyDetail: vi.fn(),
}))

vi.mock('@/context/AppStateContext', () => ({
  useAppState: vi.fn(),
}))

vi.mock('@/hooks/useCachedApprovals', () => ({
  useCachedApprovals: vi.fn(),
}))

vi.mock('@/api/proxies', () => ({
  getConfigSnippet: vi.fn(),
  deleteProxy: vi.fn(),
}))

vi.mock('@/api/audit', () => ({
  verifyAuditLogs: vi.fn().mockResolvedValue({ files: [] }),
}))

vi.mock('@/hooks/useErrorSound', () => ({
  notifyError: vi.fn(),
}))

vi.mock('@/components/ui/sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
  },
}))

// Mock heavy child components to isolate page logic
vi.mock('@/components/layout/Layout', () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))

vi.mock('@/components/ui/BackButton', () => ({
  BackButton: () => <button aria-label="Go back">Back</button>,
}))

vi.mock('@/components/detail/DetailSidebar', () => ({
  DetailSidebar: ({
    activeSection,
    onSectionChange,
  }: {
    activeSection: string
    onSectionChange: (s: string) => void
  }) => (
    <nav data-testid="detail-sidebar" data-active={activeSection}>
      <button onClick={() => onSectionChange('overview')}>Overview</button>
      <button onClick={() => onSectionChange('audit')}>Audit</button>
    </nav>
  ),
}))

vi.mock('@/components/detail/TransportFlow', () => ({
  TransportFlow: () => <div data-testid="transport-flow">TransportFlow</div>,
}))

vi.mock('@/components/detail/StatsSection', () => ({
  StatsSection: () => <div data-testid="stats-section">StatsSection</div>,
}))

vi.mock('@/components/detail/ApprovalsSection', () => ({
  ApprovalsSection: () => <div data-testid="approvals-section">ApprovalsSection</div>,
}))

vi.mock('@/components/detail/CachedSection', () => ({
  CachedSection: () => <div data-testid="cached-section">CachedSection</div>,
}))

vi.mock('@/components/detail/ActivitySection', () => ({
  ActivitySection: () => <div data-testid="activity-section">ActivitySection</div>,
}))

vi.mock('@/components/logs', () => ({
  LogViewer: () => <div data-testid="log-viewer">LogViewer</div>,
}))

vi.mock('@/components/detail/Section', () => ({
  Section: ({ children, title }: { children: React.ReactNode; title: string }) => (
    <div data-testid={`section-${title.toLowerCase().replace(/\s+/g, '-')}`}>{children}</div>
  ),
}))

vi.mock('@/components/detail/ConfigSection', () => ({
  ConfigSection: () => <div data-testid="config-section">ConfigSection</div>,
}))

vi.mock('@/components/detail/PolicySection', () => ({
  PolicySection: () => <div data-testid="policy-section">PolicySection</div>,
}))

vi.mock('@/components/detail/AuditIntegritySection', () => ({
  AuditIntegritySection: () => <div data-testid="audit-integrity">AuditIntegrity</div>,
}))

vi.mock('@/components/proxy/DeleteProxyConfirmDialog', () => ({
  DeleteProxyConfirmDialog: ({
    open,
    onConfirm,
    proxyName,
  }: {
    open: boolean
    onConfirm: (purge: boolean) => void
    proxyName: string
    onOpenChange: (open: boolean) => void
    isDeleting: boolean
  }) =>
    open ? (
      <div data-testid="delete-confirm-dialog">
        <span>Delete {proxyName}?</span>
        <button onClick={() => onConfirm(false)}>Confirm Delete</button>
      </div>
    ) : null,
}))

import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useProxyDetail } from '@/hooks/useProxyDetail'
import { useAppState } from '@/context/AppStateContext'
import { useCachedApprovals } from '@/hooks/useCachedApprovals'

const mockUseManagerProxies = vi.mocked(useManagerProxies)
const mockUseProxyDetail = vi.mocked(useProxyDetail)
const mockUseAppState = vi.mocked(useAppState)
const mockUseCachedApprovals = vi.mocked(useCachedApprovals)

const mockRunningProxy: Proxy = {
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
  },
}

const mockInactiveProxy: Proxy = {
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
}

const mockProxyDetail: ProxyDetailResponse = {
  ...mockRunningProxy,
  client_id: 'claude-ai',
  pending_approvals: [],
  cached_approvals: [],
}

function renderPage(proxyId: string, search = '') {
  return render(
    <MemoryRouter initialEntries={[`/proxy/${proxyId}${search}`]}>
      <Routes>
        <Route path="/proxy/:id" element={<ProxyDetailPage />} />
        <Route path="/" element={<div data-testid="home-page">Home</div>} />
      </Routes>
    </MemoryRouter>
  )
}

describe('ProxyDetailPage', () => {
  let clipboardWriteText: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()

    // Re-establish mock return values after clearAllMocks
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

    mockUseCachedApprovals.mockReturnValue({
      cached: [],
      ttlSeconds: 300,
      loading: false,
      clear: vi.fn(),
      deleteEntry: vi.fn(),
    })

    // Re-establish clipboard mock
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
    it('shows "Loading..." when manager proxies are loading', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [],
        loading: true,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: null,
        loading: true,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      expect(screen.getByText('Loading...')).toBeInTheDocument()
    })
  })

  describe('proxy not found', () => {
    it('shows "Proxy not found" when proxy ID does not match any proxy', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: null,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('nonexistent-id')

      expect(screen.getByText('Proxy not found')).toBeInTheDocument()
    })
  })

  describe('connecting state', () => {
    it('shows "Connecting to proxy..." when proxy is running but detail still loading', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: null,
        loading: true,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      expect(screen.getByText('Connecting to proxy...')).toBeInTheDocument()
      expect(screen.getByText(/Waiting for connection to Test Server 1/)).toBeInTheDocument()
    })
  })

  describe('proxy header', () => {
    it('renders proxy name, server name, and Running status', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      expect(screen.getByText('test-proxy-1')).toBeInTheDocument()
      expect(screen.getByText('(Test Server 1)')).toBeInTheDocument()
      expect(screen.getByText('Running')).toBeInTheDocument()
    })

    it('renders Inactive status for inactive proxy', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockInactiveProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: null,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-456')

      expect(screen.getByText('Inactive')).toBeInTheDocument()
    })
  })

  describe('tab routing', () => {
    it('defaults to overview section', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      expect(screen.getByTestId('detail-sidebar')).toHaveAttribute('data-active', 'overview')
      expect(screen.getByTestId('transport-flow')).toBeInTheDocument()
    })

    it('shows audit tab when ?section=audit', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123', '?section=audit')

      expect(screen.getByTestId('detail-sidebar')).toHaveAttribute('data-active', 'audit')
      expect(screen.getByTestId('log-viewer')).toBeInTheDocument()
    })
  })

  describe('delete button', () => {
    it('is disabled when proxy is running', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      const deleteBtn = screen.getByRole('button', { name: /delete/i })
      expect(deleteBtn).toBeDisabled()
    })

    it('is enabled when proxy is inactive and opens confirmation dialog', async () => {
      const user = userEvent.setup()
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockInactiveProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: null,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-456')

      const deleteBtn = screen.getByRole('button', { name: /delete/i })
      expect(deleteBtn).not.toBeDisabled()

      await user.click(deleteBtn)

      expect(screen.getByTestId('delete-confirm-dialog')).toBeInTheDocument()
    })
  })

  describe('copy config button', () => {
    it('calls getConfigSnippet with proxy name and copies to clipboard', async () => {
      const mockSnippet = {
        mcpServers: { 'test-proxy-1': { command: 'mcp-acp', args: ['start'] } },
        executable_path: '/usr/bin/mcp-acp',
      }
      vi.mocked(proxiesApi.getConfigSnippet).mockResolvedValue(mockSnippet)

      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      const copyBtn = screen.getByRole('button', { name: /copy client config/i })
      // Use fireEvent since userEvent.setup() replaces the clipboard API
      fireEvent.click(copyBtn)

      await waitFor(() => {
        expect(proxiesApi.getConfigSnippet).toHaveBeenCalledWith('test-proxy-1')
        expect(clipboardWriteText).toHaveBeenCalledWith(
          JSON.stringify({ mcpServers: mockSnippet.mcpServers }, null, 2)
        )
      })
    })
  })

  describe('SSE proxy_deleted redirect', () => {
    it('navigates to / when proxy-deleted event fires for this proxy', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      // Dispatch proxy-deleted event for this proxy
      window.dispatchEvent(
        new CustomEvent(SSE_EVENTS.PROXY_DELETED, {
          detail: { proxy_id: 'proxy-123', proxy_name: 'test-proxy-1' },
        })
      )

      expect(mockNavigate).toHaveBeenCalledWith('/')
    })

    it('does not navigate when proxy-deleted event is for a different proxy', () => {
      mockUseManagerProxies.mockReturnValue({
        proxies: [mockRunningProxy],
        loading: false,
        error: null,
        refetch: vi.fn(),
      })
      mockUseProxyDetail.mockReturnValue({
        proxy: mockProxyDetail,
        loading: false,
        error: null,
        refetch: vi.fn(),
      })

      renderPage('proxy-123')

      // Dispatch proxy-deleted event for a different proxy
      window.dispatchEvent(
        new CustomEvent(SSE_EVENTS.PROXY_DELETED, {
          detail: { proxy_id: 'proxy-999', proxy_name: 'other-proxy' },
        })
      )

      expect(mockNavigate).not.toHaveBeenCalled()
    })
  })
})
