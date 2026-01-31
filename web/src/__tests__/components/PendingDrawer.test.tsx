/**
 * Unit tests for PendingDrawer and ApprovalItem components.
 *
 * PendingDrawer renders ApprovalItem internally, so both are covered
 * through integration. ApprovalItem is also tested standalone for
 * compact mode, caching variants, and countdown styling.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PendingDrawer } from '@/components/approvals/PendingDrawer'
import { ApprovalItem } from '@/components/approvals/ApprovalItem'
import type { PendingApproval } from '@/types/api'

// Mock useCountdown to return stable values (avoids timer flakiness)
const { mockUseCountdown, mockFormatCountdown } = vi.hoisted(() => ({
  mockUseCountdown: vi.fn(() => 45),
  mockFormatCountdown: vi.fn((seconds: number) => {
    if (seconds <= 0) return 'expired'
    const mins = Math.floor(seconds / 60)
    const secs = Math.round(seconds % 60)
    if (mins > 0) return `${mins}m ${secs}s`
    return `${secs}s`
  }),
}))

vi.mock('@/hooks/useCountdown', () => ({
  useCountdown: mockUseCountdown,
  formatCountdown: mockFormatCountdown,
}))

function makeApproval(overrides: Partial<PendingApproval> = {}): PendingApproval {
  return {
    id: 'approval-1',
    proxy_id: 'proxy:my-proxy',
    proxy_name: 'my-proxy',
    tool_name: 'read_file',
    path: '/data/config.json',
    subject_id: 'user-1',
    created_at: new Date().toISOString(),
    timeout_seconds: 60,
    request_id: 'req-1',
    can_cache: true,
    cache_ttl_seconds: 300,
    ...overrides,
  }
}

describe('PendingDrawer', () => {
  const defaultProps = {
    open: true,
    onOpenChange: vi.fn(),
    approvals: [makeApproval()],
    onApprove: vi.fn(),
    onApproveOnce: vi.fn(),
    onDeny: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders "Pending Approvals" title when open', () => {
    render(<PendingDrawer {...defaultProps} />)
    expect(screen.getByText('Pending Approvals')).toBeInTheDocument()
  })

  it('renders "No pending approvals" when approvals array empty', () => {
    render(<PendingDrawer {...defaultProps} approvals={[]} />)
    expect(screen.getByText('No pending approvals')).toBeInTheDocument()
  })

  it('renders one item per approval entry', () => {
    const approvals = [
      makeApproval({ id: 'a1', tool_name: 'read_file' }),
      makeApproval({ id: 'a2', tool_name: 'write_file' }),
    ]
    render(<PendingDrawer {...defaultProps} approvals={approvals} />)
    expect(screen.getByText('read_file')).toBeInTheDocument()
    expect(screen.getByText('write_file')).toBeInTheDocument()
  })

  it('shows proxy ID badge for each item', () => {
    render(<PendingDrawer {...defaultProps} />)
    // PendingDrawer passes showProxy=true; proxy_name falls back to proxy_id
    expect(screen.getByText('my-proxy')).toBeInTheDocument()
  })

  it('calls onOpenChange(false) when close button clicked', async () => {
    const user = userEvent.setup()
    render(<PendingDrawer {...defaultProps} />)

    await user.click(screen.getByLabelText('Close pending approvals'))
    expect(defaultProps.onOpenChange).toHaveBeenCalledWith(false)
  })

  it('calls onApprove with correct approval.id', async () => {
    const user = userEvent.setup()
    render(<PendingDrawer {...defaultProps} />)

    // can_cache=true → shows "Allow (5m)" button
    await user.click(screen.getByRole('button', { name: /Allow \(5m\)/ }))
    expect(defaultProps.onApprove).toHaveBeenCalledWith('approval-1')
  })

  it('calls onApproveOnce with correct approval.id', async () => {
    const user = userEvent.setup()
    render(<PendingDrawer {...defaultProps} />)

    await user.click(screen.getByRole('button', { name: 'Allow once' }))
    expect(defaultProps.onApproveOnce).toHaveBeenCalledWith('approval-1')
  })

  it('calls onDeny with correct approval.id', async () => {
    const user = userEvent.setup()
    render(<PendingDrawer {...defaultProps} />)

    await user.click(screen.getByRole('button', { name: 'Deny' }))
    expect(defaultProps.onDeny).toHaveBeenCalledWith('approval-1')
  })
})

describe('ApprovalItem', () => {
  const defaultProps = {
    approval: makeApproval(),
    onApprove: vi.fn(),
    onApproveOnce: vi.fn(),
    onDeny: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows tool_name', () => {
    render(<ApprovalItem {...defaultProps} />)
    expect(screen.getByText('read_file')).toBeInTheDocument()
  })

  it('shows path when not null', () => {
    render(<ApprovalItem {...defaultProps} />)
    expect(screen.getByText('/data/config.json')).toBeInTheDocument()
  })

  it('does not render path element when path is null', () => {
    const approval = makeApproval({ path: null })
    render(<ApprovalItem {...defaultProps} approval={approval} />)
    expect(screen.queryByText('/data/config.json')).not.toBeInTheDocument()
  })

  it('shows formatted countdown text', () => {
    render(<ApprovalItem {...defaultProps} />)
    // useCountdown returns 45, formatCountdown(45) → "45s"
    expect(screen.getByText('45s')).toBeInTheDocument()
  })

  it('shows proxy name badge when showProxy=true', () => {
    render(<ApprovalItem {...defaultProps} showProxy />)
    expect(screen.getByText('my-proxy')).toBeInTheDocument()
  })

  it('does not show proxy name badge when showProxy=false', () => {
    render(<ApprovalItem {...defaultProps} showProxy={false} />)
    expect(screen.queryByText('my-proxy')).not.toBeInTheDocument()
  })

  describe('cacheable approval (can_cache=true)', () => {
    it('shows "Allow (5m)", "Allow once", and "Deny" buttons', () => {
      render(<ApprovalItem {...defaultProps} />)
      expect(screen.getByRole('button', { name: /Allow \(5m\)/ })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Allow once' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Deny' })).toBeInTheDocument()
    })
  })

  describe('non-cacheable approval (can_cache=false)', () => {
    const nonCacheApproval = makeApproval({ can_cache: false, cache_ttl_seconds: null })

    it('shows "Allow" and "Deny" only', () => {
      render(<ApprovalItem {...defaultProps} approval={nonCacheApproval} />)
      expect(screen.getByRole('button', { name: 'Allow' })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Deny' })).toBeInTheDocument()
    })

    it('does not show "Allow once" button', () => {
      render(<ApprovalItem {...defaultProps} approval={nonCacheApproval} />)
      expect(screen.queryByRole('button', { name: 'Allow once' })).not.toBeInTheDocument()
    })
  })

  it('calls correct callback per button', async () => {
    const user = userEvent.setup()
    render(<ApprovalItem {...defaultProps} />)

    await user.click(screen.getByRole('button', { name: 'Deny' }))
    expect(defaultProps.onDeny).toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: /Allow \(5m\)/ }))
    expect(defaultProps.onApprove).toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Allow once' }))
    expect(defaultProps.onApproveOnce).toHaveBeenCalled()
  })

  it('countdown text uses non-error styling when remaining >= 10', () => {
    // useCountdown returns 45 by default (>= 10)
    const { container } = render(<ApprovalItem {...defaultProps} />)
    const countdown = container.querySelector('.text-base-500')
    expect(countdown).toBeInTheDocument()
    expect(countdown).toHaveTextContent('45s')
  })

  it('countdown text uses error styling when remaining < 10', () => {
    mockUseCountdown.mockReturnValue(5)

    const { container } = render(<ApprovalItem {...defaultProps} />)
    const countdown = container.querySelector('.text-error')
    expect(countdown).toBeInTheDocument()
    expect(countdown).toHaveTextContent('5s')

    // Restore default
    mockUseCountdown.mockReturnValue(45)
  })

  describe('compact mode', () => {
    it('renders "--" for null path', () => {
      const approval = makeApproval({ path: null })
      render(<ApprovalItem {...defaultProps} approval={approval} compact />)
      expect(screen.getByText('--')).toBeInTheDocument()
    })

    it('renders tool_name, path, countdown, and action buttons', () => {
      render(<ApprovalItem {...defaultProps} compact />)
      expect(screen.getByText('read_file')).toBeInTheDocument()
      expect(screen.getByText('/data/config.json')).toBeInTheDocument()
      expect(screen.getByText('45s')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Deny' })).toBeInTheDocument()
    })
  })
})
