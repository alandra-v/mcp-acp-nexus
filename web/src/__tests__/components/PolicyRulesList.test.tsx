/**
 * Unit tests for PolicyRulesList component.
 *
 * Tests empty state, filter tabs, row rendering, expansion,
 * edit/delete actions, and delete confirmation dialog.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { PolicyRulesList } from '@/components/policy/PolicyRulesList'
import type { PolicyRuleResponse } from '@/types/api'

function makeRule(overrides: Partial<PolicyRuleResponse> = {}): PolicyRuleResponse {
  return {
    id: 'rule-1',
    effect: 'allow',
    conditions: { tool_name: 'read_file', path_pattern: '/data/**' },
    description: 'Allow reading data files',
    cache_side_effects: null,
    ...overrides,
  }
}

// Shared rule variants
const allowRule = makeRule()
const denyRule = makeRule({
  id: 'rule-2',
  effect: 'deny',
  description: 'Deny sensitive extensions',
  conditions: { extension: ['.env', '.key'] },
})
const hitlRule = makeRule({
  id: 'rule-3',
  effect: 'hitl',
  description: 'HITL for writes',
  conditions: { tool_name: 'write_file' },
  cache_side_effects: ['fs_write', 'db_write'],
})
const nullIdRule = makeRule({
  id: null,
  description: 'Rule without ID',
  conditions: { tool_name: 'bash' },
})
const emptyConditionsRule = makeRule({
  id: 'rule-5',
  description: 'Matches everything',
  conditions: {},
})

describe('PolicyRulesList', () => {
  const defaultProps = {
    rules: [allowRule, denyRule, hitlRule],
    onEdit: vi.fn(),
    onDelete: vi.fn<(id: string) => Promise<void>>().mockResolvedValue(undefined),
    mutating: false,
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('empty state', () => {
    it('shows "No rules defined" with empty array', () => {
      render(<PolicyRulesList {...defaultProps} rules={[]} />)
      expect(screen.getByText('No rules defined')).toBeInTheDocument()
    })

    it('shows "All requests will use the default action" subtext', () => {
      render(<PolicyRulesList {...defaultProps} rules={[]} />)
      expect(screen.getByText('All requests will use the default action')).toBeInTheDocument()
    })
  })

  describe('filter tabs', () => {
    it('shows filter tabs when >1 rule', () => {
      render(<PolicyRulesList {...defaultProps} />)
      expect(screen.getByRole('tablist')).toBeInTheDocument()
    })

    it('does not show filter tabs with 1 rule', () => {
      render(<PolicyRulesList {...defaultProps} rules={[allowRule]} />)
      expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
    })

    it('"All" tab selected by default', () => {
      render(<PolicyRulesList {...defaultProps} />)
      const allTab = screen.getByRole('tab', { name: 'All' })
      expect(allTab).toHaveAttribute('aria-selected', 'true')
    })

    it('clicking "Allow" tab filters to allow rules only', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      await user.click(screen.getByRole('tab', { name: 'Allow' }))
      // Only the allow rule should be visible
      expect(screen.getByText('Allow reading data files')).toBeInTheDocument()
      expect(screen.queryByText('Deny sensitive extensions')).not.toBeInTheDocument()
      expect(screen.queryByText('HITL for writes')).not.toBeInTheDocument()
    })

    it('clicking "Deny" tab filters to deny rules only', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      await user.click(screen.getByRole('tab', { name: 'Deny' }))
      expect(screen.getByText('Deny sensitive extensions')).toBeInTheDocument()
      expect(screen.queryByText('Allow reading data files')).not.toBeInTheDocument()
    })

    it('clicking "HITL" tab filters to hitl rules only', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      await user.click(screen.getByRole('tab', { name: 'HITL' }))
      expect(screen.getByText('HITL for writes')).toBeInTheDocument()
      expect(screen.queryByText('Allow reading data files')).not.toBeInTheDocument()
    })

    it('shows "No allow rules" when filter yields 0 results', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} rules={[denyRule, hitlRule]} />)

      await user.click(screen.getByRole('tab', { name: 'Allow' }))
      expect(screen.getByText('No allow rules')).toBeInTheDocument()
    })
  })

  describe('row rendering', () => {
    it('shows effect badge text per rule', () => {
      render(<PolicyRulesList {...defaultProps} />)
      expect(screen.getByText('allow')).toBeInTheDocument()
      expect(screen.getByText('deny')).toBeInTheDocument()
      expect(screen.getByText('hitl')).toBeInTheDocument()
    })

    it('shows description as primary text when present', () => {
      render(<PolicyRulesList {...defaultProps} />)
      expect(screen.getByText('Allow reading data files')).toBeInTheDocument()
      expect(screen.getByText('Deny sensitive extensions')).toBeInTheDocument()
    })

    it('shows rule.id below description when both exist', () => {
      render(<PolicyRulesList {...defaultProps} />)
      expect(screen.getByText('rule-1')).toBeInTheDocument()
    })

    it('shows "Unnamed rule" when both description and id are null', () => {
      const noNameRule = makeRule({ id: null, description: null, conditions: { tool_name: 'bash' } })
      render(<PolicyRulesList {...defaultProps} rules={[noNameRule, denyRule]} />)
      expect(screen.getByText('Unnamed rule')).toBeInTheDocument()
    })

    it('shows condition count when collapsed', () => {
      render(<PolicyRulesList {...defaultProps} />)
      // allowRule has 2 conditions (tool_name, path_pattern)
      expect(screen.getByText('2 conditions')).toBeInTheDocument()
      // denyRule and hitlRule each have 1 condition
      expect(screen.getAllByText('1 condition')).toHaveLength(2)
    })
  })

  describe('expansion', () => {
    it('expands on click, shows conditions', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const row = screen.getByText('Allow reading data files').closest('[role="button"]')!
      await user.click(row)

      expect(screen.getByText('tool_name:')).toBeInTheDocument()
      expect(screen.getByText('read_file')).toBeInTheDocument()
      expect(screen.getByText('path_pattern:')).toBeInTheDocument()
      expect(screen.getByText('/data/**')).toBeInTheDocument()
    })

    it('collapses when same row clicked again', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const row = screen.getByText('Allow reading data files').closest('[role="button"]')!
      await user.click(row) // expand
      expect(screen.getByText('tool_name:')).toBeInTheDocument()

      await user.click(row) // collapse
      expect(screen.queryByText('tool_name:')).not.toBeInTheDocument()
    })

    it('shows key: value pairs for conditions', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const row = screen.getByText('Allow reading data files').closest('[role="button"]')!
      await user.click(row)

      expect(screen.getByText('tool_name:')).toBeInTheDocument()
      expect(screen.getByText('path_pattern:')).toBeInTheDocument()
    })

    it('formats array values as comma-separated', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const row = screen.getByText('Deny sensitive extensions').closest('[role="button"]')!
      await user.click(row)

      expect(screen.getByText('.env, .key')).toBeInTheDocument()
    })

    it('shows "No conditions (matches all requests)" for empty conditions', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} rules={[emptyConditionsRule, denyRule]} />)

      const row = screen.getByText('Matches everything').closest('[role="button"]')!
      await user.click(row)

      expect(screen.getByText('No conditions (matches all requests)')).toBeInTheDocument()
    })

    it('shows approval caching indicator for expanded hitl rule with cache_side_effects', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const row = screen.getByText('HITL for writes').closest('[role="button"]')!
      await user.click(row)

      expect(screen.getByText('Approval caching: On')).toBeInTheDocument()
    })

    it('does not show approval caching indicator for non-hitl rules', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const row = screen.getByText('Allow reading data files').closest('[role="button"]')!
      await user.click(row)

      expect(screen.queryByText('Approval caching: On')).not.toBeInTheDocument()
    })
  })

  describe('edit/delete', () => {
    it('calls onEdit with rule on edit button click', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const editButtons = screen.getAllByRole('button', { name: 'Edit' })
      await user.click(editButtons[0])

      expect(defaultProps.onEdit).toHaveBeenCalledWith(allowRule)
    })

    it('edit click does not toggle expansion', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const editButtons = screen.getAllByRole('button', { name: 'Edit' })
      await user.click(editButtons[0])

      // Should NOT expand (stopPropagation prevents toggle)
      expect(screen.queryByText('tool_name:')).not.toBeInTheDocument()
    })

    it('delete button disabled when rule.id is null', () => {
      render(<PolicyRulesList {...defaultProps} rules={[nullIdRule, denyRule]} />)

      const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
      expect(deleteButtons[0]).toBeDisabled()
    })

    it('delete button disabled when mutating=true', () => {
      render(<PolicyRulesList {...defaultProps} mutating />)

      const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
      deleteButtons.forEach((btn) => expect(btn).toBeDisabled())
    })

    it('opens AlertDialog on delete click, shows "Delete Rule" and rule description', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
      await user.click(deleteButtons[0])

      expect(screen.getByRole('alertdialog')).toBeInTheDocument()
      expect(screen.getByText('Delete Rule')).toBeInTheDocument()
      // Description appears in both the row and the dialog
      expect(screen.getAllByText('Allow reading data files')).toHaveLength(2)
    })

    it('calls onDelete with rule.id on confirm', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      // Click the row Delete button (sr-only text) to open dialog
      const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
      await user.click(deleteButtons[0])

      // The AlertDialog confirm button has explicit text "Delete"
      const dialog = screen.getByRole('alertdialog')
      const confirmBtn = dialog.querySelector('button:last-child')!
      await user.click(confirmBtn)

      await waitFor(() => {
        expect(defaultProps.onDelete).toHaveBeenCalledWith('rule-1')
      })
    })

    it('calls onDelete when confirm button clicked in dialog', async () => {
      const user = userEvent.setup()
      let resolveDelete: () => void
      const onDelete = vi.fn(() => new Promise<void>((resolve) => { resolveDelete = resolve }))
      render(<PolicyRulesList {...defaultProps} onDelete={onDelete} />)

      const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
      await user.click(deleteButtons[0])

      // Click confirm in dialog
      const dialog = screen.getByRole('alertdialog')
      const confirmBtn = dialog.querySelector('button:last-child')!
      await user.click(confirmBtn)

      await waitFor(() => {
        expect(onDelete).toHaveBeenCalledWith('rule-1')
      })

      // Resolve to complete
      resolveDelete!()
    })

    it('closes dialog on Cancel without calling onDelete', async () => {
      const user = userEvent.setup()
      render(<PolicyRulesList {...defaultProps} />)

      const deleteButtons = screen.getAllByRole('button', { name: 'Delete' })
      await user.click(deleteButtons[0])

      expect(screen.getByText('Delete Rule')).toBeInTheDocument()

      await user.click(screen.getByRole('button', { name: 'Cancel' }))

      await waitFor(() => {
        expect(screen.queryByText('Delete Rule')).not.toBeInTheDocument()
      })
      expect(defaultProps.onDelete).not.toHaveBeenCalled()
    })
  })
})
