/**
 * Unit tests for RuleFormDialog component.
 *
 * Tests create vs edit mode, schema fetching, validation,
 * collapsible sections, HITL caching toggle, and submission.
 */

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuleFormDialog } from '@/components/policy/RuleFormDialog'
import type { PolicyRuleResponse, PolicyRuleCreate } from '@/types/api'

// Mock policy API — schema fetch on mount
const { mockGetPolicySchema } = vi.hoisted(() => ({
  mockGetPolicySchema: vi.fn(),
}))

vi.mock('@/api/policy', () => ({
  getPolicySchema: mockGetPolicySchema,
}))

// Mock scrollIntoView for Radix Select
beforeAll(() => {
  Element.prototype.scrollIntoView = vi.fn()
})

function makeRule(overrides: Partial<PolicyRuleResponse> = {}): PolicyRuleResponse {
  return {
    id: 'existing-rule',
    effect: 'allow',
    conditions: { tool_name: 'read_file', path_pattern: '/data/**' },
    description: 'Allow reading data',
    cache_side_effects: null,
    ...overrides,
  }
}

describe('RuleFormDialog', () => {
  const defaultProps = {
    open: true,
    onOpenChange: vi.fn(),
    rule: null as PolicyRuleResponse | null,
    onSubmit: vi.fn<(rule: PolicyRuleCreate) => Promise<void>>().mockResolvedValue(undefined),
    onCancel: vi.fn(),
    submitting: false,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockGetPolicySchema.mockResolvedValue({
      operations: ['read', 'write', 'delete', 'move'],
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe('create mode', () => {
    it('shows "Add Rule" title when rule=null', () => {
      render(<RuleFormDialog {...defaultProps} />)
      expect(screen.getByRole('heading', { name: 'Add Rule' })).toBeInTheDocument()
    })

    it('defaults effect to "deny"', () => {
      render(<RuleFormDialog {...defaultProps} />)
      // The select trigger should show "Deny"
      expect(screen.getByText('Deny')).toBeInTheDocument()
    })

    it('rule ID field is editable with placeholder', () => {
      render(<RuleFormDialog {...defaultProps} />)
      const idInput = screen.getByLabelText(/Rule ID/)
      expect(idInput).not.toBeDisabled()
      expect(idInput).toHaveAttribute('placeholder', 'e.g., allow-read-api')
    })

    it('submit button shows "Add Rule"', () => {
      render(<RuleFormDialog {...defaultProps} />)
      expect(screen.getByRole('button', { name: 'Add Rule' })).toBeInTheDocument()
    })

    it('submit disabled initially (validation needs tool_name or path_pattern)', () => {
      render(<RuleFormDialog {...defaultProps} />)
      expect(screen.getByRole('button', { name: 'Add Rule' })).toBeDisabled()
    })

    it('shows "Either tool_name or path_pattern required" validation text', () => {
      render(<RuleFormDialog {...defaultProps} />)
      expect(screen.getByText('Either tool_name or path_pattern required')).toBeInTheDocument()
    })
  })

  describe('edit mode', () => {
    const editRule = makeRule()

    it('shows "Edit Rule" title when rule provided', () => {
      render(<RuleFormDialog {...defaultProps} rule={editRule} />)
      expect(screen.getByRole('heading', { name: 'Edit Rule' })).toBeInTheDocument()
    })

    it('pre-fills all fields from rule prop', () => {
      render(<RuleFormDialog {...defaultProps} rule={editRule} />)
      expect(screen.getByLabelText(/Description/)).toHaveValue('Allow reading data')
      expect(screen.getByLabelText(/Rule ID/)).toHaveValue('existing-rule')
      expect(screen.getByLabelText(/tool_name/)).toHaveValue('read_file')
      expect(screen.getByLabelText(/path_pattern/)).toHaveValue('/data/**')
    })

    it('rule ID field is disabled', () => {
      render(<RuleFormDialog {...defaultProps} rule={editRule} />)
      expect(screen.getByLabelText(/Rule ID/)).toBeDisabled()
    })

    it('submit shows "Save Changes"', () => {
      render(<RuleFormDialog {...defaultProps} rule={editRule} />)
      expect(screen.getByRole('button', { name: 'Save Changes' })).toBeInTheDocument()
    })
  })

  describe('schema', () => {
    it('fetches operations from getPolicySchema on mount', async () => {
      render(<RuleFormDialog {...defaultProps} />)

      await waitFor(() => {
        expect(mockGetPolicySchema).toHaveBeenCalled()
      })
    })

    it('uses fallback operations when schema fetch fails', async () => {
      mockGetPolicySchema.mockRejectedValueOnce(new Error('Network error'))

      render(<RuleFormDialog {...defaultProps} />)

      // Expand Advanced to see operations
      const user = userEvent.setup()
      await user.click(screen.getByText('Advanced'))

      await waitFor(() => {
        // Fallback operations: read, write, delete
        expect(screen.getByText('read')).toBeInTheDocument()
        expect(screen.getByText('write')).toBeInTheDocument()
        expect(screen.getByText('delete')).toBeInTheDocument()
      })
    })
  })

  describe('primary conditions', () => {
    it('enables submit when tool_name entered', async () => {
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} />)

      await user.type(screen.getByLabelText(/tool_name/), 'read_file')

      expect(screen.getByRole('button', { name: 'Add Rule' })).not.toBeDisabled()
    })

    it('enables submit when path_pattern entered', async () => {
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} />)

      await user.type(screen.getByLabelText(/path_pattern/), '/data/**')

      expect(screen.getByRole('button', { name: 'Add Rule' })).not.toBeDisabled()
    })
  })

  describe('collapsible sections', () => {
    it('Move/Copy collapsed by default, expands on click', async () => {
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} />)

      expect(screen.queryByLabelText(/source_path/)).not.toBeInTheDocument()

      await user.click(screen.getByText('Move/Copy Paths'))

      expect(screen.getByLabelText(/source_path/)).toBeInTheDocument()
      expect(screen.getByLabelText(/dest_path/)).toBeInTheDocument()
    })

    it('Advanced collapsed by default, expands on click', async () => {
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} />)

      expect(screen.queryByLabelText(/extension/)).not.toBeInTheDocument()

      await user.click(screen.getByText('Advanced'))

      expect(screen.getByLabelText(/extension/)).toBeInTheDocument()
    })

    it('auto-expands Move/Copy when editing rule with source_path', () => {
      const ruleWithSource = makeRule({
        conditions: { tool_name: 'move', source_path: '/src/**' },
      })
      render(<RuleFormDialog {...defaultProps} rule={ruleWithSource} />)

      expect(screen.getByLabelText(/source_path/)).toBeInTheDocument()
    })

    it('auto-expands Advanced when editing rule with operations', () => {
      const ruleWithOps = makeRule({
        conditions: { tool_name: 'read_file', operations: ['read'] },
      })
      render(<RuleFormDialog {...defaultProps} rule={ruleWithOps} />)

      expect(screen.getByLabelText(/extension/)).toBeInTheDocument()
    })
  })

  describe('HITL', () => {
    it('shows caching switch only when effect is "hitl"', async () => {
      const hitlRule = makeRule({ effect: 'hitl', conditions: { tool_name: 'write_file' } })
      render(<RuleFormDialog {...defaultProps} rule={hitlRule} />)

      expect(screen.getByText('Allow approval caching')).toBeInTheDocument()
    })

    it('hides caching section when effect changes away from "hitl"', async () => {
      const hitlRule = makeRule({ effect: 'hitl', conditions: { tool_name: 'write_file' } })
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} rule={hitlRule} />)

      expect(screen.getByText('Allow approval caching')).toBeInTheDocument()

      // Change effect to "deny"
      const effectTrigger = screen.getByRole('combobox')
      await user.click(effectTrigger)
      await user.click(screen.getByText('Deny'))

      expect(screen.queryByText('Allow approval caching')).not.toBeInTheDocument()
    })

    it('cache toggle sets cache_side_effects', async () => {
      const hitlRule = makeRule({
        effect: 'hitl',
        conditions: { tool_name: 'write_file' },
        cache_side_effects: null,
      })
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} rule={hitlRule} />)

      const toggle = screen.getByRole('switch')
      expect(toggle).toHaveAttribute('aria-checked', 'false')

      await user.click(toggle)
      expect(toggle).toHaveAttribute('aria-checked', 'true')
    })
  })

  describe('submission', () => {
    it('calls onSubmit with form state on submit click', async () => {
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} />)

      await user.type(screen.getByLabelText(/tool_name/), 'read_file')
      await user.click(screen.getByRole('button', { name: 'Add Rule' }))

      await waitFor(() => {
        expect(defaultProps.onSubmit).toHaveBeenCalledWith(
          expect.objectContaining({
            effect: 'deny',
            conditions: expect.objectContaining({
              tool_name: expect.anything(),
            }),
          })
        )
      })
    })

    it('shows "Saving..." when submitting=true', () => {
      const editRule = makeRule()
      render(<RuleFormDialog {...defaultProps} rule={editRule} submitting />)
      expect(screen.getByRole('button', { name: 'Saving...' })).toBeInTheDocument()
    })

    it('disables Cancel during submission', () => {
      const editRule = makeRule()
      render(<RuleFormDialog {...defaultProps} rule={editRule} submitting />)
      expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    })
  })

  describe('cancel', () => {
    it('calls onCancel on Cancel click', async () => {
      const user = userEvent.setup()
      render(<RuleFormDialog {...defaultProps} />)

      await user.click(screen.getByRole('button', { name: 'Cancel' }))
      expect(defaultProps.onCancel).toHaveBeenCalled()
    })
  })
})
