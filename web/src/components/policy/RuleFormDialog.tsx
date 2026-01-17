/**
 * Dialog for adding/editing policy rules.
 *
 * Features:
 * - Form-based editing (JSON editing via JSON tab)
 * - Required fields marked with *
 * - Validation: either tool_name or path_pattern required
 * - Collapsible sections for Move/Copy and Advanced fields
 */

import { useState, useEffect, useCallback, useMemo } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'
import { getPolicySchema } from '@/api/policy'
import type {
  PolicyRuleResponse,
  PolicyRuleCreate,
  PolicyEffect,
  PolicyRuleConditions,
  PolicySideEffect,
} from '@/types/api'

interface RuleFormDialogProps {
  /** Whether dialog is open */
  open: boolean
  /** Callback to change open state */
  onOpenChange: (open: boolean) => void
  /** Rule to edit (null for new rule) */
  rule: PolicyRuleResponse | null
  /** Callback when form is submitted */
  onSubmit: (rule: PolicyRuleCreate) => Promise<void>
  /** Callback when dialog is cancelled */
  onCancel: () => void
  /** Whether submission is in progress */
  submitting: boolean
}

const EFFECT_OPTIONS: { value: PolicyEffect; label: string; description: string }[] = [
  { value: 'allow', label: 'Allow', description: 'Permit the request' },
  { value: 'deny', label: 'Deny', description: 'Block the request' },
  { value: 'hitl', label: 'HITL', description: 'Require human approval' },
]

const RESOURCE_TYPE_OPTIONS = ['tool', 'resource', 'prompt', 'server'] as const

/** Fallback operations if schema fetch fails */
const FALLBACK_OPERATIONS = ['read', 'write', 'delete']

/** All cacheable side effects - sent to backend when caching is enabled */
const ALL_CACHEABLE_SIDE_EFFECTS: PolicySideEffect[] = [
  'fs_read', 'fs_write', 'db_read', 'db_write', 'network_egress', 'network_ingress',
  'process_spawn', 'sudo_elevate', 'secrets_read', 'env_read', 'clipboard_read',
  'clipboard_write', 'browser_open', 'email_send', 'cloud_api', 'container_exec',
  'keychain_read', 'screen_capture', 'audio_capture', 'camera_capture',
]

/** Convert rule response to form state */
function ruleToFormState(rule: PolicyRuleResponse | null): PolicyRuleCreate {
  if (!rule) {
    return {
      effect: 'deny',
      conditions: {},
    }
  }
  return {
    id: rule.id || undefined,
    description: rule.description || undefined,
    effect: rule.effect,
    conditions: { ...rule.conditions },
    cache_side_effects: rule.cache_side_effects || undefined,
  }
}

/** Check if HITL options are configured */
function hasHitlOptions(rule: PolicyRuleCreate): boolean {
  return !!(rule.cache_side_effects && rule.cache_side_effects.length > 0)
}

/** Check if move/copy fields have values */
function hasMoveCopyFields(conditions: PolicyRuleConditions): boolean {
  return !!(conditions.source_path || conditions.dest_path)
}

/** Check if advanced fields have values */
function hasAdvancedFields(conditions: PolicyRuleConditions): boolean {
  return !!(
    conditions.operations?.length ||
    conditions.extension ||
    conditions.subject_id ||
    conditions.resource_type ||
    conditions.mcp_method ||
    conditions.scheme
  )
}

export function RuleFormDialog({
  open,
  onOpenChange,
  rule,
  onSubmit,
  onCancel,
  submitting,
}: RuleFormDialogProps): JSX.Element {
  const [formState, setFormState] = useState<PolicyRuleCreate>(ruleToFormState(rule))
  const [showMoveCopy, setShowMoveCopy] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [operations, setOperations] = useState<string[]>([])

  const isEditing = rule !== null

  // Fetch schema on mount
  useEffect(() => {
    const controller = new AbortController()
    getPolicySchema({ signal: controller.signal })
      .then((schema) => setOperations(schema.operations))
      .catch((err: unknown) => {
        // Ignore abort errors (component unmount)
        if (err instanceof Error && err.name === 'AbortError') return
        // Use fallback if schema fetch fails
        setOperations(FALLBACK_OPERATIONS)
      })
    return () => controller.abort()
  }, [])

  // Reset state when dialog opens/rule changes
  useEffect(() => {
    if (open) {
      const initial = ruleToFormState(rule)
      setFormState(initial)
      // Expand sections if they have values
      setShowMoveCopy(hasMoveCopyFields(initial.conditions))
      setShowAdvanced(hasAdvancedFields(initial.conditions))
    }
  }, [open, rule])

  // Update form field
  const updateField = useCallback(<K extends keyof PolicyRuleCreate>(
    field: K,
    value: PolicyRuleCreate[K]
  ) => {
    setFormState((prev) => {
      const newState = { ...prev, [field]: value }
      // Clear cache_side_effects when effect changes away from 'hitl'
      if (field === 'effect' && value !== 'hitl' && prev.cache_side_effects) {
        newState.cache_side_effects = undefined
      }
      return newState
    })
  }, [])

  // Update condition field
  const updateCondition = useCallback(<K extends keyof PolicyRuleConditions>(
    field: K,
    value: PolicyRuleConditions[K] | undefined
  ) => {
    setFormState((prev) => {
      const newConditions = { ...prev.conditions }
      if (value === undefined || value === '' || (Array.isArray(value) && value.length === 0)) {
        delete newConditions[field]
      } else {
        newConditions[field] = value
      }
      return { ...prev, conditions: newConditions }
    })
  }, [])

  // Handle submit
  const handleSubmit = useCallback(async () => {
    await onSubmit(formState)
  }, [formState, onSubmit])

  // Validation: effect required + (tool_name OR path_pattern)
  const validation = useMemo(() => {
    const hasToolOrPath = !!(
      formState.conditions.tool_name ||
      formState.conditions.path_pattern
    )
    const hasEffect = !!formState.effect

    return {
      isValid: hasEffect && hasToolOrPath,
      errors: {
        needsToolOrPath: !hasToolOrPath,
      },
    }
  }, [formState])

  // Parse comma-separated string to array
  const parseArrayField = useCallback((value: string): string[] | undefined => {
    if (!value.trim()) return undefined
    return value.split(',').map((s) => s.trim()).filter(Boolean)
  }, [])

  // Toggle operation selection
  const handleOperationToggle = useCallback((e: React.MouseEvent<HTMLButtonElement>) => {
    const op = e.currentTarget.dataset.operation
    if (!op) return
    const current = formState.conditions.operations || []
    const isSelected = current.includes(op)
    const newOps = isSelected
      ? current.filter((o) => o !== op)
      : [...current, op]
    updateCondition('operations', newOps.length > 0 ? newOps : undefined)
  }, [formState.conditions.operations, updateCondition])

  // Toggle approval caching (sends all cacheable effects or undefined)
  const handleCacheToggle = useCallback(() => {
    const isCurrentlyEnabled = formState.cache_side_effects && formState.cache_side_effects.length > 0
    updateField('cache_side_effects', isCurrentlyEnabled ? undefined : ALL_CACHEABLE_SIDE_EFFECTS)
  }, [formState.cache_side_effects, updateField])

  // Format array to comma-separated string
  const formatArrayField = useCallback((value: string | string[] | undefined): string => {
    if (!value) return ''
    if (Array.isArray(value)) return value.join(', ')
    return value
  }, [])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEditing ? 'Edit Rule' : 'Add Rule'}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-4">
          {/* Effect - Required */}
          <div className="space-y-2">
            <label htmlFor="rule-effect" className="text-sm font-medium">
              Effect <span className="text-destructive">*</span>
            </label>
            <Select
              value={formState.effect}
              onValueChange={(value) => updateField('effect', value as PolicyEffect)}
            >
              <SelectTrigger id="rule-effect">
                <SelectValue placeholder="Select effect" />
              </SelectTrigger>
              <SelectContent>
                {EFFECT_OPTIONS.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    <span className="font-medium">{option.label}</span>
                    <span className="text-muted-foreground ml-2">- {option.description}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Description */}
          <div className="space-y-2">
            <label htmlFor="rule-description" className="text-sm font-medium">Description</label>
            <Input
              id="rule-description"
              placeholder="Human-readable description of this rule"
              value={formState.description || ''}
              onChange={(e) => updateField('description', e.target.value || undefined)}
            />
          </div>

          {/* ID - Editable for new rules */}
          <div className="space-y-2">
            <label htmlFor="rule-id" className="text-sm font-medium">
              Rule ID
              {!isEditing && (
                <span className="text-muted-foreground font-normal ml-2">
                  (optional, auto-generated if empty)
                </span>
              )}
            </label>
            <Input
              id="rule-id"
              placeholder={isEditing ? '' : 'e.g., allow-read-api'}
              value={formState.id || ''}
              onChange={(e) => updateField('id', e.target.value || undefined)}
              disabled={isEditing}
              className={isEditing ? 'bg-base-900 text-muted-foreground' : ''}
            />
          </div>

          {/* Primary Conditions */}
          <div className="space-y-3 pt-2">
            <div className="flex items-center justify-between border-b border-base-800 pb-2">
              <h4 className="text-sm font-medium text-muted-foreground">
                Conditions
              </h4>
              {validation.errors.needsToolOrPath && (
                <span className="text-xs text-destructive">
                  Either tool_name or path_pattern required
                </span>
              )}
            </div>

            {/* Tool Name */}
            <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
              <label htmlFor="rule-tool-name" className="text-sm">
                tool_name
                {!formState.conditions.path_pattern && (
                  <span className="text-destructive ml-0.5">*</span>
                )}
              </label>
              <Input
                id="rule-tool-name"
                placeholder="e.g., read*, bash, * (comma-separated)"
                value={formatArrayField(formState.conditions.tool_name)}
                onChange={(e) => updateCondition('tool_name', parseArrayField(e.target.value) || e.target.value || undefined)}
              />
            </div>

            {/* Path Pattern */}
            <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
              <label htmlFor="rule-path-pattern" className="text-sm">
                path_pattern
                {!formState.conditions.tool_name && (
                  <span className="text-destructive ml-0.5">*</span>
                )}
              </label>
              <Input
                id="rule-path-pattern"
                placeholder="e.g., **/*.env, /home/** (comma-separated)"
                value={formatArrayField(formState.conditions.path_pattern)}
                onChange={(e) => updateCondition('path_pattern', parseArrayField(e.target.value) || e.target.value || undefined)}
              />
            </div>

            {/* Move/Copy Paths Toggle */}
            <button
              type="button"
              aria-expanded={showMoveCopy}
              aria-controls="move-copy-fields"
              onClick={() => setShowMoveCopy(!showMoveCopy)}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors pt-2"
            >
              {showMoveCopy ? (
                <ChevronDown className="w-4 h-4" aria-hidden="true" />
              ) : (
                <ChevronRight className="w-4 h-4" aria-hidden="true" />
              )}
              Move/Copy Paths
              {hasMoveCopyFields(formState.conditions) && (
                <span className="text-xs text-primary ml-1">(configured)</span>
              )}
            </button>

            {/* Move/Copy Fields */}
            {showMoveCopy && (
              <div id="move-copy-fields" className="space-y-3 pl-4 border-l-2 border-base-800 ml-2">
                <p className="text-xs text-muted-foreground">
                  For move/copy operations, specify source and destination patterns separately.
                </p>

                {/* Source Path */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-source-path" className="text-sm">source_path</label>
                  <Input
                    id="rule-source-path"
                    placeholder="e.g., **/src/**, /tmp/**"
                    value={formatArrayField(formState.conditions.source_path)}
                    onChange={(e) => updateCondition('source_path', parseArrayField(e.target.value) || e.target.value || undefined)}
                  />
                </div>

                {/* Dest Path */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-dest-path" className="text-sm">dest_path</label>
                  <Input
                    id="rule-dest-path"
                    placeholder="e.g., **/backup/**, /archive/**"
                    value={formatArrayField(formState.conditions.dest_path)}
                    onChange={(e) => updateCondition('dest_path', parseArrayField(e.target.value) || e.target.value || undefined)}
                  />
                </div>
              </div>
            )}

            {/* Advanced Toggle */}
            <button
              type="button"
              aria-expanded={showAdvanced}
              aria-controls="advanced-fields"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors pt-2"
            >
              {showAdvanced ? (
                <ChevronDown className="w-4 h-4" aria-hidden="true" />
              ) : (
                <ChevronRight className="w-4 h-4" aria-hidden="true" />
              )}
              Advanced
              {hasAdvancedFields(formState.conditions) && (
                <span className="text-xs text-primary ml-1">(configured)</span>
              )}
            </button>

            {/* Advanced Fields */}
            {showAdvanced && (
              <div id="advanced-fields" className="space-y-3 pl-4 border-l-2 border-base-800 ml-2">
                {/* Operations */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-start">
                  <span className="text-sm pt-2" id="operations-label">operations</span>
                  <div className="flex flex-wrap gap-2" role="group" aria-labelledby="operations-label">
                    {operations.map((op) => {
                      const isSelected = formState.conditions.operations?.includes(op)
                      return (
                        <button
                          key={op}
                          type="button"
                          aria-pressed={isSelected}
                          data-operation={op}
                          onClick={handleOperationToggle}
                          className={cn(
                            'px-3 py-1.5 text-xs rounded-md border transition-colors',
                            isSelected
                              ? 'bg-primary/20 border-primary text-primary'
                              : 'bg-base-900 border-base-700 text-muted-foreground hover:text-foreground'
                          )}
                        >
                          {op}
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Extension */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-extension" className="text-sm">extension</label>
                  <Input
                    id="rule-extension"
                    placeholder="e.g., .env, .key, .pem"
                    value={formatArrayField(formState.conditions.extension)}
                    onChange={(e) => updateCondition('extension', parseArrayField(e.target.value) || e.target.value || undefined)}
                  />
                </div>

                {/* Scheme */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-scheme" className="text-sm">scheme</label>
                  <Input
                    id="rule-scheme"
                    placeholder="e.g., file, s3, db"
                    value={formatArrayField(formState.conditions.scheme)}
                    onChange={(e) => updateCondition('scheme', parseArrayField(e.target.value) || e.target.value || undefined)}
                  />
                </div>

                {/* Subject ID */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-subject-id" className="text-sm">subject_id</label>
                  <Input
                    id="rule-subject-id"
                    placeholder="e.g., username, OIDC sub claim"
                    value={formatArrayField(formState.conditions.subject_id)}
                    onChange={(e) => updateCondition('subject_id', parseArrayField(e.target.value) || e.target.value || undefined)}
                  />
                </div>

                {/* MCP Method */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-mcp-method" className="text-sm">mcp_method</label>
                  <Input
                    id="rule-mcp-method"
                    placeholder="e.g., tools/call, resources/*"
                    value={formatArrayField(formState.conditions.mcp_method)}
                    onChange={(e) => updateCondition('mcp_method', parseArrayField(e.target.value) || e.target.value || undefined)}
                  />
                </div>

                {/* Resource Type */}
                <div className="grid grid-cols-[140px_1fr] gap-2 items-center">
                  <label htmlFor="rule-resource-type" className="text-sm">resource_type</label>
                  <Select
                    value={formState.conditions.resource_type || '_any'}
                    onValueChange={(value) => updateCondition('resource_type', value === '_any' ? undefined : value as PolicyRuleConditions['resource_type'])}
                  >
                    <SelectTrigger id="rule-resource-type">
                      <SelectValue placeholder="Any" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="_any">Any</SelectItem>
                      {RESOURCE_TYPE_OPTIONS.map((type) => (
                        <SelectItem key={type} value={type}>{type}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}
          </div>

          {/* HITL Options - Only shown when effect is 'hitl' */}
          {formState.effect === 'hitl' && (
            <div className="pt-4 border-t border-base-800">
              <label className="flex items-center gap-3 cursor-pointer">
                <button
                  type="button"
                  role="switch"
                  aria-checked={hasHitlOptions(formState)}
                  onClick={handleCacheToggle}
                  className={cn(
                    'relative w-10 h-5 rounded-full transition-colors',
                    hasHitlOptions(formState)
                      ? 'bg-yellow-500'
                      : 'bg-base-700'
                  )}
                >
                  <span
                    className={cn(
                      'absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform',
                      hasHitlOptions(formState) && 'translate-x-5'
                    )}
                  />
                </button>
                <div>
                  <span className="text-sm font-medium">Allow approval caching</span>
                  <p className="text-xs text-muted-foreground">
                    When enabled, you can cache your approval for repeated tool calls
                  </p>
                </div>
              </label>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onCancel} disabled={submitting}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!validation.isValid || submitting}>
            {submitting ? 'Saving...' : isEditing ? 'Save Changes' : 'Add Rule'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
