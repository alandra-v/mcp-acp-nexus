/**
 * Rules list for Visual Editor tab.
 *
 * Features:
 * - Expandable rows with effect badge
 * - Edit/Delete actions
 * - AlertDialog for delete confirmation
 */

import { useState, useCallback, useMemo } from 'react'
import { ChevronRight, Pencil, Trash2, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { cn } from '@/lib/utils'
import type { PolicyRuleResponse, PolicyRuleConditions } from '@/types/api'

type EffectFilter = 'all' | 'allow' | 'deny' | 'hitl'

const EFFECT_FILTER_OPTIONS: { value: EffectFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'allow', label: 'Allow' },
  { value: 'deny', label: 'Deny' },
  { value: 'hitl', label: 'HITL' },
]

interface PolicyRulesListProps {
  /** Rules to display */
  rules: PolicyRuleResponse[]
  /** Callback when edit is clicked */
  onEdit: (rule: PolicyRuleResponse) => void
  /** Callback when delete is confirmed */
  onDelete: (id: string) => Promise<void>
  /** Whether a mutation is in progress */
  mutating: boolean
}

/** Get badge styling based on effect */
function getEffectBadgeClass(effect: string): string {
  switch (effect) {
    case 'allow':
      return 'bg-green-500/20 text-green-400 border-green-500/30'
    case 'deny':
      return 'bg-red-500/20 text-red-400 border-red-500/30'
    case 'hitl':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    default:
      return ''
  }
}

/** Format a condition value for display */
function formatConditionValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.join(', ')
  }
  if (typeof value === 'string') {
    return value
  }
  return JSON.stringify(value)
}

/** Get non-empty conditions from a rule, excluding side_effects */
function getNonEmptyConditions(conditions: PolicyRuleConditions): [string, unknown][] {
  return Object.entries(conditions).filter(([key, value]) => {
    // Exclude side_effects from display
    if (key === 'side_effects') return false
    if (value === null || value === undefined) return false
    if (Array.isArray(value) && value.length === 0) return false
    if (typeof value === 'string' && value === '') return false
    return true
  })
}

export function PolicyRulesList({
  rules,
  onEdit,
  onDelete,
  mutating,
}: PolicyRulesListProps): JSX.Element {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [ruleToDelete, setRuleToDelete] = useState<PolicyRuleResponse | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [effectFilter, setEffectFilter] = useState<EffectFilter>('all')

  // Filter rules by effect
  const filteredRules = useMemo(() => {
    if (effectFilter === 'all') return rules
    return rules.filter((r) => r.effect === effectFilter)
  }, [rules, effectFilter])

  const handleFilterChange = useCallback((filter: EffectFilter) => {
    setEffectFilter(filter)
  }, [])

  const handleToggle = useCallback((ruleId: string) => {
    setExpandedId((prev) => (prev === ruleId ? null : ruleId))
  }, [])

  const handleEditClick = useCallback((e: React.MouseEvent, rule: PolicyRuleResponse) => {
    e.stopPropagation()
    onEdit(rule)
  }, [onEdit])

  const handleDeleteClick = useCallback((e: React.MouseEvent, rule: PolicyRuleResponse) => {
    e.stopPropagation()
    setRuleToDelete(rule)
    setDeleteDialogOpen(true)
  }, [])

  const handleDeleteConfirm = useCallback(async () => {
    if (!ruleToDelete?.id) return

    setDeleting(true)
    try {
      await onDelete(ruleToDelete.id)
    } finally {
      setDeleting(false)
      setDeleteDialogOpen(false)
      setRuleToDelete(null)
    }
  }, [ruleToDelete, onDelete])

  const handleDeleteCancel = useCallback(() => {
    setDeleteDialogOpen(false)
    setRuleToDelete(null)
  }, [])

  if (rules.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground border border-dashed border-base-700 rounded-lg">
        <p className="mb-2">No rules defined</p>
        <p className="text-sm">All requests will use the default action</p>
      </div>
    )
  }

  return (
    <>
      {/* Effect Filter */}
      {rules.length > 1 && (
        <div className="flex items-center justify-end mb-3">
          <div
            role="tablist"
            aria-label="Filter rules by effect"
            className="flex items-center gap-1 bg-base-900 rounded-lg p-1"
          >
            {EFFECT_FILTER_OPTIONS.map((option) => (
              <button
                key={option.value}
                role="tab"
                aria-selected={effectFilter === option.value}
                onClick={() => handleFilterChange(option.value)}
                className={cn(
                  'px-3 py-1 text-xs font-medium rounded-md transition-colors',
                  effectFilter === option.value
                    ? 'bg-base-700 text-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filtered empty state */}
      {filteredRules.length === 0 && effectFilter !== 'all' ? (
        <div className="text-center py-8 text-muted-foreground border border-dashed border-base-700 rounded-lg">
          <p>No {effectFilter} rules</p>
        </div>
      ) : (
      <div className="border border-base-800 rounded-lg overflow-hidden">
        {filteredRules.map((rule, index) => {
          const isExpanded = expandedId === (rule.id || `rule-${index}`)
          const conditions = getNonEmptyConditions(rule.conditions)
          const hasConditions = conditions.length > 0
          const isLast = index === filteredRules.length - 1
          const ruleKey = rule.id || `rule-${index}`

          return (
            <div key={ruleKey} className={cn(!isLast && 'border-b border-base-800')}>
              {/* Header Row */}
              <div
                role="button"
                tabIndex={0}
                aria-expanded={isExpanded}
                className={cn(
                  'flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-base-900/50 transition-colors',
                  isExpanded && 'bg-base-900/30'
                )}
                onClick={() => handleToggle(ruleKey)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    handleToggle(ruleKey)
                  }
                }}
              >
                {/* Expand Arrow */}
                <ChevronRight
                  aria-hidden="true"
                  className={cn(
                    'w-4 h-4 text-muted-foreground transition-transform flex-shrink-0',
                    isExpanded && 'rotate-90'
                  )}
                />

                {/* Effect Badge */}
                <Badge
                  variant="outline"
                  className={cn('uppercase text-xs font-bold flex-shrink-0', getEffectBadgeClass(rule.effect))}
                >
                  {rule.effect}
                </Badge>

                {/* Description or ID */}
                <div className="flex-1 min-w-0">
                  <span className="text-sm truncate block">
                    {rule.description || rule.id || 'Unnamed rule'}
                  </span>
                  {rule.description && rule.id && (
                    <span className="text-xs text-muted-foreground truncate block">
                      {rule.id}
                    </span>
                  )}
                </div>

                {/* Condition count hint */}
                {!isExpanded && hasConditions && (
                  <span className="text-xs text-muted-foreground flex-shrink-0">
                    {conditions.length} condition{conditions.length !== 1 ? 's' : ''}
                  </span>
                )}

                {/* Actions */}
                <div className="flex items-center gap-1 flex-shrink-0">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0"
                    onClick={(e) => handleEditClick(e, rule)}
                    disabled={mutating}
                  >
                    <Pencil className="w-3.5 h-3.5" />
                    <span className="sr-only">Edit</span>
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                    onClick={(e) => handleDeleteClick(e, rule)}
                    disabled={mutating || !rule.id}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span className="sr-only">Delete</span>
                  </Button>
                </div>
              </div>

              {/* Expanded Conditions */}
              {isExpanded && hasConditions && (
                <div className="px-4 pb-3 pl-11">
                  <div className="text-xs text-muted-foreground font-medium mb-1.5">Conditions</div>
                  <div className="space-y-1.5">
                    {conditions.map(([key, value]) => (
                    <div key={key} className="flex items-start gap-2 text-sm">
                      <span className="text-muted-foreground font-mono text-xs min-w-[120px]">
                        {key}:
                      </span>
                      <span className="font-mono text-xs break-all">
                        {formatConditionValue(value)}
                      </span>
                    </div>
                  ))}
                  </div>
                </div>
              )}

              {/* Expanded but no conditions */}
              {isExpanded && !hasConditions && (
                <div className="px-4 pb-3 pl-11">
                  <span className="text-sm text-muted-foreground">No conditions (matches all requests)</span>
                </div>
              )}

              {/* HITL approval caching indicator */}
              {isExpanded && rule.effect === 'hitl' && rule.cache_side_effects && rule.cache_side_effects.length > 0 && (
                <div className="px-4 pb-3 pl-11">
                  <span className="text-yellow-400 text-xs font-medium">
                    Approval caching: On
                  </span>
                </div>
              )}
            </div>
          )
        })}
      </div>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Rule</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this rule?
              {ruleToDelete && (
                <span className="block mt-2 font-medium text-foreground">
                  {ruleToDelete.description || ruleToDelete.id || 'Unnamed rule'}
                </span>
              )}
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={handleDeleteCancel} disabled={deleting}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDeleteConfirm}
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Deleting...
                </>
              ) : (
                'Delete'
              )}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
