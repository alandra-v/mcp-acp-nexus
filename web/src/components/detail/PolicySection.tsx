/**
 * Policy section for ProxyDetailPage.
 *
 * Features folder-style tabs:
 * - Visual Editor: Rules list with form-based add/edit
 * - JSON: Full policy JSON editor with template
 */

import { useState, useCallback } from 'react'
import { Plus, RefreshCw, Info } from 'lucide-react'
import { Section } from './Section'
import { Button } from '@/components/ui/button'
import { toast } from '@/components/ui/sonner'
import { PolicyRulesList } from '@/components/policy/PolicyRulesList'
import { PolicyJsonView } from '@/components/policy/PolicyJsonView'
import { RuleFormDialog } from '@/components/policy/RuleFormDialog'
import { usePolicy } from '@/hooks/usePolicy'
import { cn } from '@/lib/utils'
import type { PolicyRuleResponse, PolicyRuleCreate } from '@/types/api'

interface PolicySectionProps {
  loaded?: boolean
}

type TabType = 'visual' | 'json'

export function PolicySection({ loaded }: PolicySectionProps): JSX.Element {
  const {
    policy,
    loading,
    error,
    refresh,
    addRule,
    updateRule,
    deleteRule,
    updateFullPolicy,
    mutating,
  } = usePolicy()

  const [activeTab, setActiveTab] = useState<TabType>('visual')
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<PolicyRuleResponse | null>(null)

  // Handle tab switch
  const handleVisualTab = useCallback(() => {
    setActiveTab('visual')
  }, [])

  const handleJsonTab = useCallback(() => {
    setActiveTab('json')
  }, [])

  // Handle refresh with toast feedback
  const handleRefresh = useCallback(async () => {
    await refresh()
    toast.success('Policy refreshed')
  }, [refresh])

  // Open dialog for new rule
  const handleAddClick = useCallback(() => {
    setEditingRule(null)
    setDialogOpen(true)
  }, [])

  // Open dialog for editing
  const handleEditClick = useCallback((rule: PolicyRuleResponse) => {
    setEditingRule(rule)
    setDialogOpen(true)
  }, [])

  // Handle form submission
  const handleSubmit = useCallback(async (rule: PolicyRuleCreate) => {
    if (editingRule?.id) {
      await updateRule(editingRule.id, rule)
    } else {
      await addRule(rule)
    }
    setDialogOpen(false)
    setEditingRule(null)
  }, [editingRule, addRule, updateRule])

  // Handle dialog close
  const handleDialogClose = useCallback(() => {
    setDialogOpen(false)
    setEditingRule(null)
  }, [])

  return (
    <Section index={0} title="Policy" loaded={loaded}>
      {/* Folder-style Tabs */}
      <div className="relative">
        {/* Tab row */}
        <div className="flex items-end" role="tablist" aria-label="Policy view">
          {/* Visual Editor Tab */}
          <button
            role="tab"
            aria-selected={activeTab === 'visual'}
            aria-controls="policy-tabpanel"
            onClick={handleVisualTab}
            className={cn(
              'px-5 py-2.5 text-sm font-medium transition-colors rounded-t-lg border-t border-l border-r',
              activeTab === 'visual'
                ? 'bg-[oklch(0.20_0.014_228)] text-foreground border-base-700 relative z-10'
                : 'bg-base-950 text-muted-foreground border-transparent border-b border-b-base-700 hover:text-foreground hover:bg-base-900/50'
            )}
          >
            Visual Editor
          </button>

          {/* JSON Tab */}
          <button
            role="tab"
            aria-selected={activeTab === 'json'}
            aria-controls="policy-tabpanel"
            onClick={handleJsonTab}
            className={cn(
              'px-5 py-2.5 text-sm font-medium transition-colors rounded-t-lg border-t border-l border-r -ml-px',
              activeTab === 'json'
                ? 'bg-[oklch(0.20_0.014_228)] text-foreground border-base-700 relative z-10'
                : 'bg-base-950 text-muted-foreground border-transparent border-b border-b-base-700 hover:text-foreground hover:bg-base-900/50'
            )}
          >
            JSON
          </button>

          {/* Spacer with bottom border */}
          <div className="flex-1 border-b border-base-700" />

          {/* Refresh button */}
          <div className="flex items-center pb-1 pl-2 border-b border-base-700">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              disabled={loading || mutating}
              className="h-8"
              aria-label="Refresh policy"
            >
              <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
            </Button>
          </div>
        </div>

        {/* Content area with connected border */}
        <div
          id="policy-tabpanel"
          role="tabpanel"
          aria-label={activeTab === 'visual' ? 'Visual Editor' : 'JSON'}
          className="card-gradient border border-t-0 border-base-700 rounded-b-lg p-4 min-h-[400px]"
        >
          {/* Auto-reload note at top */}
          <div className="flex items-center gap-2 mb-4 pb-3 border-b border-base-800 text-xs text-muted-foreground">
            <Info className="w-3.5 h-3.5 flex-shrink-0" />
            <span>Policy changes are saved to disk and automatically reloaded.</span>
          </div>
          {loading && !policy ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground">
              Loading policy...
            </div>
          ) : error && !policy ? (
            <div className="flex flex-col items-center justify-center py-16">
              <p className="text-destructive mb-4">{error}</p>
              <Button variant="outline" size="sm" onClick={refresh}>
                Retry
              </Button>
            </div>
          ) : !policy ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground">
              <p>No policy configured</p>
            </div>
          ) : activeTab === 'visual' ? (
            <div>
              {/* Header with metadata and Add button */}
              <div className="flex items-center justify-between mb-4">
                <div className="text-sm text-muted-foreground">
                  {policy.policy_version || 'v1'} · {policy.rules_count} rule{policy.rules_count !== 1 ? 's' : ''} · Default: {policy.default_action}
                </div>
                <Button size="sm" onClick={handleAddClick} disabled={mutating}>
                  <Plus className="w-4 h-4 mr-2" />
                  Add Rule
                </Button>
              </div>

              {/* Rules List */}
              <PolicyRulesList
                rules={policy.rules}
                onEdit={handleEditClick}
                onDelete={deleteRule}
                mutating={mutating}
              />
            </div>
          ) : (
            <PolicyJsonView
              policy={policy}
              onSave={updateFullPolicy}
              onAddRule={addRule}
              mutating={mutating}
            />
          )}
        </div>
      </div>

      {/* Add/Edit Dialog */}
      <RuleFormDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        rule={editingRule}
        onSubmit={handleSubmit}
        onCancel={handleDialogClose}
        submitting={mutating}
      />
    </Section>
  )
}
