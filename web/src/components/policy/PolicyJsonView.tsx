/**
 * JSON view for policy configuration.
 *
 * Features:
 * - Editable textarea with monospace font
 * - "Add Rule from JSON" button with template
 * - Full policy JSON editing with save/discard
 *
 * Note: HITL config is in AppConfig (Config section), not here.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Save, RotateCcw, AlertTriangle, Plus } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { cn, formatValidationLoc } from '@/lib/utils'
import { ApiError } from '@/types/api'
import type { PolicyResponse, PolicyFullUpdate, PolicyRuleCreate } from '@/types/api'
import type { MutationOptions } from '@/hooks/usePolicy'

interface PolicyJsonViewProps {
  /** Current policy */
  policy: PolicyResponse
  /** Callback to save full policy */
  onSave: (policy: PolicyFullUpdate, options?: MutationOptions) => Promise<void>
  /** Callback to add a single rule */
  onAddRule: (rule: PolicyRuleCreate, options?: MutationOptions) => Promise<unknown>
  /** Whether a mutation is in progress */
  mutating: boolean
}

/** Rule JSON template for adding new rules */
const RULE_TEMPLATE: PolicyRuleCreate = {
  id: 'new-rule',
  description: 'Description of what this rule does',
  effect: 'deny',
  conditions: {
    tool_name: '*',
    path_pattern: '**/*',
  },
}

/** Convert policy response to editable format */
function policyToEditable(policy: PolicyResponse): PolicyFullUpdate {
  return {
    version: policy.version,
    default_action: policy.default_action,
    rules: policy.rules.map((rule) => ({
      id: rule.id || undefined,
      description: rule.description || undefined,
      effect: rule.effect,
      conditions: rule.conditions,
    })),
  }
}

/** Extract a detailed error message from an API or unknown error */
function getSaveErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.validationErrors?.length) {
      return err.validationErrors
        .map((ve) => {
          const loc = formatValidationLoc(ve.loc)
          return loc ? `${loc}: ${ve.msg}` : ve.msg
        })
        .join('; ')
    }
    return err.message
  }
  if (err instanceof Error) {
    return err.message
  }
  return String(err)
}

/** Parse JSON and return error message if invalid */
function parseJsonSafe<T>(text: string): { data: T | null; error: string | null } {
  try {
    return { data: JSON.parse(text) as T, error: null }
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error ? err.message : 'Invalid JSON',
    }
  }
}

export function PolicyJsonView({
  policy,
  onSave,
  onAddRule,
  mutating,
}: PolicyJsonViewProps): JSX.Element {
  // Original JSON for comparison (without HITL)
  const originalJson = useMemo(() => {
    return JSON.stringify(policyToEditable(policy), null, 2)
  }, [policy])

  const [jsonText, setJsonText] = useState(originalJson)
  const [parseError, setParseError] = useState<string | null>(null)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [addDialogOpen, setAddDialogOpen] = useState(false)
  const [addJsonText, setAddJsonText] = useState('')
  const [addParseError, setAddParseError] = useState<string | null>(null)
  const [addSaveError, setAddSaveError] = useState<string | null>(null)

  // Refs for syncing line numbers scroll
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const lineNumbersRef = useRef<HTMLDivElement>(null)

  // Line count for line numbers gutter
  const lineCount = jsonText.split('\n').length

  // Sync scroll between textarea and line numbers
  const handleScroll = useCallback(() => {
    if (textareaRef.current && lineNumbersRef.current) {
      lineNumbersRef.current.scrollTop = textareaRef.current.scrollTop
    }
  }, [])

  // Reset when policy changes externally
  useEffect(() => {
    setJsonText(originalJson)
    setParseError(null)
    setSaveError(null)
  }, [originalJson])

  // Check if dirty
  const isDirty = jsonText !== originalJson

  // Validate JSON on change
  const handleChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const text = e.target.value
    setJsonText(text)
    const { error } = parseJsonSafe(text)
    setParseError(error)
    setSaveError(null)
  }, [])

  // Handle save
  const handleSave = useCallback(async () => {
    const { data: parsed, error } = parseJsonSafe<PolicyFullUpdate>(jsonText)
    if (!parsed) {
      setParseError(error)
      return
    }

    try {
      setSaveError(null)
      await onSave(parsed, { silent: true })
    } catch (err) {
      setSaveError(getSaveErrorMessage(err))
    }
  }, [jsonText, onSave])

  // Handle cancel/reset
  const handleDiscard = useCallback(() => {
    setJsonText(originalJson)
    setParseError(null)
    setSaveError(null)
  }, [originalJson])

  // Open add dialog with template
  const handleAddClick = useCallback(() => {
    setAddJsonText(JSON.stringify(RULE_TEMPLATE, null, 2))
    setAddParseError(null)
    setAddSaveError(null)
    setAddDialogOpen(true)
  }, [])

  // Handle add JSON change
  const handleAddJsonChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const text = e.target.value
    setAddJsonText(text)
    const { error } = parseJsonSafe(text)
    setAddParseError(error)
    setAddSaveError(null)
  }, [])

  // Handle add submit
  const handleAddSubmit = useCallback(async () => {
    const { data: parsed } = parseJsonSafe<PolicyRuleCreate>(addJsonText)
    if (!parsed) return

    try {
      setAddSaveError(null)
      await onAddRule(parsed, { silent: true })
      setAddDialogOpen(false)
    } catch (err) {
      setAddSaveError(getSaveErrorMessage(err))
    }
  }, [addJsonText, onAddRule])

  return (
    <div className="space-y-4">
      {/* Header with Add button */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Edit full policy JSON (HITL config managed in Config section)
        </div>
        <Button size="sm" variant="outline" onClick={handleAddClick} disabled={mutating}>
          <Plus className="w-4 h-4 mr-2" />
          Add Rule from JSON
        </Button>
      </div>

      {/* Editor with line numbers */}
      <div className="relative">
        <div
          className={cn(
            'flex border rounded-lg overflow-hidden',
            parseError
              ? 'border-destructive focus-within:ring-2 focus-within:ring-destructive/50'
              : 'border-base-700 focus-within:ring-2 focus-within:ring-primary/50'
          )}
        >
          {/* Line numbers gutter */}
          <div
            ref={lineNumbersRef}
            className="bg-base-900 text-base-500 font-mono text-sm py-4 px-3 select-none overflow-hidden text-right border-r border-base-700"
            style={{ minHeight: '400px', maxHeight: '400px' }}
          >
            {Array.from({ length: lineCount }, (_, i) => (
              <div key={i + 1} className="leading-[1.5]">
                {i + 1}
              </div>
            ))}
          </div>

          {/* Textarea */}
          <textarea
            ref={textareaRef}
            value={jsonText}
            onChange={handleChange}
            onScroll={handleScroll}
            className={cn(
              'flex-1 min-h-[400px] p-4 font-mono text-sm leading-[1.5]',
              'bg-base-950 resize-y',
              'focus:outline-none'
            )}
            spellCheck={false}
            disabled={mutating}
          />
        </div>

        {/* Parse Error */}
        {parseError && (
          <div className="mt-2 bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
            <div className="text-sm text-destructive">
              <span className="font-medium">Invalid JSON: </span>
              <span>{parseError}</span>
            </div>
          </div>
        )}

        {/* Server Validation Error */}
        {saveError && !parseError && (
          <div className="mt-2 bg-destructive/10 border border-destructive/30 rounded-md p-3 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-destructive flex-shrink-0 mt-0.5" />
            <div className="text-sm text-destructive">
              <span className="font-medium">Validation error: </span>
              <span>{saveError}</span>
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {isDirty ? (
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 bg-yellow-500 rounded-full" />
              Unsaved changes
            </span>
          ) : (
            <span className="text-muted-foreground/50">No changes</span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleDiscard}
            disabled={!isDirty || mutating}
          >
            <RotateCcw className="w-4 h-4 mr-2" />
            Discard
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!isDirty || !!parseError || mutating}
          >
            <Save className="w-4 h-4 mr-2" />
            {mutating ? 'Saving...' : 'Save Policy'}
          </Button>
        </div>
      </div>

      {/* Add Rule from JSON Dialog */}
      <Dialog open={addDialogOpen} onOpenChange={setAddDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Rule from JSON</DialogTitle>
          </DialogHeader>

          <div className="py-4">
            <p className="text-sm text-muted-foreground mb-3">
              Edit the JSON template below and click Add to create a new rule.
            </p>
            <textarea
              value={addJsonText}
              onChange={handleAddJsonChange}
              className={cn(
                'w-full min-h-[250px] p-4 font-mono text-sm',
                'bg-base-900 border rounded-lg resize-y',
                'focus:outline-none focus:ring-2 focus:ring-primary/50',
                addParseError
                  ? 'border-destructive focus:ring-destructive/50'
                  : 'border-base-700'
              )}
              spellCheck={false}
              disabled={mutating}
            />

            {addParseError && (
              <div className="mt-2 flex items-start gap-2 text-sm text-destructive">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Invalid JSON: {addParseError}</span>
              </div>
            )}

            {addSaveError && !addParseError && (
              <div className="mt-2 flex items-start gap-2 text-sm text-destructive">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Validation error: {addSaveError}</span>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setAddDialogOpen(false)}
              disabled={mutating}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddSubmit}
              disabled={!!addParseError || !addJsonText.trim() || mutating}
            >
              {mutating ? 'Adding...' : 'Add Rule'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
