import { Button } from '@/components/ui/button'
import { useCountdown, formatCountdown } from '@/hooks/useCountdown'
import type { PendingApproval } from '@/types/api'

interface ApprovalItemProps {
  approval: PendingApproval
  onApprove: () => void
  onApproveOnce: () => void
  onDeny: () => void
  /** Show proxy name badge (for global list) */
  showProxy?: boolean
  /** Use compact horizontal layout */
  compact?: boolean
}

interface ApprovalActionsProps {
  canCache: boolean
  ttlMinutes: number | null
  onApprove: () => void
  onApproveOnce: () => void
  onDeny: () => void
  /** Use compact sizing (smaller text, tighter padding) */
  compact?: boolean
}

/**
 * Shared approval action buttons (Deny, Allow, Allow once).
 * Renders the appropriate button set based on whether caching is available.
 */
function ApprovalActions({
  canCache,
  ttlMinutes,
  onApprove,
  onApproveOnce,
  onDeny,
  compact = false,
}: ApprovalActionsProps) {
  // Compact mode adds smaller text and tighter padding
  const compactClass = compact ? ' text-xs px-3 py-1.5' : ''

  return (
    <div className="flex flex-wrap gap-2">
      <Button
        variant="outline"
        size="sm"
        onClick={onDeny}
        className={`bg-base-800 text-base-400 border-[var(--border-subtle)] hover:bg-base-700${compactClass}`}
      >
        Deny
      </Button>
      {canCache ? (
        <>
          <Button
            variant="outline"
            size="sm"
            onClick={onApprove}
            className={`bg-base-800 text-base-400 border-[var(--border-subtle)] hover:bg-base-700${compactClass}`}
          >
            Allow ({ttlMinutes}m)
          </Button>
          <Button
            size="sm"
            onClick={onApproveOnce}
            className={`bg-success-bg text-success-muted border border-success-border hover:bg-success-bg-hover${compactClass}`}
          >
            Allow once
          </Button>
        </>
      ) : (
        <Button
          size="sm"
          onClick={onApproveOnce}
          className={`bg-success-bg text-success-muted border border-success-border hover:bg-success-bg-hover${compactClass}`}
        >
          Allow
        </Button>
      )}
    </div>
  )
}

export function ApprovalItem({
  approval,
  onApprove,
  onApproveOnce,
  onDeny,
  showProxy = false,
  compact = false,
}: ApprovalItemProps) {
  // Calculate TTL in minutes for button label
  const ttlMinutes = approval.cache_ttl_seconds ? Math.floor(approval.cache_ttl_seconds / 60) : null

  // Live countdown until timeout
  const remaining = useCountdown(undefined, approval.timeout_seconds, approval.created_at)
  const isUrgent = remaining < 10

  // Use source/dest paths for two-path operations, fall back to single path
  const hasSourceDest = approval.source_path && approval.dest_path

  if (compact) {
    return (
      <div className="p-4 card-gradient border border-[oklch(0.75_0.15_85_/_0.5)] rounded-lg shadow-[0_0_8px_var(--warning)]">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <span className="font-mono text-sm text-base-300 bg-base-800 px-2.5 py-1.5 rounded">
            {approval.tool_name}
          </span>
          <span className="flex-1 min-w-0 font-mono text-sm text-base-400 break-words">
            {hasSourceDest ? (
              <>
                <span className="text-base-500">from </span>{approval.source_path}
                <span className="text-base-500"> to </span>{approval.dest_path}
              </>
            ) : (
              approval.path || '--'
            )}
          </span>
          <span className={`text-xs tabular-nums ${isUrgent ? 'text-error' : 'text-base-500'}`}>
            {formatCountdown(remaining)}
          </span>
          <ApprovalActions
            canCache={approval.can_cache}
            ttlMinutes={ttlMinutes}
            onApprove={onApprove}
            onApproveOnce={onApproveOnce}
            onDeny={onDeny}
            compact
          />
        </div>
        <div className="text-xs text-base-500 mt-2">
          {approval.subject_id}
        </div>
      </div>
    )
  }

  return (
    <div className="p-4 card-gradient border border-[var(--border-subtle)] rounded-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          {showProxy && (
            <span className="text-xs text-base-500 bg-base-800 px-2 py-1 rounded">
              {approval.proxy_name || approval.proxy_id}
            </span>
          )}
          <span className="font-mono text-sm text-base-300">
            {approval.tool_name}
          </span>
        </div>
        <span className={`text-xs tabular-nums ${isUrgent ? 'text-error' : 'text-base-500'}`}>
          {formatCountdown(remaining)}
        </span>
      </div>

      {(hasSourceDest || approval.path) && (
        <div className="font-mono text-xs text-base-400 mb-3 break-words">
          {hasSourceDest ? (
            <>
              <span className="text-base-500">from </span>{approval.source_path}
              <br />
              <span className="text-base-500">to </span>{approval.dest_path}
            </>
          ) : (
            approval.path
          )}
        </div>
      )}

      <div className="text-xs text-base-500 mb-3">
        {approval.subject_id}
      </div>

      <ApprovalActions
        canCache={approval.can_cache}
        ttlMinutes={ttlMinutes}
        onApprove={onApprove}
        onApproveOnce={onApproveOnce}
        onDeny={onDeny}
      />
    </div>
  )
}
