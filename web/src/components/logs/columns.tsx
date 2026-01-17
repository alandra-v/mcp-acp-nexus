import type { ColumnDef, VisibilityState } from '@tanstack/react-table'
import type { LogEntry } from '@/types/api'
import type { LogType } from '@/api/logs'
import { cn, formatTime, formatDateTime } from '@/lib/utils'

// =============================================================================
// Helper Functions
// =============================================================================

/** Extract subject_id from nested subject object or return direct value */
function extractSubjectId(subject: unknown): string | null {
  if (!subject) return null
  if (typeof subject === 'string') return subject
  if (typeof subject === 'object' && subject !== null) {
    const obj = subject as Record<string, unknown>
    if (typeof obj.subject_id === 'string') return obj.subject_id
  }
  return null
}

/** Truncate path from the beginning, showing the end */
function truncatePath(path: string, maxLength: number): string {
  if (path.length <= maxLength) return path
  return '...' + path.slice(-(maxLength - 3))
}

// =============================================================================
// Cell Components
// =============================================================================

/** Decision badge with color coding */
function DecisionBadge({ decision }: { decision: string | undefined }) {
  if (!decision) return <span className="text-base-600">--</span>

  const normalized = decision.toLowerCase()
  const isAllow = normalized === 'allow' || normalized === 'allowed'
  const isDeny = normalized === 'deny' || normalized === 'denied'
  const isHitl = normalized === 'hitl'

  return (
    <span
      className={cn(
        'px-2 py-0.5 rounded text-xs font-medium',
        isAllow && 'bg-success/20 text-success',
        isDeny && 'bg-error/20 text-error',
        isHitl && 'bg-warning/20 text-warning',
        !isAllow && !isDeny && !isHitl && 'bg-base-700 text-base-400'
      )}
    >
      {decision}
    </span>
  )
}

/** Status badge with color coding */
function StatusBadge({ status }: { status: string | undefined }) {
  if (!status) return <span className="text-base-600">--</span>

  const normalized = status.toLowerCase()
  const isSuccess = normalized === 'success' || normalized === 'ok' || normalized === 'completed'
  const isError = normalized === 'error' || normalized === 'failed' || normalized === 'failure'
  const isPending = normalized === 'pending' || normalized === 'waiting'

  // Normalize display text for consistency
  const displayText = isSuccess ? 'success' : isError ? 'failure' : status

  return (
    <span
      className={cn(
        'px-2 py-0.5 rounded text-xs font-medium',
        isSuccess && 'bg-success/20 text-success',
        isError && 'bg-error/20 text-error',
        isPending && 'bg-warning/20 text-warning',
        !isSuccess && !isError && !isPending && 'bg-base-700 text-base-400'
      )}
    >
      {displayText}
    </span>
  )
}

/** HITL outcome badge with cached indicator */
function HitlOutcomeBadge({ outcome, cached }: { outcome: string | undefined; cached: boolean }) {
  if (!outcome) return <span className="text-base-600">--</span>

  const normalized = outcome.toLowerCase()
  const isAllowed = normalized === 'user_allowed'
  const isDenied = normalized === 'user_denied'
  const isTimeout = normalized === 'timeout'

  const label = isAllowed ? 'Allowed' : isDenied ? 'Denied' : isTimeout ? 'Timeout' : outcome

  return (
    <span className="inline-flex items-center gap-1">
      <span
        className={cn(
          'px-2 py-0.5 rounded text-xs font-medium',
          isAllowed && 'bg-success/20 text-success',
          isDenied && 'bg-error/20 text-error',
          isTimeout && 'bg-warning/20 text-warning',
          !isAllowed && !isDenied && !isTimeout && 'bg-base-700 text-base-400'
        )}
      >
        {label}
      </span>
      {cached && (
        <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-info/20 text-info">
          cached
        </span>
      )}
    </span>
  )
}

/** Truncate long strings */
function TruncatedCell({ value, maxLength = 40 }: { value: unknown; maxLength?: number }) {
  if (value === null || value === undefined) return <span className="text-base-600">--</span>
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value)
  const truncated = str.length > maxLength ? `${str.slice(0, maxLength)}...` : str
  return (
    <span className="font-mono text-xs" title={str}>
      {truncated}
    </span>
  )
}

/** Source badge showing which log file an entry came from */
function SourceBadge({ source }: { source: string | undefined }) {
  if (!source) return <span className="text-base-600">--</span>

  const colors: Record<string, string> = {
    decisions: 'bg-primary/20 text-primary',
    operations: 'bg-info/20 text-info',
    auth: 'bg-warning/20 text-warning',
    system: 'bg-error/20 text-error',
    config_history: 'bg-base-600/20 text-base-400',
    policy_history: 'bg-base-600/20 text-base-400',
    client_wire: 'bg-success/20 text-success',
    backend_wire: 'bg-success/20 text-success',
  }

  return (
    <span className={cn('px-2 py-0.5 rounded text-xs font-medium', colors[source] || 'bg-base-700 text-base-400')}>
      {source}
    </span>
  )
}

// =============================================================================
// Column Definitions
// =============================================================================

/**
 * decisions.jsonl columns
 * Columns: time, mcp_method, decision, final_rule, hitl_outcome (with cached indicator)
 */
export const decisionsColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'mcp_method',
    header: 'Method',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-300">
        {String(row.original.mcp_method || '--')}
      </span>
    ),
  },
  {
    accessorKey: 'decision',
    header: 'Decision',
    cell: ({ row }) => <DecisionBadge decision={row.original.decision as string} />,
  },
  {
    accessorKey: 'final_rule',
    header: 'Rule',
    cell: ({ row }) => <TruncatedCell value={row.original.final_rule} maxLength={25} />,
  },
  {
    accessorKey: 'hitl_outcome',
    header: 'HITL Result',
    cell: ({ row }) => {
      const decision = row.original.decision as string
      if (decision?.toLowerCase() !== 'hitl') return <span className="text-base-600">--</span>
      const outcome = row.original.hitl_outcome as string
      const cached = row.original.hitl_cache_hit === true
      return <HitlOutcomeBadge outcome={outcome} cached={cached} />
    },
  },
]

/**
 * operations.jsonl columns
 * Columns: time, method, tool_name (if available), file paths, message (if failure)
 */
export const operationsColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'method',
    header: 'Method',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-300">
        {String(row.original.method || '--')}
      </span>
    ),
  },
  {
    accessorKey: 'tool_name',
    header: 'Tool',
    cell: ({ row }) => {
      const toolName = row.original.tool_name as string
      if (!toolName) return <span className="text-base-600">--</span>
      return <span className="font-mono text-xs text-base-300">{toolName}</span>
    },
  },
  {
    accessorKey: 'file_path',
    header: 'Path(s)',
    cell: ({ row }) => {
      const filePath = row.original.file_path as string
      const sourcePath = row.original.source_path as string
      const destPath = row.original.dest_path as string

      if (sourcePath && destPath) {
        const display = `${truncatePath(sourcePath, 20)} → ${truncatePath(destPath, 20)}`
        const full = `${sourcePath} → ${destPath}`
        return <span className="font-mono text-xs text-base-400" title={full}>{display}</span>
      }
      if (filePath) {
        return <span className="font-mono text-xs text-base-400" title={filePath}>{truncatePath(filePath, 45)}</span>
      }
      return <span className="text-base-600">--</span>
    },
  },
  {
    accessorKey: 'status',
    header: 'Status/Message',
    cell: ({ row }) => {
      const status = row.original.status as string
      const message = row.original.message as string
      const isFailure = status?.toLowerCase() === 'failure'

      if (isFailure && message) {
        return (
          <span className="font-mono text-xs text-error/80" title={message}>
            {message.length > 40 ? message.slice(0, 37) + '...' : message}
          </span>
        )
      }
      return <StatusBadge status={status} />
    },
  },
]

/**
 * auth.jsonl columns
 * Columns: time, bound_session_id, event_type, status, subject_id (extracted)
 */
export const authColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'bound_session_id',
    header: 'Session',
    cell: ({ row }) => <TruncatedCell value={row.original.bound_session_id} maxLength={15} />,
  },
  {
    accessorKey: 'event_type',
    header: 'Event',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-300">
        {String(row.original.event_type || '--')}
      </span>
    ),
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ row }) => <StatusBadge status={row.original.status as string} />,
  },
  {
    accessorKey: 'subject',
    header: 'Subject',
    cell: ({ row }) => {
      const subjectId = extractSubjectId(row.original.subject)
      if (!subjectId) return <span className="text-base-600">--</span>
      return <TruncatedCell value={subjectId} maxLength={25} />
    },
  },
]

/**
 * system.jsonl columns
 */
export const systemColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatDateTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'event',
    header: 'Event',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-300">
        {String(row.original.event || '--')}
      </span>
    ),
  },
  {
    accessorKey: 'error_type',
    header: 'Error Type',
    cell: ({ row }) => {
      const errorType = row.original.error_type as string
      if (!errorType) return <span className="text-base-600">--</span>
      return (
        <span className="px-2 py-0.5 rounded text-xs font-medium bg-error/20 text-error">
          {errorType}
        </span>
      )
    },
  },
  {
    accessorKey: 'message',
    header: 'Message',
    cell: ({ row }) => <TruncatedCell value={row.original.message} maxLength={50} />,
  },
  {
    accessorKey: 'session_id',
    header: 'Session',
    cell: ({ row }) => <TruncatedCell value={row.original.session_id} maxLength={12} />,
  },
]

/**
 * config_history.jsonl columns
 */
export const configHistoryColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatDateTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'event',
    header: 'Event',
    cell: ({ row }) => <TruncatedCell value={row.original.event} />,
  },
  {
    accessorKey: 'config_version',
    header: 'Version',
    cell: ({ row }) => <TruncatedCell value={row.original.config_version} />,
  },
  {
    accessorKey: 'message',
    header: 'Message',
    cell: ({ row }) => <TruncatedCell value={row.original.message} maxLength={50} />,
  },
]

/**
 * policy_history.jsonl columns
 */
export const policyHistoryColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatDateTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'event',
    header: 'Event',
    cell: ({ row }) => <TruncatedCell value={row.original.event} />,
  },
  {
    accessorKey: 'policy_version',
    header: 'Version',
    cell: ({ row }) => <TruncatedCell value={row.original.policy_version} />,
  },
  {
    accessorKey: 'rules_count',
    header: 'Rules',
    cell: ({ row }) => <TruncatedCell value={row.original.rules_count} />,
  },
  {
    accessorKey: 'message',
    header: 'Message',
    cell: ({ row }) => <TruncatedCell value={row.original.message} maxLength={40} />,
  },
]

/**
 * Wire logs columns (client_wire, backend_wire)
 */
export const wireColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: 'direction',
    header: 'Dir',
    cell: ({ row }) => {
      const dir = row.original.direction as string
      return (
        <span className={cn(
          'font-mono text-xs font-bold',
          dir === 'in' && 'text-success',
          dir === 'out' && 'text-warning'
        )}>
          {dir === 'in' ? '<<<' : dir === 'out' ? '>>>' : '--'}
        </span>
      )
    },
  },
  {
    accessorKey: 'method',
    header: 'Method',
    cell: ({ row }) => <TruncatedCell value={row.original.method} maxLength={20} />,
  },
  {
    accessorKey: 'session_id',
    header: 'Session',
    cell: ({ row }) => <TruncatedCell value={row.original.session_id} maxLength={12} />,
  },
  {
    accessorKey: 'request_id',
    header: 'Request',
    cell: ({ row }) => <TruncatedCell value={row.original.request_id} maxLength={12} />,
  },
]

/**
 * Merged columns for viewing all files in a folder
 */
export const mergedColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: '_source',
    header: 'Source',
    cell: ({ row }) => <SourceBadge source={(row.original as Record<string, unknown>)._source as string} />,
  },
  {
    accessorKey: 'method',
    header: 'Method',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-300">
        {String(row.original.method || row.original.mcp_method || row.original.event_type || '--')}
      </span>
    ),
  },
  {
    accessorKey: 'decision',
    header: 'Decision/Status',
    cell: ({ row }) => {
      const decision = row.original.decision as string
      const status = row.original.status as string
      if (decision) return <DecisionBadge decision={decision} />
      if (status) return <StatusBadge status={status} />
      return <span className="text-base-600">--</span>
    },
  },
  {
    accessorKey: 'subject',
    header: 'Subject',
    cell: ({ row }) => {
      // Try to extract subject_id from nested object or use direct subject_id
      const subjectId = extractSubjectId(row.original.subject) || (row.original.subject_id as string)
      if (!subjectId) return <span className="text-base-600">--</span>
      return <TruncatedCell value={subjectId} maxLength={20} />
    },
  },
  {
    accessorKey: 'session_id',
    header: 'Session',
    cell: ({ row }) => <TruncatedCell value={row.original.session_id} maxLength={12} />,
  },
]

/**
 * Merged columns for system folder (time, source, event, message)
 */
export const systemMergedColumns: ColumnDef<LogEntry>[] = [
  {
    accessorKey: 'time',
    header: 'Time',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-500">
        {formatDateTime(row.original.time)}
      </span>
    ),
  },
  {
    accessorKey: '_source',
    header: 'Source',
    cell: ({ row }) => <SourceBadge source={(row.original as Record<string, unknown>)._source as string} />,
  },
  {
    accessorKey: 'event',
    header: 'Event',
    cell: ({ row }) => (
      <span className="font-mono text-xs text-base-300">
        {String(row.original.event || '--')}
      </span>
    ),
  },
  {
    accessorKey: 'message',
    header: 'Message',
    cell: ({ row }) => <TruncatedCell value={row.original.message} maxLength={80} />,
  },
]

// =============================================================================
// Column Config Map
// =============================================================================

export interface ColumnConfig {
  columns: ColumnDef<LogEntry>[]
  defaultVisibility: VisibilityState
}

/** Get merged column config for "All Files" view within a folder */
export function getMergedColumnConfig(folder: string): ColumnConfig {
  // System folder uses simplified columns: time, event, message
  if (folder === 'system') {
    return {
      columns: systemMergedColumns,
      defaultVisibility: {},
    }
  }

  return {
    columns: mergedColumns,
    defaultVisibility: {
      session_id: false,
    },
  }
}

/** Get column config for a log type */
export function getColumnConfig(logType: LogType): ColumnConfig {
  switch (logType) {
    case 'decisions':
      return {
        columns: decisionsColumns,
        defaultVisibility: {},
      }
    case 'operations':
      return {
        columns: operationsColumns,
        defaultVisibility: {},
      }
    case 'auth':
      return {
        columns: authColumns,
        defaultVisibility: {},
      }
    case 'system':
      return {
        columns: systemColumns,
        defaultVisibility: {},
      }
    case 'config_history':
      return {
        columns: configHistoryColumns,
        defaultVisibility: {},
      }
    case 'policy_history':
      return {
        columns: policyHistoryColumns,
        defaultVisibility: {},
      }
    case 'client_wire':
    case 'backend_wire':
      return {
        columns: wireColumns,
        defaultVisibility: {},
      }
    default:
      return {
        columns: decisionsColumns,
        defaultVisibility: {},
      }
  }
}
