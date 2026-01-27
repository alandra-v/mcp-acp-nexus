import { useState } from 'react'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Section } from './Section'
import { DataState } from '@/components/ui/DataState'
import { cn, formatTime } from '@/lib/utils'
import { useLogs } from '@/hooks/useLogs'
import { ChevronDown, ChevronRight } from 'lucide-react'

interface ActivitySectionProps {
  loaded?: boolean
  /** Proxy ID for manager-level API access */
  proxyId?: string
}

export function ActivitySection({
  loaded = true,
  proxyId,
}: ActivitySectionProps) {
  // Fetch recent operations - last 5 minutes, max 20 entries
  // Use manager endpoint when proxyId is provided
  const { logs, loading } = useLogs('operations', { time_range: '5m' }, 20, true, { proxyId })

  return (
    <Section
      index={0}
      title="Recent Activity"
      loaded={loaded}
    >
      <div className="border border-[var(--border-subtle)] rounded-lg card-gradient overflow-hidden">
        <ScrollArea className="h-[300px]">
          <DataState
            loading={loading}
            hasData={logs.length > 0}
            loadingMessage="Loading logs..."
            emptyMessage="No recent activity"
          >
            <div>
              {logs.map((log, i) => (
                <LogEntryRow
                  key={`${log.time}-${log.tool_name ?? ''}-${i}`}
                  log={log}
                />
              ))}
            </div>
          </DataState>
        </ScrollArea>
      </div>
      <p className="mt-2 text-xs text-base-600">
        Showing entries from operations.jsonl
      </p>
    </Section>
  )
}

interface LogEntryRowProps {
  log: {
    time?: string
    method?: unknown
    tool_name?: unknown
    status?: unknown
    message?: unknown
    file_path?: unknown
    source_path?: unknown
    dest_path?: unknown
    [key: string]: unknown
  }
}

function LogEntryRow({ log }: LogEntryRowProps) {
  const [expanded, setExpanded] = useState(false)
  const timestamp = formatTime(log.time)
  const method = String(log.method || '--')
  const toolName = log.tool_name ? String(log.tool_name) : null
  const status = String(log.status || '--')
  const isFailure = status.toLowerCase() === 'failure'
  const message = log.message ? String(log.message) : null

  // Get file paths - could be file_path, or source_path + dest_path
  const filePath = log.file_path ? String(log.file_path) : null
  const sourcePath = log.source_path ? String(log.source_path) : null
  const destPath = log.dest_path ? String(log.dest_path) : null

  // Build display path
  let displayPath = '--'
  let fullPath = ''
  if (sourcePath && destPath) {
    const srcShort = truncatePath(sourcePath, 25)
    const dstShort = truncatePath(destPath, 25)
    displayPath = `${srcShort} → ${dstShort}`
    fullPath = `${sourcePath} → ${destPath}`
  } else if (filePath) {
    displayPath = truncatePath(filePath, 50)
    fullPath = filePath
  }

  return (
    <div className="border-b border-[var(--border-subtle)] last:border-b-0">
      <div
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        className={cn(
          "flex items-center gap-3 px-4 py-3 hover:bg-base-900 transition-smooth text-sm cursor-pointer",
          expanded && "bg-base-900/50"
        )}
        onClick={() => setExpanded(!expanded)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault()
            setExpanded(!expanded)
          }
        }}
      >
        <span className="text-base-500" aria-hidden="true">
          {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        </span>
        <span className="font-mono text-xs text-base-600 min-w-[60px]">
          {timestamp}
        </span>
        <span className="font-mono text-xs text-base-400 min-w-[70px]">
          {method}
        </span>
        {toolName && (
          <span className="font-mono text-xs text-base-300 min-w-[80px]">
            {toolName}
          </span>
        )}
        <span
          className={cn(
            'px-2 py-0.5 rounded text-xs font-medium min-w-[55px] text-center',
            status.toLowerCase() === 'success' && 'bg-success/20 text-success',
            isFailure && 'bg-error/20 text-error',
            !['success', 'failure'].includes(status.toLowerCase()) && 'bg-base-700 text-base-400'
          )}
        >
          {status}
        </span>
        {isFailure && message ? (
          <span className="font-mono text-xs text-error/80 flex-1 truncate" title={message}>
            {message.length > 40 ? message.slice(0, 37) + '...' : message}
          </span>
        ) : (
          <span className="font-mono text-xs text-base-500 flex-1 truncate" title={fullPath || undefined}>
            {displayPath}
          </span>
        )}
      </div>
      {expanded && (
        <div className="px-4 py-3 bg-base-950/50 border-t border-[var(--border-subtle)]">
          <pre className="text-xs font-mono text-base-400 overflow-x-auto whitespace-pre-wrap">
            {JSON.stringify(log, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function truncatePath(path: string, maxLength: number): string {
  if (path.length <= maxLength) return path
  return '...' + path.slice(-(maxLength - 3))
}
