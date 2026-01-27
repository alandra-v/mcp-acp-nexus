import { useState, useMemo, useEffect } from 'react'
import type { Row } from '@tanstack/react-table'
import { RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DataTable } from './DataTable'
import { getColumnConfig, getMergedColumnConfig } from './columns'
import { useLogs } from '@/hooks/useLogs'
import { useMultiLogs } from '@/hooks/useMultiLogs'
import { useConfig } from '@/hooks/useConfig'
import type { LogType, TimeRange, LogFilters } from '@/api/logs'
import type { LogEntry } from '@/types/api'
import { cn } from '@/lib/utils'

/** Log folder to file mapping */
const LOG_FOLDERS: Record<string, { label: string; files: { value: string; label: string }[] }> = {
  audit: {
    label: 'Audit',
    files: [
      { value: '_all', label: 'All Files' },
      { value: 'decisions', label: 'Decisions' },
      { value: 'operations', label: 'Operations' },
      { value: 'auth', label: 'Auth' },
    ],
  },
  system: {
    label: 'System',
    files: [
      { value: '_all', label: 'All Files' },
      { value: 'system', label: 'System' },
      { value: 'config_history', label: 'Config History' },
      { value: 'policy_history', label: 'Policy History' },
    ],
  },
  debug: {
    label: 'Debug',
    files: [
      { value: '_all', label: 'All Files' },
      { value: 'client_wire', label: 'Client Wire' },
      { value: 'backend_wire', label: 'Backend Wire' },
    ],
  },
}

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '5m', label: 'Last 5 min' },
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24h' },
  { value: 'all', label: 'All time' },
]

const DECISIONS: { value: string; label: string }[] = [
  { value: '_all', label: 'All decisions' },
  { value: 'allow', label: 'Allow' },
  { value: 'deny', label: 'Deny' },
  { value: 'hitl', label: 'HITL' },
]

const HITL_OUTCOMES: { value: string; label: string }[] = [
  { value: '_all', label: 'All outcomes' },
  { value: 'allowed', label: 'Allowed' },
  { value: 'denied', label: 'Denied' },
  { value: 'timeout', label: 'Timeout' },
]

const LOG_LEVELS: { value: string; label: string }[] = [
  { value: '_all', label: 'All levels' },
  { value: 'ERROR', label: 'Error' },
  { value: 'WARNING', label: 'Warning' },
  { value: 'INFO', label: 'Info' },
  { value: 'DEBUG', label: 'Debug' },
]

// LocalStorage keys for filter persistence
const STORAGE_KEYS = {
  folder: 'logViewerFolder',
  logType: 'logViewerLogType',
  timeRange: 'logViewerTimeRange',
} as const

interface LogViewerProps {
  /** Initial folder to display */
  initialFolder?: string
  /** Initial log type to display (or '_all' for all files in folder) */
  initialLogType?: string
  /** Initial time range */
  initialTimeRange?: TimeRange
  /** Hide the log type selector (for embedded views) */
  hideLogTypeSelector?: boolean
  /** Show compact view (less padding) */
  compact?: boolean
  /**
   * When provided, uses manager-level endpoints to access logs
   * regardless of whether the proxy is running.
   */
  proxyId?: string
}

export function LogViewer({
  initialFolder = 'audit',
  initialLogType = '_all',
  initialTimeRange = '5m',
  hideLogTypeSelector = false,
  compact = false,
  proxyId,
}: LogViewerProps) {
  // Config for checking debug log availability
  const { config } = useConfig({ proxyId })
  const debugEnabled = config?.logging.log_level === 'DEBUG'

  // Filter state - initialize from localStorage or props
  const [folder, setFolder] = useState(() => {
    const stored = localStorage.getItem(STORAGE_KEYS.folder)
    return stored && LOG_FOLDERS[stored] ? stored : initialFolder
  })
  const [logType, setLogType] = useState<string>(() => {
    const storedFolder = localStorage.getItem(STORAGE_KEYS.folder) || initialFolder
    const stored = localStorage.getItem(STORAGE_KEYS.logType)
    // Validate that stored logType is valid for the folder
    if (stored && LOG_FOLDERS[storedFolder]?.files.some(f => f.value === stored)) {
      return stored
    }
    return initialLogType
  })
  const [timeRange, setTimeRange] = useState<TimeRange>(() => {
    const stored = localStorage.getItem(STORAGE_KEYS.timeRange)
    if (stored && TIME_RANGES.some(t => t.value === stored)) {
      return stored as TimeRange
    }
    return initialTimeRange
  })
  const [sessionId, setSessionId] = useState('')
  const [requestId, setRequestId] = useState('')
  const [decision, setDecision] = useState('_all')
  const [hitlOutcome, setHitlOutcome] = useState('_all')
  const [level, setLevel] = useState('_all')
  const [configVersion, setConfigVersion] = useState('')
  const [policyVersion, setPolicyVersion] = useState('')

  // Persist filter selections to localStorage
  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.folder, folder)
  }, [folder])

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.logType, logType)
  }, [logType])

  useEffect(() => {
    localStorage.setItem(STORAGE_KEYS.timeRange, timeRange)
  }, [timeRange])

  // Check if debug folder is selected but debug logging is not enabled
  const debugFolderWithoutDebug = folder === 'debug' && !debugEnabled

  // Normalize version input: "1" -> "v1", "v1" -> "v1"
  const normalizeVersion = (input: string): string => {
    if (!input) return input
    const trimmed = input.trim()
    // If it's just a number, prepend "v"
    if (/^\d+$/.test(trimmed)) {
      return `v${trimmed}`
    }
    return trimmed
  }

  // Build filters object (exclude _all values)
  const filters = useMemo<Omit<LogFilters, 'before' | 'limit'>>(() => {
    const f: Omit<LogFilters, 'before' | 'limit'> = {
      time_range: timeRange,
    }
    if (sessionId) f.session_id = sessionId
    if (requestId) f.request_id = requestId
    if (decision && decision !== '_all') f.decision = decision
    if (hitlOutcome && hitlOutcome !== '_all') f.hitl_outcome = hitlOutcome
    if (level && level !== '_all') f.level = level
    if (configVersion) f.config_version = normalizeVersion(configVersion)
    if (policyVersion) f.policy_version = normalizeVersion(policyVersion)
    return f
  }, [timeRange, sessionId, requestId, decision, hitlOutcome, level, configVersion, policyVersion])

  // Get log types to fetch (all in folder or single type)
  const logTypesToFetch = useMemo<LogType[]>(() => {
    if (logType === '_all') {
      const folderConfig = LOG_FOLDERS[folder]
      if (!folderConfig) return ['decisions']
      return folderConfig.files
        .filter(f => f.value !== '_all')
        .map(f => f.value as LogType)
    }
    return [logType as LogType]
  }, [folder, logType])

  const isMultiType = logType === '_all'

  // Fetch logs using appropriate hook (only one is active at a time)
  // Disable fetching when debug folder is selected but debug logging is not enabled
  const singleResult = useLogs(
    logType as LogType,
    filters,
    50,
    !isMultiType && !debugFolderWithoutDebug,
    { proxyId }
  )
  const multiResult = useMultiLogs(
    isMultiType && !debugFolderWithoutDebug ? logTypesToFetch : [],
    filters,
    50,
    { proxyId }
  )

  // Select the active result
  const { logs, loading, hasMore, totalScanned, logFile, loadMore, refresh } = isMultiType
    ? multiResult
    : singleResult

  // Get column config for current log type
  const { columns, defaultVisibility } = useMemo(() => {
    if (isMultiType) {
      return getMergedColumnConfig(folder)
    }
    return getColumnConfig(logType as LogType)
  }, [isMultiType, folder, logType])

  // Determine which filters to show based on folder/log type
  // Decision filter only when viewing decisions file specifically (not _all)
  const showDecisionFilter = logType === 'decisions'
  const showHitlFilter = logType === 'decisions'
  const showLevelFilter = logType === 'system'
  const showSessionFilter = folder !== 'system' || logType === 'system'
  const showRequestFilter = folder === 'audit' || folder === 'debug'
  // Version filters: only show when viewing the specific history file
  const showPolicyVersionFilter = logType === 'policy_history' || logType === 'decisions'
  const showConfigVersionFilter = logType === 'config_history' || logType === 'operations'

  // Render expanded row with full JSON
  const renderExpandedRow = (row: Row<LogEntry>) => (
    <div className="p-4 bg-base-950/50">
      <pre className="text-xs font-mono text-base-400 overflow-x-auto whitespace-pre-wrap">
        {JSON.stringify(row.original, null, 2)}
      </pre>
    </div>
  )

  return (
    <div className={cn('space-y-4', compact && 'space-y-3')}>
      {/* Filter Bar */}
      <div className={cn(
        'flex flex-wrap items-center gap-3',
        compact ? 'pb-2' : 'pb-4'
      )}>
        {/* Log Type Selector */}
        {!hideLogTypeSelector && (
          <>
            <Select value={folder} onValueChange={(newFolder) => {
              setFolder(newFolder)
              // Reset to "All Files" when changing folder
              setLogType('_all')
            }}>
              <SelectTrigger className="w-[120px] h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.entries(LOG_FOLDERS).map(([key, folderConfig]) => (
                  <SelectItem key={key} value={key} className="text-xs">
                    {folderConfig.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={logType} onValueChange={setLogType}>
              <SelectTrigger className="w-[140px] h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LOG_FOLDERS[folder]?.files.map((file) => (
                  <SelectItem key={file.value} value={file.value} className="text-xs">
                    {file.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </>
        )}

        {/* Time Range */}
        <Select value={timeRange} onValueChange={(v) => setTimeRange(v as TimeRange)}>
          <SelectTrigger className="w-[120px] h-8 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TIME_RANGES.map((tr) => (
              <SelectItem key={tr.value} value={tr.value} className="text-xs">
                {tr.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {/* Decision Filter */}
        {showDecisionFilter && (
          <Select value={decision} onValueChange={setDecision}>
            <SelectTrigger className="w-[130px] h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {DECISIONS.map((d) => (
                <SelectItem key={d.value} value={d.value} className="text-xs">
                  {d.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {/* HITL Outcome Filter (only show when decision is hitl) */}
        {showHitlFilter && decision === 'hitl' && (
          <Select value={hitlOutcome} onValueChange={setHitlOutcome}>
            <SelectTrigger className="w-[130px] h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {HITL_OUTCOMES.map((o) => (
                <SelectItem key={o.value} value={o.value} className="text-xs">
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {/* Level Filter */}
        {showLevelFilter && (
          <Select value={level} onValueChange={setLevel}>
            <SelectTrigger className="w-[120px] h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {LOG_LEVELS.map((l) => (
                <SelectItem key={l.value} value={l.value} className="text-xs">
                  {l.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {/* Session ID Filter */}
        {showSessionFilter && (
          <Input
            placeholder="MCP Session..."
            value={sessionId}
            onChange={(e) => setSessionId(e.target.value)}
            className="w-[140px] h-8 text-xs"
            aria-label="Filter by MCP session ID"
          />
        )}

        {/* Request ID Filter */}
        {showRequestFilter && (
          <Input
            placeholder="Request ID..."
            value={requestId}
            onChange={(e) => setRequestId(e.target.value)}
            className="w-[140px] h-8 text-xs"
            aria-label="Filter by request ID"
          />
        )}

        {/* Version Filters - only show for relevant log types */}
        {showPolicyVersionFilter && (
          <Input
            placeholder="Policy version..."
            value={policyVersion}
            onChange={(e) => setPolicyVersion(e.target.value)}
            className="w-[130px] h-8 text-xs"
            aria-label="Filter by policy version"
          />
        )}
        {showConfigVersionFilter && (
          <Input
            placeholder="Config version..."
            value={configVersion}
            onChange={(e) => setConfigVersion(e.target.value)}
            className="w-[130px] h-8 text-xs"
            aria-label="Filter by config version"
          />
        )}

        {/* Spacer */}
        <div className="flex-1" />

        {/* Stats and Refresh */}
        <span className="text-xs text-base-500">
          {logs.length} entries{totalScanned > 0 && ` / ${totalScanned} scanned`}
        </span>

        <Button
          variant="ghost"
          size="sm"
          onClick={refresh}
          disabled={loading}
          className="h-8 px-2"
          aria-label="Refresh logs"
        >
          <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
        </Button>
      </div>

      {/* Log file path (when viewing single file) */}
      {logFile && (
        <div className="text-xs text-base-600 font-mono truncate" title={logFile}>
          {logFile}
        </div>
      )}

      {/* Data Table or Debug Not Enabled Message */}
      {debugFolderWithoutDebug ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <p className="text-muted-foreground mb-2">
            Debug logs are not available.
          </p>
          <p className="text-sm text-muted-foreground/70">
            Set <code className="px-1.5 py-0.5 bg-base-800 rounded text-xs">log_level</code> to{' '}
            <code className="px-1.5 py-0.5 bg-base-800 rounded text-xs">DEBUG</code> in config to enable wire-level logging.
          </p>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={logs}
          defaultColumnVisibility={defaultVisibility}
          onLoadMore={loadMore}
          hasMore={hasMore}
          loading={loading}
          renderExpandedRow={renderExpandedRow}
        />
      )}
    </div>
  )
}
