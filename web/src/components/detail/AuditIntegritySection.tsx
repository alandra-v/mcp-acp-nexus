/**
 * Audit integrity section showing hash chain status and verification controls.
 */

import { useState, useEffect, useCallback } from 'react'
import { Shield, ShieldCheck, ShieldAlert, RefreshCw, Wrench, Archive } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  verifyAuditLogs,
  repairAuditLogs,
  type AuditVerifyResponse,
  type AuditFileResult,
} from '@/api/audit'
import { toast } from '@/components/ui/sonner'
import { notifyError } from '@/hooks/useErrorSound'
import { cn } from '@/lib/utils'
import { SSE_EVENTS } from '@/constants'

interface AuditIntegritySectionProps {
  proxyId?: string
  /** Callback when broken status changes (for sidebar indicator) */
  onBrokenStatusChange?: (hasBroken: boolean) => void
}

const STATUS_CONFIG: Record<string, { icon: typeof Shield; color: string; label: string; description: string }> = {
  protected: {
    icon: ShieldCheck,
    color: 'text-success',
    label: 'Verified',
    description: 'Tamper-proof: entries cannot be modified or deleted without detection',
  },
  unprotected: {
    icon: Shield,
    color: 'text-muted-foreground',
    label: 'Unprotected',
    description: 'No hash chain protection',
  },
  broken: {
    icon: ShieldAlert,
    color: 'text-error',
    label: 'Broken',
    description: 'Hash chain verification failed',
  },
  missing: {
    icon: ShieldAlert,
    color: 'text-error',
    label: 'Missing',
    description: 'File was deleted after being protected',
  },
  empty: {
    icon: Shield,
    color: 'text-muted-foreground',
    label: 'Empty',
    description: 'No entries yet',
  },
  not_created: {
    icon: Shield,
    color: 'text-base-600',
    label: 'Not Created',
    description: 'File will be created when proxy runs',
  },
  error: {
    icon: ShieldAlert,
    color: 'text-error',
    label: 'Error',
    description: 'Failed to read file',
  },
}

// Files that are only protected during proxy runtime (CLI writes without hash chains)
const RUNTIME_ONLY_FILES = ['config-history', 'policy-history']

function formatFileSize(bytes: number): string {
  if (bytes > 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }
  if (bytes > 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`
  }
  return `${bytes} bytes`
}

function FileStatusRow({ file }: { file: AuditFileResult }) {
  const config = STATUS_CONFIG[file.status] || STATUS_CONFIG.error
  const Icon = config.icon
  const isRuntimeOnly = RUNTIME_ONLY_FILES.includes(file.name) && file.status === 'unprotected'
  const isBroken = file.status === 'broken' || file.status === 'missing'
  const hasBackups = file.backups && file.backups.length > 0

  return (
    <div className={cn(
      'py-2 px-3 rounded-lg',
      isBroken ? 'bg-error/10 border border-error/20' : 'bg-base-900/50'
    )}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Icon className={cn('w-4 h-4', config.color)} />
          <div>
            <span className="text-sm font-medium">{file.description}</span>
            <span className="text-xs text-muted-foreground ml-2">({file.name})</span>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs">
          {file.entry_count !== null && (
            <span className="text-muted-foreground">
              {file.entry_count.toLocaleString()} entries
            </span>
          )}
          <span className={cn('font-medium', config.color)}>{config.label}</span>
        </div>
      </div>
      {/* Status description */}
      <p className="text-xs text-muted-foreground mt-1 ml-7">
        {isRuntimeOnly ? 'Protected during runtime only' : config.description}
      </p>
      {/* Error messages for broken files */}
      {isBroken && file.errors && file.errors.length > 0 && (
        <div className="mt-2 ml-7 space-y-1">
          {file.errors.map((error, i) => (
            <p key={i} className="text-xs text-error">
              {error}
            </p>
          ))}
        </div>
      )}
      {/* Backup files */}
      {hasBackups && (
        <div className="mt-2 ml-7">
          <div className="flex items-center gap-1 text-xs text-warning mb-1">
            <Archive className="w-3 h-3" />
            <span>{file.backups.length} backup{file.backups.length > 1 ? 's' : ''}</span>
          </div>
          <div className="space-y-0.5">
            {file.backups.map((backup) => (
              <p key={backup.filename} className="text-xs text-muted-foreground font-mono">
                {backup.filename} ({formatFileSize(backup.size_bytes)})
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function LoadingSkeleton() {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-4">
        <Skeleton className="h-5 w-48" />
        <div className="flex gap-2">
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-8 w-24" />
        </div>
      </div>
      {[1, 2, 3, 4, 5, 6].map((i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  )
}

export function AuditIntegritySection({ proxyId, onBrokenStatusChange }: AuditIntegritySectionProps) {
  const [status, setStatus] = useState<AuditVerifyResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [repairing, setRepairing] = useState(false)
  const [showRepairDialog, setShowRepairDialog] = useState(false)

  const fetchStatus = useCallback(async (signal?: AbortSignal) => {
    if (!proxyId) return
    try {
      setLoading(true)
      const data = await verifyAuditLogs(proxyId, { signal })
      setStatus(data)
    } catch (err) {
      // Ignore aborted requests
      if (err instanceof DOMException && err.name === 'AbortError') return
      notifyError('Failed to load audit status')
    } finally {
      setLoading(false)
    }
  }, [proxyId])

  useEffect(() => {
    const controller = new AbortController()
    fetchStatus(controller.signal)
    return () => controller.abort()
  }, [fetchStatus])

  // Refresh status when proxy connects or disconnects
  useEffect(() => {
    const handleProxyChange = () => fetchStatus()
    window.addEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)
    return () => {
      window.removeEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)
    }
  }, [fetchStatus])

  const handleVerify = useCallback(async () => {
    if (!proxyId) return
    try {
      setVerifying(true)
      const result = await verifyAuditLogs(proxyId)
      setStatus(result)

      if (result.overall_status === 'passed') {
        toast.success(`All ${result.total_protected} files passed integrity check`)
      } else if (result.overall_status === 'failed') {
        toast.error(`${result.total_broken} file(s) failed integrity check`)
      } else {
        toast.info('No log files to verify')
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      notifyError('Verification failed')
    } finally {
      setVerifying(false)
    }
  }, [proxyId])

  const handleRepairConfirm = useCallback(async () => {
    if (!proxyId) return
    try {
      setRepairing(true)
      setShowRepairDialog(false)
      const result = await repairAuditLogs(proxyId)

      if (result.success) {
        toast.success(result.message)
      } else {
        toast.error(result.message)
      }

      // Refresh status after repair
      await fetchStatus()
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') return
      notifyError('Repair failed')
    } finally {
      setRepairing(false)
    }
  }, [proxyId, fetchStatus])

  // Calculate summary using API totals
  const protectedCount = status?.total_protected ?? 0
  const brokenCount = status?.total_broken ?? 0
  const brokenFiles = status?.files.filter((f) => f.status === 'broken' || f.status === 'missing' || f.status === 'error') ?? []
  const totalFiles = status?.files.length ?? 0

  const summaryStatus =
    brokenCount > 0
      ? 'broken'
      : protectedCount === totalFiles && totalFiles > 0
        ? 'all_protected'
        : 'partial'

  // Notify parent when broken status changes
  useEffect(() => {
    onBrokenStatusChange?.(brokenCount > 0)
  }, [brokenCount, onBrokenStatusChange])

  if (loading) {
    return (
      <div className="mt-8 p-6 rounded-lg border border-[var(--border-subtle)]">
        <LoadingSkeleton />
      </div>
    )
  }

  if (!status) {
    return null
  }

  return (
    <div className="mt-8 p-6 rounded-lg border border-[var(--border-subtle)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          {summaryStatus === 'broken' ? (
            <ShieldAlert className="w-5 h-5 text-error" />
          ) : summaryStatus === 'all_protected' ? (
            <ShieldCheck className="w-5 h-5 text-success" />
          ) : (
            <Shield className="w-5 h-5 text-muted-foreground" />
          )}
          <div>
            <h3 className="text-sm font-semibold">Hash Chain Integrity</h3>
            <p className="text-xs text-muted-foreground">
              {summaryStatus === 'broken'
                ? `${brokenCount} file(s) have integrity issues`
                : summaryStatus === 'all_protected'
                  ? 'All audit logs verified'
                  : `${protectedCount} of ${totalFiles} files verified`}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleVerify}
            disabled={verifying || repairing}
          >
            <RefreshCw className={cn('w-4 h-4 mr-2', verifying && 'animate-spin')} />
            {verifying ? 'Verifying...' : 'Verify'}
          </Button>
          {brokenCount > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowRepairDialog(true)}
              disabled={verifying || repairing}
              className="text-warning border-warning/30 hover:bg-warning/10"
            >
              <Wrench className={cn('w-4 h-4 mr-2', repairing && 'animate-spin')} />
              {repairing ? 'Repairing...' : 'Repair'}
            </Button>
          )}
        </div>
      </div>

      {/* File list */}
      <div className="space-y-2">
        {status.files.map((file) => (
          <FileStatusRow key={file.name} file={file} />
        ))}
      </div>

      {/* State file indicator */}
      <div className="mt-4 pt-4 border-t border-[var(--border-subtle)]">
        <p className="text-xs text-muted-foreground">
          Integrity state file:{' '}
          <span className={status.state_file_present ? 'text-success' : 'text-muted-foreground'}>
            {status.state_file_present ? 'present' : 'not found'}
          </span>
        </p>
      </div>

      {/* Repair confirmation dialog */}
      <Dialog open={showRepairDialog} onOpenChange={setShowRepairDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Repair Audit Logs</DialogTitle>
            <DialogDescription>
              The following files have integrity issues and will be repaired:
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-2 my-4">
            {brokenFiles.map((file) => (
              <div key={file.name} className="flex items-center gap-2 p-2 rounded bg-base-900/50">
                <ShieldAlert className="w-4 h-4 text-error flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-sm font-medium">{file.description}</p>
                  <p className="text-xs text-muted-foreground break-words">
                    {file.status === 'missing'
                      ? 'Stale integrity state will be cleared'
                      : `${file.entry_count?.toLocaleString() ?? 0} entries will be backed up`}
                  </p>
                </div>
              </div>
            ))}
          </div>

          <div className="text-sm text-muted-foreground space-y-1">
            <p>Repair will:</p>
            <ol className="list-decimal list-inside space-y-1 ml-2">
              <li>Backup current files with <code className="text-xs bg-base-800 px-1 rounded">.broken.TIMESTAMP.jsonl</code> suffix</li>
              <li>Create fresh empty log files</li>
            </ol>
          </div>

          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setShowRepairDialog(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRepairConfirm}
              disabled={repairing}
            >
              {repairing ? 'Repairing...' : 'Confirm Repair'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
