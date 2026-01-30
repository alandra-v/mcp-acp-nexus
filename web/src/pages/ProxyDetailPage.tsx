import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { useParams, useSearchParams, useNavigate } from 'react-router-dom'
import { Copy, Check, Trash2 } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { Button } from '@/components/ui/button'
import { BackButton } from '@/components/ui/BackButton'
import { DetailSidebar, type DetailSection } from '@/components/detail/DetailSidebar'
import { TransportFlow } from '@/components/detail/TransportFlow'
import { StatsSection } from '@/components/detail/StatsSection'
import { ApprovalsSection } from '@/components/detail/ApprovalsSection'
import { CachedSection } from '@/components/detail/CachedSection'
import { ActivitySection } from '@/components/detail/ActivitySection'
import { LogViewer } from '@/components/logs'
import { Section } from '@/components/detail/Section'
import { ConfigSection } from '@/components/detail/ConfigSection'
import { PolicySection } from '@/components/detail/PolicySection'
import { AuditIntegritySection } from '@/components/detail/AuditIntegritySection'
import { useManagerProxies } from '@/hooks/useManagerProxies'
import { useProxyDetail } from '@/hooks/useProxyDetail'
import { useAppState } from '@/context/AppStateContext'
import { useCachedApprovals } from '@/hooks/useCachedApprovals'
import { getConfigSnippet, deleteProxy } from '@/api/proxies'
import { verifyAuditLogs } from '@/api/audit'
import { ApiError } from '@/types/api'
import { notifyError } from '@/hooks/useErrorSound'
import { toast } from '@/components/ui/sonner'
import { DeleteProxyConfirmDialog } from '@/components/proxy/DeleteProxyConfirmDialog'
import { COPY_FEEDBACK_DURATION_MS, SSE_EVENTS } from '@/constants'
import { cn } from '@/lib/utils'

const VALID_SECTIONS: DetailSection[] = ['overview', 'audit', 'policy', 'config']

export function ProxyDetailPage() {
  const { id: proxyId } = useParams<{ id: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const navigate = useNavigate()
  const { proxies: managerProxies, loading: managerLoading } = useManagerProxies()
  const { approve, approveOnce, deny } = useAppState()
  const { clear: clearCached, deleteEntry: deleteCached } = useCachedApprovals()
  const [loaded, setLoaded] = useState(false)
  const [copied, setCopied] = useState(false)
  const [auditHasIssues, setAuditHasIssues] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const deletingLocallyRef = useRef(false)

  // Get section from URL or default to 'overview'
  const sectionParam = searchParams.get('section')
  const activeSection: DetailSection = VALID_SECTIONS.includes(sectionParam as DetailSection)
    ? (sectionParam as DetailSection)
    : 'overview'

  const setActiveSection = useCallback((section: DetailSection) => {
    setSearchParams({ section }, { replace: true })
  }, [setSearchParams])

  // Find proxy by ID from manager proxies (config data)
  const managerProxy = useMemo(
    () => managerProxies.find((p) => p.proxy_id === proxyId),
    [managerProxies, proxyId]
  )

  // Fetch full proxy detail including pending/cached approvals
  const { proxy: proxyDetail, loading: detailLoading } = useProxyDetail(proxyId)

  // Trigger section load animation
  useEffect(() => {
    const timer = setTimeout(() => setLoaded(true), 100)
    return () => clearTimeout(timer)
  }, [])

  // Fetch audit status for sidebar indicator
  useEffect(() => {
    if (!proxyId) return

    const controller = new AbortController()

    const fetchAuditStatus = async () => {
      try {
        const status = await verifyAuditLogs(proxyId, { signal: controller.signal })
        const hasBroken = status.files.some((f) => f.status === 'broken')
        setAuditHasIssues(hasBroken)
      } catch (err) {
        // Ignore aborted requests and other errors - indicator just won't show
        if (err instanceof DOMException && err.name === 'AbortError') return
        // Non-critical: indicator won't show but page still works
      }
    }

    fetchAuditStatus()

    // Refetch on proxy connect/disconnect
    const handleProxyChange = () => fetchAuditStatus()
    window.addEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)

    // Navigate away if this proxy is deleted externally (CLI or another tab)
    const handleProxyDeleted = (e: Event) => {
      const detail = (e as CustomEvent).detail
      if (detail?.proxy_id === proxyId && !deletingLocallyRef.current) {
        toast.info(`Proxy '${detail.proxy_name || proxyId}' was deleted`)
        navigate('/')
      }
    }
    window.addEventListener(SSE_EVENTS.PROXY_DELETED, handleProxyDeleted)

    return () => {
      controller.abort()
      window.removeEventListener(SSE_EVENTS.PROXY_REGISTERED, handleProxyChange)
      window.removeEventListener(SSE_EVENTS.PROXY_DELETED, handleProxyDeleted)
    }
  }, [proxyId, navigate])

  const handleCopyConfig = useCallback(async () => {
    const proxyName = managerProxy?.proxy_name
    if (!proxyName) return

    try {
      const response = await getConfigSnippet(proxyName)
      await navigator.clipboard.writeText(JSON.stringify({ mcpServers: response.mcpServers }, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), COPY_FEEDBACK_DURATION_MS)
    } catch {
      notifyError('Failed to copy config')
    }
  }, [managerProxy?.proxy_name])

  const handleDeleteProxy = useCallback(async () => {
    if (!proxyId) return

    setIsDeleting(true)
    deletingLocallyRef.current = true
    try {
      await deleteProxy(proxyId)
      setShowDeleteConfirm(false)
      toast.success(`Proxy '${managerProxy?.proxy_name}' deleted`)
      navigate('/')
    } catch (e) {
      deletingLocallyRef.current = false
      if (e instanceof ApiError) {
        notifyError(e.message || 'Failed to delete proxy')
      } else {
        notifyError('Failed to delete proxy')
      }
    } finally {
      setIsDeleting(false)
    }
  }, [proxyId, managerProxy?.proxy_name, navigate])

  if (managerLoading) {
    return (
      <Layout>
        <div className="text-center py-16 text-muted-foreground">
          Loading...
        </div>
      </Layout>
    )
  }

  if (!managerProxy) {
    return (
      <Layout>
        <div className="max-w-[1200px] mx-auto px-8 py-12">
          <div className="mb-8">
            <BackButton />
          </div>
          <div className="text-center">
            <h1 className="font-display text-2xl font-semibold mb-4">
              Proxy not found
            </h1>
            <p className="text-muted-foreground">
              The requested proxy does not exist in the configuration.
            </p>
          </div>
        </div>
      </Layout>
    )
  }

  // Show connecting state if proxy is running but detail not yet loaded
  if (detailLoading && managerProxy.status === 'running') {
    return (
      <Layout>
        <div className="max-w-[1200px] mx-auto px-8 py-12">
          <div className="mb-8">
            <BackButton />
          </div>
          <div className="text-center">
            <h1 className="font-display text-2xl font-semibold mb-4">
              Connecting to proxy...
            </h1>
            <p className="text-muted-foreground">
              Waiting for connection to {managerProxy.server_name}.
            </p>
          </div>
        </div>
      </Layout>
    )
  }

  const isActive = managerProxy.status === 'running'
  const isRunning = proxyDetail?.status === 'running'

  // Get pending approvals from detail response
  const proxyPending = proxyDetail?.pending_approvals ?? []

  // Get cached approvals from detail response
  const proxyCached = proxyDetail?.cached_approvals ?? []

  return (
    <Layout showFooter={false}>
      <div className="grid grid-cols-[180px_1fr] gap-12 max-w-[1200px] mx-auto px-8 py-8">
        {/* Header */}
        <div className="col-span-2 flex items-center gap-6 pb-6 border-b border-[var(--border-subtle)] mb-2">
          <BackButton />
          <div className="flex-1 flex items-center gap-3">
            <h1 className="font-display text-xl font-semibold">
              {managerProxy.proxy_name}
            </h1>
            <span className="text-sm text-muted-foreground">
              ({managerProxy.server_name})
            </span>
            <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <span
                className={cn(
                  'w-2 h-2 rounded-full',
                  isActive
                    ? 'bg-success shadow-[0_0_8px_var(--success-border)]'
                    : 'bg-base-600'
                )}
              />
              {isActive ? 'Running' : 'Inactive'}
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={handleCopyConfig}>
            {copied ? (
              <>
                <Check className="w-4 h-4 mr-2" />
                Copied!
              </>
            ) : (
              <>
                <Copy className="w-4 h-4 mr-2" />
                Copy Client Config
              </>
            )}
          </Button>
          <span title={isActive ? 'Stop the proxy before deleting' : 'Delete this proxy'}>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => setShowDeleteConfirm(true)}
              disabled={isActive}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Delete
            </Button>
          </span>
        </div>

        {/* Sidebar */}
        <DetailSidebar
          activeSection={activeSection}
          onSectionChange={setActiveSection}
          auditHasIssues={auditHasIssues}
        />

        {/* Content */}
        <div className="min-w-0">
          {activeSection === 'overview' && (
            <>
              <TransportFlow
                backendTransport={proxyDetail?.backend_transport}
                mtlsEnabled={proxyDetail?.mtls_enabled}
                backendName={managerProxy.server_name}
                clientId={proxyDetail?.client_id}
                loaded={loaded}
                inactive={!isRunning}
              />
              <StatsSection loaded={loaded} />
              <ApprovalsSection
                approvals={proxyPending}
                onApprove={approve}
                onApproveOnce={approveOnce}
                onDeny={deny}
                loaded={loaded}
              />
              <CachedSection
                cached={proxyCached}
                loading={detailLoading}
                onClear={clearCached}
                onDelete={deleteCached}
                loaded={loaded}
              />
              <ActivitySection loaded={loaded} proxyId={proxyId} />
            </>
          )}

          {activeSection === 'audit' && (
            <>
              <Section index={0} title="Audit Logs" loaded={loaded}>
                <LogViewer
                  initialFolder="audit"
                  initialLogType="_all"
                  initialTimeRange="all"
                  proxyId={proxyId}
                />
              </Section>
              <Section index={1} title="Log Integrity" loaded={loaded}>
                <AuditIntegritySection proxyId={proxyId} onBrokenStatusChange={setAuditHasIssues} />
              </Section>
            </>
          )}

          {activeSection === 'policy' && (
            <PolicySection loaded={loaded} proxyId={proxyId} />
          )}

          {activeSection === 'config' && (
            <ConfigSection loaded={loaded} proxyId={proxyId} />
          )}
        </div>
      </div>

      <DeleteProxyConfirmDialog
        open={showDeleteConfirm}
        onOpenChange={setShowDeleteConfirm}
        proxyName={managerProxy.proxy_name}
        onConfirm={handleDeleteProxy}
        isDeleting={isDeleting}
      />
    </Layout>
  )
}
