import { useState, useEffect, useMemo } from 'react'
import { Layout } from '@/components/layout/Layout'
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
import { useProxies } from '@/hooks/useProxies'
import { useAppState } from '@/context/AppStateContext'
import { useCachedApprovals } from '@/hooks/useCachedApprovals'
import { cn } from '@/lib/utils'

export function ProxyDetailPage() {
  const { proxies, loading: proxiesLoading } = useProxies()
  const { pending, approve, approveOnce, deny } = useAppState()
  const { cached, loading: cachedLoading, clear: clearCached, deleteEntry: deleteCached } = useCachedApprovals()
  const [activeSection, setActiveSection] = useState<DetailSection>('overview')
  const [loaded, setLoaded] = useState(false)

  // Single proxy mode - use first proxy
  const proxy = proxies[0]

  // Filter pending approvals for this proxy
  const proxyPending = useMemo(
    () => pending.filter((p) => p.proxy_id === proxy?.id),
    [pending, proxy?.id]
  )

  // Trigger section load animation
  useEffect(() => {
    const timer = setTimeout(() => setLoaded(true), 100)
    return () => clearTimeout(timer)
  }, [])

  if (proxiesLoading) {
    return (
      <Layout>
        <div className="text-center py-16 text-muted-foreground">
          Loading...
        </div>
      </Layout>
    )
  }

  if (!proxy) {
    return (
      <Layout>
        <div className="max-w-[1200px] mx-auto px-8 py-12 text-center">
          <h1 className="font-display text-2xl font-semibold mb-4">
            Waiting for proxy...
          </h1>
          <p className="text-muted-foreground">
            Unable to connect. Check that the proxy is running.
          </p>
        </div>
      </Layout>
    )
  }

  const isActive = proxy.status === 'running'

  return (
    <Layout showFooter={false}>
      <div className="grid grid-cols-[180px_1fr] gap-12 max-w-[1200px] mx-auto px-8 py-8">
        {/* Header */}
        <div className="col-span-2 flex items-center gap-6 pb-6 border-b border-[var(--border-subtle)] mb-2">
          <div className="flex-1 flex items-center gap-3">
            <h1 className="font-display text-xl font-semibold">
              {proxy.backend_id}
            </h1>
            <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <span
                className={cn(
                  'w-2 h-2 rounded-full',
                  isActive
                    ? 'bg-success shadow-[0_0_8px_var(--success-border)]'
                    : 'bg-base-600'
                )}
              />
              {isActive ? 'Active' : 'Inactive'}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <DetailSidebar
          activeSection={activeSection}
          onSectionChange={setActiveSection}
        />

        {/* Content */}
        <div className="min-w-0">
          {activeSection === 'overview' && (
            <>
              <TransportFlow
                clientTransport={proxy.client_transport}
                backendTransport={proxy.backend_transport}
                mtlsEnabled={proxy.mtls_enabled}
                backendName={proxy.backend_id}
                clientId={proxy.client_id}
                loaded={loaded}
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
                cached={cached}
                loading={cachedLoading}
                onClear={clearCached}
                onDelete={deleteCached}
                loaded={loaded}
              />
              <ActivitySection loaded={loaded} />
            </>
          )}

          {activeSection === 'logs' && (
            <Section index={0} title="Logs" loaded={loaded}>
              <LogViewer
                initialFolder="audit"
                initialLogType="_all"
                initialTimeRange="5m"
              />
            </Section>
          )}

          {activeSection === 'policy' && (
            <PolicySection loaded={loaded} />
          )}

          {activeSection === 'config' && (
            <ConfigSection loaded={loaded} />
          )}
        </div>
      </div>
    </Layout>
  )
}
