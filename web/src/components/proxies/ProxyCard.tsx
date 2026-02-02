/**
 * Proxy card component for the proxy list grid.
 *
 * Displays proxy name, server, command/URL, and stats.
 * Links to the proxy detail page.
 *
 * Status dot colors:
 * - Green: running proxy, no issues
 * - Grey: inactive proxy, no issues
 * - Red: has issues (incidents or audit problems)
 */

import { Link } from 'react-router-dom'
import { cn } from '@/lib/utils'
import type { Proxy } from '@/types/api'

function formatLatency(ms: number | null | undefined): string {
  if (ms == null) return '\u2013'
  if (ms >= 1000) return `~${(ms / 1000).toFixed(1)}s`
  return `~${ms.toFixed(0)}ms`
}

interface ProxyCardProps {
  proxy: Proxy
  /** Whether proxy has issues (incidents or audit problems) */
  hasIssues?: boolean
}

export function ProxyCard({ proxy, hasIssues = false }: ProxyCardProps) {
  const isActive = proxy.status === 'running'
  const stats = proxy.stats

  return (
    <Link to={`/proxy/${proxy.proxy_id}`} className="proxy-card">
      <div className="proxy-card-inner flex flex-col">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <span className="proxy-name">{proxy.proxy_name}</span>
          <div className="proxy-status">
            <span
              className={cn(
                'status-dot',
                hasIssues && 'has-issues',
                !isActive && !hasIssues && 'inactive'
              )}
            />
            {isActive ? 'Running' : 'Inactive'}
          </div>
        </div>

        {/* Meta - grows to fill space */}
        <div className="proxy-meta flex-1">
          <div className="proxy-meta-row">
            <span className="proxy-meta-label">Server</span>
            <span className="proxy-meta-value">{proxy.server_name}</span>
          </div>
          {proxy.command && (
            <div className="proxy-meta-row">
              <span className="proxy-meta-label">Cmd</span>
              <span className="proxy-meta-value">{proxy.command}</span>
            </div>
          )}
          {proxy.args && proxy.args.length > 0 && (
            <div className="proxy-meta-row">
              <span className="proxy-meta-label">Args</span>
              <span className="proxy-meta-value">{proxy.args.join(', ')}</span>
            </div>
          )}
          {proxy.url && (
            <div className="proxy-meta-row">
              <span className="proxy-meta-label">URL</span>
              <span className="proxy-meta-value">{proxy.url}</span>
            </div>
          )}
        </div>

        {/* Stats - always at bottom */}
        <div className="proxy-stats mt-auto">
          {isActive ? (
            <>
              <div className="proxy-stat">
                <span className="proxy-stat-value">{stats?.requests_total ?? '-'}</span>
                <span className="proxy-stat-label">Requests</span>
              </div>
              <div className="proxy-stat">
                <span className="proxy-stat-value">{formatLatency(stats?.proxy_latency_ms)}</span>
                <span className="proxy-stat-label">Latency</span>
              </div>
            </>
          ) : (
            <div className="text-xs text-muted-foreground">Inactive</div>
          )}
        </div>
      </div>
    </Link>
  )
}
