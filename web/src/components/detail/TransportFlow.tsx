import { Lock, Monitor, Server, Shield } from 'lucide-react'
import { cn } from '@/lib/utils'
import { ClaudeLogo } from '@/assets/ClaudeLogo'
import { CLIENT_DISPLAY_NAMES } from '@/constants'

interface TransportFlowProps {
  backendTransport: string
  mtlsEnabled: boolean
  backendName: string
  clientId: string | null
  loaded?: boolean
}

/**
 * Format transport type for display.
 * Converts internal names to user-friendly labels.
 */
function formatTransport(transport: string): string {
  switch (transport) {
    case 'streamablehttp':
      return 'http'
    case 'stdio':
      return 'stdio'
    case 'sse':
      return 'sse'
    default:
      return transport
  }
}

export function TransportFlow({
  backendTransport,
  mtlsEnabled,
  backendName,
  clientId,
  loaded = true,
}: TransportFlowProps) {
  // Client transport is always stdio (Claude Desktop → Proxy)
  const clientLabel = 'stdio'
  const backendLabel = formatTransport(backendTransport)

  // Check if client is Claude Desktop
  const isClaudeDesktop = clientId === 'claude-ai'
  const clientDisplayName = clientId ? (CLIENT_DISPLAY_NAMES[clientId] ?? clientId) : 'Client'

  return (
    <div
      className={cn(
        'mb-8 opacity-0 translate-y-4',
        loaded && 'animate-section-load'
      )}
      style={
        loaded
          ? {
              animationDelay: '0ms',
              animationFillMode: 'forwards',
            }
          : undefined
      }
    >
      <div className="flex items-center justify-center gap-4 text-sm py-4">
        {/* Client */}
        <div className="flex items-center gap-2">
          {isClaudeDesktop ? (
            <ClaudeLogo className="w-4 h-4" />
          ) : (
            <Monitor className="w-4 h-4 text-base-400" />
          )}
          <span className="font-display font-medium text-foreground">{clientDisplayName}</span>
        </div>

        {/* Client -> Proxy connection */}
        <div className="flex items-center gap-2 text-base-500">
          <span className="text-xs">&larr;</span>
          <span className="px-2 py-0.5 bg-base-900 rounded text-xs font-mono text-base-400">
            {clientLabel}
          </span>
          <span className="text-xs">&rarr;</span>
        </div>

        {/* Proxy */}
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-base-400" />
          <span className="font-display font-medium text-foreground">Proxy</span>
        </div>

        {/* Proxy -> Backend connection */}
        <div className="flex items-center gap-2 text-base-500">
          <span className="text-xs">&larr;</span>
          <span className="px-2 py-0.5 bg-base-900 rounded text-xs font-mono text-base-400 flex items-center gap-1.5">
            {backendLabel}
            {mtlsEnabled && (
              <>
                <Lock
                  className="w-3 h-3 text-base-300"
                  style={{ filter: 'drop-shadow(0 0 3px oklch(0.55 0.02 228))' }}
                />
                <span className="text-base-500 text-[10px] uppercase tracking-wide">mTLS</span>
              </>
            )}
          </span>
          <span className="text-xs">&rarr;</span>
        </div>

        {/* Backend */}
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-base-400" />
          <span className="font-display font-medium text-foreground">{backendName}</span>
        </div>
      </div>
    </div>
  )
}
