import { useEffect, useState } from 'react'
import { CheckCircle2, Loader2, WifiOff, X } from 'lucide-react'
import { useAppState, type ConnectionStatus } from '@/context/AppStateContext'

/**
 * Persistent banner for SSE connection status to the manager.
 *
 * Shows when connection to the manager is lost or reconnecting.
 * Auto-dismisses after successful reconnection.
 *
 * Pattern:
 * - First disconnect: Show "Reconnecting..." (auto-retry in progress)
 * - Reconnection success: Show "Connected" briefly, then hide
 * - Max retries exceeded: Show "Connection lost" with manual retry
 */
export function ConnectionStatusBanner() {
  const { connectionStatus } = useAppState()
  const [showSuccess, setShowSuccess] = useState(false)
  const [prevStatus, setPrevStatus] = useState<ConnectionStatus>(connectionStatus)
  const [dismissed, setDismissed] = useState(false)
  const [hasConnectedOnce, setHasConnectedOnce] = useState(false)

  useEffect(() => {
    // Show success banner briefly when REconnecting (not first connect)
    if (connectionStatus === 'connected' && prevStatus !== 'connected') {
      if (hasConnectedOnce) {
        // Only show "Connection restored" on reconnection, not first connect
        setShowSuccess(true)
        setDismissed(false)
        const timer = setTimeout(() => {
          setShowSuccess(false)
        }, 3000)
        setPrevStatus(connectionStatus)
        return () => clearTimeout(timer)
      } else {
        // First connection - just mark as connected, no banner
        setHasConnectedOnce(true)
      }
    }

    // Reset dismissed state when connection status changes
    if (connectionStatus !== 'connected') {
      setDismissed(false)
    }

    setPrevStatus(connectionStatus)
  }, [connectionStatus, prevStatus, hasConnectedOnce])

  // Don't show banner if connected and not showing success message
  if (connectionStatus === 'connected' && !showSuccess) {
    return null
  }

  // Don't show reconnecting/disconnected banner until we've connected at least once
  // (initial connection attempt shouldn't show banner - that's expected on page load)
  if (!hasConnectedOnce && connectionStatus !== 'connected') {
    return null
  }

  // Don't show if user dismissed (only for reconnecting state)
  if (dismissed && connectionStatus === 'reconnecting') {
    return null
  }

  const handleRetry = () => {
    // Reload the page to force SSE reconnection
    window.location.reload()
  }

  const handleDismiss = () => {
    setDismissed(true)
  }

  return (
    <div
      className={`
        fixed top-0 left-0 right-0 z-[100]
        px-4 py-2
        flex items-center justify-center gap-2
        text-sm font-medium
        transition-all duration-300
        ${connectionStatus === 'connected'
          ? 'bg-emerald-500/90 text-white'
          : connectionStatus === 'reconnecting'
            ? 'bg-amber-500/90 text-white'
            : 'bg-red-500/90 text-white'
        }
      `}
    >
      {connectionStatus === 'connected' && showSuccess && (
        <>
          <CheckCircle2 className="h-4 w-4" />
          <span>Connection restored</span>
        </>
      )}

      {connectionStatus === 'reconnecting' && (
        <>
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Connection to manager lost. Reconnecting...</span>
          <button
            onClick={handleDismiss}
            className="ml-2 p-1 hover:bg-white/20 rounded"
            aria-label="Dismiss"
          >
            <X className="h-3 w-3" />
          </button>
        </>
      )}

      {connectionStatus === 'disconnected' && (
        <>
          <WifiOff className="h-4 w-4" />
          <span>Unable to connect to manager</span>
          <button
            onClick={handleRetry}
            className="ml-2 px-2 py-0.5 bg-white/20 hover:bg-white/30 rounded text-xs"
          >
            Retry
          </button>
        </>
      )}
    </div>
  )
}
