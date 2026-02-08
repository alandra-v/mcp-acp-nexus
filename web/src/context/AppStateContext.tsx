/**
 * AppStateContext - SSE lifecycle management.
 *
 * This component only manages the SSE EventSource connection lifecycle.
 * All state management is delegated to the Zustand store (appStore).
 *
 * Re-exports useAppState and ConnectionStatus for backward compatibility
 * with existing imports.
 */

import { useEffect, useRef, type ReactNode } from 'react'
import { subscribeToPendingApprovals } from '@/api/approvals'
import { useAppStore } from '@/store/appStore'

// Re-export for backward compatibility
export { useAppState, type ConnectionStatus } from '@/store/appStore'

export function AppStateProvider({ children }: { children: ReactNode }) {
  const eventSourceRef = useRef<EventSource | null>(null)
  const handleSSEEvent = useAppStore((s) => s.handleSSEEvent)
  const handleSSEError = useAppStore((s) => s.handleSSEError)

  useEffect(() => {
    let cancelled = false

    const connect = async () => {
      try {
        const es = await subscribeToPendingApprovals(handleSSEEvent, handleSSEError)
        if (cancelled) {
          es.close()
          return
        }
        eventSourceRef.current = es
      } catch {
        if (!cancelled) {
          handleSSEError()
        }
      }
    }

    connect()

    return () => {
      cancelled = true
      eventSourceRef.current?.close()
    }
  }, [handleSSEEvent, handleSSEError])

  return <>{children}</>
}
