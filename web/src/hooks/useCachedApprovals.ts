import { useAppState } from '@/context/AppStateContext'
import type { CachedApproval } from '@/types/api'

interface UseCachedApprovalsReturn {
  cached: CachedApproval[]
  ttlSeconds: number
  loading: boolean
  clear: () => Promise<void>
  deleteEntry: (subjectId: string, toolName: string, path: string | null) => Promise<void>
  refresh: () => void
}

/**
 * Hook for accessing cached approvals from SSE-powered context.
 *
 * Cached approvals are now delivered via SSE (no polling).
 * State is managed centrally in AppStateContext.
 */
export function useCachedApprovals(): UseCachedApprovalsReturn {
  const { cached, cachedTtlSeconds, connected, clearCached, deleteCached } = useAppState()

  return {
    cached,
    ttlSeconds: cachedTtlSeconds,
    // We're "loading" until we receive the first SSE snapshot
    loading: !connected,
    clear: clearCached,
    deleteEntry: deleteCached,
    // Refresh is now a no-op since SSE delivers updates automatically
    refresh: () => {},
  }
}
