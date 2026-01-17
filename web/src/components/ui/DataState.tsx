import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

interface DataStateProps {
  /** Whether data is currently loading */
  loading?: boolean
  /** Whether there is data to display */
  hasData: boolean
  /** Message to show while loading (default: "Loading...") */
  loadingMessage?: string
  /** Message to show when empty (default: "No data") */
  emptyMessage?: string
  /** Additional class names for the message container */
  className?: string
  /** Content to render when data is available */
  children: ReactNode
}

/**
 * Handles common loading and empty state patterns.
 *
 * Behavior:
 * - Shows loading message when loading=true AND no data (initial load)
 * - Shows empty message when not loading AND no data
 * - Shows children when there is data (even if loading, to show stale data during refresh)
 */
export function DataState({
  loading = false,
  hasData,
  loadingMessage = 'Loading...',
  emptyMessage = 'No data',
  className,
  children,
}: DataStateProps) {
  // Show loading state when loading and no data yet (initial load)
  if (loading && !hasData) {
    return (
      <div className={cn('text-center py-8 text-muted-foreground text-sm', className)}>
        {loadingMessage}
      </div>
    )
  }

  // Show empty state when not loading and no data
  if (!hasData) {
    return (
      <div className={cn('text-center py-8 text-muted-foreground text-sm', className)}>
        {emptyMessage}
      </div>
    )
  }

  // Render children when data is available (even if still loading/refreshing)
  return <>{children}</>
}
