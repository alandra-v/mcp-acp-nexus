/**
 * Skeleton loader for ProxyCard.
 * Matches the layout of ProxyCard for a smooth loading experience.
 */

import { Skeleton } from '@/components/ui/skeleton'

export function ProxyCardSkeleton() {
  return (
    <div className="proxy-card pointer-events-none">
      <div className="proxy-card-inner flex flex-col">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <Skeleton className="h-5 w-28" />
          <Skeleton className="h-4 w-16" />
        </div>

        {/* Meta */}
        <div className="proxy-meta flex-1">
          <div className="proxy-meta-row">
            <Skeleton className="h-3 w-12" />
            <Skeleton className="h-3 w-32" />
          </div>
          <div className="proxy-meta-row">
            <Skeleton className="h-3 w-10" />
            <Skeleton className="h-3 w-40" />
          </div>
        </div>

        {/* Stats */}
        <div className="proxy-stats mt-auto">
          <div className="proxy-stat">
            <Skeleton className="h-5 w-8 mb-1" />
            <Skeleton className="h-2 w-14" />
          </div>
          <div className="proxy-stat">
            <Skeleton className="h-5 w-6 mb-1" />
            <Skeleton className="h-2 w-10" />
          </div>
          <div className="proxy-stat">
            <Skeleton className="h-5 w-6 mb-1" />
            <Skeleton className="h-2 w-12" />
          </div>
        </div>
      </div>
    </div>
  )
}

/** Grid of skeleton proxy cards for loading state */
export function ProxyGridSkeleton({ count = 3 }: { count?: number }) {
  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] gap-5">
      {Array.from({ length: count }).map((_, i) => (
        <ProxyCardSkeleton key={i} />
      ))}
    </div>
  )
}
