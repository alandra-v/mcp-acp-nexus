import { cn } from '@/lib/utils'

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {}

/**
 * Skeleton loading placeholder component.
 * Uses a subtle pulse animation to indicate loading state.
 */
function Skeleton({ className, ...props }: SkeletonProps) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-base-800', className)}
      {...props}
    />
  )
}

export { Skeleton }
