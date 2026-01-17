import { cn } from '@/lib/utils'

interface SectionProps {
  /** Optional section index for staggered animations (defaults to 0) */
  index?: number
  title: string
  titleExtra?: React.ReactNode
  children: React.ReactNode
  className?: string
  loaded?: boolean
}

export function Section({
  index = 0,
  title,
  titleExtra,
  children,
  className,
  loaded = true,
}: SectionProps): JSX.Element {
  return (
    <div
      className={cn(
        'mb-10 opacity-0 translate-y-4',
        loaded && 'animate-section-load',
        className
      )}
      style={
        loaded
          ? {
              animationDelay: `${index * 100 + 100}ms`,
              animationFillMode: 'forwards',
            }
          : undefined
      }
    >
      <div className="flex items-center gap-4 mb-5">
        <span className="font-display text-sm font-semibold uppercase tracking-wide text-base-400">
          {title}
        </span>
        {titleExtra}
        <span
          className={cn(
            'flex-1 h-px bg-[var(--border-subtle)] origin-left scale-x-0',
            loaded && 'animate-line-load'
          )}
          style={
            loaded
              ? {
                  animationDelay: `${index * 100 + 50}ms`,
                  animationFillMode: 'forwards',
                }
              : undefined
          }
        />
      </div>
      {children}
    </div>
  )
}
