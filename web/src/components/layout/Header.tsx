import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { AlertTriangle, Clock } from 'lucide-react'
import { AuthDropdown } from '@/components/auth/AuthDropdown'
import { PendingDrawer } from '@/components/approvals/PendingDrawer'
import { useIncidentsContext } from '@/context/IncidentsContext'
import { useAppState } from '@/context/AppStateContext'
import { cn } from '@/lib/utils'

/** Count badge for nav items */
function CountBadge({ count, variant = 'error' }: { count: number; variant?: 'error' | 'warning' }) {
  const styles = variant === 'warning'
    ? 'bg-warning text-base-950 shadow-[0_0_6px_var(--warning)]'
    : 'bg-red-500 text-white shadow-[0_0_6px_rgba(239,68,68,0.5)]'

  return (
    <span className={`absolute -top-1 -right-1 min-w-[16px] h-[16px] flex items-center justify-center rounded-full text-[10px] font-semibold ${styles}`}>
      {count}
    </span>
  )
}

export function Header() {
  const location = useLocation()
  const { unreadCount } = useIncidentsContext()
  const { pending, approve, approveOnce, deny } = useAppState()
  const [drawerOpen, setDrawerOpen] = useState(false)

  // Page loader state
  const [isLoading, setIsLoading] = useState(false)
  const [loaderKey, setLoaderKey] = useState(0)

  useEffect(() => {
    setIsLoading(true)
    setLoaderKey((k) => k + 1)
    const timer = setTimeout(() => setIsLoading(false), 600)
    return () => clearTimeout(timer)
  }, [location.pathname])

  return (
    <header className="flex items-center justify-between px-8 py-4 border-b border-[var(--border-subtle)] bg-gradient-to-b from-base-950 to-background sticky top-0 z-50">
      {/* Page transition loader - positioned on the border */}
      <div
        key={loaderKey}
        className={cn(
          'absolute bottom-0 left-0 h-px',
          'bg-gradient-to-r from-base-600 via-base-500 to-base-600',
          isLoading ? 'animate-page-load' : 'w-0 opacity-0'
        )}
      />
      <div className="flex items-center gap-4">
        <Link
          to="/"
          className="font-brand font-semibold text-lg tracking-wide text-base-200 hover:text-foreground transition-smooth"
        >
          MCP ACP
        </Link>
      </div>

      <div className="flex items-center gap-4">
        {/* Pending Approvals Button */}
        <button
          onClick={() => setDrawerOpen(true)}
          className="relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium text-muted-foreground hover:text-foreground hover:bg-base-900 transition-smooth"
        >
          <Clock className="w-4 h-4" />
          Pending
          {pending.length > 0 && <CountBadge count={pending.length} variant="warning" />}
        </button>

        {/* Incidents Link with Badge */}
        <Link
          to="/incidents"
          className={cn(
            'relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-smooth',
            location.pathname === '/incidents'
              ? 'bg-base-800 text-foreground'
              : 'text-muted-foreground hover:text-foreground hover:bg-base-900'
          )}
        >
          <AlertTriangle className="w-4 h-4" />
          Incidents
          {unreadCount > 0 && <CountBadge count={unreadCount} />}
        </Link>

        <AuthDropdown />
      </div>

      {/* Pending Approvals Drawer */}
      <PendingDrawer
        open={drawerOpen}
        onOpenChange={setDrawerOpen}
        approvals={pending}
        onApprove={approve}
        onApproveOnce={approveOnce}
        onDeny={deny}
      />
    </header>
  )
}
