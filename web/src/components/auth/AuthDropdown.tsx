import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, X } from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { LoginDialog } from '@/components/auth/LoginDialog'
import { LogoutConfirmDialog, type LogoutType } from '@/components/auth/LogoutConfirmDialog'
import { cn } from '@/lib/utils'
import { useAuth } from '@/hooks/useAuth'

export function AuthDropdown() {
  const navigate = useNavigate()
  const { status, loading, logout, logoutFederated, refresh, popupBlockedUrl, clearPopupBlockedUrl } = useAuth()
  const [loginDialogOpen, setLoginDialogOpen] = useState(false)
  const [logoutDialogOpen, setLogoutDialogOpen] = useState(false)
  const [logoutType, setLogoutType] = useState<LogoutType>('local')

  const isConfigured = status?.configured ?? false
  const isAuthenticated = status?.authenticated ?? false
  const hasProvider = !!status?.provider

  // Display name logic:
  // - If authenticated: show email/name
  // - If not configured: show "Auth disabled"
  // - Otherwise: show "Not logged in"
  const displayName = isAuthenticated
    ? (status?.email || status?.name || 'Authenticated')
    : (isConfigured ? 'Not logged in' : 'Auth disabled')

  const handleLogoutClick = useCallback(() => {
    setLogoutType('local')
    setLogoutDialogOpen(true)
  }, [])

  const handleLogoutFederatedClick = useCallback(() => {
    setLogoutType('federated')
    setLogoutDialogOpen(true)
  }, [])

  const handleLogoutConfirm = useCallback(async () => {
    if (logoutType === 'local') {
      await logout()
    } else {
      await logoutFederated()
    }
  }, [logoutType, logout, logoutFederated])

  const handleSettings = useCallback(() => {
    navigate('/auth')
  }, [navigate])

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium hover:bg-base-900 transition-smooth outline-none">
          <span
            className={cn(
              'w-2 h-2 rounded-full',
              isAuthenticated
                ? 'bg-success shadow-[0_0_6px_var(--success-border)]'
                : isConfigured
                  ? 'bg-error-indicator shadow-[0_0_6px_var(--error-indicator)]'
                  : 'bg-base-600'
            )}
          />
          <span className={loading ? 'opacity-50' : ''}>
            {loading ? 'Loading...' : displayName}
          </span>
          <ChevronDown className="w-3 h-3 text-base-500" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuItem
            onClick={() => !isAuthenticated && setLoginDialogOpen(true)}
            disabled={isAuthenticated}
            className={cn(isAuthenticated && 'opacity-40 cursor-not-allowed')}
          >
            Login
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => isAuthenticated && handleLogoutClick()}
            disabled={!isAuthenticated}
            className={cn(!isAuthenticated && 'opacity-40 cursor-not-allowed')}
          >
            Logout
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={() => hasProvider && handleLogoutFederatedClick()}
            disabled={!hasProvider}
            className={cn(!hasProvider && 'opacity-40 cursor-not-allowed')}
          >
            Logout (federated)
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={handleSettings}>
            Auth details
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <LoginDialog
        open={loginDialogOpen}
        onOpenChange={setLoginDialogOpen}
        onSuccess={refresh}
      />

      <LogoutConfirmDialog
        open={logoutDialogOpen}
        onOpenChange={setLogoutDialogOpen}
        type={logoutType}
        onConfirm={handleLogoutConfirm}
      />

      {popupBlockedUrl && (
        <div className="fixed top-16 right-4 z-50 max-w-sm bg-base-800 border border-base-700 rounded-lg p-3 shadow-lg">
          <div className="flex items-start gap-2">
            <div className="flex-1 text-sm">
              <div className="text-muted-foreground mb-1">Popup blocked. Open this URL manually:</div>
              <a
                href={popupBlockedUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent-blue hover:underline break-all text-xs"
              >
                {popupBlockedUrl}
              </a>
            </div>
            <button
              onClick={clearPopupBlockedUrl}
              className="text-base-500 hover:text-base-300 p-1"
              aria-label="Dismiss"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </>
  )
}
