import { useState, useCallback } from 'react'
import { User, Shield, Key, RefreshCw, X } from 'lucide-react'
import { Layout } from '@/components/layout/Layout'
import { Button } from '@/components/ui/button'
import { BackButton } from '@/components/ui/BackButton'
import { LoginDialog } from '@/components/auth/LoginDialog'
import { LogoutConfirmDialog, type LogoutType } from '@/components/auth/LogoutConfirmDialog'
import { useAuth } from '@/hooks/useAuth'
import { cn } from '@/lib/utils'

export function AuthPage() {
  const { status, loading, logout, logoutFederated, refresh, popupBlockedUrl, clearPopupBlockedUrl } = useAuth()
  const [loginDialogOpen, setLoginDialogOpen] = useState(false)
  const [logoutDialogOpen, setLogoutDialogOpen] = useState(false)
  const [logoutType, setLogoutType] = useState<LogoutType>('local')

  const isAuthenticated = status?.authenticated ?? false

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

  return (
    <Layout showFooter={false}>
      <div className="max-w-[800px] mx-auto px-8 py-8">
        {/* Header */}
        <div className="flex items-center gap-6 pb-6 border-b border-[var(--border-subtle)] mb-8">
          <BackButton />
          <h1 className="font-display text-xl font-semibold">Auth details</h1>
        </div>

        {/* Auth Section */}
        <section className="mb-10">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="w-5 h-5 text-base-500" />
            <h2 className="font-display text-lg font-semibold">Authentication</h2>
          </div>

          <div className="p-6 card-gradient border border-[var(--border-subtle)] rounded-lg">
            {/* Status */}
            <div className="flex items-center justify-between mb-6 pb-6 border-b border-[var(--border-subtle)]">
              <div className="flex items-center gap-3">
                <div
                  className={cn(
                    'w-10 h-10 rounded-full flex items-center justify-center',
                    isAuthenticated ? 'bg-success-bg' : 'bg-base-800'
                  )}
                >
                  <User
                    className={cn(
                      'w-5 h-5',
                      isAuthenticated ? 'text-success-muted' : 'text-base-500'
                    )}
                  />
                </div>
                <div>
                  <div className="font-medium">
                    {loading ? 'Loading...' : isAuthenticated ? 'Authenticated' : 'Not authenticated'}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {status?.email || status?.name || 'No user logged in'}
                  </div>
                </div>
              </div>
              <button
                onClick={refresh}
                className="p-2 text-muted-foreground hover:text-foreground hover:bg-base-800 rounded-lg transition-smooth"
                title="Refresh status"
              >
                <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
              </button>
            </div>

            {/* Details */}
            {status && (
              <div className="grid grid-cols-2 gap-4 mb-6 pb-6 border-b border-[var(--border-subtle)]">
                <div>
                  <div className="text-xs text-base-500 uppercase tracking-wide mb-1">Identity Provider</div>
                  <div className="font-mono text-sm text-base-300">
                    {status.provider || '--'}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-base-500 uppercase tracking-wide mb-1">Storage Backend</div>
                  <div className="font-mono text-sm text-base-300">
                    {status.storage_backend || '--'}
                  </div>
                </div>
                {isAuthenticated && (
                  <>
                    <div>
                      <div className="text-xs text-base-500 uppercase tracking-wide mb-1">Subject ID</div>
                      <div className="font-mono text-sm text-base-300 truncate">
                        {status.subject_id || '--'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-base-500 uppercase tracking-wide mb-1">Email</div>
                      <div className="font-mono text-sm text-base-300 truncate">
                        {status.email || '--'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-base-500 uppercase tracking-wide mb-1">Token Expires</div>
                      <div className="font-mono text-sm text-base-300">
                        {status.token_expires_in_hours !== null
                          ? `${status.token_expires_in_hours.toFixed(1)} hours`
                          : '--'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-base-500 uppercase tracking-wide mb-1">Refresh Token</div>
                      <div className="font-mono text-sm text-base-300">
                        {status.has_refresh_token ? 'Yes' : 'No'}
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-3">
              {!isAuthenticated ? (
                <Button
                  onClick={() => setLoginDialogOpen(true)}
                  className="bg-success-bg text-success-muted border border-success-border hover:bg-success-bg-hover"
                >
                  <Key className="w-4 h-4 mr-2" />
                  Login
                </Button>
              ) : (
                <>
                  <Button
                    variant="outline"
                    onClick={handleLogoutClick}
                    className="text-base-300"
                  >
                    Logout
                  </Button>
                  <Button
                    variant="outline"
                    onClick={handleLogoutFederatedClick}
                    className="text-base-300"
                  >
                    Logout (federated)
                  </Button>
                </>
              )}
            </div>
          </div>
        </section>

        {/* Info */}
        <div className="text-center text-sm text-base-600">
          <p>Authentication tokens are stored securely in your system keychain.</p>
          <p className="mt-1">Federated logout will also sign you out from the identity provider.</p>
        </div>
      </div>

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
    </Layout>
  )
}
