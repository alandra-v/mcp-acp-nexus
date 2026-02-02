import { useState, useEffect, useCallback } from 'react'
import { ExternalLink } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { useDeviceFlow } from '@/hooks/useDeviceFlow'

interface LoginDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSuccess: () => void
}

export function LoginDialog({ open, onOpenChange, onSuccess }: LoginDialogProps) {
  const [popupBlocked, setPopupBlocked] = useState(false)

  const handleSuccess = useCallback(() => {
    onOpenChange(false)
    onSuccess()
  }, [onOpenChange, onSuccess])

  const { state, start, reset } = useDeviceFlow(handleSuccess)

  // Reset state when dialog closes
  useEffect(() => {
    if (!open) {
      reset()
      setPopupBlocked(false)
    }
  }, [open, reset])

  // Start login when dialog opens
  useEffect(() => {
    if (open && !state.userCode && !state.error && !state.polling) {
      start()
    }
  }, [open, state.userCode, state.error, state.polling, start])

  const handleOpenVerification = useCallback(() => {
    const url = state.verificationUriComplete || state.verificationUri
    const popup = window.open(url, '_blank')
    if (!popup) {
      setPopupBlocked(true)
    }
  }, [state.verificationUriComplete, state.verificationUri])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="font-display">Login</DialogTitle>
          <DialogDescription>Complete authentication in your browser</DialogDescription>
        </DialogHeader>

        {state.error ? (
          <div className="py-4">
            <div className="text-error-muted mb-4">{state.error}</div>
            <Button onClick={start} variant="outline">
              Try Again
            </Button>
          </div>
        ) : state.userCode ? (
          <div className="py-4 space-y-4">
            <div>
              <div className="text-xs text-muted-foreground uppercase tracking-wide mb-2">
                Your code
              </div>
              <div className="font-mono text-2xl font-bold tracking-widest text-center p-4 bg-base-900 rounded-lg">
                {state.userCode}
              </div>
            </div>

            <div className="text-sm text-muted-foreground text-center">
              Enter this code at the verification page
            </div>

            <Button
              className="w-full"
              onClick={handleOpenVerification}
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              Open Verification Page
            </Button>

            {popupBlocked && (
              <div className="text-sm text-muted-foreground bg-base-800 rounded-lg p-3">
                <div className="mb-1">Popup blocked. Open this URL manually:</div>
                <a
                  href={state.verificationUriComplete || state.verificationUri}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-accent-blue hover:underline break-words"
                >
                  {state.verificationUriComplete || state.verificationUri}
                </a>
              </div>
            )}

            {state.polling && (
              <div className="text-center text-sm text-muted-foreground">
                <span className="inline-block w-2 h-2 bg-base-500 rounded-full animate-pulse mr-2" />
                Waiting for authentication...
              </div>
            )}
          </div>
        ) : (
          <div className="py-8 text-center text-muted-foreground">
            <span className="inline-block w-4 h-4 border-2 border-base-500 border-t-transparent rounded-full animate-spin mr-2" />
            Starting login...
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
