import { useState, useCallback } from 'react'
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'

interface DeleteProxyConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  proxyName: string
  onConfirm: (purge: boolean) => void
  isDeleting: boolean
}

export function DeleteProxyConfirmDialog({
  open,
  onOpenChange,
  proxyName,
  onConfirm,
  isDeleting,
}: DeleteProxyConfirmDialogProps) {
  const [isPurge, setIsPurge] = useState(false)

  const handleOpenChange = useCallback((nextOpen: boolean) => {
    if (!nextOpen) setIsPurge(false)
    onOpenChange(nextOpen)
  }, [onOpenChange])

  const handleConfirm = useCallback(() => {
    onConfirm(isPurge)
  }, [onConfirm, isPurge])

  return (
    <AlertDialog open={open} onOpenChange={handleOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {isPurge ? 'Purge Proxy' : 'Delete Proxy'}
          </AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-3">
              <p>
                Are you sure you want to {isPurge ? 'permanently delete' : 'delete'}{' '}
                <strong>{proxyName}</strong>?
              </p>
              {isPurge ? (
                <div>
                  <p className="font-medium text-destructive text-sm">
                    Everything will be permanently deleted:
                  </p>
                  <ul className="list-disc list-inside text-sm mt-1 space-y-0.5">
                    <li>Configuration and policy</li>
                    <li>Audit logs (security trail)</li>
                    <li>System logs</li>
                    <li>Debug logs</li>
                    <li>Backend credentials</li>
                  </ul>
                  <p className="text-sm mt-2 text-destructive">
                    Nothing will be archived. This cannot be undone.
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <p className="font-medium text-foreground text-sm">What will be archived (preserved):</p>
                    <ul className="list-disc list-inside text-sm mt-1 space-y-0.5">
                      <li>Configuration and policy</li>
                      <li>Audit logs (security trail)</li>
                      <li>System logs</li>
                    </ul>
                  </div>
                  <div>
                    <p className="font-medium text-foreground text-sm">What will be deleted permanently:</p>
                    <ul className="list-disc list-inside text-sm mt-1 space-y-0.5">
                      <li>Debug logs</li>
                      <li>Backend credentials</li>
                    </ul>
                  </div>
                  <p className="text-sm">
                    You can restore this proxy later or purge the archived data.
                  </p>
                </>
              )}
              <div className="flex items-center gap-2 pt-1">
                <Switch
                  id="purge-toggle"
                  checked={isPurge}
                  onCheckedChange={setIsPurge}
                  disabled={isDeleting}
                />
                <label htmlFor="purge-toggle" className="text-sm cursor-pointer select-none">
                  Permanently delete all data (skip archive)
                </label>
              </div>
              <p className="text-sm text-muted-foreground">
                Don't forget to also remove <strong>{proxyName}</strong> from your client
                configuration (e.g., Claude Desktop's claude_desktop_config.json).
              </p>
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
          <Button
            variant="destructive"
            onClick={handleConfirm}
            disabled={isDeleting}
          >
            {isDeleting
              ? (isPurge ? 'Purging...' : 'Deleting...')
              : (isPurge ? 'Purge' : 'Delete')}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
