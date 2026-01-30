import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'

interface DeleteProxyConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  proxyName: string
  onConfirm: () => void
  isDeleting: boolean
}

export function DeleteProxyConfirmDialog({
  open,
  onOpenChange,
  proxyName,
  onConfirm,
  isDeleting,
}: DeleteProxyConfirmDialogProps) {
  const handleConfirm = () => {
    onConfirm()
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Proxy</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div className="space-y-3">
              <p>
                Are you sure you want to delete <strong>{proxyName}</strong>?
              </p>
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
              <p className="text-sm text-muted-foreground">
                Don't forget to also remove <strong>{proxyName}</strong> from your client
                configuration (e.g., Claude Desktop's claude_desktop_config.json).
              </p>
            </div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={isDeleting}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={handleConfirm}
            disabled={isDeleting}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {isDeleting ? 'Deleting...' : 'Delete'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
