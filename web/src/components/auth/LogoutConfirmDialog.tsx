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

export type LogoutType = 'local' | 'federated'

interface LogoutConfirmDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  type: LogoutType
  onConfirm: () => void
}

export function LogoutConfirmDialog({
  open,
  onOpenChange,
  type,
  onConfirm,
}: LogoutConfirmDialogProps) {
  const isLocal = type === 'local'

  const handleConfirm = () => {
    onConfirm()
    onOpenChange(false)
  }

  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {isLocal ? 'Logout' : 'Federated Logout'}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {isLocal ? (
              <>
                This will log you out of the <strong>local session only</strong>. Your identity
                provider session will remain active.
              </>
            ) : (
              <>
                This will log you out of both this application <strong>and your identity
                provider</strong>. This may affect other applications using the same provider.
              </>
            )}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={handleConfirm}>
            {isLocal ? 'Logout' : 'Logout Everywhere'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
