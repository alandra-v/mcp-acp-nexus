/**
 * Dialog components for managing backend API keys (set/update and delete).
 */
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

interface SetApiKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  isUpdate: boolean
  apiKeyInput: string
  onApiKeyInputChange: (value: string) => void
  onSave: () => void | Promise<void>
  saving: boolean
}

export function SetApiKeyDialog({
  open,
  onOpenChange,
  isUpdate,
  apiKeyInput,
  onApiKeyInputChange,
  onSave,
  saving,
}: SetApiKeyDialogProps) {
  return (
    <Dialog open={open} onOpenChange={(o) => {
      onOpenChange(o)
      if (!o) onApiKeyInputChange('')
    }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {isUpdate ? 'Update API Key' : 'Set API Key'}
          </DialogTitle>
          <DialogDescription>
            The API key will be stored securely in your OS keychain, not in config files.
          </DialogDescription>
        </DialogHeader>

        <div className="py-4">
          <Input
            type="password"
            placeholder="Enter API key or bearer token"
            value={apiKeyInput}
            onChange={(e) => onApiKeyInputChange(e.target.value)}
            autoFocus
          />
          <p className="text-xs text-muted-foreground mt-2">
            This key is used for backend authentication when using HTTP transport.
          </p>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={onSave}
            disabled={!apiKeyInput.trim() || saving}
          >
            {saving ? 'Saving...' : 'Save'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

interface DeleteApiKeyDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onDelete: () => void | Promise<void>
  saving: boolean
}

export function DeleteApiKeyDialog({
  open,
  onOpenChange,
  onDelete,
  saving,
}: DeleteApiKeyDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Remove API Key</DialogTitle>
          <DialogDescription>
            This will delete the API key from your OS keychain. The proxy will no longer authenticate with the backend server. You can set a new API key at any time.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={onDelete}
            disabled={saving}
          >
            {saving ? 'Removing...' : 'Remove'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
