import { X } from 'lucide-react'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { ScrollArea } from '@/components/ui/scroll-area'
import { ApprovalItem } from '@/components/approvals/ApprovalItem'
import type { PendingApproval } from '@/types/api'

interface PendingDrawerProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  approvals: PendingApproval[]
  onApprove: (id: string) => void
  onApproveOnce: (id: string) => void
  onDeny: (id: string) => void
}

export function PendingDrawer({
  open,
  onOpenChange,
  approvals,
  onApprove,
  onApproveOnce,
  onDeny,
}: PendingDrawerProps) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[480px] bg-base-950 border-l border-border p-0" hideCloseButton>
        <SheetHeader className="px-6 py-6 border-b border-[var(--border-subtle)]">
          <div className="flex items-center justify-between">
            <SheetTitle className="font-display text-lg font-semibold">
              Pending Approvals
            </SheetTitle>
            <button
              onClick={() => onOpenChange(false)}
              className="w-8 h-8 flex items-center justify-center bg-transparent border border-[var(--border-subtle)] rounded-full text-muted-foreground hover:bg-base-800 hover:text-foreground transition-smooth"
              aria-label="Close pending approvals"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </SheetHeader>

        <ScrollArea className="flex-1 h-[calc(100vh-80px)]">
          <div className="p-6 space-y-3">
            {approvals.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground text-sm">
                No pending approvals
              </div>
            ) : (
              approvals.map((approval) => (
                <ApprovalItem
                  key={approval.id}
                  approval={approval}
                  onApprove={() => onApprove(approval.id)}
                  onApproveOnce={() => onApproveOnce(approval.id)}
                  onDeny={() => onDeny(approval.id)}
                  showProxyId
                />
              ))
            )}
          </div>
        </ScrollArea>
      </SheetContent>
    </Sheet>
  )
}
