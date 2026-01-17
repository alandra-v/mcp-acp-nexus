import { Section } from './Section'
import { ApprovalItem } from '@/components/approvals/ApprovalItem'
import { DataState } from '@/components/ui/DataState'
import type { PendingApproval } from '@/types/api'

interface ApprovalsSectionProps {
  approvals: PendingApproval[]
  onApprove: (id: string) => void
  onApproveOnce: (id: string) => void
  onDeny: (id: string) => void
  loaded?: boolean
}

export function ApprovalsSection({
  approvals,
  onApprove,
  onApproveOnce,
  onDeny,
  loaded = true,
}: ApprovalsSectionProps) {
  return (
    <Section index={0} title="Pending Approvals" loaded={loaded}>
      <div className="space-y-3">
        <DataState hasData={approvals.length > 0} emptyMessage="No pending approvals">
          {approvals.map((approval) => (
            <ApprovalItem
              key={approval.id}
              approval={approval}
              onApprove={() => onApprove(approval.id)}
              onApproveOnce={() => onApproveOnce(approval.id)}
              onDeny={() => onDeny(approval.id)}
              compact
            />
          ))}
        </DataState>
      </div>
    </Section>
  )
}
