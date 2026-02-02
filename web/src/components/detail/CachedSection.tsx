import { Trash2 } from 'lucide-react'
import { Section } from './Section'
import { Button } from '@/components/ui/button'
import { DataState } from '@/components/ui/DataState'
import { useCountdown, formatCountdown } from '@/hooks/useCountdown'
import type { CachedApproval } from '@/types/api'

interface CachedSectionProps {
  cached: CachedApproval[]
  loading?: boolean
  onClear: () => void
  onDelete: (subjectId: string, toolName: string, path: string | null) => void
  loaded?: boolean
}

export function CachedSection({
  cached,
  loading = false,
  onClear,
  onDelete,
  loaded = true,
}: CachedSectionProps) {
  return (
    <Section index={0} title="Cached Decisions" loaded={loaded}>
      <div className="space-y-3">
        <DataState
          loading={loading}
          hasData={cached.length > 0}
          emptyMessage="No cached decisions"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-base-500">
              {cached.length} cached decision{cached.length !== 1 ? 's' : ''}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={onClear}
              className="text-xs text-base-500 hover:text-base-300 h-7 px-2"
            >
              <Trash2 className="w-3 h-3 mr-1" />
              Clear all
            </Button>
          </div>
          {cached.map((item) => (
            <CachedItem key={item.request_id} item={item} onDelete={onDelete} />
          ))}
        </DataState>
      </div>
    </Section>
  )
}

interface CachedItemProps {
  item: CachedApproval
  onDelete: (subjectId: string, toolName: string, path: string | null) => void
}

function CachedItem({ item, onDelete }: CachedItemProps) {
  // Live countdown - expires_in_seconds is relative to when data was fetched
  const remaining = useCountdown(undefined, item.expires_in_seconds)
  const isExpiring = remaining < 30

  return (
    <div className="p-3 card-gradient-dark border border-[var(--border-subtle)] rounded-lg group">
      <div className="flex items-center gap-4">
        <span className="font-mono text-sm text-base-300 bg-base-800 px-2 py-1 rounded">
          {item.tool_name}
        </span>
        <span className="flex-1 font-mono text-xs text-base-500 break-words">
          {item.path || '--'}
        </span>
        <span className={`text-xs tabular-nums ${isExpiring ? 'text-warning' : 'text-base-600'}`}>
          {remaining > 0 ? `expires in ${formatCountdown(remaining)}` : 'expired'}
        </span>
        <button
          onClick={() => onDelete(item.subject_id, item.tool_name, item.path)}
          className="opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity p-1 hover:bg-base-700 rounded text-base-500 hover:text-base-300"
          aria-label="Delete cached approval"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
      <div className="text-xs text-base-500 mt-1.5">
        {item.subject_id}
      </div>
    </div>
  )
}
