/**
 * Displays pending config changes (saved but not yet active until proxy restart).
 */
import { cn } from '@/lib/utils'
import type { ConfigChange } from '@/api/config'

/** Format a config value for display in the changes table. */
function formatValue(value: string | number | boolean | string[] | null | undefined): string {
  if (value === null || value === undefined) return '(not set)'
  if (Array.isArray(value)) return value.join(', ') || '(empty)'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string' && value === '') return '(empty)'
  return String(value)
}

interface PendingChangesSectionProps {
  changes: ConfigChange[]
}

export function PendingChangesSection({ changes }: PendingChangesSectionProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
        <h3 className="text-sm font-semibold text-amber-400">
          Pending Changes ({changes.length})
        </h3>
      </div>
      <p className="text-xs text-muted-foreground">
        These changes are saved to the config file but not yet active. Restart the proxy to apply.
      </p>
      <div className="bg-base-900/50 rounded-md border border-base-800 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-base-800 bg-base-900/50">
              <th className="text-left px-3 py-2 font-medium text-muted-foreground">Field</th>
              <th className="text-left px-3 py-2 font-medium text-muted-foreground">Running</th>
              <th className="text-left px-3 py-2 font-medium text-muted-foreground">Saved</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((change, idx) => (
              <tr
                key={change.field}
                className={cn(
                  'border-b border-base-800/50 last:border-0',
                  idx % 2 === 0 ? 'bg-transparent' : 'bg-base-900/30'
                )}
              >
                <td className="px-3 py-2 font-mono text-base-300">{change.field}</td>
                <td className="px-3 py-2 text-red-400/80">
                  <span className="line-through opacity-60">{formatValue(change.running_value)}</span>
                </td>
                <td className="px-3 py-2 text-green-400/80">
                  {formatValue(change.saved_value)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
