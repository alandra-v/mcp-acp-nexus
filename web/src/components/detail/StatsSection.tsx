import { useAppState } from '@/context/AppStateContext'
import { Section } from './Section'

interface StatsSectionProps {
  loaded?: boolean
}

export function StatsSection({ loaded = true }: StatsSectionProps) {
  const { stats } = useAppState()

  return (
    <Section index={0} title="Session Statistics" loaded={loaded}>
      <div className="grid grid-cols-4 gap-4">
        <StatBox label="Total Requests" value={stats?.requests_total.toString() ?? '0'} />
        <StatBox label="Allowed" value={stats?.requests_allowed.toString() ?? '0'} />
        <StatBox label="Denied" value={stats?.requests_denied.toString() ?? '0'} />
        <StatBox label="HITL" value={stats?.requests_hitl.toString() ?? '0'} />
      </div>
    </Section>
  )
}

interface StatBoxProps {
  label: string
  value: string
}

function StatBox({ label, value }: StatBoxProps) {
  return (
    <div className="p-5 card-gradient border border-[var(--border-subtle)] rounded-lg">
      <div className="font-display text-3xl font-semibold mb-1">{value}</div>
      <div className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
    </div>
  )
}
