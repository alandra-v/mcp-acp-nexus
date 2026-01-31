import { useAppState } from '@/context/AppStateContext'
import { Section } from './Section'

interface StatsSectionProps {
  proxyId?: string
  loaded?: boolean
}

export function StatsSection({ proxyId, loaded = true }: StatsSectionProps) {
  const { stats } = useAppState()
  const proxyStats = proxyId ? stats[proxyId] : undefined

  return (
    <Section index={0} title="Session Statistics" loaded={loaded}>
      <div className="grid grid-cols-4 gap-4">
        <StatBox label="Total Requests" value={proxyStats?.requests_total.toString() ?? '0'} />
        <StatBox label="Allowed" value={proxyStats?.requests_allowed.toString() ?? '0'} />
        <StatBox label="Denied" value={proxyStats?.requests_denied.toString() ?? '0'} />
        <StatBox label="HITL" value={proxyStats?.requests_hitl.toString() ?? '0'} />
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
