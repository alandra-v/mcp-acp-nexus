import { cn } from '@/lib/utils'

export type DetailSection = 'overview' | 'audit' | 'policy' | 'config'

interface DetailSidebarProps {
  activeSection: DetailSection
  onSectionChange: (section: DetailSection) => void
}

const sections: { id: DetailSection; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'audit', label: 'Audit' },
  { id: 'policy', label: 'Policy' },
  { id: 'config', label: 'Config' },
]

export function DetailSidebar({
  activeSection,
  onSectionChange,
}: DetailSidebarProps) {
  return (
    <aside className="sticky top-[100px] h-fit">
      <nav className="flex flex-col gap-1">
        {sections.map((section) => (
          <button
            key={section.id}
            onClick={() => onSectionChange(section.id)}
            className={cn(
              'relative flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-smooth text-left',
              activeSection === section.id
                ? 'text-foreground bg-base-800'
                : 'text-muted-foreground hover:text-foreground hover:bg-base-900'
            )}
          >
            {activeSection === section.id && (
              <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 bg-base-500 rounded-r" />
            )}
            {section.label}
          </button>
        ))}
      </nav>
    </aside>
  )
}
