import { useNavigate } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'

interface BackButtonProps {
  /** Path to navigate to (defaults to '/') */
  to?: string
  /** Custom click handler (overrides `to`) */
  onClick?: () => void
  /** Accessible label for screen readers */
  'aria-label'?: string
}

/**
 * Reusable back navigation button with consistent styling.
 */
export function BackButton({
  to = '/',
  onClick,
  'aria-label': ariaLabel = 'Go back',
}: BackButtonProps) {
  const navigate = useNavigate()

  const handleClick = onClick ?? (() => navigate(to))

  return (
    <button
      onClick={handleClick}
      className="inline-flex items-center gap-2 px-4 py-2 bg-transparent border border-[var(--border-subtle)] rounded-lg text-muted-foreground text-sm hover:bg-base-900 hover:text-foreground transition-smooth"
      aria-label={ariaLabel}
    >
      <ArrowLeft className="w-4 h-4" />
      Back
    </button>
  )
}
