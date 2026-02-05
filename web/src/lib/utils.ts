import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Format a validation error location path for display.
 *
 * Strips the leading "body" segment (FastAPI implementation detail)
 * and uses bracket notation for numeric indices.
 *
 * Example: ["body", "rules", 0, "effect"] → "rules[0].effect"
 */
export function formatValidationLoc(loc: (string | number)[]): string {
  const parts = loc[0] === 'body' ? loc.slice(1) : loc
  return parts.reduce<string>((path, part) => {
    if (typeof part === 'number') return `${path}[${part}]`
    return path ? `${path}.${part}` : String(part)
  }, '')
}

/**
 * Format ISO timestamp to readable time (HH:MM:SS).
 */
export function formatTime(ts: string | undefined): string {
  if (!ts) return '--:--:--'
  try {
    const date = new Date(ts)
    return date.toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return '--:--:--'
  }
}

/**
 * Format ISO timestamp to readable date + time.
 */
export function formatDateTime(ts: string | undefined): string {
  if (!ts) return '--'
  try {
    const date = new Date(ts)
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    })
  } catch {
    return '--'
  }
}
