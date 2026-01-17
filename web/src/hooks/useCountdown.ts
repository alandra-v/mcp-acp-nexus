import { useState, useEffect, useRef } from 'react'

/**
 * Hook for live countdown timer.
 *
 * @param expiresAt - ISO timestamp when the item expires
 * @param timeoutSeconds - Total timeout duration (used with createdAt)
 * @param createdAt - ISO timestamp when the item was created
 * @returns Seconds remaining (0 if expired)
 */
export function useCountdown(
  expiresAt?: string,
  timeoutSeconds?: number,
  createdAt?: string
): number {
  const [secondsRemaining, setSecondsRemaining] = useState(() =>
    calculateRemaining(expiresAt, timeoutSeconds, createdAt)
  )

  // Store the initial calculation timestamp to avoid drift
  const startTimeRef = useRef(Date.now())
  const initialRemainingRef = useRef(secondsRemaining)

  useEffect(() => {
    // Reset refs when inputs change
    const newRemaining = calculateRemaining(expiresAt, timeoutSeconds, createdAt)
    startTimeRef.current = Date.now()
    initialRemainingRef.current = newRemaining
    setSecondsRemaining(newRemaining)

    if (newRemaining <= 0) return

    const interval = setInterval(() => {
      const elapsed = (Date.now() - startTimeRef.current) / 1000
      const remaining = Math.max(0, initialRemainingRef.current - elapsed)
      setSecondsRemaining(remaining)

      if (remaining <= 0) {
        clearInterval(interval)
      }
    }, 1000)

    return () => clearInterval(interval)
  }, [expiresAt, timeoutSeconds, createdAt])

  return secondsRemaining
}

/**
 * Calculate seconds remaining until expiration.
 * Supports multiple input patterns for flexibility.
 *
 * @param expiresAt - ISO timestamp when item expires (highest priority)
 * @param timeoutSeconds - Timeout duration in seconds
 * @param createdAt - ISO timestamp when item was created (used with timeoutSeconds)
 * @returns Seconds remaining (0 if expired or invalid input)
 */
function calculateRemaining(
  expiresAt?: string,
  timeoutSeconds?: number,
  createdAt?: string
): number {
  // If we have an explicit expiration timestamp
  if (expiresAt) {
    const expiresMs = new Date(expiresAt).getTime()
    return Math.max(0, (expiresMs - Date.now()) / 1000)
  }

  // If we have timeout + createdAt, calculate expiration
  if (timeoutSeconds !== undefined && createdAt) {
    const createdMs = new Date(createdAt).getTime()
    const expiresMs = createdMs + timeoutSeconds * 1000
    return Math.max(0, (expiresMs - Date.now()) / 1000)
  }

  // If we only have timeout (for expires_in_seconds style), treat as relative
  if (timeoutSeconds !== undefined) {
    return Math.max(0, timeoutSeconds)
  }

  return 0
}

/**
 * Format seconds as "Xm Ys" or "Xs" if under a minute.
 */
export function formatCountdown(seconds: number): string {
  if (seconds <= 0) return 'expired'

  const mins = Math.floor(seconds / 60)
  const secs = Math.round(seconds % 60)

  if (mins > 0) {
    return `${mins}m ${secs}s`
  }
  return `${secs}s`
}
