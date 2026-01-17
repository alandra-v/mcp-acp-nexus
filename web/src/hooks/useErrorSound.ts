/**
 * Error notification sound and combined toast+sound utilities.
 * Uses Web Audio API for triple-beep error sound (880Hz sine x 3).
 */

import { toast } from '@/components/ui/sonner'
import { playToneSequence } from '@/utils/audioUtils'

/**
 * Play a triple-beep error sound (A5 x 3).
 */
export async function playErrorSound(): Promise<void> {
  await playToneSequence([
    { frequency: 880, duration: 0.15, delay: 0, volume: 0.28 },
    { frequency: 880, duration: 0.15, delay: 0.2, volume: 0.28 },
    { frequency: 880, duration: 0.15, delay: 0.4, volume: 0.28 },
  ])
}

/**
 * Show error toast and play error sound together.
 * Consolidates the common pattern of toast.error() + playErrorSound().
 */
export function notifyError(message: string): void {
  toast.error(message)
  playErrorSound()
}
