/**
 * Notification sound using Web Audio API.
 * Plays a two-tone chime on pending approval.
 */

import { playToneSequence, closeAudioContext } from '@/utils/audioUtils'

/**
 * Play a two-tone approval chime (C5 -> E5).
 */
export async function playApprovalChime(): Promise<void> {
  await playToneSequence([
    { frequency: 523, duration: 0.2, delay: 0, volume: 0.3 },      // C5
    { frequency: 659, duration: 0.2, delay: 0.12, volume: 0.3 },   // E5
  ])
}

export { closeAudioContext }
