/**
 * Shared audio utilities using Web Audio API.
 * Provides common audio context management for notification and error sounds.
 */

let audioContext: AudioContext | null = null

/**
 * Get or create the shared AudioContext.
 * Resumes the context if it's suspended (browser autoplay policy).
 */
export async function getAudioContext(): Promise<AudioContext> {
  if (!audioContext) {
    audioContext = new AudioContext()
  }
  if (audioContext.state === 'suspended') {
    await audioContext.resume()
  }
  return audioContext
}

/**
 * Close the audio context to release system resources.
 * Call this when the app is unmounting or audio is no longer needed.
 */
export async function closeAudioContext(): Promise<void> {
  if (audioContext) {
    await audioContext.close()
    audioContext = null
  }
}

/**
 * Play a single tone with the given parameters.
 * @param frequency - Frequency in Hz (e.g., 440 for A4)
 * @param duration - Duration in seconds
 * @param delay - Delay before starting in seconds (default 0)
 * @param volume - Volume level 0-1 (default 0.3)
 * @param type - Oscillator type (default 'sine')
 */
export async function playTone(
  frequency: number,
  duration: number,
  delay: number = 0,
  volume: number = 0.3,
  type: OscillatorType = 'sine'
): Promise<void> {
  const ctx = await getAudioContext()
  const now = ctx.currentTime
  const startTime = now + delay

  const osc = ctx.createOscillator()
  const gain = ctx.createGain()

  osc.type = type
  osc.frequency.value = frequency

  gain.gain.setValueAtTime(volume, startTime)
  gain.gain.exponentialRampToValueAtTime(0.001, startTime + duration)

  osc.connect(gain)
  gain.connect(ctx.destination)

  osc.start(startTime)
  osc.stop(startTime + duration)
}

/**
 * Play multiple tones in sequence.
 * @param tones - Array of tone definitions
 */
export async function playToneSequence(
  tones: Array<{
    frequency: number
    duration: number
    delay: number
    volume?: number
    type?: OscillatorType
  }>
): Promise<void> {
  await Promise.all(
    tones.map((tone) =>
      playTone(tone.frequency, tone.duration, tone.delay, tone.volume, tone.type)
    )
  )
}
