import { useState, useEffect, useRef, useCallback } from 'react'
import { startLogin } from '@/api/auth'
import { notifyError } from '@/hooks/useErrorSound'
import { useAppStore, type AuthLoginResult } from '@/store/appStore'

interface DeviceFlowState {
  userCode?: string
  verificationUri?: string
  verificationUriComplete?: string
  polling: boolean
  error?: string
}

interface UseDeviceFlowReturn {
  state: DeviceFlowState
  start: () => Promise<void>
  reset: () => void
}

export function useDeviceFlow(onSuccess: () => void): UseDeviceFlowReturn {
  const [state, setState] = useState<DeviceFlowState>({ polling: false })
  const activeRef = useRef(false)
  // Generation counter to detect stale start() completions after reset()
  const generationRef = useRef(0)

  // Subscribe to lastAuthLoginResult from store
  const lastAuthLoginResult = useAppStore((s) => s.lastAuthLoginResult)

  // Track mount-time value to skip stale results
  const mountResultRef = useRef<AuthLoginResult | null>(lastAuthLoginResult)

  // Handle auth login result from SSE via store
  useEffect(() => {
    // Skip if this is the mount-time value or flow is not active
    if (!activeRef.current) return
    if (lastAuthLoginResult === mountResultRef.current) return
    if (!lastAuthLoginResult) return

    activeRef.current = false

    if (lastAuthLoginResult.type === 'auth_login') {
      setState({ polling: false })
      // Success toast handled by SSE event in AppStateContext
      onSuccess()
    } else if (lastAuthLoginResult.type === 'auth_login_failed') {
      const reason = lastAuthLoginResult.reason
      const message = lastAuthLoginResult.message

      let errorMsg: string
      if (reason === 'expired') {
        errorMsg = message || 'Code expired'
      } else if (reason === 'denied') {
        errorMsg = message || 'Authorization denied'
      } else {
        errorMsg = message || 'Login failed'
      }

      setState((prev) => ({ ...prev, polling: false, error: errorMsg }))
      // Toast is already shown by appStore showSystemToast
    }
  }, [lastAuthLoginResult, onSuccess])

  const reset = useCallback(() => {
    activeRef.current = false
    generationRef.current++
    setState({ polling: false })
  }, [])

  const start = useCallback(async () => {
    activeRef.current = false
    generationRef.current++
    const thisGeneration = generationRef.current
    setState({ polling: false })

    try {
      const response = await startLogin()
      // Guard against stale completion: if reset() or another start()
      // was called while startLogin() was awaiting, discard result
      if (generationRef.current !== thisGeneration) return
      activeRef.current = true
      // Update mount ref to current value so we catch new events
      mountResultRef.current = useAppStore.getState().lastAuthLoginResult
      setState({
        userCode: response.user_code,
        verificationUri: response.verification_uri,
        verificationUriComplete: response.verification_uri_complete || undefined,
        polling: true,
      })
      // Backend polls Auth0 in background — SSE event will notify us
    } catch (err) {
      if (generationRef.current !== thisGeneration) return
      setState({ polling: false, error: err instanceof Error ? err.message : 'Failed to start login' })
      notifyError('Failed to start login')
    }
  }, [])

  return { state, start, reset }
}
