import { useState, useEffect, useRef, useCallback } from 'react'
import { startLogin } from '@/api/auth'
import { notifyError } from '@/hooks/useErrorSound'

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

  const reset = useCallback(() => {
    activeRef.current = false
    generationRef.current++
    setState({ polling: false })
  }, [])

  // Listen for SSE auth-login-result events while flow is active
  useEffect(() => {
    const handler = (e: Event) => {
      if (!activeRef.current) return
      const detail = (e as CustomEvent).detail
      if (!detail) return

      activeRef.current = false

      if (detail.type === 'auth_login') {
        setState({ polling: false })
        // Success toast handled by SSE event in AppStateContext
        onSuccess()
      } else if (detail.type === 'auth_login_failed') {
        const reason = detail.reason as string | undefined
        const message = detail.message as string | undefined

        let errorMsg: string
        if (reason === 'expired') {
          errorMsg = message || 'Code expired'
        } else if (reason === 'denied') {
          errorMsg = message || 'Authorization denied'
        } else {
          errorMsg = message || 'Login failed'
        }

        setState((prev) => ({ ...prev, polling: false, error: errorMsg }))
        // Toast is already shown by AppStateContext showSystemToast
      }
    }

    window.addEventListener('auth-login-result', handler)
    return () => {
      window.removeEventListener('auth-login-result', handler)
    }
  }, [onSuccess])

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
