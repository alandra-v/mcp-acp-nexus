import { useState, useEffect, useRef, useCallback } from 'react'
import { startLogin, pollLogin } from '@/api/auth'
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
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const clearPolling = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current)
      pollIntervalRef.current = null
    }
  }, [])

  const reset = useCallback(() => {
    clearPolling()
    setState({ polling: false })
  }, [clearPolling])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      clearPolling()
    }
  }, [clearPolling])

  const start = useCallback(async () => {
    clearPolling()
    setState({ polling: false })

    try {
      const response = await startLogin()
      setState({
        userCode: response.user_code,
        verificationUri: response.verification_uri,
        verificationUriComplete: response.verification_uri_complete || undefined,
        polling: true,
      })

      // Start polling
      pollIntervalRef.current = setInterval(async () => {
        try {
          const pollResponse = await pollLogin(response.user_code)

          if (pollResponse.status === 'complete') {
            clearPolling()
            setState({ polling: false })
            // Success toast handled by SSE auth_login event
            onSuccess()
          } else if (pollResponse.status === 'expired') {
            clearPolling()
            setState((prev) => ({
              ...prev,
              polling: false,
              error: pollResponse.message || 'Code expired',
            }))
            notifyError('Code expired, please try again')
          } else if (pollResponse.status === 'denied') {
            clearPolling()
            setState((prev) => ({
              ...prev,
              polling: false,
              error: pollResponse.message || 'Authorization denied',
            }))
            notifyError('Authorization denied')
          } else if (pollResponse.status === 'error') {
            clearPolling()
            setState((prev) => ({
              ...prev,
              polling: false,
              error: pollResponse.message || 'Login failed',
            }))
            notifyError('Login failed')
          }
        } catch {
          clearPolling()
          setState((prev) => ({ ...prev, polling: false, error: 'Polling failed' }))
          notifyError('Login failed')
        }
      }, response.interval * 1000)
    } catch (err) {
      setState({ polling: false, error: err instanceof Error ? err.message : 'Failed to start login' })
      notifyError('Failed to start login')
    }
  }, [clearPolling, onSuccess])

  return { state, start, reset }
}
