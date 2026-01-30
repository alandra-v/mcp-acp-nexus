import { useState, useEffect, useCallback, useMemo } from 'react'
import { createProxy } from '@/api/proxies'
import { notifyError } from '@/hooks/useErrorSound'
import { toast } from '@/components/ui/sonner'
import { COPY_FEEDBACK_DURATION_MS, DEFAULT_HTTP_TIMEOUT_SECONDS } from '@/constants'
import { ApiError, ErrorCode, type CreateProxyRequest, type CreateProxyResponse, type ErrorCodeType } from '@/types/api'
import {
  type ModalView,
  formatCreateError,
  getInitialFormState,
  PROXY_NAME_MAX_LENGTH,
  PROXY_NAME_PATTERN,
  RESERVED_NAMES,
  URL_PATTERN,
  SHA256_PATTERN,
} from './addProxyConstants'

/** Options for the useAddProxyForm hook. */
export interface UseAddProxyFormOptions {
  open: boolean
  onCreated: () => void
  onOpenChange: (open: boolean) => void
}

/** Result interface for useAddProxyForm hook. */
export interface UseAddProxyFormResult {
  // View
  view: ModalView

  // Form state
  formState: CreateProxyRequest
  touched: Record<string, boolean>
  updateField: <K extends keyof CreateProxyRequest>(field: K, value: CreateProxyRequest[K]) => void
  handleBlur: (field: string) => void
  handleArgsChange: (value: string) => void

  // Transport derived
  isStdio: boolean
  isHttp: boolean
  isHttpOnly: boolean

  // Validation
  fieldErrors: Record<string, string>
  isValid: boolean

  // Submission
  submitting: boolean
  error: string | null
  handleSubmit: () => Promise<void>

  // Advanced toggle
  showAdvanced: boolean
  setShowAdvanced: (show: boolean) => void
  hasAdvancedValues: boolean

  // Success view
  result: CreateProxyResponse | null
  copied: boolean
  handleCopy: () => Promise<void>
  handleDone: () => void

  // Health check confirmation
  showHealthCheckConfirm: boolean
  healthCheckMessage: string
  setShowHealthCheckConfirm: (open: boolean) => void
  handleConfirmSkipHealthCheck: () => Promise<void>

  // Duplicate confirmation
  showDuplicateConfirm: boolean
  duplicateMessage: string
  setShowDuplicateConfirm: (open: boolean) => void
  handleConfirmSkipDuplicate: () => Promise<void>
}

/**
 * Hook managing all form state, validation, and submission logic
 * for the Add Proxy modal. Returns a flat result object consumed
 * by the presentation component.
 */
export function useAddProxyForm(options: UseAddProxyFormOptions): UseAddProxyFormResult {
  const { open, onCreated, onOpenChange } = options

  const [view, setView] = useState<ModalView>('form')
  const [formState, setFormState] = useState<CreateProxyRequest>(getInitialFormState())
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CreateProxyResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [touched, setTouched] = useState<Record<string, boolean>>({})
  const [showHealthCheckConfirm, setShowHealthCheckConfirm] = useState(false)
  const [healthCheckMessage, setHealthCheckMessage] = useState('')
  const [showDuplicateConfirm, setShowDuplicateConfirm] = useState(false)
  const [duplicateMessage, setDuplicateMessage] = useState('')

  const isStdio = formState.transport === 'stdio' || formState.transport === 'auto'
  const isHttp = formState.transport === 'streamablehttp' || formState.transport === 'auto'
  const isHttpOnly = formState.transport === 'streamablehttp'

  // Reset state when dialog opens
  useEffect(() => {
    if (open) {
      setView('form')
      setFormState(getInitialFormState())
      setError(null)
      setResult(null)
      setCopied(false)
      setShowAdvanced(false)
      setTouched({})
      setShowHealthCheckConfirm(false)
      setHealthCheckMessage('')
      setShowDuplicateConfirm(false)
      setDuplicateMessage('')
    }
  }, [open])

  // Update form field
  const updateField = useCallback(<K extends keyof CreateProxyRequest>(
    field: K,
    value: CreateProxyRequest[K]
  ) => {
    setFormState((prev) => ({ ...prev, [field]: value }))
    setError(null)
  }, [])

  // Field-level validation
  const fieldErrors = useMemo(() => {
    const errors: Record<string, string> = {}
    const nameTrimmed = formState.name.trim()

    // Name validation
    if (!nameTrimmed) {
      errors.name = 'Name is required'
    } else if (nameTrimmed.length > PROXY_NAME_MAX_LENGTH) {
      errors.name = `Name too long (max ${PROXY_NAME_MAX_LENGTH} characters)`
    } else if (!PROXY_NAME_PATTERN.test(nameTrimmed)) {
      errors.name = 'Must start with letter or number, then letters, numbers, hyphens, or underscores'
    } else if (RESERVED_NAMES.includes(nameTrimmed.toLowerCase())) {
      errors.name = `"${nameTrimmed}" is reserved. Choose a different name.`
    }

    // Server name validation
    if (!formState.server_name.trim()) {
      errors.server_name = 'Server name is required'
    }

    // Command validation (STDIO/Auto)
    if (isStdio && !formState.command?.trim()) {
      errors.command = 'Command is required for STDIO transport'
    }

    // URL validation (HTTP/Auto)
    const urlTrimmed = formState.url?.trim()
    if (isHttpOnly && !urlTrimmed) {
      errors.url = 'URL is required for HTTP transport'
    } else if (urlTrimmed && !URL_PATTERN.test(urlTrimmed)) {
      errors.url = 'URL must start with http:// or https://'
    }

    // SHA-256 validation (if provided)
    const sha256Trimmed = formState.attestation_sha256?.trim()
    if (sha256Trimmed && !SHA256_PATTERN.test(sha256Trimmed)) {
      errors.attestation_sha256 = 'Must be exactly 64 hexadecimal characters'
    }

    // mTLS validation: all or none
    const hasMtls = formState.mtls_cert || formState.mtls_key || formState.mtls_ca
    const hasAllMtls = formState.mtls_cert && formState.mtls_key && formState.mtls_ca
    if (hasMtls && !hasAllMtls) {
      errors.mtls = 'mTLS requires all three: cert, key, and CA'
    }

    return errors
  }, [formState, isStdio, isHttpOnly])

  // Overall validation
  const isValid = useMemo(() => Object.keys(fieldErrors).length === 0, [fieldErrors])

  // Handle field blur for validation
  const handleBlur = useCallback((field: string) => {
    setTouched((prev) => ({ ...prev, [field]: true }))
  }, [])

  // Build CreateProxyRequest from current form state
  const buildRequest = useCallback((overrides?: Partial<CreateProxyRequest>): CreateProxyRequest => {
    const request: CreateProxyRequest = {
      name: formState.name.trim(),
      server_name: formState.server_name.trim(),
      transport: formState.transport,
      ...overrides,
    }

    // STDIO fields
    if (isStdio && formState.command) {
      request.command = formState.command.trim()
      if (formState.args && formState.args.length > 0) {
        request.args = formState.args
      }
    }

    // Attestation fields
    if (isStdio) {
      if (formState.attestation_slsa_owner?.trim()) {
        request.attestation_slsa_owner = formState.attestation_slsa_owner.trim()
      }
      if (formState.attestation_sha256?.trim()) {
        request.attestation_sha256 = formState.attestation_sha256.trim()
      }
      if (formState.attestation_require_signature) {
        request.attestation_require_signature = true
      }
    }

    // HTTP fields
    if (isHttp && formState.url) {
      request.url = formState.url.trim()
      if (formState.timeout && formState.timeout !== DEFAULT_HTTP_TIMEOUT_SECONDS) {
        request.timeout = formState.timeout
      }
      if (formState.api_key?.trim()) {
        request.api_key = formState.api_key.trim()
      }
    }

    // mTLS fields
    if (formState.mtls_cert && formState.mtls_key && formState.mtls_ca) {
      request.mtls_cert = formState.mtls_cert.trim()
      request.mtls_key = formState.mtls_key.trim()
      request.mtls_ca = formState.mtls_ca.trim()
    }

    return request
  }, [formState, isStdio, isHttp])

  // Consolidated submit helper
  const submitWithOverrides = useCallback(async (
    overrides?: Partial<CreateProxyRequest>,
    interceptErrors?: Partial<Record<ErrorCodeType, (err: ApiError) => void>>
  ): Promise<void> => {
    setSubmitting(true)
    setError(null)
    try {
      const response = await createProxy(buildRequest(overrides))
      setResult(response)
      toast.success(`Proxy "${response.proxy_name}" created`)
      onCreated()
      setView('success')
    } catch (err) {
      if (err instanceof ApiError && interceptErrors) {
        for (const [code, handler] of Object.entries(interceptErrors)) {
          if (err.hasCode(code as ErrorCodeType)) {
            handler(err)
            return
          }
        }
      }
      setError(formatCreateError(err))
    } finally {
      setSubmitting(false)
    }
  }, [buildRequest, onCreated])

  // Handle submit
  const handleSubmit = useCallback(async () => {
    if (!isValid) return

    await submitWithOverrides(undefined, {
      [ErrorCode.BACKEND_UNREACHABLE]: (err) => {
        setHealthCheckMessage(err.message)
        setShowHealthCheckConfirm(true)
      },
      [ErrorCode.BACKEND_DUPLICATE]: (err) => {
        setDuplicateMessage(err.message)
        setShowDuplicateConfirm(true)
      },
    })
  }, [isValid, submitWithOverrides])

  // Resubmit with skip_health_check after user confirms
  const handleConfirmSkipHealthCheck = useCallback(async () => {
    setShowHealthCheckConfirm(false)
    await submitWithOverrides({ skip_health_check: true }, {
      [ErrorCode.BACKEND_DUPLICATE]: (err) => {
        setDuplicateMessage(err.message)
        setShowDuplicateConfirm(true)
      },
    })
  }, [submitWithOverrides])

  // Resubmit with skip_duplicate_check after user confirms
  const handleConfirmSkipDuplicate = useCallback(async () => {
    setShowDuplicateConfirm(false)
    await submitWithOverrides({
      skip_duplicate_check: true,
      skip_health_check: true,
    })
  }, [submitWithOverrides])

  // Handle copy snippet
  const handleCopy = useCallback(async () => {
    if (!result?.claude_desktop_snippet) return

    try {
      const snippet = { mcpServers: result.claude_desktop_snippet }
      await navigator.clipboard.writeText(JSON.stringify(snippet, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), COPY_FEEDBACK_DURATION_MS)
    } catch {
      notifyError('Failed to copy to clipboard')
    }
  }, [result])

  // Handle done
  const handleDone = useCallback(() => {
    onOpenChange(false)
    onCreated()
  }, [onOpenChange, onCreated])

  // Parse args input
  const handleArgsChange = useCallback((value: string) => {
    // Split by spaces, respecting quoted strings
    const args = value.trim() ? value.split(/\s+/) : []
    updateField('args', args)
  }, [updateField])

  // Check if advanced section has values
  const hasAdvancedValues = !!(
    formState.api_key ||
    formState.mtls_cert || formState.mtls_key || formState.mtls_ca ||
    (formState.timeout && formState.timeout !== DEFAULT_HTTP_TIMEOUT_SECONDS) ||
    formState.attestation_slsa_owner ||
    formState.attestation_sha256 ||
    formState.attestation_require_signature
  )

  return {
    view,
    formState,
    touched,
    updateField,
    handleBlur,
    handleArgsChange,
    isStdio,
    isHttp,
    isHttpOnly,
    fieldErrors,
    isValid,
    submitting,
    error,
    handleSubmit,
    showAdvanced,
    setShowAdvanced,
    hasAdvancedValues,
    result,
    copied,
    handleCopy,
    handleDone,
    showHealthCheckConfirm,
    healthCheckMessage,
    setShowHealthCheckConfirm,
    handleConfirmSkipHealthCheck,
    showDuplicateConfirm,
    duplicateMessage,
    setShowDuplicateConfirm,
    handleConfirmSkipDuplicate,
  }
}
