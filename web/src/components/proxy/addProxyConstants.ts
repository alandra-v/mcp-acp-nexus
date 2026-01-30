import { DEFAULT_HTTP_TIMEOUT_SECONDS } from '@/constants'
import { ApiError, type CreateProxyRequest, type TransportType } from '@/types/api'

// Validation constants (aligned with CLI)
export const PROXY_NAME_MAX_LENGTH = 64
export const PROXY_NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/
export const RESERVED_NAMES = ['manager', 'all', 'default']
export const URL_PATTERN = /^https?:\/\/.+/i
export const SHA256_PATTERN = /^[a-fA-F0-9]{64}$/

export type ModalView = 'form' | 'success'

export const TRANSPORT_OPTIONS: { value: TransportType; label: string; description: string }[] = [
  { value: 'stdio', label: 'STDIO', description: 'Local command (npx, python, etc.)' },
  { value: 'streamablehttp', label: 'HTTP', description: 'Remote HTTP server' },
  { value: 'auto', label: 'Auto', description: 'Prefer HTTP if reachable, fallback to STDIO' },
]

/** Format proxy creation error for display. */
export function formatCreateError(err: unknown): string {
  if (err instanceof ApiError) {
    const proxyName = err.getDetail<string>('proxy_name')
    return proxyName ? `Proxy "${proxyName}": ${err.message}` : err.message
  }
  if (err instanceof Error) return err.message
  return 'Failed to create proxy'
}

/** Return a blank CreateProxyRequest with default values. */
export function getInitialFormState(): CreateProxyRequest {
  return {
    name: '',
    server_name: '',
    transport: 'stdio',
    command: '',
    args: [],
    url: '',
    timeout: DEFAULT_HTTP_TIMEOUT_SECONDS,
    api_key: '',
    mtls_cert: '',
    mtls_key: '',
    mtls_ca: '',
    attestation_slsa_owner: '',
    attestation_sha256: '',
    attestation_require_signature: false,
  }
}
