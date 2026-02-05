/**
 * Pure data transforms between ConfigResponse and the flat form state
 * used by ConfigSection for editing.
 */
import type { ConfigResponse, ConfigUpdateRequest, TransportType, OIDCConfigUpdate, MTLSConfigUpdate, StdioAttestationUpdate } from '@/api/config'

/** Common OAuth scopes shown as checkboxes. */
export const COMMON_SCOPES = [
  { value: 'openid', label: 'OpenID', description: 'Required for OIDC' },
  { value: 'profile', label: 'Profile', description: 'User profile info' },
  { value: 'email', label: 'Email', description: 'Email address' },
  { value: 'offline_access', label: 'Offline Access', description: 'Refresh tokens' },
] as const

/** Flat form state that mirrors ConfigResponse for editing. */
export interface FormState {
  // Proxy
  proxy_name: string
  // Backend
  backend_server_name: string
  backend_transport: TransportType
  // STDIO
  stdio_command: string
  stdio_args: string // comma-separated
  // STDIO Attestation
  attestation_slsa_owner: string
  attestation_sha256: string
  attestation_require_signature: boolean
  // HTTP
  http_url: string
  http_timeout: string
  // Logging
  log_dir: string
  log_level: string
  include_payloads: boolean
  // Auth - OIDC
  oidc_issuer: string
  oidc_client_id: string
  oidc_audience: string
  oidc_scopes: string[] // array of scope values
  // Auth - mTLS
  mtls_client_cert_path: string
  mtls_client_key_path: string
  mtls_ca_bundle_path: string
  // HITL
  hitl_timeout_seconds: string
  hitl_approval_ttl_seconds: string
}

/**
 * Convert ConfigResponse to form state for editing.
 * Transforms nested config structure to flat form fields.
 */
export function configToFormState(config: ConfigResponse): FormState {
  return {
    proxy_name: config.proxy.name,
    backend_server_name: config.backend.server_name,
    backend_transport: config.backend.transport ?? 'auto',
    stdio_command: config.backend.stdio?.command || '',
    stdio_args: config.backend.stdio?.args.join(', ') || '',
    attestation_slsa_owner: config.backend.stdio?.attestation?.slsa_owner || '',
    attestation_sha256: config.backend.stdio?.attestation?.expected_sha256 || '',
    attestation_require_signature: config.backend.stdio?.attestation?.require_code_signature || false,
    http_url: config.backend.http?.url || '',
    http_timeout: config.backend.http?.timeout.toString() || '30',
    log_dir: config.logging.log_dir,
    log_level: config.logging.log_level,
    include_payloads: config.logging.include_payloads,
    oidc_issuer: config.auth?.oidc?.issuer || '',
    oidc_client_id: config.auth?.oidc?.client_id || '',
    oidc_audience: config.auth?.oidc?.audience || '',
    oidc_scopes: config.auth?.oidc?.scopes || [],
    mtls_client_cert_path: config.auth?.mtls?.client_cert_path || '',
    mtls_client_key_path: config.auth?.mtls?.client_key_path || '',
    mtls_ca_bundle_path: config.auth?.mtls?.ca_bundle_path || '',
    hitl_timeout_seconds: config.hitl.timeout_seconds.toString(),
    hitl_approval_ttl_seconds: config.hitl.approval_ttl_seconds.toString(),
  }
}

/**
 * Shallow equality check for two FormState objects.
 * Compares primitives directly and the oidc_scopes array by value.
 */
export function formStatesEqual(a: FormState, b: FormState): boolean {
  const keys = Object.keys(a) as (keyof FormState)[]
  return keys.every((k) => {
    const va = a[k]
    const vb = b[k]
    if (Array.isArray(va) && Array.isArray(vb)) {
      return va.length === vb.length && va.every((v, i) => v === vb[i])
    }
    return va === vb
  })
}

/**
 * Build update request from form state changes.
 * Only includes fields that differ from the original config.
 */
export function formStateToUpdateRequest(
  form: FormState,
  original: ConfigResponse
): ConfigUpdateRequest {
  const updates: ConfigUpdateRequest = {}

  // Proxy name is immutable (used as directory key, log paths, keychain entries)

  // Backend
  const backendUpdates: ConfigUpdateRequest['backend'] = {}
  if (form.backend_server_name !== original.backend.server_name) {
    backendUpdates.server_name = form.backend_server_name
  }
  if (form.backend_transport !== original.backend.transport) {
    backendUpdates.transport = form.backend_transport
  }

  // STDIO (command, args, attestation)
  const originalStdioCommand = original.backend.stdio?.command || ''
  const originalStdioArgs = original.backend.stdio?.args.join(', ') || ''
  const originalSlsaOwner = original.backend.stdio?.attestation?.slsa_owner || ''
  const originalSha256 = original.backend.stdio?.attestation?.expected_sha256 || ''
  const originalRequireSig = original.backend.stdio?.attestation?.require_code_signature || false

  const stdioChanged = form.stdio_command !== originalStdioCommand ||
    form.stdio_args !== originalStdioArgs ||
    form.attestation_slsa_owner !== originalSlsaOwner ||
    form.attestation_sha256 !== originalSha256 ||
    form.attestation_require_signature !== originalRequireSig

  if (stdioChanged) {
    const args = form.stdio_args
      .split(',')
      .map((a) => a.trim())
      .filter(Boolean)

    // Build attestation update: send null to clear, object to set
    const hasAttestation = form.attestation_slsa_owner || form.attestation_sha256 || form.attestation_require_signature
    const hadAttestation = original.backend.stdio?.attestation != null
    let attestationUpdate: StdioAttestationUpdate | null | undefined
    if (hasAttestation) {
      attestationUpdate = {
        slsa_owner: form.attestation_slsa_owner || null,
        expected_sha256: form.attestation_sha256 || null,
        require_code_signature: form.attestation_require_signature,
      }
    } else if (hadAttestation) {
      // All attestation fields cleared — send null to remove the object
      attestationUpdate = null
    }

    backendUpdates.stdio = {
      command: form.stdio_command || undefined,
      args,
      attestation: attestationUpdate,
    }
  }

  // HTTP
  const originalHttpUrl = original.backend.http?.url || ''
  const originalHttpTimeout = original.backend.http?.timeout.toString() || '30'
  if (form.http_url !== originalHttpUrl || form.http_timeout !== originalHttpTimeout) {
    backendUpdates.http = {
      url: form.http_url || undefined,
      timeout: form.http_timeout ? parseInt(form.http_timeout, 10) : undefined,
    }
  }

  if (Object.keys(backendUpdates).length > 0) {
    updates.backend = backendUpdates
  }

  // Logging (log_dir is derived from proxy name, not editable)
  const loggingUpdates: ConfigUpdateRequest['logging'] = {}
  if (form.log_level !== original.logging.log_level) {
    loggingUpdates.log_level = form.log_level
  }
  if (form.include_payloads !== original.logging.include_payloads) {
    loggingUpdates.include_payloads = form.include_payloads
  }
  if (Object.keys(loggingUpdates).length > 0) {
    updates.logging = loggingUpdates
  }

  // Auth - OIDC
  if (original.auth?.oidc) {
    const oidc: OIDCConfigUpdate = {}
    const originalScopes = original.auth.oidc.scopes
    if (form.oidc_issuer !== original.auth.oidc.issuer) {
      oidc.issuer = form.oidc_issuer
    }
    if (form.oidc_client_id !== original.auth.oidc.client_id) {
      oidc.client_id = form.oidc_client_id
    }
    if (form.oidc_audience !== original.auth.oidc.audience) {
      oidc.audience = form.oidc_audience
    }
    // Compare scopes arrays
    const scopesChanged =
      form.oidc_scopes.length !== originalScopes.length ||
      form.oidc_scopes.some((s) => !originalScopes.includes(s))
    if (scopesChanged) {
      oidc.scopes = form.oidc_scopes
    }
    if (Object.keys(oidc).length > 0) {
      updates.auth = { ...updates.auth, oidc }
    }
  }

  // Auth - mTLS (handle both updates and new configuration)
  const formHasMtls = form.mtls_client_cert_path || form.mtls_client_key_path || form.mtls_ca_bundle_path
  const hadMtls = original.auth?.mtls != null
  if (hadMtls && !formHasMtls) {
    // All mTLS fields cleared — send null to remove the entire mTLS config
    updates.auth = { ...updates.auth, mtls: null }
  } else if (formHasMtls) {
    const originalCert = original.auth?.mtls?.client_cert_path || ''
    const originalKey = original.auth?.mtls?.client_key_path || ''
    const originalCa = original.auth?.mtls?.ca_bundle_path || ''

    const mtls: MTLSConfigUpdate = {}
    if (form.mtls_client_cert_path !== originalCert) {
      mtls.client_cert_path = form.mtls_client_cert_path
    }
    if (form.mtls_client_key_path !== originalKey) {
      mtls.client_key_path = form.mtls_client_key_path
    }
    if (form.mtls_ca_bundle_path !== originalCa) {
      mtls.ca_bundle_path = form.mtls_ca_bundle_path
    }
    if (Object.keys(mtls).length > 0) {
      updates.auth = { ...updates.auth, mtls }
    }
  }

  // HITL
  const hitlUpdates: ConfigUpdateRequest['hitl'] = {}
  const originalTimeout = original.hitl.timeout_seconds.toString()
  const originalTtl = original.hitl.approval_ttl_seconds.toString()
  if (form.hitl_timeout_seconds !== originalTimeout) {
    hitlUpdates.timeout_seconds = parseInt(form.hitl_timeout_seconds, 10)
  }
  if (form.hitl_approval_ttl_seconds !== originalTtl) {
    hitlUpdates.approval_ttl_seconds = parseInt(form.hitl_approval_ttl_seconds, 10)
  }
  if (Object.keys(hitlUpdates).length > 0) {
    updates.hitl = hitlUpdates
  }

  return updates
}
