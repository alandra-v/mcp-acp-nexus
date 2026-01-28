import { apiGet, apiPost, type RequestOptions } from './client'

// =============================================================================
// Response Types
// =============================================================================

export interface AuditFileStatus {
  name: string
  description: string
  /** Status: 'protected', 'unprotected', 'broken', 'empty', 'not_created', 'error' */
  status: string
  entry_count: number | null
  last_sequence: number | null
  errors: string[]
}

export interface AuditStatusResponse {
  proxy_name: string
  proxy_id: string
  state_file_present: boolean
  files: AuditFileStatus[]
}

export interface AuditVerifyResult {
  name: string
  description: string
  /** Status: 'passed', 'failed', 'skipped' */
  status: string
  entry_count: number
  errors: string[]
}

export interface AuditVerifyResponse {
  proxy_name: string
  proxy_id: string
  results: AuditVerifyResult[]
  total_passed: number
  total_failed: number
  total_skipped: number
  /** Overall: 'passed', 'failed', 'no_files' */
  overall_status: string
}

export interface AuditRepairResult {
  name: string
  description: string
  /** Action: 'repaired', 'backed_up', 'skipped', 'no_action', 'error' */
  action: string
  message: string
}

export interface AuditRepairResponse {
  proxy_name: string
  proxy_id: string
  results: AuditRepairResult[]
  success: boolean
  message: string
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Get audit log integrity status for a proxy.
 *
 * @param proxyId - Stable proxy identifier
 * @param options - Request options with optional abort signal
 * @returns Status of each audit log file
 */
export async function getAuditStatus(
  proxyId: string,
  options?: RequestOptions
): Promise<AuditStatusResponse> {
  return apiGet<AuditStatusResponse>(
    `/manager/proxies/${encodeURIComponent(proxyId)}/audit/status`,
    options
  )
}

/**
 * Verify audit log hash chain integrity for a proxy.
 *
 * @param proxyId - Stable proxy identifier
 * @param options - Request options with optional abort signal
 * @returns Verification results for each file
 */
export async function verifyAuditLogs(
  proxyId: string,
  options?: RequestOptions
): Promise<AuditVerifyResponse> {
  return apiGet<AuditVerifyResponse>(
    `/manager/proxies/${encodeURIComponent(proxyId)}/audit/verify`,
    options
  )
}

/**
 * Repair audit log integrity state for a proxy.
 *
 * @param proxyId - Stable proxy identifier
 * @param options - Request options with optional abort signal
 * @returns Repair results for each file
 */
export async function repairAuditLogs(
  proxyId: string,
  options?: RequestOptions
): Promise<AuditRepairResponse> {
  return apiPost<AuditRepairResponse>(
    `/manager/proxies/${encodeURIComponent(proxyId)}/audit/repair`,
    undefined,
    options
  )
}
