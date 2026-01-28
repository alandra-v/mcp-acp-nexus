import { apiGet, apiPost, type RequestOptions } from './client'
import type { BackupFileInfo } from '@/types/api'

// Re-export for convenience
export type { BackupFileInfo }

// =============================================================================
// Response Types
// =============================================================================

export interface AuditFileResult {
  name: string
  description: string
  /** Status: 'protected', 'unprotected', 'broken', 'empty', 'not_created', 'error' */
  status: string
  entry_count: number | null
  last_sequence: number | null
  errors: string[]
  backups: BackupFileInfo[]
}

export interface AuditVerifyResponse {
  proxy_name: string
  proxy_id: string
  state_file_present: boolean
  files: AuditFileResult[]
  total_protected: number
  total_broken: number
  total_unprotected: number
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
 * Verify audit log integrity and get status for a proxy.
 *
 * This is the single endpoint for audit integrity - it verifies all files
 * and returns comprehensive status including state file presence, per-file
 * status, entry counts, and verification errors.
 *
 * @param proxyId - Stable proxy identifier
 * @param options - Request options with optional abort signal
 * @returns Verification results and status for each file
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
