/**
 * Policy API client for CRUD operations.
 *
 * Provides functions for:
 * - Fetching current policy configuration
 * - Adding, updating, and deleting policy rules
 * - Updating the full policy JSON
 */

import { apiGet, apiPost, apiPut, apiDelete, type RequestOptions } from './client'
import type {
  PolicyResponse,
  PolicyRuleResponse,
  PolicyRuleCreate,
  PolicyRuleMutationResponse,
  PolicyFullUpdate,
  PolicySchemaResponse,
} from '@/types/api'

/**
 * Get current policy configuration with metadata.
 *
 * Note: HITL config is in AppConfig, use getConfig() from config.ts instead.
 *
 * @param options - Request options with optional abort signal
 * @returns Policy configuration including rules and metadata
 */
export function getPolicy(options?: RequestOptions): Promise<PolicyResponse> {
  return apiGet<PolicyResponse>('/policy', options)
}

/**
 * Get simplified list of policy rules.
 *
 * @param options - Request options with optional abort signal
 * @returns Array of policy rules
 */
export function getPolicyRules(options?: RequestOptions): Promise<PolicyRuleResponse[]> {
  return apiGet<PolicyRuleResponse[]>('/policy/rules', options)
}

/**
 * Get policy schema information.
 *
 * Returns valid values for policy fields (operations, etc.)
 *
 * @param options - Request options with optional abort signal
 * @returns Schema with valid operations
 */
export function getPolicySchema(options?: RequestOptions): Promise<PolicySchemaResponse> {
  return apiGet<PolicySchemaResponse>('/policy/schema', options)
}

/**
 * Add a new policy rule.
 *
 * Rule is validated by backend and policy is auto-reloaded on success.
 *
 * @param rule - Rule data to create
 * @param options - Request options with optional abort signal
 * @returns Created rule with policy version
 */
export function addPolicyRule(
  rule: PolicyRuleCreate,
  options?: RequestOptions
): Promise<PolicyRuleMutationResponse> {
  return apiPost<PolicyRuleMutationResponse>('/policy/rules', rule, options)
}

/**
 * Update an existing policy rule.
 *
 * Policy is auto-reloaded on success.
 *
 * @param ruleId - ID of the rule to update
 * @param rule - Updated rule data
 * @param options - Request options with optional abort signal
 * @returns Updated rule with policy version
 */
export function updatePolicyRule(
  ruleId: string,
  rule: PolicyRuleCreate,
  options?: RequestOptions
): Promise<PolicyRuleMutationResponse> {
  return apiPut<PolicyRuleMutationResponse>(`/policy/rules/${encodeURIComponent(ruleId)}`, rule, options)
}

/**
 * Delete a policy rule.
 *
 * Policy is auto-reloaded on success.
 *
 * @param ruleId - ID of the rule to delete
 * @param options - Request options with optional abort signal
 */
export async function deletePolicyRule(
  ruleId: string,
  options?: RequestOptions
): Promise<void> {
  await apiDelete<void>(`/policy/rules/${encodeURIComponent(ruleId)}`, options)
}

/**
 * Update the full policy configuration.
 *
 * Replaces entire policy and auto-reloads.
 *
 * @param policy - Full policy data
 * @param options - Request options with optional abort signal
 * @returns Updated policy configuration
 */
export function updateFullPolicy(
  policy: PolicyFullUpdate,
  options?: RequestOptions
): Promise<PolicyResponse> {
  return apiPut<PolicyResponse>('/policy', policy, options)
}
