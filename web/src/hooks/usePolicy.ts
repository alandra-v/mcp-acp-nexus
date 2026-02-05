/**
 * Hook for fetching and managing policy configuration.
 *
 * Provides:
 * - Policy data with rules and HITL config
 * - CRUD operations for rules
 * - Full policy update for JSON editor
 * - Auto-refresh after mutations
 */

import { useState, useEffect, useCallback } from 'react'
import {
  getPolicy,
  addPolicyRule,
  updatePolicyRule,
  deletePolicyRule,
  updateFullPolicy,
  getProxyPolicy,
  addProxyPolicyRule,
  updateProxyPolicyRule,
  deleteProxyPolicyRule,
  updateProxyPolicy,
} from '@/api/policy'
import { notifyError } from '@/hooks/useErrorSound'
import { formatValidationLoc } from '@/lib/utils'
import type {
  PolicyResponse,
  PolicyRuleCreate,
  PolicyRuleResponse,
  PolicyFullUpdate,
  ApiError,
} from '@/types/api'

/** Options for mutation functions */
export interface MutationOptions {
  /** When true, suppress error toast (caller handles display) */
  silent?: boolean
}

/** Result interface for usePolicy hook */
export interface UsePolicyResult {
  /** Current policy configuration */
  policy: PolicyResponse | null
  /** Loading state for initial fetch */
  loading: boolean
  /** Error message if fetch failed */
  error: string | null
  /** Refresh policy from server */
  refresh: () => Promise<void>
  /** Add a new rule */
  addRule: (rule: PolicyRuleCreate, options?: MutationOptions) => Promise<PolicyRuleResponse>
  /** Update an existing rule */
  updateRule: (id: string, rule: PolicyRuleCreate) => Promise<PolicyRuleResponse>
  /** Delete a rule */
  deleteRule: (id: string) => Promise<void>
  /** Update full policy (for JSON editor) */
  updateFullPolicy: (policy: PolicyFullUpdate, options?: MutationOptions) => Promise<void>
  /** Whether a mutation is in progress */
  mutating: boolean
}

/**
 * Type guard for ApiError.
 */
function isApiError(error: unknown): error is ApiError {
  return (
    error instanceof Error &&
    'status' in error &&
    typeof (error as ApiError).status === 'number'
  )
}

/**
 * Format FastAPI validation error detail.
 */
function formatValidationErrors(detail: unknown): string {
  if (typeof detail === 'string') {
    return detail
  }
  if (Array.isArray(detail)) {
    // FastAPI validation errors: [{loc: [...], msg: "...", type: "..."}]
    return detail
      .map((err) => {
        if (typeof err === 'object' && err !== null && 'msg' in err) {
          const loc = Array.isArray(err.loc)
            ? formatValidationLoc(err.loc as (string | number)[])
            : ''
          return loc ? `${loc}: ${err.msg}` : err.msg
        }
        return String(err)
      })
      .join('; ')
  }
  if (typeof detail === 'object' && detail !== null) {
    return JSON.stringify(detail)
  }
  return String(detail)
}

/**
 * Extract error message from API error or unknown error.
 */
function getErrorMessage(error: unknown): string {
  if (isApiError(error)) {
    // Try to parse API error detail from response body
    try {
      const parsed = JSON.parse(error.message)
      if (parsed.detail !== undefined) {
        return formatValidationErrors(parsed.detail)
      }
    } catch {
      // Not JSON, use message as-is
    }
    return error.message
  }
  if (error instanceof Error) {
    return error.message
  }
  return 'Unknown error'
}

/** Options for usePolicy hook */
export interface UsePolicyOptions {
  /**
   * When provided, uses manager-level endpoints to access policy
   * regardless of whether the proxy is running.
   * When undefined, uses the default proxy-level endpoints.
   */
  proxyId?: string
}

/**
 * Hook for managing policy configuration.
 *
 * Fetches policy on mount and provides mutation functions
 * that automatically refresh after success.
 *
 * @param options - Optional configuration including proxyId for manager-level access
 */
export function usePolicy(options?: UsePolicyOptions): UsePolicyResult {
  const proxyId = options?.proxyId
  const [policy, setPolicy] = useState<PolicyResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [mutating, setMutating] = useState(false)

  const fetchPolicy = useCallback(async (options?: { signal?: AbortSignal; silent?: boolean }) => {
    try {
      setError(null)
      const data = proxyId
        ? await getProxyPolicy(proxyId, { signal: options?.signal })
        : await getPolicy({ signal: options?.signal })
      setPolicy(data)
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return
      const message = getErrorMessage(e)
      setError(message)
      // Only show notification for non-silent fetches (e.g., manual refresh)
      if (!options?.silent) {
        notifyError(`Failed to load policy: ${message}`)
      }
    }
  }, [proxyId])

  // Initial fetch (silent - no error notification on initial load)
  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      setLoading(true)
      try {
        await fetchPolicy({ signal: controller.signal, silent: true })
      } finally {
        setLoading(false)
      }
    }

    load()
    return () => controller.abort()
  }, [fetchPolicy])

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      await fetchPolicy()
    } finally {
      setLoading(false)
    }
  }, [fetchPolicy])

  const handleAddRule = useCallback(async (
    rule: PolicyRuleCreate,
    options?: MutationOptions
  ): Promise<PolicyRuleResponse> => {
    setMutating(true)
    try {
      const result = proxyId
        ? await addProxyPolicyRule(proxyId, rule)
        : await addPolicyRule(rule)
      // Success toast comes from SSE policy_reloaded event (if proxy running)
      await fetchPolicy()
      return result.rule
    } catch (e) {
      if (!options?.silent) {
        const message = getErrorMessage(e)
        notifyError(`Failed to add rule: ${message}`)
      }
      throw e
    } finally {
      setMutating(false)
    }
  }, [proxyId, fetchPolicy])

  const handleUpdateRule = useCallback(async (
    id: string,
    rule: PolicyRuleCreate
  ): Promise<PolicyRuleResponse> => {
    setMutating(true)
    try {
      const result = proxyId
        ? await updateProxyPolicyRule(proxyId, id, rule)
        : await updatePolicyRule(id, rule)
      // Success toast comes from SSE policy_reloaded event (if proxy running)
      await fetchPolicy()
      return result.rule
    } catch (e) {
      const message = getErrorMessage(e)
      notifyError(`Failed to update rule: ${message}`)
      throw e
    } finally {
      setMutating(false)
    }
  }, [proxyId, fetchPolicy])

  const handleDeleteRule = useCallback(async (id: string): Promise<void> => {
    setMutating(true)
    try {
      if (proxyId) {
        await deleteProxyPolicyRule(proxyId, id)
      } else {
        await deletePolicyRule(id)
      }
      // Success toast comes from SSE policy_reloaded event (if proxy running)
      await fetchPolicy()
    } catch (e) {
      const message = getErrorMessage(e)
      notifyError(`Failed to delete rule: ${message}`)
      throw e
    } finally {
      setMutating(false)
    }
  }, [proxyId, fetchPolicy])

  const handleUpdateFullPolicy = useCallback(async (
    policyData: PolicyFullUpdate,
    options?: MutationOptions
  ): Promise<void> => {
    setMutating(true)
    try {
      const result = proxyId
        ? await updateProxyPolicy(proxyId, policyData)
        : await updateFullPolicy(policyData)
      // Success toast comes from SSE policy_reloaded event (if proxy running)
      setPolicy(result)
    } catch (e) {
      if (!options?.silent) {
        const message = getErrorMessage(e)
        notifyError(`Failed to save policy: ${message}`)
      }
      throw e
    } finally {
      setMutating(false)
    }
  }, [proxyId])

  return {
    policy,
    loading,
    error,
    refresh,
    addRule: handleAddRule,
    updateRule: handleUpdateRule,
    deleteRule: handleDeleteRule,
    updateFullPolicy: handleUpdateFullPolicy,
    mutating,
  }
}
