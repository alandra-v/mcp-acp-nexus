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
} from '@/api/policy'
import { notifyError } from '@/hooks/useErrorSound'
import type {
  PolicyResponse,
  PolicyRuleCreate,
  PolicyRuleResponse,
  PolicyFullUpdate,
  ApiError,
} from '@/types/api'

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
  addRule: (rule: PolicyRuleCreate) => Promise<PolicyRuleResponse>
  /** Update an existing rule */
  updateRule: (id: string, rule: PolicyRuleCreate) => Promise<PolicyRuleResponse>
  /** Delete a rule */
  deleteRule: (id: string) => Promise<void>
  /** Update full policy (for JSON editor) */
  updateFullPolicy: (policy: PolicyFullUpdate) => Promise<void>
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
          const loc = Array.isArray(err.loc) ? err.loc.join('.') : ''
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

/**
 * Hook for managing policy configuration.
 *
 * Fetches policy on mount and provides mutation functions
 * that automatically refresh after success.
 */
export function usePolicy(): UsePolicyResult {
  const [policy, setPolicy] = useState<PolicyResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [mutating, setMutating] = useState(false)

  const fetchPolicy = useCallback(async () => {
    try {
      setError(null)
      const data = await getPolicy()
      setPolicy(data)
    } catch (e) {
      const message = getErrorMessage(e)
      setError(message)
      notifyError(`Failed to load policy: ${message}`)
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    const controller = new AbortController()

    async function load() {
      setLoading(true)
      try {
        const data = await getPolicy({ signal: controller.signal })
        setPolicy(data)
        setError(null)
      } catch (e) {
        if (e instanceof DOMException && e.name === 'AbortError') return
        const message = getErrorMessage(e)
        setError(message)
      } finally {
        setLoading(false)
      }
    }

    load()
    return () => controller.abort()
  }, [])

  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      await fetchPolicy()
    } finally {
      setLoading(false)
    }
  }, [fetchPolicy])

  const handleAddRule = useCallback(async (rule: PolicyRuleCreate): Promise<PolicyRuleResponse> => {
    setMutating(true)
    try {
      const result = await addPolicyRule(rule)
      // Success toast comes from SSE policy_reloaded event
      await fetchPolicy()
      return result.rule
    } catch (e) {
      const message = getErrorMessage(e)
      notifyError(`Failed to add rule: ${message}`)
      throw e
    } finally {
      setMutating(false)
    }
  }, [fetchPolicy])

  const handleUpdateRule = useCallback(async (
    id: string,
    rule: PolicyRuleCreate
  ): Promise<PolicyRuleResponse> => {
    setMutating(true)
    try {
      const result = await updatePolicyRule(id, rule)
      // Success toast comes from SSE policy_reloaded event
      await fetchPolicy()
      return result.rule
    } catch (e) {
      const message = getErrorMessage(e)
      notifyError(`Failed to update rule: ${message}`)
      throw e
    } finally {
      setMutating(false)
    }
  }, [fetchPolicy])

  const handleDeleteRule = useCallback(async (id: string): Promise<void> => {
    setMutating(true)
    try {
      await deletePolicyRule(id)
      // Success toast comes from SSE policy_reloaded event
      await fetchPolicy()
    } catch (e) {
      const message = getErrorMessage(e)
      notifyError(`Failed to delete rule: ${message}`)
      throw e
    } finally {
      setMutating(false)
    }
  }, [fetchPolicy])

  const handleUpdateFullPolicy = useCallback(async (policyData: PolicyFullUpdate): Promise<void> => {
    setMutating(true)
    try {
      const result = await updateFullPolicy(policyData)
      // Success toast comes from SSE policy_reloaded event
      setPolicy(result)
    } catch (e) {
      const message = getErrorMessage(e)
      notifyError(`Failed to save policy: ${message}`)
      throw e
    } finally {
      setMutating(false)
    }
  }, [])

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
