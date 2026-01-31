import { apiGet, apiPost, apiDelete, createSSEConnection } from './client'
import type { ApprovalCacheResponse, SSEEvent } from '@/types/api'

// SSE subscription for real-time updates (pending approvals come via this)
export async function subscribeToPendingApprovals(
  onEvent: (event: SSEEvent) => void,
  onError?: (error: Event) => void
): Promise<EventSource> {
  return createSSEConnection<SSEEvent>('/events', onEvent, onError)
}

export async function approveRequest(id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/approvals/pending/${id}/approve`)
}

export async function approveOnceRequest(id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/approvals/pending/${id}/allow-once`)
}

export async function denyRequest(id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/approvals/pending/${id}/deny`)
}

// Cached approvals
export async function fetchCachedApprovals(): Promise<ApprovalCacheResponse> {
  return apiGet('/approvals/cached')
}

export async function clearCachedApprovals(): Promise<{ cleared: number; status: string }> {
  return apiDelete('/approvals/cached')
}

export async function deleteCachedApproval(
  subjectId: string,
  toolName: string,
  path: string | null
): Promise<{ deleted: boolean; status: string }> {
  const params = new URLSearchParams({ subject_id: subjectId, tool_name: toolName })
  if (path) params.set('path', path)
  return apiDelete(`/approvals/cached/entry?${params}`)
}
