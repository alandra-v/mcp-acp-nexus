import { apiPost, apiDelete, createSSEConnection } from './client'
import type { SSEEvent } from '@/types/api'

// SSE subscription for real-time updates (pending approvals come via this)
export async function subscribeToPendingApprovals(
  onEvent: (event: SSEEvent) => void,
  onError?: (error: Event) => void
): Promise<EventSource> {
  return createSSEConnection<SSEEvent>('/events', onEvent, onError)
}

export async function approveProxyRequest(proxyName: string, id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/proxy/${encodeURIComponent(proxyName)}/approvals/pending/${id}/approve`)
}

export async function approveOnceProxyRequest(proxyName: string, id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/proxy/${encodeURIComponent(proxyName)}/approvals/pending/${id}/allow-once`)
}

export async function denyProxyRequest(proxyName: string, id: string): Promise<{ status: string; approval_id: string }> {
  return apiPost(`/proxy/${encodeURIComponent(proxyName)}/approvals/pending/${id}/deny`)
}

// Cached approvals (proxy-scoped via forwarding endpoint)
export async function clearProxyCachedApprovals(proxyName: string): Promise<{ cleared: number; status: string }> {
  return apiDelete(`/proxy/${encodeURIComponent(proxyName)}/approvals/cached`)
}

export async function deleteProxyCachedApproval(
  proxyName: string,
  subjectId: string,
  toolName: string,
  path: string | null
): Promise<{ deleted: boolean; status: string }> {
  const params = new URLSearchParams({ subject_id: subjectId, tool_name: toolName })
  if (path) params.set('path', path)
  return apiDelete(`/proxy/${encodeURIComponent(proxyName)}/approvals/cached/entry?${params}`)
}
