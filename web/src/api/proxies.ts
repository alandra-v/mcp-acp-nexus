/**
 * Proxies API client.
 *
 * Manager-level API: /api/manager/proxies - lists all configured proxies with config + runtime data
 */

import { apiGet, apiPost, type RequestOptions } from './client'
import type {
  Proxy,
  ProxyDetailResponse,
  CreateProxyRequest,
  CreateProxyResponse,
  ConfigSnippetResponse,
} from '@/types/api'

/**
 * Get all configured proxies.
 * Returns config data (server_name, transport, created_at) + runtime data (status, stats).
 * Shows all configured proxies, not just running ones.
 */
export async function getManagerProxies(options?: RequestOptions): Promise<Proxy[]> {
  return apiGet<Proxy[]>('/manager/proxies', options)
}

/**
 * Get full proxy detail by proxy_id.
 * Returns config + runtime data including pending/cached approvals.
 */
export async function getProxyDetail(
  proxyId: string,
  options?: RequestOptions
): Promise<ProxyDetailResponse> {
  return apiGet<ProxyDetailResponse>(
    `/manager/proxies/${encodeURIComponent(proxyId)}`,
    options
  )
}

/**
 * Create a new proxy configuration.
 * Mirrors CLI 'mcp-acp proxy add' functionality.
 */
export async function createProxy(
  request: CreateProxyRequest,
  options?: RequestOptions
): Promise<CreateProxyResponse> {
  return apiPost<CreateProxyResponse>('/manager/proxies', request, options)
}

/**
 * Get Claude Desktop config snippet from backend.
 * Uses full executable path for reliable config.
 *
 * @param proxy - Optional proxy name. If omitted, returns all proxies.
 */
export async function getConfigSnippet(
  proxy?: string,
  options?: RequestOptions
): Promise<ConfigSnippetResponse> {
  const url = proxy ? `/manager/config-snippet?proxy=${encodeURIComponent(proxy)}` : '/manager/config-snippet'
  return apiGet<ConfigSnippetResponse>(url, options)
}
