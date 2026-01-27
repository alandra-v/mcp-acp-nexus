/**
 * Proxies API client.
 *
 * Two levels of proxy APIs:
 * - Manager level: /api/manager/proxies - lists all configured proxies with config + runtime data
 * - Proxy level: /api/proxies - runtime info from a specific running proxy
 */

import { apiGet, apiPost, type RequestOptions } from './client'
import type {
  Proxy,
  EnhancedProxy,
  ProxyDetailResponse,
  CreateProxyRequest,
  CreateProxyResponse,
  ConfigSnippetResponse,
} from '@/types/api'

// =============================================================================
// Manager-level API (multi-proxy)
// =============================================================================

/**
 * Get all configured proxies with enhanced info.
 * Returns config data (server_name, transport, created_at) + runtime data (status, stats).
 * Shows all configured proxies, not just running ones.
 */
export async function getManagerProxies(options?: RequestOptions): Promise<EnhancedProxy[]> {
  return apiGet<EnhancedProxy[]>('/manager/proxies', options)
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

// =============================================================================
// Proxy-level API (single proxy runtime)
// =============================================================================

/**
 * Get runtime info from a running proxy.
 * Uses fallback routing (works when exactly one proxy is running).
 * @deprecated Use getManagerProxies() for multi-proxy support
 */
export async function getProxies(options?: RequestOptions): Promise<Proxy[]> {
  return apiGet<Proxy[]>('/proxies', options)
}

/**
 * Get runtime info for a specific proxy by ID.
 * @deprecated Use getManagerProxies() for multi-proxy support
 */
export async function getProxy(id: string, options?: RequestOptions): Promise<Proxy> {
  return apiGet<Proxy>(`/proxies/${id}`, options)
}
