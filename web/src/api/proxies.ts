/**
 * Proxies API client.
 *
 * Two levels of proxy APIs:
 * - Manager level: /api/manager/proxies - lists all configured proxies with config + runtime data
 * - Proxy level: /api/proxies - runtime info from a specific running proxy
 */

import { apiGet, apiPost, type RequestOptions } from './client'
import { APP_NAME } from '@/constants'
import type {
  Proxy,
  EnhancedProxy,
  CreateProxyRequest,
  CreateProxyResponse,
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
  return apiGet<EnhancedProxy[]>('/api/manager/proxies', options)
}

/**
 * Create a new proxy configuration.
 * Mirrors CLI 'mcp-acp proxy add' functionality.
 */
export async function createProxy(
  request: CreateProxyRequest,
  options?: RequestOptions
): Promise<CreateProxyResponse> {
  return apiPost<CreateProxyResponse>('/api/manager/proxies', request, options)
}

/**
 * Generate Claude Desktop config snippet for a proxy.
 * Used for copy-to-clipboard functionality.
 */
export function generateClaudeDesktopSnippet(proxyName: string): Record<string, unknown> {
  return {
    [proxyName]: {
      command: APP_NAME,
      args: ['start', '--proxy', proxyName],
    },
  }
}

/**
 * Generate Claude Desktop config snippet for all proxies.
 * Used for "Export All Configs" functionality.
 */
export function generateAllProxiesSnippet(proxies: EnhancedProxy[]): Record<string, unknown> {
  const mcpServers: Record<string, unknown> = {}
  for (const proxy of proxies) {
    mcpServers[proxy.proxy_name] = {
      command: APP_NAME,
      args: ['start', '--proxy', proxy.proxy_name],
    }
  }
  return { mcpServers }
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
