/**
 * Application constants.
 *
 * Centralized constants to avoid magic values throughout the codebase.
 * Mirrors backend constants from src/mcp_acp/constants.py where applicable.
 */

/** Application name - must match backend APP_NAME in src/mcp_acp/constants.py */
export const APP_NAME = 'mcp-acp'

/** Default limit for paginated incident queries */
export const DEFAULT_INCIDENT_LIMIT = 100

/** Default limit for paginated log queries */
export const DEFAULT_LOG_LIMIT = 50

/** SSE event names dispatched via window for cross-component communication */
export const SSE_EVENTS = {
  PROXY_REGISTERED: 'proxy-registered',
  PROXY_DISCONNECTED: 'proxy-disconnected',
  AUTH_STATE_CHANGED: 'auth-state-changed',
} as const

/** Duration to show "Copied!" feedback before reverting */
export const COPY_FEEDBACK_DURATION_MS = 2000

/** Default HTTP timeout in seconds */
export const DEFAULT_HTTP_TIMEOUT_SECONDS = 30
