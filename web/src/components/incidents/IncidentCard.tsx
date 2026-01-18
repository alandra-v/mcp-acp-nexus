/**
 * Incident card component for displaying shutdown, bootstrap, and emergency incidents.
 * Uses a timeline-style layout with colored markers and badges.
 */

import { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn, formatDateTime } from '@/lib/utils'
import type { IncidentEntry } from '@/hooks/useIncidents'

interface IncidentCardProps {
  incident: IncidentEntry
  /** Whether this is the last item (hides the timeline connector) */
  isLast?: boolean
}

const INCIDENT_CONFIG = {
  shutdown: {
    label: 'SHUTDOWN',
    dotClass: 'bg-red-500',
    badgeClass: 'bg-red-500/15 text-red-400 border-red-500/25',
  },
  bootstrap: {
    label: 'STARTUP ERROR',
    dotClass: 'bg-amber-500',
    badgeClass: 'bg-amber-500/15 text-amber-400 border-amber-500/25',
  },
  emergency: {
    label: 'AUDIT FAILURE',
    dotClass: 'bg-purple-500',
    badgeClass: 'bg-purple-500/15 text-purple-400 border-purple-500/25',
  },
}

export function IncidentCard({ incident, isLast = false }: IncidentCardProps) {
  const [expanded, setExpanded] = useState(false)
  const config = INCIDENT_CONFIG[incident.incident_type]

  // Extract key fields from incident
  const title = getIncidentTitle(incident)
  const description = getIncidentDescription(incident)
  const exitCode = incident.exit_code as number | undefined

  return (
    <div className="relative flex gap-4">
      {/* Timeline marker */}
      <div className="flex flex-col items-center">
        {/* Dot */}
        <div
          className={cn(
            'w-3 h-3 rounded-full shrink-0 mt-1.5 ring-4 ring-background',
            config.dotClass
          )}
        />
        {/* Connector line */}
        {!isLast && (
          <div className="w-px flex-1 bg-base-700 mt-2" />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 pb-8">
        {/* Badge + Timestamp row */}
        <div className="flex items-center gap-3 mb-2">
          <span
            className={cn(
              'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border uppercase tracking-wide',
              config.badgeClass
            )}
          >
            {config.label}
          </span>
          <span className="text-xs text-muted-foreground">
            {formatDateTime(incident.time)}
          </span>
        </div>

        {/* Title */}
        <h3 className="font-medium text-foreground mb-1">{title}</h3>

        {/* Description */}
        {description && (
          <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
            {description}
          </p>
        )}

        {/* Exit Code (inline) */}
        {exitCode !== undefined && (
          <p className="text-xs text-muted-foreground mb-2">
            Exit code: <code className="font-mono text-foreground">{exitCode}</code>
          </p>
        )}

        {/* Expand/Collapse */}
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setExpanded(!expanded)}
          className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground -ml-2"
        >
          {expanded ? (
            <>
              Hide details <ChevronUp className="w-3.5 h-3.5 ml-1" />
            </>
          ) : (
            <>
              Show details <ChevronDown className="w-3.5 h-3.5 ml-1" />
            </>
          )}
        </Button>

        {/* Expanded Details */}
        {expanded && (
          <div className="mt-3 max-w-full overflow-hidden">
            <pre className="text-xs font-mono bg-base-900/50 border border-base-800 rounded-lg p-3 overflow-x-auto max-h-64 overflow-y-auto whitespace-pre-wrap break-all">
              {JSON.stringify(incident, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

/**
 * Extract a title from the incident entry.
 */
function getIncidentTitle(incident: IncidentEntry): string {
  // Shutdown events (intentional security shutdowns)
  if (incident.failure_type) {
    return formatFailureType(incident.failure_type as string)
  }

  // Bootstrap events
  if (incident.event) {
    return formatEventType(incident.event as string)
  }

  // Emergency audit events
  if (incident.event_type) {
    return `Emergency: ${incident.event_type}`
  }

  return 'Unknown Incident'
}

/**
 * Extract a description from the incident entry.
 */
function getIncidentDescription(incident: IncidentEntry): string | null {
  if (incident.reason) return incident.reason as string
  if (incident.message) return incident.message as string
  if (incident.error_message) return incident.error_message as string
  if (incident.failure_reason) return incident.failure_reason as string
  return null
}

/**
 * Format failure_type to human-readable title.
 */
function formatFailureType(failureType: string): string {
  const mapping: Record<string, string> = {
    audit_failure: 'Audit Log Integrity Failure',
    policy_failure: 'Policy Enforcement Failure',
    identity_failure: 'Identity Verification Failure',
    session_binding_violation: 'Session Binding Violation',
    device_health_failure: 'Device Health Check Failure',
    authentication_error: 'Authentication Error',
  }
  return mapping[failureType] || failureType.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

/**
 * Format event type to human-readable title.
 */
function formatEventType(event: string): string {
  const mapping: Record<string, string> = {
    config_validation_failed: 'Configuration Validation Failed',
    policy_validation_failed: 'Policy Validation Failed',
    emergency_audit: 'Emergency Audit Entry',
    // Startup errors
    config_not_found: 'Configuration Not Found',
    mtls_cert_not_found: 'mTLS Certificate Not Found',
    backend_timeout: 'Backend Connection Timeout',
    backend_connection_failed: 'Backend Connection Failed',
    ssl_error: 'SSL/TLS Error',
    audit_failure: 'Audit Log Failure',
    auth_not_configured: 'Authentication Not Configured',
    not_authenticated: 'Not Authenticated',
    auth_expired: 'Authentication Expired',
    auth_failed: 'Authentication Failed',
    device_health_failed: 'Device Health Check Failed',
    startup_failed: 'Startup Failed',
  }
  return mapping[event] || event.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}
