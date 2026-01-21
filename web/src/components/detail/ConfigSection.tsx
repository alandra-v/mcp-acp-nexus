import { useState, useEffect, useMemo, useCallback, useId, cloneElement, isValidElement, Children } from 'react'
import { Section } from './Section'
import { useConfig } from '@/hooks/useConfig'
import { useAuth } from '@/hooks/useAuth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { toast } from '@/components/ui/sonner'
import { notifyError } from '@/hooks/useErrorSound'
import { cn } from '@/lib/utils'
import type { ConfigResponse, ConfigUpdateRequest, TransportType, ConfigChange } from '@/api/config'

interface ConfigSectionProps {
  loaded?: boolean
}

// Common OAuth scopes
const COMMON_SCOPES = [
  { value: 'openid', label: 'OpenID', description: 'Required for OIDC' },
  { value: 'profile', label: 'Profile', description: 'User profile info' },
  { value: 'email', label: 'Email', description: 'Email address' },
  { value: 'offline_access', label: 'Offline Access', description: 'Refresh tokens' },
] as const

// Form state type - mirrors ConfigResponse but with mutable fields
interface FormState {
  // Proxy
  proxy_name: string
  // Backend
  backend_server_name: string
  backend_transport: TransportType
  // STDIO
  stdio_command: string
  stdio_args: string // comma-separated
  // HTTP
  http_url: string
  http_timeout: string
  // Logging
  log_dir: string
  log_level: string
  include_payloads: boolean
  // Auth - OIDC
  oidc_issuer: string
  oidc_client_id: string
  oidc_audience: string
  oidc_scopes: string[] // array of scope values
  // Auth - mTLS
  mtls_client_cert_path: string
  mtls_client_key_path: string
  mtls_ca_bundle_path: string
  // HITL
  hitl_timeout_seconds: string
  hitl_approval_ttl_seconds: string
}

/**
 * Convert ConfigResponse to form state for editing.
 * Transforms nested config structure to flat form fields.
 */
function configToFormState(config: ConfigResponse): FormState {
  return {
    proxy_name: config.proxy.name,
    backend_server_name: config.backend.server_name,
    backend_transport: config.backend.transport ?? 'auto',
    stdio_command: config.backend.stdio?.command || '',
    stdio_args: config.backend.stdio?.args.join(', ') || '',
    http_url: config.backend.http?.url || '',
    http_timeout: config.backend.http?.timeout.toString() || '30',
    log_dir: config.logging.log_dir,
    log_level: config.logging.log_level,
    include_payloads: config.logging.include_payloads,
    oidc_issuer: config.auth?.oidc?.issuer || '',
    oidc_client_id: config.auth?.oidc?.client_id || '',
    oidc_audience: config.auth?.oidc?.audience || '',
    oidc_scopes: config.auth?.oidc?.scopes || [],
    mtls_client_cert_path: config.auth?.mtls?.client_cert_path || '',
    mtls_client_key_path: config.auth?.mtls?.client_key_path || '',
    mtls_ca_bundle_path: config.auth?.mtls?.ca_bundle_path || '',
    hitl_timeout_seconds: config.hitl.timeout_seconds.toString(),
    hitl_approval_ttl_seconds: config.hitl.approval_ttl_seconds.toString(),
  }
}

/**
 * Build update request from form state changes.
 * Only includes fields that differ from the original config.
 */
function formStateToUpdateRequest(
  form: FormState,
  original: ConfigResponse
): ConfigUpdateRequest {
  const updates: ConfigUpdateRequest = {}

  // Proxy
  if (form.proxy_name !== original.proxy.name) {
    updates.proxy = { name: form.proxy_name }
  }

  // Backend
  const backendUpdates: ConfigUpdateRequest['backend'] = {}
  if (form.backend_server_name !== original.backend.server_name) {
    backendUpdates.server_name = form.backend_server_name
  }
  if (form.backend_transport !== original.backend.transport) {
    backendUpdates.transport = form.backend_transport
  }

  // STDIO
  const originalStdioCommand = original.backend.stdio?.command || ''
  const originalStdioArgs = original.backend.stdio?.args.join(', ') || ''
  if (form.stdio_command !== originalStdioCommand || form.stdio_args !== originalStdioArgs) {
    const args = form.stdio_args
      .split(',')
      .map((a) => a.trim())
      .filter(Boolean)
    backendUpdates.stdio = {
      command: form.stdio_command || undefined,
      args: args.length > 0 ? args : undefined,
    }
  }

  // HTTP
  const originalHttpUrl = original.backend.http?.url || ''
  const originalHttpTimeout = original.backend.http?.timeout.toString() || '30'
  if (form.http_url !== originalHttpUrl || form.http_timeout !== originalHttpTimeout) {
    backendUpdates.http = {
      url: form.http_url || undefined,
      timeout: form.http_timeout ? parseInt(form.http_timeout, 10) : undefined,
    }
  }

  if (Object.keys(backendUpdates).length > 0) {
    updates.backend = backendUpdates
  }

  // Logging
  const loggingUpdates: ConfigUpdateRequest['logging'] = {}
  if (form.log_dir !== original.logging.log_dir) {
    loggingUpdates.log_dir = form.log_dir
  }
  if (form.log_level !== original.logging.log_level) {
    loggingUpdates.log_level = form.log_level
  }
  if (form.include_payloads !== original.logging.include_payloads) {
    loggingUpdates.include_payloads = form.include_payloads
  }
  if (Object.keys(loggingUpdates).length > 0) {
    updates.logging = loggingUpdates
  }

  // Auth - OIDC
  if (original.auth?.oidc) {
    const oidcUpdates: ConfigUpdateRequest['auth'] = { oidc: {} }
    const originalScopes = original.auth.oidc.scopes
    if (form.oidc_issuer !== original.auth.oidc.issuer) {
      oidcUpdates.oidc!.issuer = form.oidc_issuer
    }
    if (form.oidc_client_id !== original.auth.oidc.client_id) {
      oidcUpdates.oidc!.client_id = form.oidc_client_id
    }
    if (form.oidc_audience !== original.auth.oidc.audience) {
      oidcUpdates.oidc!.audience = form.oidc_audience
    }
    // Compare scopes arrays
    const scopesChanged =
      form.oidc_scopes.length !== originalScopes.length ||
      form.oidc_scopes.some((s) => !originalScopes.includes(s))
    if (scopesChanged) {
      oidcUpdates.oidc!.scopes = form.oidc_scopes
    }
    if (Object.keys(oidcUpdates.oidc!).length > 0) {
      updates.auth = { ...updates.auth, ...oidcUpdates }
    }
  }

  // Auth - mTLS
  if (original.auth?.mtls) {
    const mtlsUpdates: ConfigUpdateRequest['auth'] = { mtls: {} }
    if (form.mtls_client_cert_path !== original.auth.mtls.client_cert_path) {
      mtlsUpdates.mtls!.client_cert_path = form.mtls_client_cert_path
    }
    if (form.mtls_client_key_path !== original.auth.mtls.client_key_path) {
      mtlsUpdates.mtls!.client_key_path = form.mtls_client_key_path
    }
    if (form.mtls_ca_bundle_path !== original.auth.mtls.ca_bundle_path) {
      mtlsUpdates.mtls!.ca_bundle_path = form.mtls_ca_bundle_path
    }
    if (Object.keys(mtlsUpdates.mtls!).length > 0) {
      updates.auth = { ...updates.auth, ...mtlsUpdates }
    }
  }

  // HITL
  const hitlUpdates: ConfigUpdateRequest['hitl'] = {}
  const originalTimeout = original.hitl.timeout_seconds.toString()
  const originalTtl = original.hitl.approval_ttl_seconds.toString()
  if (form.hitl_timeout_seconds !== originalTimeout) {
    hitlUpdates.timeout_seconds = parseInt(form.hitl_timeout_seconds, 10)
  }
  if (form.hitl_approval_ttl_seconds !== originalTtl) {
    hitlUpdates.approval_ttl_seconds = parseInt(form.hitl_approval_ttl_seconds, 10)
  }
  if (Object.keys(hitlUpdates).length > 0) {
    updates.hitl = hitlUpdates
  }

  return updates
}

export function ConfigSection({ loaded = true }: ConfigSectionProps) {
  const { config, loading, saving, save, refresh, pendingChanges, hasPendingChanges } = useConfig()
  const { status: authStatus } = useAuth()
  const [form, setForm] = useState<FormState | null>(null)

  // Initialize form from config
  useEffect(() => {
    if (config && !form) {
      setForm(configToFormState(config))
    }
  }, [config, form])

  // Update form when config refreshes (after successful save)
  useEffect(() => {
    if (config && form) {
      // Only reset form if config actually changed (successful save)
      const newFormState = configToFormState(config)
      if (JSON.stringify(newFormState) !== JSON.stringify(form)) {
        setForm(newFormState)
      }
    }
  }, [config]) // eslint-disable-line react-hooks/exhaustive-deps

  // Check if form is dirty (has unsaved changes)
  const isDirty = useMemo(() => {
    if (!config || !form) return false
    const original = configToFormState(config)
    return JSON.stringify(form) !== JSON.stringify(original)
  }, [config, form])

  // Update form field
  const updateField = useCallback(
    <K extends keyof FormState>(field: K, value: FormState[K]) => {
      setForm((prev) => (prev ? { ...prev, [field]: value } : null))
    },
    []
  )

  // Discard changes
  const handleDiscard = useCallback(() => {
    if (config) {
      setForm(configToFormState(config))
    }
  }, [config])

  // Save changes
  const handleSave = useCallback(async () => {
    if (!config || !form) return

    // Check if user is still authenticated
    if (!authStatus?.authenticated) {
      notifyError('You must be logged in to save config changes')
      return
    }

    const updates = formStateToUpdateRequest(form, config)
    if (Object.keys(updates).length === 0) {
      toast.info('No changes to save')
      return
    }

    const success = await save(updates)
    if (success) {
      // Form will be updated via useEffect when config changes
    }
  }, [config, form, authStatus, save])

  if (loading) {
    return (
      <Section index={0} title="Configuration" loaded={loaded}>
        <div className="text-center py-8 text-muted-foreground">Loading configuration...</div>
      </Section>
    )
  }

  if (!config || !form) {
    return (
      <Section index={0} title="Configuration" loaded={loaded}>
        <div className="text-center py-8 text-muted-foreground">
          Failed to load configuration.
          <Button variant="ghost" size="sm" onClick={refresh} className="ml-2">
            Retry
          </Button>
        </div>
      </Section>
    )
  }

  const isStdioActive = form.backend_transport === 'stdio' || form.backend_transport === 'auto'
  const isHttpActive = form.backend_transport === 'streamablehttp' || form.backend_transport === 'auto'

  return (
    <Section index={0} title="Configuration" loaded={loaded}>
      <div
        className={cn(
          'space-y-8 p-6 rounded-lg border transition-all duration-300',
          isDirty
            ? 'border-orange-500/60 shadow-[0_0_8px_-4px_rgba(249,115,22,0.4)]'
            : 'border-[var(--border-subtle)] bg-transparent'
        )}
      >
        {/* Proxy Settings */}
        <FormSection title="Proxy">
          <FormRow label="Name" hint="Display name for this proxy">
            <Input
              value={form.proxy_name}
              onChange={(e) => updateField('proxy_name', e.target.value)}
              className="max-w-md"
            />
          </FormRow>
        </FormSection>

        {/* Backend Settings */}
        <FormSection title="Backend">
          <FormRow label="Server Name" hint="Name of the backend MCP server">
            <Input
              value={form.backend_server_name}
              onChange={(e) => updateField('backend_server_name', e.target.value)}
              className="max-w-md"
            />
          </FormRow>
          <FormRow label="Transport" hint="How to connect to the backend">
            <Select
              value={form.backend_transport}
              onValueChange={(v) => updateField('backend_transport', v as TransportType)}
            >
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Auto-detect</SelectItem>
                <SelectItem value="stdio">STDIO</SelectItem>
                <SelectItem value="streamablehttp">Streamable HTTP</SelectItem>
              </SelectContent>
            </Select>
          </FormRow>

          {/* STDIO Config */}
          <div className={cn('space-y-4 pl-4 border-l-2', isStdioActive ? 'border-base-500' : 'border-base-800 opacity-50')}>
            <div className="text-xs uppercase tracking-wide text-muted-foreground">STDIO Transport</div>
            <FormRow label="Command" hint="Command to launch the server">
              <Input
                value={form.stdio_command}
                onChange={(e) => updateField('stdio_command', e.target.value)}
                className="max-w-md"
                disabled={!isStdioActive}
              />
            </FormRow>
            <FormRow label="Arguments" hint="Comma-separated list of arguments">
              <Input
                value={form.stdio_args}
                onChange={(e) => updateField('stdio_args', e.target.value)}
                className="max-w-md"
                placeholder="e.g., -y, @modelcontextprotocol/server-filesystem"
                disabled={!isStdioActive}
              />
            </FormRow>
          </div>

          {/* HTTP Config */}
          <div className={cn('space-y-4 pl-4 border-l-2', isHttpActive ? 'border-base-500' : 'border-base-800 opacity-50')}>
            <div className="text-xs uppercase tracking-wide text-muted-foreground">HTTP Transport</div>
            <FormRow label="URL" hint="Backend server URL">
              <Input
                value={form.http_url}
                onChange={(e) => updateField('http_url', e.target.value)}
                className="max-w-md"
                placeholder="http://localhost:3010/mcp"
                disabled={!isHttpActive}
              />
            </FormRow>
            <FormRow label="Timeout" hint="Connection timeout in seconds (1-300)">
              <Input
                type="number"
                min={1}
                max={300}
                value={form.http_timeout}
                onChange={(e) => updateField('http_timeout', e.target.value)}
                className="w-24"
                disabled={!isHttpActive}
              />
            </FormRow>
          </div>
        </FormSection>

        {/* Logging Settings */}
        <FormSection title="Logging">
          <FormRow label="Log Directory" hint="Where log files are stored">
            <Input
              value={form.log_dir}
              onChange={(e) => updateField('log_dir', e.target.value)}
              className="max-w-md"
            />
          </FormRow>
          <FormRow label="Log Level" hint="DEBUG enables wire logs">
            <Select value={form.log_level} onValueChange={(v) => updateField('log_level', v)}>
              <SelectTrigger className="w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="INFO">INFO</SelectItem>
                <SelectItem value="DEBUG">DEBUG</SelectItem>
              </SelectContent>
            </Select>
          </FormRow>
          <FormRow label="Include Payloads" hint="Include full message content in debug logs">
            <Switch
              checked={form.include_payloads}
              onCheckedChange={(checked) => updateField('include_payloads', checked)}
            />
          </FormRow>
        </FormSection>

        {/* Auth - OIDC (only if configured) */}
        {config.auth?.oidc && (
          <FormSection title="Authentication - OIDC">
            <FormRow label="Issuer" hint="OIDC issuer URL">
              <Input
                value={form.oidc_issuer}
                onChange={(e) => updateField('oidc_issuer', e.target.value)}
                className="max-w-md"
              />
            </FormRow>
            <FormRow label="Client ID" hint="Auth0 application client ID">
              <Input
                value={form.oidc_client_id}
                onChange={(e) => updateField('oidc_client_id', e.target.value)}
                className="max-w-md"
              />
            </FormRow>
            <FormRow label="Audience" hint="API audience for token validation">
              <Input
                value={form.oidc_audience}
                onChange={(e) => updateField('oidc_audience', e.target.value)}
                className="max-w-md"
              />
            </FormRow>
            <FormRow label="Scopes" hint="OAuth scopes to request">
              <div className="flex flex-wrap gap-4">
                {COMMON_SCOPES.map((scope) => (
                  <label
                    key={scope.value}
                    className="flex items-center gap-2 cursor-pointer group"
                  >
                    <input
                      type="checkbox"
                      checked={form.oidc_scopes.includes(scope.value)}
                      onChange={(e) => {
                        const newScopes = e.target.checked
                          ? [...form.oidc_scopes, scope.value]
                          : form.oidc_scopes.filter((s) => s !== scope.value)
                        updateField('oidc_scopes', newScopes)
                      }}
                      className="w-4 h-4 rounded border-base-600 bg-base-900 text-primary focus:ring-primary/50"
                    />
                    <span className="text-sm">
                      {scope.label}
                      <span className="text-xs text-muted-foreground ml-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        ({scope.description})
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            </FormRow>
          </FormSection>
        )}

        {/* Auth - mTLS (only if configured) */}
        {config.auth?.mtls && (
          <FormSection title="Authentication - mTLS">
            <FormRow label="Client Cert Path" hint="Path to client certificate (PEM)">
              <Input
                value={form.mtls_client_cert_path}
                onChange={(e) => updateField('mtls_client_cert_path', e.target.value)}
                className="max-w-md"
              />
            </FormRow>
            <FormRow label="Client Key Path" hint="Path to client private key (PEM)">
              <Input
                value={form.mtls_client_key_path}
                onChange={(e) => updateField('mtls_client_key_path', e.target.value)}
                className="max-w-md"
              />
            </FormRow>
            <FormRow label="CA Bundle Path" hint="Path to CA bundle for server verification">
              <Input
                value={form.mtls_ca_bundle_path}
                onChange={(e) => updateField('mtls_ca_bundle_path', e.target.value)}
                className="max-w-md"
              />
            </FormRow>
          </FormSection>
        )}

        {/* HITL Settings */}
        <FormSection title="Human-in-the-Loop (HITL)">
          <p className="text-sm text-muted-foreground -mt-2 mb-4">
            Requests matching HITL rules require manual approval before proceeding.
            When approval caching is enabled for a rule, you can approve a tool once for a
            specific resource path and it will remain approved until the TTL expires.
            The cache is keyed by user, tool, and path.
          </p>
          <FormRow label="Timeout" hint="Seconds to wait for user approval (5-300)">
            <Input
              type="number"
              min={5}
              max={300}
              value={form.hitl_timeout_seconds}
              onChange={(e) => updateField('hitl_timeout_seconds', e.target.value)}
              className="w-24"
            />
          </FormRow>
          <FormRow label="Approval TTL" hint="Seconds cached approvals remain valid (300-900)">
            <Input
              type="number"
              min={300}
              max={900}
              value={form.hitl_approval_ttl_seconds}
              onChange={(e) => updateField('hitl_approval_ttl_seconds', e.target.value)}
              className="w-24"
            />
          </FormRow>
        </FormSection>

        {/* Pending Changes (saved but not running) */}
        {hasPendingChanges && (
          <div className="pt-4 border-t border-[var(--border-subtle)]">
            <PendingChangesSection changes={pendingChanges} />
          </div>
        )}

        {/* Config File Path (read-only) */}
        <div className="pt-4 border-t border-[var(--border-subtle)]">
          <div className="text-xs text-muted-foreground space-y-1">
            <div>Config file: <span className="font-mono">{config.config_path}</span></div>
            <div>Changes require proxy restart to take effect.</div>
          </div>
        </div>

        {/* Save Actions */}
        <div className="flex flex-col items-end gap-2 pt-4 border-t border-[var(--border-subtle)]">
          <div className="flex items-center gap-3">
            <Button
              variant="ghost"
              onClick={handleDiscard}
              disabled={!isDirty || saving}
            >
              Discard Changes
            </Button>
            <Button
              onClick={handleSave}
              disabled={!isDirty || saving}
            >
              {saving ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
          {isDirty && (
            <span className="text-xs text-orange-400/80">Unsaved changes</span>
          )}
        </div>
      </div>
    </Section>
  )
}

// =============================================================================
// Helper Components
// =============================================================================

interface FormSectionProps {
  title: string
  children: React.ReactNode
}

function FormSection({ title, children }: FormSectionProps) {
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-base-300 uppercase tracking-wide">{title}</h3>
      <div className="space-y-4">{children}</div>
    </div>
  )
}

interface FormRowProps {
  label: string
  hint?: string
  children: React.ReactNode
}

function FormRow({ label, hint, children }: FormRowProps) {
  const id = useId()

  // Clone child element to inject id for label association
  const childWithId = Children.only(children)
  const enhancedChild = isValidElement(childWithId)
    ? cloneElement(childWithId as React.ReactElement<{ id?: string }>, { id })
    : children

  return (
    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-center sm:gap-4">
      <div className="sm:w-40 shrink-0">
        <label htmlFor={id} className="text-sm font-medium">{label}</label>
        {hint && <p id={`${id}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
      </div>
      <div className="flex-1">{enhancedChild}</div>
    </div>
  )
}

interface PendingChangesSectionProps {
  changes: ConfigChange[]
}

/**
 * Format a value for display in the changelog.
 */
function formatValue(value: string | number | boolean | string[] | null): string {
  if (value === null || value === undefined) return '(not set)'
  if (Array.isArray(value)) return value.join(', ') || '(empty)'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'string' && value === '') return '(empty)'
  return String(value)
}

/**
 * Display pending changes between running and saved config.
 * These are changes that will take effect after restart.
 */
function PendingChangesSection({ changes }: PendingChangesSectionProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
        <h3 className="text-sm font-semibold text-amber-400">
          Pending Changes ({changes.length})
        </h3>
      </div>
      <p className="text-xs text-muted-foreground">
        These changes are saved to the config file but not yet active. Restart the proxy to apply.
      </p>
      <div className="bg-base-900/50 rounded-md border border-base-800 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-base-800 bg-base-900/50">
              <th className="text-left px-3 py-2 font-medium text-muted-foreground">Field</th>
              <th className="text-left px-3 py-2 font-medium text-muted-foreground">Running</th>
              <th className="text-left px-3 py-2 font-medium text-muted-foreground">Saved</th>
            </tr>
          </thead>
          <tbody>
            {changes.map((change, idx) => (
              <tr
                key={change.field}
                className={cn(
                  'border-b border-base-800/50 last:border-0',
                  idx % 2 === 0 ? 'bg-transparent' : 'bg-base-900/30'
                )}
              >
                <td className="px-3 py-2 font-mono text-base-300">{change.field}</td>
                <td className="px-3 py-2 text-red-400/80">
                  <span className="line-through opacity-60">{formatValue(change.running_value)}</span>
                </td>
                <td className="px-3 py-2 text-green-400/80">
                  {formatValue(change.saved_value)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
