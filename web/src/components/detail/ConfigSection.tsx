import { useState, useEffect, useMemo, useCallback, useId, cloneElement, isValidElement, Children } from 'react'
import { Key, Trash2 } from 'lucide-react'
import { Section } from './Section'
import { SetApiKeyDialog, DeleteApiKeyDialog } from './ApiKeyDialogs'
import { PendingChangesSection } from './PendingChangesSection'
import { configToFormState, formStatesEqual, formStateToUpdateRequest, COMMON_SCOPES } from './configTransform'
import type { FormState } from './configTransform'
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
import { setProxyApiKey, deleteProxyApiKey } from '@/api/config'
import type { TransportType } from '@/api/config'

interface ConfigSectionProps {
  loaded?: boolean
  /** When provided, uses manager-level endpoints to access config regardless of proxy status */
  proxyId?: string
}

export function ConfigSection({ loaded = true, proxyId }: ConfigSectionProps) {
  const { config, loading, saving, save, refresh, setConfig, pendingChanges, hasPendingChanges } = useConfig({ proxyId })
  const { status: authStatus } = useAuth()
  const [form, setForm] = useState<FormState | null>(null)

  // API Key management state
  const [showApiKeyDialog, setShowApiKeyDialog] = useState(false)
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [savingApiKey, setSavingApiKey] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

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
      if (!formStatesEqual(newFormState, form)) {
        setForm(newFormState)
      }
    }
  }, [config]) // eslint-disable-line react-hooks/exhaustive-deps

  // Check if form is dirty (has unsaved changes)
  const isDirty = useMemo(() => {
    if (!config || !form) return false
    const original = configToFormState(config)
    return !formStatesEqual(form, original)
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

  // Set/Update API Key
  const handleSetApiKey = useCallback(async () => {
    if (!proxyId || !apiKeyInput.trim()) return

    if (!authStatus?.authenticated) {
      notifyError('You must be logged in to manage API keys')
      return
    }

    try {
      setSavingApiKey(true)
      const result = await setProxyApiKey(proxyId, apiKeyInput.trim())
      if (result.success) {
        toast.success(result.message)
        setShowApiKeyDialog(false)
        setApiKeyInput('')
        // Update credential_key locally — avoids full refresh which would lose dirty form edits
        if (config?.backend.http) {
          setConfig({
            ...config,
            backend: {
              ...config.backend,
              http: { ...config.backend.http, credential_key: result.credential_key },
            },
          })
        }
      } else {
        notifyError(result.message)
      }
    } catch (err) {
      if (err instanceof Error) {
        notifyError(err.message)
      } else {
        notifyError('Failed to set API key')
      }
    } finally {
      setSavingApiKey(false)
    }
  }, [proxyId, apiKeyInput, authStatus, config, setConfig])

  // Delete API Key
  const handleDeleteApiKey = useCallback(async () => {
    if (!proxyId) return

    if (!authStatus?.authenticated) {
      notifyError('You must be logged in to manage API keys')
      return
    }

    try {
      setSavingApiKey(true)
      const result = await deleteProxyApiKey(proxyId)
      if (result.success) {
        toast.success(result.message)
        setShowDeleteConfirm(false)
        // Update credential_key locally — avoids full refresh which would lose dirty form edits
        if (config?.backend.http) {
          setConfig({
            ...config,
            backend: {
              ...config.backend,
              http: { ...config.backend.http, credential_key: null },
            },
          })
        }
      } else {
        notifyError(result.message)
      }
    } catch (err) {
      if (err instanceof Error) {
        notifyError(err.message)
      } else {
        notifyError('Failed to delete API key')
      }
    } finally {
      setSavingApiKey(false)
    }
  }, [proxyId, authStatus, config, setConfig])

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

        {/* Logging Settings */}
        <FormSection title="Logging">
          <FormRow label="Log Directory" hint="Derived from proxy name (read-only)">
            <Input
              value={form.log_dir}
              className="max-w-md bg-base-900/50 text-muted-foreground"
              disabled
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
          {form.log_level === 'DEBUG' && (
            <FormRow label="Include Payloads" hint="Include full message content in debug logs">
              <Switch
                checked={form.include_payloads}
                onCheckedChange={(checked) => updateField('include_payloads', checked)}
              />
            </FormRow>
          )}
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

        {/* Backend Authentication - Binary Attestation, mTLS, API Key */}
        {(isStdioActive || isHttpActive) && (
          <FormSection title="Backend Authentication">
            {/* Binary Attestation - for STDIO */}
            {isStdioActive && (
              <>
                <div className="text-xs uppercase tracking-wide text-muted-foreground">Binary Attestation</div>
                <FormRow label="SLSA Owner" hint="GitHub owner/repo for SLSA verification">
                  <Input
                    value={form.attestation_slsa_owner}
                    onChange={(e) => updateField('attestation_slsa_owner', e.target.value)}
                    className="max-w-md"
                    placeholder="e.g., github-owner/repo"
                  />
                </FormRow>
                <FormRow label="SHA-256" hint="Expected binary hash (64 hex characters)">
                  <Input
                    value={form.attestation_sha256}
                    onChange={(e) => updateField('attestation_sha256', e.target.value)}
                    className="max-w-md"
                    placeholder="64-character hex hash"
                  />
                </FormRow>
                <FormRow label="Require Signature" hint="Require code signature (macOS only)">
                  <Switch
                    checked={form.attestation_require_signature}
                    onCheckedChange={(checked) => updateField('attestation_require_signature', checked)}
                  />
                </FormRow>
              </>
            )}

            {/* mTLS - for HTTP */}
            {isHttpActive && (
              <>
                {isStdioActive && <div className="border-t border-base-800 my-4" />}
                <div className="text-xs uppercase tracking-wide text-muted-foreground">mTLS Authentication</div>
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

                {/* API Key */}
                <div className="pt-4 text-xs uppercase tracking-wide text-muted-foreground">Backend API Key</div>
                <FormRow label="API Key" hint="Stored securely in OS keychain">
                  <div className="flex items-center gap-3">
                    {config.backend.http?.credential_key ? (
                      <>
                        <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-success-bg text-success-muted text-xs font-medium rounded border border-success-border">
                          <span className="w-1.5 h-1.5 rounded-full bg-success" />
                          Configured
                        </span>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setShowApiKeyDialog(true)}
                          disabled={savingApiKey}
                        >
                          <Key className="w-3.5 h-3.5 mr-1.5" />
                          Update
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setShowDeleteConfirm(true)}
                          disabled={savingApiKey}
                          className="text-error border-error/30 hover:bg-error/10"
                        >
                          <Trash2 className="w-3.5 h-3.5 mr-1.5" />
                          Remove
                        </Button>
                      </>
                    ) : (
                      <>
                        <span className="inline-flex items-center gap-1.5 px-2 py-1 bg-base-800 text-muted-foreground text-xs font-medium rounded border border-base-700">
                          Not configured
                        </span>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setShowApiKeyDialog(true)}
                          disabled={savingApiKey}
                        >
                          <Key className="w-3.5 h-3.5 mr-1.5" />
                          Set API Key
                        </Button>
                      </>
                    )}
                  </div>
                </FormRow>
              </>
            )}
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

      {/* API Key Dialogs */}
      <SetApiKeyDialog
        open={showApiKeyDialog}
        onOpenChange={setShowApiKeyDialog}
        isUpdate={!!config.backend.http?.credential_key}
        apiKeyInput={apiKeyInput}
        onApiKeyInputChange={setApiKeyInput}
        onSave={handleSetApiKey}
        saving={savingApiKey}
      />
      <DeleteApiKeyDialog
        open={showDeleteConfirm}
        onOpenChange={setShowDeleteConfirm}
        onDelete={handleDeleteApiKey}
        saving={savingApiKey}
      />
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
