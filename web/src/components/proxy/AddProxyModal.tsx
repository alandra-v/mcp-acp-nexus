/**
 * Modal for adding a new proxy configuration.
 *
 * Features:
 * - Form with transport-specific fields
 * - Field validation on blur
 * - Collapsible Advanced section:
 *   - Attestation (STDIO/Auto transports)
 *   - mTLS and timeout (HTTP/Auto transports)
 * - Success state showing Claude Desktop snippet
 * - Copy to clipboard button
 */

import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DEFAULT_HTTP_TIMEOUT_SECONDS } from '@/constants'
import type { TransportType } from '@/types/api'
import { TRANSPORT_OPTIONS } from './addProxyConstants'
import { useAddProxyForm } from './useAddProxyForm'

interface AddProxyModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated: () => void
}

export function AddProxyModal({
  open,
  onOpenChange,
  onCreated,
}: AddProxyModalProps) {
  const {
    view,
    formState,
    touched,
    fieldErrors,
    isValid,
    isStdio,
    isHttp,
    isHttpOnly,
    submitting,
    error,
    result,
    copied,
    showAdvanced,
    setShowAdvanced,
    hasAdvancedValues,
    showHealthCheckConfirm,
    healthCheckMessage,
    setShowHealthCheckConfirm,
    showDuplicateConfirm,
    duplicateMessage,
    setShowDuplicateConfirm,
    updateField,
    handleBlur,
    handleArgsChange,
    handleSubmit,
    handleCopy,
    handleDone,
    handleConfirmSkipHealthCheck,
    handleConfirmSkipDuplicate,
  } = useAddProxyForm({ open, onCreated, onOpenChange })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        {view === 'form' ? (
          <>
            <DialogHeader>
              <DialogTitle>Add Proxy</DialogTitle>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {/* Error message */}
              {error && (
                <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-md text-sm text-destructive">
                  {error}
                </div>
              )}

              {/* Name */}
              <div className="space-y-2">
                <label htmlFor="proxy-name" className="text-sm font-medium">
                  Name <span className="text-destructive">*</span>
                </label>
                <Input
                  id="proxy-name"
                  placeholder="e.g., filesystem, github-api"
                  value={formState.name}
                  onChange={(e) => updateField('name', e.target.value)}
                  onBlur={() => handleBlur('name')}
                  className={touched.name && fieldErrors.name ? 'border-destructive' : ''}
                />
                {touched.name && fieldErrors.name ? (
                  <p className="text-xs text-destructive">{fieldErrors.name}</p>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Unique identifier (must start with letter or number)
                  </p>
                )}
              </div>

              {/* Server Name */}
              <div className="space-y-2">
                <label htmlFor="proxy-server-name" className="text-sm font-medium">
                  Server Name <span className="text-destructive">*</span>
                </label>
                <Input
                  id="proxy-server-name"
                  placeholder="e.g., MCP Filesystem Server"
                  value={formState.server_name}
                  onChange={(e) => updateField('server_name', e.target.value)}
                  onBlur={() => handleBlur('server_name')}
                  className={touched.server_name && fieldErrors.server_name ? 'border-destructive' : ''}
                />
                {touched.server_name && fieldErrors.server_name ? (
                  <p className="text-xs text-destructive">{fieldErrors.server_name}</p>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Display name shown in the UI
                  </p>
                )}
              </div>

              {/* Transport Type */}
              <div className="space-y-2">
                <label htmlFor="proxy-transport" className="text-sm font-medium">
                  Transport <span className="text-destructive">*</span>
                </label>
                <Select
                  value={formState.transport}
                  onValueChange={(value) => updateField('transport', value as TransportType)}
                >
                  <SelectTrigger id="proxy-transport">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TRANSPORT_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        <span className="font-medium">{option.label}</span>
                        <span className="text-muted-foreground ml-2">- {option.description}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* STDIO Fields */}
              {isStdio && (
                <div className="space-y-3 pt-2 border-t border-base-800">
                  <h4 className="text-sm font-medium text-muted-foreground">STDIO Configuration</h4>

                  {/* Command */}
                  <div className="space-y-1">
                    <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                      <label htmlFor="proxy-command" className="text-sm">
                        Command <span className="text-destructive">*</span>
                      </label>
                      <Input
                        id="proxy-command"
                        placeholder="e.g., npx, python, node"
                        value={formState.command || ''}
                        onChange={(e) => updateField('command', e.target.value)}
                        onBlur={() => handleBlur('command')}
                        className={touched.command && fieldErrors.command ? 'border-destructive' : ''}
                      />
                    </div>
                    {touched.command && fieldErrors.command && (
                      <p className="text-xs text-destructive ml-[108px]">{fieldErrors.command}</p>
                    )}
                  </div>

                  {/* Args */}
                  <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                    <label htmlFor="proxy-args" className="text-sm">Arguments</label>
                    <Input
                      id="proxy-args"
                      placeholder="e.g., @modelcontextprotocol/server-filesystem /path"
                      value={formState.args?.join(' ') || ''}
                      onChange={(e) => handleArgsChange(e.target.value)}
                    />
                  </div>
                </div>
              )}

              {/* HTTP Fields */}
              {isHttp && (
                <div className="space-y-3 pt-2 border-t border-base-800">
                  <h4 className="text-sm font-medium text-muted-foreground">HTTP Configuration</h4>

                  {/* URL */}
                  <div className="space-y-1">
                    <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                      <label htmlFor="proxy-url" className="text-sm">
                        URL {isHttpOnly && <span className="text-destructive">*</span>}
                      </label>
                      <Input
                        id="proxy-url"
                        placeholder="e.g., http://localhost:3000/mcp"
                        value={formState.url || ''}
                        onChange={(e) => updateField('url', e.target.value)}
                        onBlur={() => handleBlur('url')}
                        className={touched.url && fieldErrors.url ? 'border-destructive' : ''}
                      />
                    </div>
                    {touched.url && fieldErrors.url && (
                      <p className="text-xs text-destructive ml-[108px]">{fieldErrors.url}</p>
                    )}
                  </div>
                </div>
              )}

              {/* Advanced Toggle */}
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors pt-2"
              >
                {showAdvanced ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                Advanced
                {hasAdvancedValues && <span className="text-xs text-primary ml-1">(configured)</span>}
              </button>

              {/* Advanced Fields */}
              {showAdvanced && (
                <div className="space-y-4 pl-4 border-l-2 border-base-800 ml-2">
                  {/* Attestation - for STDIO and Auto */}
                  {isStdio && (
                    <div className="space-y-3">
                      <p className="text-xs text-muted-foreground font-medium">
                        SLSA Attestation (binary verification)
                      </p>

                      <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                        <label htmlFor="proxy-slsa-owner" className="text-sm">SLSA Owner</label>
                        <Input
                          id="proxy-slsa-owner"
                          placeholder="e.g., github-owner/repo"
                          value={formState.attestation_slsa_owner || ''}
                          onChange={(e) => updateField('attestation_slsa_owner', e.target.value)}
                        />
                      </div>

                      <div className="space-y-1">
                        <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                          <label htmlFor="proxy-sha256" className="text-sm">SHA-256</label>
                          <Input
                            id="proxy-sha256"
                            placeholder="64-character hex hash"
                            value={formState.attestation_sha256 || ''}
                            onChange={(e) => updateField('attestation_sha256', e.target.value)}
                            onBlur={() => handleBlur('attestation_sha256')}
                            className={touched.attestation_sha256 && fieldErrors.attestation_sha256 ? 'border-destructive' : ''}
                          />
                        </div>
                        {touched.attestation_sha256 && fieldErrors.attestation_sha256 && (
                          <p className="text-xs text-destructive ml-[108px]">{fieldErrors.attestation_sha256}</p>
                        )}
                      </div>

                      <label className="flex items-center gap-2 text-sm">
                        <input
                          type="checkbox"
                          checked={formState.attestation_require_signature || false}
                          onChange={(e) => updateField('attestation_require_signature', e.target.checked)}
                          className="rounded border-base-600"
                        />
                        Require code signature (macOS only)
                      </label>
                    </div>
                  )}

                  {/* mTLS, API Key, and Timeout - for HTTP and Auto */}
                  {isHttp && (
                    <div className="space-y-3">
                      <p className="text-xs text-muted-foreground font-medium">
                        HTTP Options
                      </p>

                      {/* API Key */}
                      <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                        <label htmlFor="proxy-api-key" className="text-sm">API Key</label>
                        <Input
                          id="proxy-api-key"
                          type="password"
                          placeholder="Optional - stored in keychain"
                          value={formState.api_key || ''}
                          onChange={(e) => updateField('api_key', e.target.value)}
                        />
                      </div>

                      {/* Timeout */}
                      <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                        <label htmlFor="proxy-timeout" className="text-sm">Timeout (s)</label>
                        <Input
                          id="proxy-timeout"
                          type="number"
                          min={1}
                          max={300}
                          value={formState.timeout || DEFAULT_HTTP_TIMEOUT_SECONDS}
                          onChange={(e) => updateField('timeout', parseInt(e.target.value) || DEFAULT_HTTP_TIMEOUT_SECONDS)}
                        />
                      </div>

                      {/* mTLS */}
                      <p className="text-xs text-muted-foreground pt-2">
                        mTLS client certificates (all three required if any specified)
                      </p>
                      {touched.mtls && fieldErrors.mtls && (
                        <p className="text-xs text-destructive">{fieldErrors.mtls}</p>
                      )}

                      <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                        <label htmlFor="proxy-mtls-cert" className="text-sm">Cert Path</label>
                        <Input
                          id="proxy-mtls-cert"
                          placeholder="/path/to/client.pem"
                          value={formState.mtls_cert || ''}
                          onChange={(e) => updateField('mtls_cert', e.target.value)}
                          onBlur={() => handleBlur('mtls')}
                        />
                      </div>

                      <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                        <label htmlFor="proxy-mtls-key" className="text-sm">Key Path</label>
                        <Input
                          id="proxy-mtls-key"
                          placeholder="/path/to/client.key"
                          value={formState.mtls_key || ''}
                          onChange={(e) => updateField('mtls_key', e.target.value)}
                          onBlur={() => handleBlur('mtls')}
                        />
                      </div>

                      <div className="grid grid-cols-[100px_1fr] gap-2 items-center">
                        <label htmlFor="proxy-mtls-ca" className="text-sm">CA Path</label>
                        <Input
                          id="proxy-mtls-ca"
                          placeholder="/path/to/ca.pem"
                          value={formState.mtls_ca || ''}
                          onChange={(e) => updateField('mtls_ca', e.target.value)}
                          onBlur={() => handleBlur('mtls')}
                        />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
                Cancel
              </Button>
              <Button onClick={handleSubmit} disabled={!isValid || submitting}>
                {submitting ? 'Creating...' : 'Create Proxy'}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Proxy Created</DialogTitle>
            </DialogHeader>

            <div className="py-6 space-y-4">
              <p className="text-sm text-muted-foreground">
                Add this to your Claude Desktop configuration file:
              </p>

              {/* Snippet */}
              <div className="relative">
                <pre className="p-4 bg-base-900 rounded-lg text-sm font-mono overflow-x-auto">
                  {JSON.stringify({ mcpServers: result?.claude_desktop_snippet }, null, 2)}
                </pre>
                <Button
                  variant="outline"
                  size="sm"
                  className="absolute top-2 right-2"
                  onClick={handleCopy}
                >
                  {copied ? (
                    <>
                      <Check className="w-4 h-4 mr-1" />
                      Copied!
                    </>
                  ) : (
                    <>
                      <Copy className="w-4 h-4 mr-1" />
                      Copy
                    </>
                  )}
                </Button>
              </div>

              <p className="text-xs text-muted-foreground">
                Config location: <code className="text-base-400">{result?.config_path}</code>
              </p>
            </div>

            <DialogFooter>
              <Button onClick={handleDone}>Done</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>

      {/* Health check confirmation dialog */}
      <AlertDialog open={showHealthCheckConfirm} onOpenChange={setShowHealthCheckConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Server unreachable</AlertDialogTitle>
            <AlertDialogDescription>
              {healthCheckMessage}
              {' '}The server may be offline temporarily. Continue anyway?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleConfirmSkipHealthCheck}>
              Continue
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Duplicate backend confirmation dialog */}
      <AlertDialog open={showDuplicateConfirm} onOpenChange={setShowDuplicateConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Duplicate backend</AlertDialogTitle>
            <AlertDialogDescription>
              {duplicateMessage} Continue anyway?
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleConfirmSkipDuplicate}>
              Continue
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Dialog>
  )
}
