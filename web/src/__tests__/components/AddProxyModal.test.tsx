/**
 * Unit tests for AddProxyModal component.
 *
 * Tests field validation on blur, transport-conditional rendering,
 * form submission, and state reset behavior.
 */

import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AddProxyModal } from '@/components/proxy/AddProxyModal'
import * as proxiesApi from '@/api/proxies'
import type { CreateProxyResponse } from '@/types/api'

// Mock the API module
vi.mock('@/api/proxies', () => ({
  createProxy: vi.fn(),
}))

// Mock error sound
vi.mock('@/hooks/useErrorSound', () => ({
  notifyError: vi.fn(),
}))

// Mock toast
vi.mock('@/components/ui/sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

// Mock scrollIntoView for Radix Select (not available in JSDOM)
beforeAll(() => {
  Element.prototype.scrollIntoView = vi.fn()
})

describe('AddProxyModal', () => {
  const defaultProps = {
    open: true,
    onOpenChange: vi.fn(),
    onCreated: vi.fn(),
  }

  const mockResponse: CreateProxyResponse = {
    ok: true,
    proxy_name: 'test-proxy',
    proxy_id: 'test-proxy-id-123',
    config_path: '/path/to/config.json',
    policy_path: '/path/to/policy.json',
    claude_desktop_snippet: {
      'test-proxy': {
        command: 'mcp-acp',
        args: ['start', '--proxy', 'test-proxy'],
      },
    },
    message: 'Proxy created successfully',
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.resetAllMocks()
  })

  describe('initial render', () => {
    it('renders form when open', () => {
      render(<AddProxyModal {...defaultProps} />)

      expect(screen.getByText('Add Proxy')).toBeInTheDocument()
      expect(screen.getByLabelText(/^Name/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Server Name/)).toBeInTheDocument()
    })

    it('does not show validation errors initially', () => {
      render(<AddProxyModal {...defaultProps} />)

      expect(screen.queryByText('Name is required')).not.toBeInTheDocument()
      expect(screen.queryByText('Server name is required')).not.toBeInTheDocument()
    })

    it('shows STDIO as default transport', () => {
      render(<AddProxyModal {...defaultProps} />)

      // STDIO fields should be visible by default
      expect(screen.getByLabelText(/Command/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Arguments/)).toBeInTheDocument()
    })

    it('has submit button disabled initially due to validation', () => {
      render(<AddProxyModal {...defaultProps} />)

      const submitButton = screen.getByRole('button', { name: /Create Proxy/i })
      expect(submitButton).toBeDisabled()
    })
  })

  describe('field validation on blur', () => {
    it('shows name error after blur when empty', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const nameInput = screen.getByLabelText(/^Name/)
      await user.click(nameInput)
      await user.tab() // blur

      expect(screen.getByText('Name is required')).toBeInTheDocument()
    })

    it('shows name error for invalid characters after blur', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const nameInput = screen.getByLabelText(/^Name/)
      await user.type(nameInput, 'invalid name!')
      await user.tab()

      expect(screen.getByText(/Must start with letter or number/)).toBeInTheDocument()
    })

    it('shows error when name starts with underscore', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.type(screen.getByLabelText(/^Name/), '_invalid')
      await user.tab()

      expect(screen.getByText(/Must start with letter or number/)).toBeInTheDocument()
    })

    it('shows error for reserved name', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.type(screen.getByLabelText(/^Name/), 'manager')
      await user.tab()

      expect(screen.getByText(/reserved/i)).toBeInTheDocument()
    })

    it('shows error when name too long', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.type(screen.getByLabelText(/^Name/), 'a'.repeat(65))
      await user.tab()

      expect(screen.getByText(/too long/i)).toBeInTheDocument()
    })

    it('clears name error when valid input entered', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const nameInput = screen.getByLabelText(/^Name/)
      await user.click(nameInput)
      await user.tab() // blur - shows error

      expect(screen.getByText('Name is required')).toBeInTheDocument()

      await user.type(nameInput, 'valid-name')

      expect(screen.queryByText('Name is required')).not.toBeInTheDocument()
    })

    it('shows server name error after blur when empty', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const serverNameInput = screen.getByLabelText(/Server Name/)
      await user.click(serverNameInput)
      await user.tab()

      expect(screen.getByText('Server name is required')).toBeInTheDocument()
    })

    it('shows command error after blur when empty (STDIO transport)', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const commandInput = screen.getByLabelText(/Command/)
      await user.click(commandInput)
      await user.tab()

      expect(screen.getByText('Command is required for STDIO transport')).toBeInTheDocument()
    })

    it('shows URL error after blur when empty (HTTP transport)', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      // Change to HTTP transport
      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      const urlInput = screen.getByLabelText(/URL/)
      await user.click(urlInput)
      await user.tab()

      expect(screen.getByText('URL is required for HTTP transport')).toBeInTheDocument()
    })

    it('shows error for URL without scheme', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      // Switch to HTTP transport
      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      await user.type(screen.getByLabelText(/URL/), 'localhost:3000')
      await user.tab()

      expect(screen.getByText(/must start with http/i)).toBeInTheDocument()
    })

    it('accepts valid http URL', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      await user.type(screen.getByLabelText(/URL/), 'http://localhost:3000')
      await user.tab()

      expect(screen.queryByText(/must start with http/i)).not.toBeInTheDocument()
    })

    it('shows mTLS error when partially configured', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      // Change to HTTP transport to see mTLS fields
      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      // Expand Advanced section
      await user.click(screen.getByText('Advanced'))

      // Fill only cert path
      const certInput = screen.getByLabelText(/Cert Path/)
      await user.type(certInput, '/path/to/cert.pem')
      await user.tab()

      expect(screen.getByText('mTLS requires all three: cert, key, and CA')).toBeInTheDocument()
    })

    it('shows error for invalid SHA-256 length', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.click(screen.getByText('Advanced'))
      await user.type(screen.getByLabelText(/SHA-256/), 'abc123')
      await user.tab()

      expect(screen.getByText(/64 hexadecimal/i)).toBeInTheDocument()
    })

    it('accepts valid SHA-256 hash', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.click(screen.getByText('Advanced'))
      // Valid 64-character hex string
      await user.type(screen.getByLabelText(/SHA-256/), 'a'.repeat(64))
      await user.tab()

      expect(screen.queryByText(/64 hexadecimal/i)).not.toBeInTheDocument()
    })
  })

  describe('transport-conditional rendering', () => {
    it('shows STDIO fields for stdio transport', () => {
      render(<AddProxyModal {...defaultProps} />)

      expect(screen.getByText('STDIO Configuration')).toBeInTheDocument()
      expect(screen.getByLabelText(/Command/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Arguments/)).toBeInTheDocument()
    })

    it('shows HTTP fields for streamablehttp transport', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      expect(screen.getByText('HTTP Configuration')).toBeInTheDocument()
      expect(screen.getByLabelText(/URL/)).toBeInTheDocument()
      // STDIO fields should not be visible
      expect(screen.queryByText('STDIO Configuration')).not.toBeInTheDocument()
      // API Key is in the Advanced section, not the main HTTP section
      expect(screen.queryByLabelText(/API Key/)).not.toBeInTheDocument()
      await user.click(screen.getByText('Advanced'))
      expect(screen.getByLabelText(/API Key/)).toBeInTheDocument()
    })

    it('shows both STDIO and HTTP fields for auto transport', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^Auto/))

      expect(screen.getByText('STDIO Configuration')).toBeInTheDocument()
      expect(screen.getByText('HTTP Configuration')).toBeInTheDocument()
    })

    it('shows attestation in Advanced for STDIO transport', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.click(screen.getByText('Advanced'))

      expect(screen.getByText('SLSA Attestation (binary verification)')).toBeInTheDocument()
      expect(screen.getByLabelText(/SLSA Owner/)).toBeInTheDocument()
      expect(screen.getByLabelText(/SHA-256/)).toBeInTheDocument()
      expect(screen.getByText(/Require code signature/)).toBeInTheDocument()
      // mTLS should not be visible for STDIO
      expect(screen.queryByText('HTTP Options')).not.toBeInTheDocument()
    })

    it('shows mTLS in Advanced for HTTP transport', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      await user.click(screen.getByText('Advanced'))

      expect(screen.getByText('HTTP Options')).toBeInTheDocument()
      expect(screen.getByLabelText(/Timeout/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Cert Path/)).toBeInTheDocument()
      expect(screen.getByLabelText(/Key Path/)).toBeInTheDocument()
      expect(screen.getByLabelText(/CA Path/)).toBeInTheDocument()
      // Attestation should not be visible for HTTP
      expect(screen.queryByText('SLSA Attestation (binary verification)')).not.toBeInTheDocument()
    })

    it('shows both attestation and mTLS in Advanced for auto transport', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^Auto/))

      await user.click(screen.getByText('Advanced'))

      expect(screen.getByText('SLSA Attestation (binary verification)')).toBeInTheDocument()
      expect(screen.getByText('HTTP Options')).toBeInTheDocument()
    })

    it('shows correct auto transport description', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)

      expect(screen.getByText(/Prefer HTTP if reachable, fallback to STDIO/)).toBeInTheDocument()
    })
  })

  describe('form submission', () => {
    it('submits with correct payload for STDIO proxy', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockResolvedValue(mockResponse)

      render(<AddProxyModal {...defaultProps} />)

      // Fill required fields
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')
      await user.type(screen.getByLabelText(/Arguments/), '-y @test/server')

      // Submit
      const submitButton = screen.getByRole('button', { name: /Create Proxy/i })
      await user.click(submitButton)

      await waitFor(() => {
        expect(proxiesApi.createProxy).toHaveBeenCalledWith(
          expect.objectContaining({
            name: 'test-proxy',
            server_name: 'Test Server',
            transport: 'stdio',
            command: 'npx',
            args: ['-y', '@test/server'],
          })
        )
      })
    })

    it('submits with correct payload for HTTP proxy', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockResolvedValue(mockResponse)

      render(<AddProxyModal {...defaultProps} />)

      // Fill required fields
      await user.type(screen.getByLabelText(/^Name/), 'http-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'HTTP Server')

      // Change to HTTP transport
      const transportTrigger = screen.getByRole('combobox')
      await user.click(transportTrigger)
      await user.click(screen.getByText(/^HTTP/))

      await user.type(screen.getByLabelText(/URL/), 'http://localhost:3000/mcp')

      // Submit
      const submitButton = screen.getByRole('button', { name: /Create Proxy/i })
      await user.click(submitButton)

      await waitFor(() => {
        expect(proxiesApi.createProxy).toHaveBeenCalledWith(
          expect.objectContaining({
            name: 'http-proxy',
            server_name: 'HTTP Server',
            transport: 'streamablehttp',
            url: 'http://localhost:3000/mcp',
          })
        )
      })
    })

    it('shows success view after successful submission', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockResolvedValue(mockResponse)
      const { toast } = await import('@/components/ui/sonner')

      render(<AddProxyModal {...defaultProps} />)

      // Fill required fields
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')

      // Submit
      await user.click(screen.getByRole('button', { name: /Create Proxy/i }))

      await waitFor(() => {
        expect(screen.getByText('Proxy Created')).toBeInTheDocument()
      })

      expect(toast.success).toHaveBeenCalledWith('Proxy "test-proxy" created')
      expect(screen.getByText(/Add this to your Claude Desktop/)).toBeInTheDocument()
    })

    it('shows error message on submission failure', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockRejectedValue(new Error('Proxy already exists'))

      render(<AddProxyModal {...defaultProps} />)

      // Fill required fields
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')

      // Submit
      await user.click(screen.getByRole('button', { name: /Create Proxy/i }))

      await waitFor(() => {
        expect(screen.getByText('Proxy already exists')).toBeInTheDocument()
      })
    })

    it('disables submit button during submission', async () => {
      const user = userEvent.setup()
      let resolvePromise: (value: CreateProxyResponse) => void
      vi.mocked(proxiesApi.createProxy).mockImplementation(
        () => new Promise((resolve) => { resolvePromise = resolve })
      )

      render(<AddProxyModal {...defaultProps} />)

      // Fill required fields
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')

      // Submit
      const submitButton = screen.getByRole('button', { name: /Create Proxy/i })
      await user.click(submitButton)

      expect(screen.getByRole('button', { name: /Creating.../i })).toBeDisabled()

      // Resolve to complete the test
      resolvePromise!(mockResponse)
    })

    it('does not submit when validation errors exist', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      // Fill only name, leave others empty
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')

      const submitButton = screen.getByRole('button', { name: /Create Proxy/i })
      expect(submitButton).toBeDisabled()

      expect(proxiesApi.createProxy).not.toHaveBeenCalled()
    })
  })

  describe('success view', () => {
    it('shows copied feedback when copy button clicked', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockResolvedValue(mockResponse)

      render(<AddProxyModal {...defaultProps} />)

      // Fill and submit
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')
      await user.click(screen.getByRole('button', { name: /Create Proxy/i }))

      await waitFor(() => {
        expect(screen.getByText('Proxy Created')).toBeInTheDocument()
      })

      // Click copy button - should show "Copied!" feedback
      await user.click(screen.getByRole('button', { name: /Copy/i }))

      await waitFor(() => {
        expect(screen.getByText('Copied!')).toBeInTheDocument()
      })
    })

    it('calls onCreated and onOpenChange when Done clicked', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockResolvedValue(mockResponse)

      render(<AddProxyModal {...defaultProps} />)

      // Fill and submit
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')
      await user.click(screen.getByRole('button', { name: /Create Proxy/i }))

      await waitFor(() => {
        expect(screen.getByText('Proxy Created')).toBeInTheDocument()
      })

      // Click Done
      await user.click(screen.getByRole('button', { name: /Done/i }))

      expect(defaultProps.onOpenChange).toHaveBeenCalledWith(false)
      expect(defaultProps.onCreated).toHaveBeenCalled()
    })
  })

  describe('reset on open', () => {
    it('resets form when modal opens', async () => {
      const user = userEvent.setup()
      const { rerender } = render(<AddProxyModal {...defaultProps} />)

      // Fill some fields
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')

      // Close and reopen
      rerender(<AddProxyModal {...defaultProps} open={false} />)
      rerender(<AddProxyModal {...defaultProps} open={true} />)

      // Fields should be empty
      expect(screen.getByLabelText(/^Name/)).toHaveValue('')
      expect(screen.getByLabelText(/Server Name/)).toHaveValue('')
    })

    it('clears touched state when modal opens', async () => {
      const user = userEvent.setup()
      const { rerender } = render(<AddProxyModal {...defaultProps} />)

      // Trigger validation error
      const nameInput = screen.getByLabelText(/^Name/)
      await user.click(nameInput)
      await user.tab()
      expect(screen.getByText('Name is required')).toBeInTheDocument()

      // Close and reopen
      rerender(<AddProxyModal {...defaultProps} open={false} />)
      rerender(<AddProxyModal {...defaultProps} open={true} />)

      // Error should not be visible
      expect(screen.queryByText('Name is required')).not.toBeInTheDocument()
    })

    it('resets to form view after success when reopened', async () => {
      const user = userEvent.setup()
      vi.mocked(proxiesApi.createProxy).mockResolvedValue(mockResponse)
      const { rerender } = render(<AddProxyModal {...defaultProps} />)

      // Fill and submit
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')
      await user.click(screen.getByRole('button', { name: /Create Proxy/i }))

      await waitFor(() => {
        expect(screen.getByText('Proxy Created')).toBeInTheDocument()
      })

      // Close and reopen
      rerender(<AddProxyModal {...defaultProps} open={false} />)
      rerender(<AddProxyModal {...defaultProps} open={true} />)

      // Should be back to form view
      expect(screen.getByText('Add Proxy')).toBeInTheDocument()
      expect(screen.queryByText('Proxy Created')).not.toBeInTheDocument()
    })
  })

  describe('cancel button', () => {
    it('calls onOpenChange with false when Cancel clicked', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      await user.click(screen.getByRole('button', { name: /Cancel/i }))

      expect(defaultProps.onOpenChange).toHaveBeenCalledWith(false)
    })

    it('Cancel button is disabled during submission', async () => {
      const user = userEvent.setup()
      let resolvePromise: (value: CreateProxyResponse) => void
      vi.mocked(proxiesApi.createProxy).mockImplementation(
        () => new Promise((resolve) => { resolvePromise = resolve })
      )

      render(<AddProxyModal {...defaultProps} />)

      // Fill required fields
      await user.type(screen.getByLabelText(/^Name/), 'test-proxy')
      await user.type(screen.getByLabelText(/Server Name/), 'Test Server')
      await user.type(screen.getByLabelText(/Command/), 'npx')

      // Submit
      await user.click(screen.getByRole('button', { name: /Create Proxy/i }))

      expect(screen.getByRole('button', { name: /Cancel/i })).toBeDisabled()

      // Resolve to complete the test
      resolvePromise!(mockResponse)
    })
  })

  describe('Advanced section toggle', () => {
    it('shows "(configured)" when advanced values are set', async () => {
      const user = userEvent.setup()
      render(<AddProxyModal {...defaultProps} />)

      // Expand Advanced and fill attestation
      await user.click(screen.getByText('Advanced'))
      await user.type(screen.getByLabelText(/SLSA Owner/), 'owner/repo')

      // Collapse and check indicator
      await user.click(screen.getByText('Advanced'))

      expect(screen.getByText('(configured)')).toBeInTheDocument()
    })

    it('collapses Advanced section by default', () => {
      render(<AddProxyModal {...defaultProps} />)

      expect(screen.queryByText('SLSA Attestation (binary verification)')).not.toBeInTheDocument()
    })
  })
})
