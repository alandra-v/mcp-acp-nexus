# Backend Authentication

Backend authentication secures the connection between the proxy and backend MCP servers.

---

## API Key / Bearer Token

For HTTP backends that require API key or bearer token authentication, credentials are stored securely in the OS keychain and sent with each request.

### Configuration

**Interactive setup** (during `mcp-acp proxy add`):

```
$ mcp-acp proxy add
...
Configure API key for backend authentication? (y/n) y
API key (will be stored securely in keychain): ****
```

**Non-interactive setup**:

```bash
mcp-acp proxy add \
  --name my-proxy \
  --server-name backend \
  --connection-type http \
  --url https://backend.example.com/mcp \
  --api-key "sk-your-api-key-here"
```

### How It Works

1. API key is stored in OS keychain (never in config files)
2. Config file stores only a reference key:
   ```json
   {
     "http": {
       "url": "https://backend.example.com/mcp",
       "timeout": 30,
       "credential_key": "proxy:my-proxy:backend"
     }
   }
   ```
3. At runtime, proxy retrieves credential from keychain
4. Credential sent as `Authorization: Bearer <token>` header

### Secure Storage

Credentials are stored using OS-native secure storage:

| Platform | Storage Backend |
|----------|-----------------|
| macOS | Keychain (via `keyring`) |
| Linux | Secret Service / D-Bus |
| Windows | Credential Locker |
| Fallback | Encrypted file (Fernet AES-128-CBC with PBKDF2-SHA256) |

**Keychain service name**: `mcp-acp`
**Credential key format**: `proxy:{proxy_name}:backend`

### Updating Credentials

To update an API key, re-run proxy add or use the credential storage directly:

```bash
# Remove and re-add the proxy
mcp-acp proxy remove my-proxy
mcp-acp proxy add --name my-proxy --api-key "new-key" ...
```

---

## mTLS (Mutual TLS)

mTLS provides mutual authentication - the proxy presents a client certificate to prove its identity to the backend.

```
Standard TLS (one-way):
┌───────┐                    ┌─────────┐
│ Proxy │ ──── TLS ────────► │ Backend │
│       │ ◄─ Server Cert ─── │         │
└───────┘    (verified)      └─────────┘
Backend identity verified, but backend doesn't know who proxy is

mTLS (two-way):
┌───────┐                    ┌─────────┐
│ Proxy │ ──── TLS ────────► │ Backend │
│       │ ◄─ Server Cert ─── │         │  Backend presents cert
│       │ ── Client Cert ──► │         │  Proxy presents cert
└───────┘    (both verified) └─────────┘
```

### Configuration

mTLS is configured during `mcp-acp init` when an HTTPS backend is detected:

```json
{
  "auth": {
    "mtls": {
      "client_cert_path": "/path/to/client.pem",
      "client_key_path": "/path/to/client-key.pem",
      "ca_bundle_path": "/path/to/ca-bundle.pem"
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `client_cert_path` | Client certificate (PEM) - presented to backend |
| `client_key_path` | Client private key (PEM) - must match certificate |
| `ca_bundle_path` | CA bundle (PEM) - verifies backend's server certificate |

### Certificate Requirements

- All certificates must be **PEM format**
- Client certificate and key must be a matching pair
- CA bundle must contain the CA that signed the backend's certificate
- File permissions: `0600` recommended
- Paths support `~` expansion

### Behavior

| Scenario | Result |
|----------|--------|
| Backend doesn't require mTLS | Works fine - backend ignores client cert |
| Backend requires mTLS | Proxy presents cert during TLS handshake |
| No mTLS configured for HTTPS | Standard TLS only (no client cert) |

### Startup Validation

At proxy startup, mTLS certificates are validated:

1. All three paths must exist
2. Files must be valid PEM-encoded
3. Certificate and private key must match

If validation fails, proxy refuses to start.

### Certificate Expiry

| Status | Condition | Behavior |
|--------|-----------|----------|
| Valid | > 14 days remaining | Normal operation |
| Warning | 7-14 days remaining | Warning in `auth status` |
| Critical | < 7 days remaining | Critical warning |
| Expired | Past expiry date | Proxy refuses to start |

Check status: `mcp-acp auth status`

### Converting Certificate Formats

The proxy expects PEM format:

```bash
# DER to PEM
openssl x509 -in cert.der -inform DER -out cert.pem

# PKCS#12 to PEM
openssl pkcs12 -in cert.p12 -out cert.pem -nodes

# PKCS#7 to PEM
openssl pkcs7 -in cert.p7b -print_certs -out cert.pem
```

---

## Binary Attestation (STDIO Backends)

For STDIO backends, the proxy can verify the backend binary before spawning it. This prevents execution of tampered or unauthorized binaries.

### Configuration

Add `attestation` to the `stdio` config:

```json
{
  "backend": {
    "transport": "stdio",
    "stdio": {
      "command": "node",
      "args": ["server.js"],
      "attestation": {
        "expected_sha256": "3be943172b502b245545fbfd57706c210fabb9ee058829c5bf00c3f67c8fb474",
        "require_signature": true,
        "slsa_owner": "github-username"
      }
    }
  }
}
```

All attestation fields are optional. If `attestation` is omitted or `null`, no verification is performed.

### Verification Modes

| Field | Description | Platform |
|-------|-------------|----------|
| `expected_sha256` | Binary hash must match (hex string, 64 chars) | All |
| `require_signature` | Require valid code signature via `codesign -v` | macOS only |
| `slsa_owner` | Verify SLSA provenance via `gh attestation verify --owner` | All (requires `gh` CLI) |

All configured checks must pass. If any check fails, the proxy refuses to start.

### Hash Verification

Verifies the binary hasn't been modified:

```bash
# Get hash for configuration
shasum -a 256 $(which node)
# Output: 3be943172b502b245545fbfd57706c210fabb9ee058829c5bf00c3f67c8fb474  /opt/homebrew/bin/node
```

The proxy resolves the command via `PATH`, follows symlinks with `realpath()`, then computes SHA-256. Hash comparison uses constant-time `hmac.compare_digest()`.

### Code Signature Verification (macOS)

Verifies the binary has a valid Apple code signature:

```bash
# What the proxy runs internally
codesign -v --strict /path/to/binary
```

System binaries (`/bin/ls`, `/usr/bin/node`) are signed. Scripts and most npm packages are not.

**Default**: `false` (opt-in). Set `require_signature: true` to enable.

### SLSA Provenance Verification

Verifies the binary was built by a trusted CI/CD pipeline using [SLSA](https://slsa.dev/) attestations:

```bash
# What the proxy runs internally
gh attestation verify --owner <slsa_owner> /path/to/binary
```

**Requirements**:
- `gh` CLI installed and authenticated (`gh auth login`)
- Binary must have GitHub attestation from the specified owner

**Use case**: Standalone binaries distributed via GitHub releases (e.g., Go/Rust compiled tools). Does not apply to npm packages.

### Applicability

| Binary Type | Hash | Codesign | SLSA |
|-------------|------|----------|------|
| System binaries (`/bin/ls`) | Yes | Yes | No |
| Node.js (`node`) | Yes | Yes (if from official installer) | No |
| npm packages (via `npx`) | Verify `node` binary | Verify `node` binary | No |
| GitHub release binaries | Yes | Rarely | Yes |

For npm-based MCP servers, attestation verifies the `node` binary, not the JavaScript package. npm has its own integrity model via `package-lock.json` checksums.

### Failure Behavior

If any configured attestation check fails:

1. Error logged with details (expected vs actual hash, signature error, etc.)
2. Proxy refuses to start
3. Human-readable error message displayed

This is fail-closed - the backend is never spawned if attestation fails.

---

## See Also

- [Authentication](auth.md) for user authentication
- [Configuration](../getting-started/configuration.md) for full config reference
- [Security](security.md) for security architecture
