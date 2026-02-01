# Backend Authentication

Backend authentication secures the connection between the proxy and backend MCP servers.

---

## API Key / Bearer Token

For HTTP backends that require API key or bearer token authentication, credentials are stored securely in the OS keychain and sent with each request.

### Setup

Set an API key during proxy creation or update it later:

```bash
# During proxy creation
mcp-acp proxy add --name my-proxy --api-key "sk-your-key" ...

# Update an existing key
mcp-acp proxy auth set-key --proxy my-proxy

# Remove a key
mcp-acp proxy auth delete-key --proxy my-proxy
```

The interactive `mcp-acp proxy add` flow will also prompt for an API key when configuring an HTTP backend.

### How It Works

1. API key is stored in OS keychain (never in config files)
2. Per-proxy config file stores only a reference key:
   ```json
   {
     "backend": {
       "server_name": "backend",
       "transport": "streamablehttp",
       "http": {
         "url": "https://backend.example.com/mcp",
         "timeout": 30,
         "credential_key": "proxy:my-proxy:backend"
       }
     }
   }
   ```
3. At runtime, proxy retrieves the credential from keychain
4. Credential sent as `Authorization: Bearer <token>` header

### Secure Storage

Backend credentials are stored using OS-native secure storage via the `keyring` library:

| Platform | Storage Backend |
|----------|-----------------|
| macOS | Keychain |
| Linux | Secret Service / D-Bus (GNOME Keyring, KDE Wallet) |
| Windows | Credential Locker |

Backend credentials require a working keyring. There is no encrypted file fallback (unlike OAuth token storage, which falls back to Fernet-encrypted files when keyring is unavailable).

**Keychain service name**: `mcp-acp`
**Credential key format**: `proxy:{proxy_name}:backend`

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

Configure mTLS per-proxy during `mcp-acp proxy add`:

```bash
mcp-acp proxy add \
  --name my-proxy \
  --server-name backend \
  --connection-type http \
  --url https://backend.example.com/mcp \
  --mtls-cert /path/to/client.pem \
  --mtls-key /path/to/client-key.pem \
  --mtls-ca /path/to/ca-bundle.pem
```

In the per-proxy config file (`proxies/{name}/config.json`), mTLS is a top-level field (separate from `auth`, which contains OIDC config):

```json
{
  "proxy_id": "px_a1b2c3d4:backend",
  "backend": { ... },
  "mtls": {
    "client_cert_path": "/path/to/client.pem",
    "client_key_path": "/path/to/client-key.pem",
    "ca_bundle_path": "/path/to/ca-bundle.pem"
  }
}
```

| Field | Description |
|-------|-------------|
| `client_cert_path` | Client certificate (PEM) - presented to backend |
| `client_key_path` | Client private key (PEM) - must match certificate |
| `ca_bundle_path` | CA bundle (PEM) - verifies backend's server certificate |

Different proxies can use different certificates for different backends.

### Certificate Requirements

- All certificates must be **PEM format**
- Client certificate and key must be a matching pair
- CA bundle must contain the CA that signed the backend's certificate
- File permissions: `0600` recommended
- Paths support `~` expansion

### Behavior

mTLS is only applied when the backend URL starts with `https://`. For `http://` URLs, the mTLS config is silently ignored.

| Scenario | Result |
|----------|--------|
| HTTPS backend, mTLS configured | Proxy presents client cert during TLS handshake |
| HTTPS backend, no mTLS configured | Standard TLS only (no client cert) |
| HTTPS backend doesn't require mTLS | Works fine - backend ignores client cert |
| HTTP backend, mTLS configured | mTLS config is ignored (no TLS) |

### Startup Validation

At proxy startup, mTLS certificates are validated:

1. All three paths must exist
2. Files must be valid PEM-encoded
3. Certificate and private key must match

If validation fails, proxy refuses to start.

### Certificate Expiry

The proxy checks certificate expiry at startup:

| Status | Condition | Behavior |
|--------|-----------|----------|
| Valid | > 14 days remaining | Normal operation |
| Warning | 8-14 days remaining | Warning logged at startup |
| Critical | <= 7 days remaining | Critical warning logged at startup |
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

Add `attestation` to the `stdio` config in the per-proxy config file:

```json
{
  "backend": {
    "server_name": "my-server",
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

All attestation fields are optional. If `attestation` is omitted or `null`, no verification is performed. All configured checks must pass - if any fails, the proxy refuses to start.

| Field | Description | Platform |
|-------|-------------|----------|
| `expected_sha256` | Binary hash must match (hex string, 64 chars) | All |
| `require_signature` | Require valid code signature via `codesign -v`. Default: `false` (opt-in). | macOS only (ignored elsewhere) |
| `slsa_owner` | Verify SLSA provenance via `gh attestation verify --owner` | All (requires `gh` CLI) |

### Hash Verification

Verifies the binary hasn't been modified:

```bash
# Get hash for configuration
shasum -a 256 $(which node)
```

The proxy resolves the command via `PATH`, follows symlinks to the real binary, then computes and compares the SHA-256 hash.

### Code Signature Verification (macOS)

Verifies the binary has a valid Apple code signature (`codesign -v --strict`). System binaries are signed; scripts and most npm packages are not. Has a 10-second timeout.

### SLSA Provenance Verification

Verifies the binary was built by a trusted CI/CD pipeline using [SLSA](https://slsa.dev/) attestations. Requires `gh` CLI installed and authenticated, and network access to GitHub API (30-second timeout).

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

All attestation is fail-closed. If any configured check fails, the backend is never spawned and the proxy refuses to start with a descriptive error message.

Post-spawn process path verification (confirming the running process matches the verified binary) is implemented for macOS and Linux but **not yet integrated** into the transport layer.

---

## See Also

- [Authentication](auth.md) for user authentication
- [Configuration](../getting-started/configuration.md) for full config reference
- [Security](security.md) for security architecture
