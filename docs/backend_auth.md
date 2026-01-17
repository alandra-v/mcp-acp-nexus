# Backend Authentication

Backend authentication secures the connection between the proxy and backend MCP servers.

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

mTLS is configured during `mcp-acp-nexus init` when an HTTPS backend is detected:

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

Check status: `mcp-acp-nexus auth status`

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

## See Also

- [Authentication](auth.md) for user authentication
- [Configuration](configuration.md) for full config reference
- [Security](security.md) for security architecture
