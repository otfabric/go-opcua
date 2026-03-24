# Security Guide

> Configuring OPC-UA security for the `github.com/otfabric/go-opcua` library.

---

## Overview

OPC-UA security operates at the transport level using a two-phase key exchange:

1. **Asymmetric handshake** — RSA-based `OpenSecureChannel` to establish trust and exchange nonces
2. **Symmetric session** — AES/HMAC-based message encryption derived from the exchanged nonces

The library handles this automatically. You configure certificates, policies, and authentication modes; the protocol layers do the rest.

---

## Security Policies

The `uapolicy` package implements six security policies:

| Policy | Encryption | Signature | Min Key | Status |
|--------|-----------|-----------|---------|--------|
| **None** | — | — | — | Active |
| **Basic128Rsa15** | AES-128-CBC | HMAC-SHA1 | 1024-bit | Deprecated |
| **Basic256** | AES-256-CBC | HMAC-SHA1 | 1024-bit | Deprecated |
| **Basic256Sha256** | AES-256-CBC | HMAC-SHA256 | 1024-bit | Active |
| **Aes128_Sha256_RsaOaep** | AES-128-CBC | HMAC-SHA256 | 2048-bit | Modern |
| **Aes256_Sha256_RsaPss** | AES-256-CBC | HMAC-SHA256 | 2048-bit | Modern |

**Recommendation:** Use `Basic256Sha256` for broad compatibility or `Aes256_Sha256_RsaPss` for maximum security. Avoid `Basic128Rsa15` and `Basic256` — they are deprecated by the OPC Foundation.

### Policy Selection

Policies can be specified by short name or full URI:

```go
// Short name (auto-prefixed)
opcua.SecurityPolicy("Basic256Sha256")

// Full URI
opcua.SecurityPolicy("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256")
```

List supported policies programmatically:

```go
policies := uapolicy.SupportedPolicies() // []string of full URIs

// Get security level (higher = more secure)
level := uapolicy.SecurityLevel(
    "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
    ua.MessageSecurityModeSignAndEncrypt,
) // Returns uint8
```

---

## Message Security Modes

Each policy can operate in three modes:

| Mode | Integrity | Confidentiality | Use Case |
|------|-----------|-----------------|----------|
| `MessageSecurityModeNone` | No | No | Trusted networks only |
| `MessageSecurityModeSign` | Yes | No | Tamper detection |
| `MessageSecurityModeSignAndEncrypt` | Yes | Yes | Sensitive data (recommended) |

`MessageSecurityModeNone` can only be used with `SecurityPolicy#None`.

---

## Certificate Generation

OPC-UA requires X.509 certificates for secure communication. The library includes a certificate generator for testing.

### Test Certificates

Generate self-signed certificates for development:

```go
import (
    "crypto/rsa"
    "crypto/tls"
    "time"
)

// Using the test helper
certPEM, keyPEM, err := GenerateCert(
    []string{"localhost", "myhost.local", "192.168.1.100"},
    2048,                        // RSA key size
    365 * 24 * time.Hour,        // Validity period
)
if err != nil {
    log.Fatal(err)
}

// Write to files
os.WriteFile("cert.pem", certPEM, 0600)
os.WriteFile("key.pem", keyPEM, 0600)
```

Using OpenSSL from the command line:

```bash
# Generate a 2048-bit RSA key and self-signed certificate
openssl req -x509 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=OPC-UA Test" \
    -addext "subjectAltName=URI:urn:otfabric:opcua:client,DNS:localhost"

# For modern policies (Aes256_Sha256_RsaPss), use 4096-bit keys
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=OPC-UA Test" \
    -addext "subjectAltName=URI:urn:otfabric:opcua:client,DNS:localhost"
```

### Certificate Requirements

- **Format:** X.509, PEM-encoded files (DER-encoded internally)
- **Key type:** RSA only (ECDSA not supported)
- **Key size:** 2048+ bits (4096 for `Aes128_Sha256_RsaOaep` and `Aes256_Sha256_RsaPss`)
- **SAN:** Must include an `ApplicationURI` as a URI subject alternative name
- **Key usage:** `DigitalSignature`, `KeyEncipherment`, `DataEncipherment`
- **Extended key usage:** `ServerAuth`, `ClientAuth`

### Production Certificate Management

For production, use a proper PKI infrastructure:

1. **Use a Certificate Authority (CA)** — Don't use self-signed certificates in production
2. **Rotate certificates** before expiration (the library reads certs at connection time)
3. **Secure private keys** — Use file permissions (`0600`), hardware security modules, or vault solutions
4. **Include all SANs** — Every hostname and IP the server/client may use
5. **Monitor expiration** — Set up alerts before certificate expiry

---

## Authentication Modes

Three authentication modes determine how clients identify themselves to the server:

### Anonymous

No credentials required. Use when the secure channel provides sufficient trust.

```go
// Client
c, _ := opcua.NewClient(endpoint,
    opcua.AuthAnonymous(),
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
)

// Server
s := server.New(
    server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.Certificate(certBytes),
    server.PrivateKey(privateKey),
)
```

### Username/Password

Traditional credential-based authentication. **Always use with encryption** — passwords are transmitted after the secure channel is established.

```go
// Client
c, _ := opcua.NewClient(endpoint,
    opcua.AuthUsername("operator", "s3cret"),
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
)

// Server
s := server.New(
    server.EnableAuthMode(ua.UserTokenTypeUserName),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.Certificate(certBytes),
    server.PrivateKey(privateKey),
)
```

### Certificate-Based

Client presents a certificate for authentication, separate from the secure channel certificate.

```go
// Client
c, _ := opcua.NewClient(endpoint,
    opcua.AuthCertificate(clientCert),
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
)

// Server
s := server.New(
    server.EnableAuthMode(ua.UserTokenTypeCertificate),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.Certificate(certBytes),
    server.PrivateKey(privateKey),
)
```

---

## Common Security Configurations

### Development (No Security)

For local development and testing only:

```go
// Client
c, _ := opcua.NewClient("opc.tcp://localhost:4840",
    opcua.SecurityPolicy("None"),
    opcua.SecurityMode(ua.MessageSecurityModeNone),
    opcua.AuthAnonymous(),
)

// Server
s := server.New(
    server.EndPoint("localhost", 4840),
    server.EnableSecurity("None", ua.MessageSecurityModeNone),
    server.EnableAuthMode(ua.UserTokenTypeAnonymous),
)
```

### Internal Network (Signed)

For trusted networks where you want tamper detection without encryption overhead:

```go
c, _ := opcua.NewClient(endpoint,
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSign),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
    opcua.AuthAnonymous(),
)
```

### Production (Full Security)

For production environments with encryption and authentication:

```go
c, _ := opcua.NewClient(endpoint,
    opcua.SecurityPolicy("Aes256_Sha256_RsaPss"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
    opcua.AuthUsername("operator", password),
)
```

### Auto-Detection

Let the library choose the best security from available server endpoints:

```go
// Discover endpoints
endpoints, _ := opcua.GetEndpoints(ctx, "opc.tcp://server:4840")

// Select the most secure endpoint
ep := opcua.SelectEndpoint(endpoints, policy, mode)

opts := []opcua.Option{
    opcua.SecurityFromEndpoint(ep, authType),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
}
```

---

## Access Control (Server)

The server supports fine-grained authorization through the `AccessController` interface:

```go
type AccessController interface {
    CheckRead(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
    CheckWrite(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
    CheckBrowse(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
    CheckCall(ctx context.Context, session *session, methodID *ua.NodeID) ua.StatusCode
}
```

### Custom Access Controller

```go
type RoleBasedAC struct {
    adminNodes map[string]bool
}

func (ac *RoleBasedAC) CheckWrite(ctx context.Context, sess *session, nodeID *ua.NodeID) ua.StatusCode {
    if ac.adminNodes[nodeID.String()] {
        // Only allow admin sessions to write protected nodes
        // Check session identity against your authorization backend
        return ua.StatusBadUserAccessDenied
    }
    return ua.StatusOK
}

// Apply to server
s := server.New(
    server.WithAccessController(&RoleBasedAC{
        adminNodes: map[string]bool{"ns=1;i=1001": true},
    }),
    // ... other options
)
```

The `DefaultAccessController` allows all operations. Override it to enforce your security model.

---

## Server Certificate Validation

When connecting with `Sign` or `SignAndEncrypt` security mode, the client
validates the server's X.509 certificate by default.

### Trusting Server Certificates

If the server uses a certificate signed by a public CA already in the system
trust store, no extra configuration is needed. For self-signed certificates or
private CAs, add the CA certificate to the trust pool:

```go
// Load the CA certificate that signed the server's certificate
caCert, _ := loadX509Cert("server-ca.pem")

c, _ := opcua.NewClient(endpoint,
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(clientCert),
    opcua.PrivateKey(clientKey),
    opcua.TrustedCertificates(caCert),
)
```

`TrustedCertificates` accepts one or more `*x509.Certificate` values. They are merged with the system CA pool. The client then validates:

| Check | Description |
|-------|-------------|
| **Trust chain** | Certificate must chain to a trusted root (system pool + supplied certs) |
| **Expiration** | Rejects expired or not-yet-valid certificates |
| **Key usage** | Warns if DigitalSignature / KeyEncipherment bits are missing |

### Skipping Validation (Development Only)

For development and testing with self-signed certificates where you don't have the CA:

```go
c, _ := opcua.NewClient(endpoint,
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
    opcua.InsecureSkipVerify(),
)
```

> **Warning:** `InsecureSkipVerify` disables all certificate validation. The certificate is still parsed for its public key, but trust chain, expiration, and usage are not checked. Never use this in production.

---

## Security Checklist

- [ ] Use `MessageSecurityModeSignAndEncrypt` in production
- [ ] Use `Basic256Sha256` or newer policies (avoid `Basic128Rsa15`, `Basic256`)
- [ ] Use 2048-bit+ RSA keys (4096-bit for modern policies)
- [ ] Include proper SANs in certificates (hostnames, IPs, ApplicationURI)
- [ ] Never use `SecurityPolicy#None` outside development
- [ ] Always pair username/password auth with encryption
- [ ] Set file permissions on private keys (`0600`)
- [ ] Validate server certificates with `TrustedCertificates()` or use `InsecureSkipVerify()` explicitly
- [ ] Implement `AccessController` for fine-grained server authorization
- [ ] Monitor certificate expiration dates
- [ ] Rotate certificates on a regular schedule
