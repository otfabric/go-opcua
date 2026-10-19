# Security Guide

> Configuring OPC-UA security for the `github.com/otfabric/go-opcua` library.

---

## Overview

OPC-UA security operates at the transport level using a two-phase key exchange:

1. **Asymmetric handshake** — `OpenSecureChannel` signed with the RSA or ECC application certificate to establish trust and exchange nonces
2. **Symmetric session** — message protection (AES-CBC with HMAC, or AES-GCM / ChaCha20-Poly1305 for the AEAD policies) with keys derived from the exchanged nonces

The library handles this automatically. You configure certificates, policies, and authentication modes; the protocol layers do the rest.

---

## Security Policies

The `uapolicy` package implements eleven security policies:

| Policy | Encryption | Signature | Application key | Status |
|--------|-----------|-----------|-----------------|--------|
| **None** | — | — | — | Active |
| **Basic128Rsa15** | AES-128-CBC | HMAC-SHA1 | RSA 1024-bit+ | Deprecated |
| **Basic256** | AES-256-CBC | HMAC-SHA1 | RSA 1024-bit+ | Deprecated |
| **Basic256Sha256** | AES-256-CBC | HMAC-SHA256 | RSA 2048-bit+ | Active |
| **Aes128_Sha256_RsaOaep** | AES-128-CBC | HMAC-SHA256 | RSA 2048-bit+ | Modern |
| **Aes256_Sha256_RsaPss** | AES-256-CBC | HMAC-SHA256 | RSA 2048-bit+ | Modern |
| **ECC_nistP256** | AES-128-CBC | HMAC-SHA256 | ECDSA P-256 or P-384 | ECC (OPC UA 1.05) |
| **ECC_nistP384** | AES-256-CBC | HMAC-SHA384 | ECDSA P-384 | ECC (OPC UA 1.05) |
| **ECC_nistP256_AesGcm** | AES-128-GCM | AES-128-GCM tag | ECDSA P-256 or P-384 | ECC, AEAD (OPC UA 1.05.07) |
| **ECC_nistP256_ChaChaPoly** | ChaCha20-Poly1305 | Poly1305 tag | ECDSA P-256 or P-384 | ECC, AEAD (OPC UA 1.05.07) |
| **ECC_curve25519** | ChaCha20-Poly1305 | Poly1305 tag | Ed25519 | ECC, AEAD (OPC UA 1.05.07) |

Everything is implemented with the Go standard library, except ChaCha20-Poly1305, which comes from `golang.org/x/crypto` (the one dependency this library has for cryptography).

**Recommendation:** Use `Basic256Sha256` for broad compatibility or `Aes256_Sha256_RsaPss` for maximum security with RSA certificates. Avoid `Basic128Rsa15` and `Basic256` — they are deprecated by the OPC Foundation. Use the ECC policies where the peer supports them and you want forward secrecy and small keys; among them prefer the three with authenticated encryption (AEAD), which are the ones current stacks enable by default.

### ECC Security Policies

`ECC_nistP256` and `ECC_nistP384` are the elliptic curve policies of OPC UA 1.05 (Part 6 §6.8). They work differently from the RSA policies. The three newer policies with authenticated encryption share everything in this table and are described in [the next section](#ecc-policies-with-authenticated-encryption):

| | RSA policies | ECC policies |
|---|---|---|
| Application certificate | RSA | ECDSA on P-256 / P-384 |
| OpenSecureChannel messages | signed and encrypted (RSA) | signed (ECDSA); not encrypted |
| Nonces | random bytes | ephemeral ECDH public keys |
| Symmetric keys | P_SHA256 over both nonces | HKDF over the ECDH shared secret |
| Forward secrecy | no | yes: fresh ephemeral keys for every SecurityToken, including renewals |
| Passwords and issued tokens | RSA encrypted | `EccEncryptedSecret`: ephemeral key agreement + ECDSA signature |
| Sequence numbers | start below 1024 | start at 0 |

Nothing about this shows in the API beyond the key type: pick the policy, supply an ECC certificate and key.

```go
// Client: an ECDSA key instead of an RSA key.
c, _ := opcua.NewClient(endpoint,
    opcua.SecurityPolicy("ECC_nistP256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.CertificateFile("client-ecc.crt"),
    opcua.PrivateKeyFile("client-ecc.key"),   // PKCS #8 or SEC 1 ("EC PRIVATE KEY")
    opcua.AuthUsername("operator", "s3cret"), // protected with an EccEncryptedSecret
)
```

A server that offers RSA **and** ECC endpoints needs one application instance certificate per key type. `server.ApplicationIdentity` adds them; for every SecureChannel the server uses the certificate that fits the policy the client asked for, and every endpoint advertises the certificate of its policy:

```go
s, _ := server.New(
    server.Certificate(rsaCert), server.PrivateKey(rsaKey),  // RSA policies
    server.ApplicationIdentity(p256Cert, p256Key),           // ECC_nistP256
    server.ApplicationIdentity(p384Cert, p384Key),           // ECC_nistP384 (and ECC_nistP256)
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableSecurity("ECC_nistP256", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableSecurity("ECC_nistP384", ua.MessageSecurityModeSignAndEncrypt),
)
```

All certificates of one application should carry the same `ApplicationURI`. `Start` fails if an ECC policy is enabled without a certificate that fits it.

Things to know:

- **Key type and policy must match.** See the table below. An RSA certificate on an ECC policy (or the reverse), or an ECDSA certificate on `ECC_curve25519` (or the reverse), is rejected, on the client with `ErrInvalidSecurityConfig` before anything is sent.
- **Keys in an HSM.** An ECC application key only ever signs, so `PrivateKeySigner`, `AuthPrivateKeySigner` and `ApplicationIdentity` accept any `crypto.Signer` with an ECDSA or Ed25519 public key. (RSA keys also decrypt and must be `*rsa.PrivateKey`.)
- **Ranking.** ECC endpoints get a higher `SecurityLevel` than the RSA ones, and the AEAD policies a higher one than the others: `ECC_curve25519` (103) > `ECC_nistP256_ChaChaPoly` (93) > `ECC_nistP256_AesGcm` (83) > `ECC_nistP384` (73) > `ECC_nistP256` (63) > `Aes256_Sha256_RsaPss` (53) > … (`SignAndEncrypt`; `Sign` is one less). The numbers continue the existing scheme of one decade per policy. Within the AEAD group the order is by what a policy adds: AES-GCM, then ChaCha20-Poly1305 (a 256 bit key, constant time without hardware support), then Curve25519 with Ed25519 certificates. A client can only use the endpoints its certificate fits; see [Auto-Detection](#auto-detection).
- **Not implemented:** `ECC_curve448`, `ECC_brainpoolP256r1` and `ECC_brainpoolP384r1`. They need primitives neither the Go standard library nor `golang.org/x/crypto` has (Ed448/X448, Brainpool curves). A client refuses them by name with `ErrUnsupportedSecurityPolicy`.
- **Peers.** Proven against open62541 v1.5.9 (OpenSSL) in both directions. Recent revisions of Part 7, and open62541 with them, treat `ECC_nistP256` / `ECC_nistP384` as superseded by the AEAD policies; open62541 keeps them available but no longer enables them by default.
- **Prefer `SignAndEncrypt` with other stacks.** In `Sign` mode the key derivation follows open62541 v1.5.9: the length `L` that goes into the HKDF salt covers the signing key, the encrypting key and the IV. OPC UA 1.05.07 (Part 6 §6.8.1) changed `L` for Sign-only channels to the signing key alone, and the current OPC Foundation .NET stack does that. A peer following the newer rule derives different signing keys, so `Sign` mode is not expected to interoperate with it; `SignAndEncrypt` is the same in both.

### ECC Policies with Authenticated Encryption

`ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` and `ECC_curve25519` are the ECC policies of OPC UA 1.05.07. They are the ECC policies open62541 v1.5.9 enables by default. Using one is a matter of naming it and supplying a certificate of the right key type:

| Policy | Application certificate | Signatures | Key agreement | Cipher |
|---|---|---|---|---|
| `ECC_nistP256_AesGcm` | ECDSA P-256 (or P-384) | ECDSA-SHA256 | ECDH P-256 | AES-128-GCM |
| `ECC_nistP256_ChaChaPoly` | ECDSA P-256 (or P-384) | ECDSA-SHA256 | ECDH P-256 | ChaCha20-Poly1305 |
| `ECC_curve25519` | Ed25519 | Ed25519 | X25519 | ChaCha20-Poly1305 |
| `ECC_nistP256` | ECDSA P-256 (or P-384) | ECDSA-SHA256 | ECDH P-256 | AES-128-CBC + HMAC-SHA256 |
| `ECC_nistP384` | ECDSA P-384 | ECDSA-SHA384 | ECDH P-384 | AES-256-CBC + HMAC-SHA384 |

A P-256 certificate therefore serves three policies and an Ed25519 certificate one. A server that offers all of them has an RSA, an ECDSA and an Ed25519 certificate (`server.ApplicationIdentity`, once each). X.509 user certificates follow the same rule: an Ed25519 user certificate for `ECC_curve25519`, an ECDSA one for the others.

```go
// Client: Curve25519 with an Ed25519 certificate (PKCS #8 key file).
c, err := opcua.NewClient("opc.tcp://server:4840",
    opcua.SecurityPolicy("ECC_curve25519"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.CertificateFile("client-ed25519-cert.pem"),
    opcua.PrivateKeyFile("client-ed25519-key.pem"),
    opcua.TrustedCertificates(ca),
)

// Server: all three, next to whatever else it offers.
srv, err := server.New(
    server.ApplicationIdentity(p256Cert, p256Key),       // ECC_nistP256_AesGcm, _ChaChaPoly (and ECC_nistP256)
    server.ApplicationIdentity(ed25519Cert, ed25519Key), // ECC_curve25519
    server.EnableSecurity("ECC_nistP256_AesGcm", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableSecurity("ECC_nistP256_ChaChaPoly", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableSecurity("ECC_curve25519", ua.MessageSecurityModeSignAndEncrypt),
    // ...
)
```

What is different on the wire (all of it handled by the library):

- **Message chunks.** A chunk of an open channel has no padding and ends in a 16 byte authentication tag instead of an HMAC. In `SignAndEncrypt` mode the 16 header bytes (message header, SecureChannelId, TokenId) are authenticated and everything after them, the sequence header included, is encrypted. In `Sign` mode nothing is encrypted and the tag covers the whole chunk.
- **Nonces.** Every chunk is sealed with its own nonce: the derived IV with its first eight bytes XORed with the TokenId and with the sequence number of the chunk sent before it in the same direction. Each direction of each SecurityToken has its own key, a renewal changes key, IV and TokenId together, and the library refuses to seal a chunk whose nonce could have been used with the key before (which would take 2^32 chunks under one token). A chunk that is modified, truncated, repeated or delivered out of order fails the tag check and closes the channel.
- **Keys.** HKDF-SHA256 over the shared secret as for the other ECC policies, but without a signing key: `EncryptingKey | IV` (16 + 12 bytes for AES-GCM, 32 + 12 for ChaCha20-Poly1305).
- **Passwords and issued tokens.** The `EccEncryptedSecret` is sealed with the cipher of the policy: the header of the secret is the additional authenticated data, the IV is used as derived, and the tag follows the ciphertext.
- **SecureChannelEnhancements** (`ECC_nistP256_AesGcm` and `ECC_nistP256_ChaChaPoly`; `uapolicy.SecureChannelEnhancements` tells):
  - *ChannelThumbprint.* The signature of the first OpenSecureChannel response also covers the signature of the request. That signature identifies the channel to both applications (`SecureChannel.ChannelThumbprint`).
  - *Key chaining.* A renewal derives its keys from the new shared secret XORed with the key material of the previous token, so the keys of every token depend on all exchanges since the channel was opened.
  - *Channel bound signatures.* The signatures of CreateSession and ActivateSession (and of an X.509 user token) cover the ChannelThumbprint, both session nonces and SHA-256 hashes of the certificates instead of a certificate and a nonce. A signature captured on one channel is of no use on another. When a client reconnects, it activates its session on the new channel with a signature for the new thumbprint.

**Where this follows open62541 rather than the text of the specification.** The policies are new and the implementations had no second stack to test against when this was written; the behaviour here is the one proven against open62541 v1.5.9, the reference being its source. Known differences from OPC UA Part 6 / Part 4 v1.05.07 as published:

| Topic | Specification | open62541 v1.5.9 and this library |
|---|---|---|
| `ECC_curve25519` key material | Policies with authenticated encryption derive no signing key (`L` = EncryptingKey + IV) | A 32 byte signing key is derived in front of the encrypting key (`L` = 32 + 32 + 12). It makes the tags of `Sign` mode; `SignAndEncrypt` uses the encrypting key. |
| `ECC_curve25519` and the SecureChannelEnhancements | Apply to the policies whose profile sets the property (not checked for this policy against Part 7) | Not applied: no ChannelThumbprint, no key chaining, classic session signatures (certificate + nonce) |
| Hash of a certificate in a channel bound signature | The CertificateThumbprintAlgorithm of the policy | SHA-256 of the DER encoded leaf certificate |
| ChannelThumbprint | "appending the bytes of the Signature from the first Request to the bytes of the first Response" | Signed data is the response chunk followed by the request signature (the same reading) |
| `Sign` mode key derivation | Encrypting key and IV lengths are zero in `L` for Sign-only channels | `L` is the same in both modes (as for `ECC_nistP256`, see above) |
| `SignatureData.algorithm` of the session signatures | empty for the enhanced policies | open62541 sends the policy URI for an X.509 user token signature and ignores the field on receipt; this library sends it empty and ignores it too |

The differences only matter with a third stack that follows the text literally. `ECC_nistP256_AesGcm` and `ECC_nistP256_ChaChaPoly` in `SignAndEncrypt` mode differ from the text in the certificate hash alone (if at all: the thumbprint algorithm of these policies may well be SHA-256). The adapter this library is tested with offers the three policies in `SignAndEncrypt` mode only. `Sign` mode is covered between two instances of this library; against open62541 it was checked once by hand (its client reading from a go-opcua server over each of the three policies) and is not part of the interoperability suite.

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

**Replay protection.** In both secure modes the client and the server verify that every chunk they receive follows the one before it (Part 6 §6.7.2.4, including both wrap rules). A chunk that is repeated, missing or out of order is refused with `BadSequenceNumberInvalid` (the AEAD policies refuse it already when the authentication tag is checked) and the channel is given up: the server closes it, a client with `AutoReconnect` opens a new one. Sequence numbers of channels without security are not verified.

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

# 4096-bit keys also work with every RSA policy (Aes256_Sha256_RsaPss etc.)
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=OPC-UA Test" \
    -addext "subjectAltName=URI:urn:otfabric:opcua:client,DNS:localhost"

# For the ECC policies: an ECDSA key on P-256 (ECC_nistP256,
# ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly) or P-384 (ECC_nistP384; also
# accepted by the three nistP256 policies). Use secp384r1 for P-384.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=OPC-UA Test" \
    -addext "keyUsage=digitalSignature,nonRepudiation" \
    -addext "subjectAltName=URI:urn:otfabric:opcua:client,DNS:localhost"

# For ECC_curve25519: an Ed25519 key.
openssl req -x509 -newkey ed25519 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=OPC-UA Test" \
    -addext "keyUsage=digitalSignature,nonRepudiation" \
    -addext "subjectAltName=URI:urn:otfabric:opcua:client,DNS:localhost"
```

### Certificate Requirements

- **Format:** X.509, PEM-encoded files (DER-encoded internally)
- **Key type:** RSA for the RSA policies; ECDSA P-256 or P-384 for the nistP256 / nistP384 ECC policies; Ed25519 for `ECC_curve25519`
- **Key files:** PKCS #1 (`RSA PRIVATE KEY`), PKCS #8 (`PRIVATE KEY`: RSA, ECDSA, Ed25519) or SEC 1 (`EC PRIVATE KEY`), PEM or DER; `uapolicy.ParsePrivateKey` reads all of them
- **Key size:** RSA 2048+ bits for `Basic256Sha256`, `Aes128_Sha256_RsaOaep` and `Aes256_Sha256_RsaPss` (4096 is also accepted)
- **SAN:** Must include an `ApplicationURI` as a URI subject alternative name
- **Key usage:** RSA: `DigitalSignature`, `KeyEncipherment`, `DataEncipherment`. ECC: `DigitalSignature` (an ECC key enciphers nothing)
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
s, err := server.New(
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
s, err := server.New(
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
s, err := server.New(
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
s, err := server.New(
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

// Select the most secure endpoint this client can use with its certificate.
// policy and mode may be "" and ua.MessageSecurityModeInvalid ("don't care").
ep, err := opcua.SelectEndpoint(endpoints, policy, mode, cert)

opts := []opcua.Option{
    opcua.SecurityFromEndpoint(ep, authType),
    opcua.Certificate(cert),
    opcua.PrivateKeySigner(key), // RSA, ECDSA or Ed25519
}
```

`opcua.SelectEndpoint` ranks by the server's `SecurityLevel` like `ua.SelectEndpoint`, but only among the endpoints the client can use: it leaves out policies this library does not implement and secured endpoints whose policy does not fit the key type of the certificate. That matters with servers that offer RSA and ECC endpoints, where the highest ranked endpoint is an ECC one that a client with an RSA certificate cannot open.

Where a server gives several usable endpoints the same `SecurityLevel` the ranking of this library decides (see [ECC Security Policies](#ecc-security-policies)). open62541 does that for all its ECC policies; a client with a P-256 certificate then gets `ECC_nistP256_ChaChaPoly`, one with an Ed25519 certificate `ECC_curve25519`.

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
s, err := server.New(
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
| **Key usage** | Rejects certificates that declare `KeyUsage` without `DigitalSignature` (and, for RSA certificates, `KeyEncipherment` for SignAndEncrypt) |
| **ApplicationURI SAN** | When using `SecurityFromEndpoint`, URI SANs must match the endpoint `ApplicationDescription` |

### Validating Client Certificates (server)

Reject untrusted client application certificates at **OpenSecureChannel** (CreateSession is still checked as defense-in-depth):

```go
caDER, _ := os.ReadFile("client-ca.der")
s, _ := server.New(
    server.WithClientCertificateTrustList(caDER),
    // ...
)
```

Untrusted clients receive `BadCertificateUntrusted`.

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

## Reverse Connect

With reverse connect the server opens the TCP connection to a listening
client ([client guide](client-guide.md#reverse-connect),
[server guide](server-guide.md#reverse-connect)). That changes who exposes a
port, not how the two applications authenticate each other, but it adds an
unauthenticated message in front of the usual exchange. Keep the following in
mind.

**The ReverseHello message proves nothing.** It carries a ServerUri and an
EndpointUrl in plain text and is neither signed nor encrypted. Anyone who can
reach the client's listener can send one with any content. go-opcua uses it
only to decide which waiting client gets the connection; the server is
authenticated afterwards, as on every connection, by its certificate when the
secure channel is opened.

- Use `Sign` or `SignAndEncrypt` and validate the server certificate
  (`TrustedCertificates`). With `SecurityPolicy#None` a reverse connection
  gives no assurance about who connected: whoever reaches the listener first
  with the expected ServerUri is the server. The same is true for an outgoing
  None connection that is redirected, but here the peer does not even have
  to intercept anything.
- With security, the client additionally requires the announced ServerUri
  to be the ApplicationUri (URI subject alternative name) of the server
  certificate it is configured with, and fails with
  `errors.ErrReverseHelloRejected` otherwise. A connection announced by one
  application can therefore not be taken for the connection to another, even
  when both hold certificates the client trusts. `InsecureSkipVerify`
  disables this check along with all other certificate validation.
- The server certificate cannot be learned from the connection itself
  before the channel is opened. Obtain the endpoint description, and with it
  the certificate, through `GetEndpoints` over a reverse connection, or
  provision the certificate out of band, and pin it with
  `TrustedCertificates`. An endpoint description fetched over an unsecured
  reverse connection is exactly as trustworthy as one fetched over an
  unsecured outgoing connection: validate the certificate it contains
  against your trust list rather than trusting it because it arrived.
- State the ServerUri you expect with `ReverseServerURI`. It is not a
  security boundary by itself, but it keeps misdirected servers out and is
  what selects the right connection on a shared listener.

**The client now listens.** An open port is attack surface the client did
not have before.

- Bind the listener to the interface the servers come from, not to all
  interfaces, and restrict the source addresses with a firewall.
- The listener reads at most one message of at most 8208 bytes (two strings
  of up to 4096 bytes, the limit of Part 6) from a peer before it decides,
  and refuses anything else, so a peer cannot make it allocate or parse more.
- `uacp.ReverseListenerConfig` bounds what unauthenticated peers can hold:
  `HelloTimeout` (10 s) for delivering the ReverseHello, `MaxHandshakes` (16)
  connections that have not announced themselves, `MaxPending` (16) announced
  connections waiting for a client; a newer connection of the same server
  replaces the older one. `Filter` admits only known ServerUris. Refused
  peers are told that they were refused, not why.
- A connection that was announced and then goes silent is only discovered
  when a client tries to use it. The client then waits for the server to
  connect again, within its `DialTimeout`.

**The server connects out.** `WithReverseConnect` targets are configuration:
the server sends its ApplicationUri and endpoint URL to whatever answers at
that address.

- Configure targets by an address you control. The announcement contains
  nothing secret, but a peer at a wrong address learns that the server exists
  and can try to open a secure channel, where it is subject to the same
  checks as any client: `WithClientCertificateTrustList`, user
  authentication, and the access controller.
- The number of connections a target can keep in use is limited
  (`ReverseConnectMaxConnections`), and failed attempts back off, so a peer
  at the target address cannot make the server open connections without
  bound.
- Reverse connect does not replace the server's own endpoint: the server
  still listens. If it must not be reachable from outside, that is for the
  firewall to enforce.

---

## Discovery

The discovery roles of a server are opt-in, and each widens what the network
learns about the server or what the network can tell its clients.

### Who may register with a Local Discovery Server

A registration decides what `FindServers` tells clients: whoever can register
can point clients at a server of their choosing, replace the entry of a real
server, or remove it. A go-opcua discovery server (`WithLocalDiscoveryServer`)
therefore accepts `RegisterServer` and `RegisterServer2`

- only on a SecureChannel with Sign or SignAndEncrypt
  (`BadSecurityModeInsufficient` otherwise), and
- only for the `ServerUri` that is an application URI of the certificate the
  channel was opened with (`BadServerUriInvalid`): an application can register
  and unregister itself, nobody else.

Which certificates can open a secured channel at all is decided by
`WithClientCertificateTrustList`. **Without a trust list every certificate is
accepted**, so the two rules above only prove that the registrant holds the
private key of *some* certificate with that URI; configure the trust list on
a discovery server that is reachable by more than the machines you control.

| Option | Effect | Use |
|--------|--------|-----|
| `LDSAllowInsecureRegistration()` | Registration without security: anybody who reaches the port can add, replace and remove servers | Tests, closed lab networks, servers without certificates |
| `LDSSkipServerURICheck()` | A certificate may register any `ServerUri` | A gateway registering the servers behind it |
| `LDSMaxRegisteredServers(n)` | Bounds the table (default 1024) | Limits what a registrant can make the server hold |

Other things a discovery server takes from a registrant: the discovery URLs
(returned to clients verbatim; at most 16 per server), and a semaphore file
path, whose **existence the discovery server checks** on its own file system
with the rights of the server process. A registrant can thus probe whether a
path exists. This is how the specification defines the mechanism; do not run
a discovery server with insecure registration where that matters.

`FindServers`, `FindServersOnNetwork` and `GetEndpoints` are answered without
security and without a session, as the specification requires: what a
discovery server knows is public to everybody who can reach it.

### Registering with a discovery server

A server with `WithDiscoveryRegistration` opens a channel to the discovery
server with its own certificate: it takes the most secure endpoint of the
discovery server that one of its certificates fits (an RSA certificate for
the RSA policies, an ECDSA or Ed25519 one for the ECC policies). It refuses to register without security
unless `RegisterInsecure()` is given, and then still prefers a secured
endpoint if both sides have one. **The certificate of the discovery server
is not validated by default**: a party that can impersonate the discovery
server learns the registration (application URI, names, discovery URLs,
capabilities, which are public on a real discovery server anyway) and can
make the registration go nowhere. Set `RegisterCertificateValidator` to pin
or verify the certificate where that matters.

### Multicast discovery (mDNS)

`WithMulticastDiscovery` announces the server to everybody on the local
network segment (name, host name, port, path, capabilities, IP addresses of
the interface), answers their queries, and fills the `ServerOnNetwork` table
from what others announce. mDNS has no authentication:

- **Exposure.** The announcement makes the server easy to find for anyone on
  the segment. Restrict it with `MulticastInterfaces` to the networks where
  discovery is wanted; it is off unless enabled.
- **Trust.** Anyone on the segment can announce a server, including one that
  imitates the name of a real one. `FindServersOnNetwork` reports
  announcements, not verified facts. A client must treat a discovery URL from
  it like any other unverified address: fetch the endpoints, validate the
  server certificate (`TrustedCertificates`) and its application URI, and
  only then send credentials. Announced data is checked for well-formedness
  (host name characters, UTF-8, lengths) before it is handed to clients, the
  table is bounded (`MulticastMaxServersOnNetwork`), and an announcement
  cannot displace the record of the server itself or of a server registered
  with it.
- **Input handling.** The DNS decoder checks every length and offset, rejects
  forward and looping compression pointers, and is fuzzed. Packets from
  sources that are not on the local link of the receiving interface are
  dropped (RFC 6762 §11).
- **Port.** mDNS uses UDP 5353, shared with Avahi/Bonjour if they run.

## Security Checklist

- [ ] Use `MessageSecurityModeSignAndEncrypt` in production
- [ ] Use `Basic256Sha256` or newer policies (avoid `Basic128Rsa15`, `Basic256`)
- [ ] Use 2048-bit+ RSA keys
- [ ] Include proper SANs in certificates (hostnames, IPs, ApplicationURI)
- [ ] Never use `SecurityPolicy#None` outside development
- [ ] Always pair username/password auth with encryption
- [ ] Set file permissions on private keys (`0600`)
- [ ] Validate server certificates with `TrustedCertificates()` or use `InsecureSkipVerify()` explicitly
- [ ] On servers, configure `WithClientCertificateTrustList` when accepting encrypted client connections
- [ ] For reverse connect: use a secured endpoint, pin the server certificate, set `ReverseServerURI`, and bind and firewall the client's listener
- [ ] Implement `AccessController` for fine-grained server authorization
- [ ] On a Local Discovery Server, keep secured registration (no `LDSAllowInsecureRegistration`) and configure `WithClientCertificateTrustList`
- [ ] Enable `WithMulticastDiscovery` only on interfaces where the server should be discoverable, and never trust a discovered URL without validating the server certificate
- [ ] Monitor certificate expiration dates
- [ ] Rotate certificates on a regular schedule
