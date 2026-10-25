# Architecture Guide

> Internal architecture of the `github.com/otfabric/go-opcua` Go library.

---

## Package Layering

The library follows a layered architecture aligned with the OPC-UA specification:

```
┌──────────────────────────────────────────────────┐
│              Application Layer                    │
│   opcua (client) │ server/ │ monitor/ │ gds/      │
│   pubsub/ (Part 14, beside the client/server)     │
├──────────────────────────────────────────────────┤
│           Service Layer (ua/)                     │
│   Request/Response types, encoding/decoding       │
├──────────────────────────────────────────────────┤
│     Secure Conversation Layer (uasc/)             │
│   Encryption, signing, token management;          │
│   the HTTPS channel (no secure conversation)      │
├──────────────────────────────────────────────────┤
│     Connection Protocol Layer (uacp/)             │
│   TCP and TLS WebSocket transports, HEL/ACK       │
├──────────────────────────────────────────────────┤
│     Security Policies (uapolicy/)                 │
│   RSA, ECC (ECDH, ECDSA, EdDSA), AES, ChaCha20,   │
│   HMAC, HKDF; certificate parsing                 │
└──────────────────────────────────────────────────┘
```

### Package Ownership and Stability

Packages are tiered by intended audience and stability commitment:

**Tier 1 — Stable public API.** Intended for normal downstream use. Breaking changes require a major version bump.

| Package | Responsibility |
|---------|---------------|
| `opcua` (root) | High-level client API: `Client`, `Node`, `Subscription`, `SubscriptionBuilder` |
| `server/` | High-level server: address space, service handlers, session management |
| `ua/` | OPC-UA data types, service request/response structs, binary encoding |
| `id/` | Generated OPC-UA standard node ID constants and reverse lookup |
| `monitor/` | Convenience subscription API with callback/channel patterns |
| `gds/` | Certificate management clients of Part 12: push model (`Client`, against a server's ServerConfiguration) and pull model (`PullClient`, against a Global Discovery Server) |
| `gds/gdsserver/` | Global Discovery Server (Part 12 §6, §7.9) attached to a `server.Server` |
| `gds/gdsid/` | NodeIds of the GDS information model |
| `pubsub/` | PubSub runtime (Part 14) and its sub-packages (`message`, `uadp`, `jsonmsg`, `transport/...`, `security`, `sks`, `remote`) |
| `errors/` | Sentinel errors and error types for `errors.Is` / `errors.As` |

**Tier 2 — Advanced public API.** Public but specialized. Useful for custom transports, security, or schema loading. Documented and versioned but more likely to evolve.

| Package | Responsibility |
|---------|---------------|
| `uacp/` | TCP and WebSocket (`opc.wss`) transports, connection handshake, listeners, reverse connect |
| `uasc/` | Secure channel management, message chunking, token renewal; the HTTPS channel (`opc.https`) |
| `uapolicy/` | Cryptographic algorithms per security policy; certificates and keys `crypto/x509` cannot handle |
| `schema/` | OPC-UA schema input files (CSVs, BSD, XSD) for code generators |
| `server/attrs/` | Server attribute helpers |
| `server/refs/` | Server reference helpers |

**Tier 3 — Internal.** Not part of the supported public API. May change without notice.

| Package | Responsibility |
|---------|---------------|
| `internal/schema/` | NodeSet2 XML types, parser, and embedded spec data |
| `internal/stats/` | Metrics collection (experimental, `expvar`-based) |
| `internal/testutil/` | Test server/client helpers for integration tests |
| `internal/goname/` | Shared identifier normalization for code generators |
| `internal/websocket/` | RFC 6455 framing and handshake of the `opc.wss` transport |
| `internal/mqtt/`, `internal/amqp/`, `internal/mdns/` | MQTT 3.1.1 / 5.0 and AMQP 1.0 clients of the PubSub transports; the mDNS responder of multicast discovery |
| `internal/cmd/gen/` | Go-based code generation driver |

---

## Message Flow

### Client Side

A typical client operation (e.g., `ReadValue`) flows through the layers:

```
Client.ReadValue(nodeID)
  │
  ▼
Client.Read(ctx, req)         ← Build ua.ReadRequest
  │
  ▼
Client.Send(ctx, req, h)      ← Generic send; h type-asserts the response
  │
  ▼
SecureChannel.SendRequest()   ← Serialize, encrypt, sign, chunk
  │
  ▼
UACP conn.Write()             ← TCP or WebSocket send
  │
  ▼
  ... network ...
  │
  ▼
UACP conn.Read()              ← TCP or WebSocket receive
  │
  ▼
SecureChannel handler          ← Reassemble chunks, decrypt, verify
  │
  ▼
Response delivered via channel  ← Correlated by requestID
  │
  ▼
Client receives typed response
```

Key details:
- Over `opc.https` there is no UACP connection and no secure conversation: `SecureChannel.SendRequest` posts the encoded request over HTTPS and the response body is the answer
- `SecureChannel` correlates requests and responses by `requestID`
- Responses are delivered through Go channels to the waiting caller
- The secure channel is stored in an `atomic.Value` for lock-free reads

### Server Side

Incoming requests flow through the server's handler dispatch:

```
UACP Listener.Accept()              ← opc.tcp, or opc.wss (TLS + WebSocket upgrade)
  │
  ▼
Server.acceptAndRegister()          ← One goroutine per connection
  │
  ▼
ChannelBroker.RegisterConn()        ← Create SecureChannel, start receive loop
  │
  ▼
Messages sent to central msgChan    ← All connections feed one channel
  │
  ▼
Server.monitorConnections()         ← Main dispatch loop
  │
  ▼
Service handler lookup by TypeID    ← map[uint16]Handler
  │
  ▼
Handler executes (e.g., Read, Browse, Subscribe)
  │
  ▼
SecureChannel.SendResponseWithContext()
```

The handler signature is:

```go
type Handler func(ctx context.Context, sc *uasc.SecureChannel, req ua.Request, reqID uint32) (ua.Response, error)
```

An `opc.https` request takes another path in: the HTTPS listener decodes the POST body and hands the request to the same dispatch on a virtual secure channel per security policy, and writes the response as the HTTP answer.

Handlers receive a request-scoped `context.Context` for cancellation and timeouts; use it for downstream calls (e.g. access control, method handlers) where applicable.

Service handlers are registered at server construction for: Discovery, Session, View, Attribute, Method, Subscription, MonitoredItem, Query, and NodeManagement.

---

## Security Model

OPC-UA security uses a two-phase key exchange:

### Phase 1: Asymmetric Handshake

```
Client                              Server
  │                                    │
  │──── OpenSecureChannel ────────────▶│
  │     (encrypted with server's       │
  │      public key, signed with       │
  │      client's private key)         │
  │                                    │
  │     Contains: client nonce         │
  │                                    │
  │◀── OpenSecureChannel Response ─────│
  │     (encrypted with client's       │
  │      public key, signed with       │
  │      server's private key)         │
  │                                    │
  │     Contains: server nonce,        │
  │     security token                 │
  │                                    │
```

- RSA policies: the messages are encrypted and signed with RSA (1024–4096 bit keys depending on policy) and the nonces are random
- ECC policies: the messages are signed (ECDSA or EdDSA), not encrypted, and the nonces are ephemeral ECDH public keys (Part 6 §6.8)
- Each side proves identity via certificate
- Nonces are exchanged to derive symmetric keys

### Phase 2: Symmetric Communication

After the handshake, both sides derive symmetric keys from the exchanged nonces:

```
Client nonce + Server nonce → Key derivation (P_SHA for RSA, HKDF over the ECDH secret for ECC)
  → Symmetric encryption key (AES-128, AES-256 or ChaCha20)
  → Symmetric signing key (HMAC-SHA1 / SHA256 / SHA384), or an AEAD tag (AES-GCM, Poly1305)
```

All subsequent messages use symmetric encryption, which is much faster than asymmetric.

### Supported Security Policies

| Policy | Symmetric | Asymmetric | Status |
|--------|-----------|------------|--------|
| None | — | — | Active |
| Basic128Rsa15 | AES-128 / HMAC-SHA1 | RSA-15 | Deprecated |
| Basic256 | AES-256 / HMAC-SHA1 | RSA-OAEP | Deprecated |
| Basic256Sha256 | AES-256 / HMAC-SHA256 | RSA-OAEP | Active |
| Aes128_Sha256_RsaOaep | AES-128 / HMAC-SHA256 | RSA-OAEP | Modern |
| Aes256_Sha256_RsaPss | AES-256 / HMAC-SHA256 | RSA-OAEP-SHA256, RSA-PSS-SHA256 | Modern |
| ECC_nistP256, ECC_nistP384 | AES-128 / HMAC-SHA256, AES-256 / HMAC-SHA384 | ECDSA, ECDH P-256 / P-384 | ECC |
| ECC_brainpoolP256r1, ECC_brainpoolP384r1 | as the NIST pair | ECDSA, ECDH on Brainpool | ECC (not constant time) |
| ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly | AES-128-GCM, ChaCha20-Poly1305 | ECDSA, ECDH P-256 | ECC, AEAD |
| ECC_curve25519, ECC_curve448 | ChaCha20-Poly1305 | Ed25519 / X25519, Ed448 / X448 | ECC, AEAD |

Details and the points where the library follows open62541 rather than the text of the specification are in the [Security Guide](security.md#security-policies).

---

## Token Lifecycle and Renewal

Security tokens have a limited lifetime negotiated during `OpenSecureChannel`. The library handles renewal automatically:

```
┌─────────────┐
│ Token Active │ ← Normal message exchange
└──────┬──────┘
       │  Approaching expiration
       ▼
┌──────────────────────┐
│ Renew Secure Channel │ ← New nonces, new token
│ (asymmetric message) │
└──────┬───────────────┘
       │  Server responds with new token
       ▼
┌──────────────────────┐
│ New Token Active     │ ← Old token discarded
└──────────────────────┘
```

The `uasc.SecureChannel` manages instances (old and new channel states) during renewal. A custom condition locker pauses outgoing messages while token renewal is in progress, preventing messages from being sent with a stale token.

---

## Reconnection State Machine

The client maintains a connection state machine for automatic recovery:

```
         ┌────────┐
         │ Closed │
         └───┬────┘
             │ Connect()
             ▼
        ┌───────────┐
        │ Connecting │
        └─────┬─────┘
              │ Success
              ▼
  ┌──────────────────┐
  │    Connected     │ ◀──────────────────┐
  └───────┬──────────┘                    │
          │ Error / EOF                   │ Recovery success
          ▼                               │
  ┌──────────────────┐                    │
  │  Disconnected    │                    │
  └───────┬──────────┘                    │
          │ AutoReconnect enabled         │
          ▼                               │
  ┌──────────────────┐                    │
  │  Reconnecting    │────────────────────┘
  └───────┬──────────┘
          │ Recovery failed (connection refused)
          ▼
     ┌────────┐
     │ Closed │
     └────────┘
```

### Recovery Actions

The reconnect loop tries progressively more expensive recovery actions:

1. **createSecureChannel** — Channel lost (EOF, invalid channel ID). Cheapest fix.
2. **restoreSession** — Channel rejected current session. Reactivates existing session.
3. **recreateSession** — Session invalid on server. Creates new session.
4. **transferSubscriptions** — Moves subscriptions to the new session.
5. **restoreSubscriptions** — Republishes missed notifications using sequence numbers.
6. **abortReconnect** — Critical failure (e.g., connection refused). No recovery possible.

The reconnect interval is configurable via `ReconnectInterval(duration)`.

---

## Namespace Abstraction Model

The server's address space is partitioned into namespaces, each independently managed:

```
Server Address Space
├── Namespace 0 (Standard OPC-UA)       ← NodeNameSpace (auto-populated)
│   ├── Root
│   ├── Objects
│   ├── Types
│   ├── Views
│   └── Server (status, capabilities, diagnostics)
│
├── Namespace 1 (Custom Application)     ← NodeNameSpace or MapNamespace
│   ├── Devices/
│   │   ├── Sensor1 (temperature)
│   │   └── Sensor2 (pressure)
│   └── Methods/
│       └── Calibrate
│
└── Namespace N ...
```

Two namespace implementations are provided:

| | **NodeNameSpace** | **MapNamespace** |
|---|---|---|
| **Model** | Full OPC-UA node graph | Key-value mapping |
| **Complexity** | Rich (references, types) | Simple (auto-generated) |
| **Best for** | Enterprise, complex models | IoT, sensor data |
| **Methods** | Full support | Not supported |
| **Events** | `EmitEvent` + `EmitBaseEvent` (EventFilter) | Basic support |

Each namespace implements the `NameSpace` interface:

```go
type NameSpace interface {
    Name() string
    AddNode(n *Node) *Node
    DeleteNode(id *ua.NodeID) ua.StatusCode
    Node(id *ua.NodeID) *Node
    Objects() *Node
    Root() *Node
    Browse(req *ua.BrowseDescription) *ua.BrowseResult
    ID() uint16
    SetID(uint16)
    Attribute(*ua.NodeID, ua.AttributeID) *ua.DataValue
    SetAttribute(*ua.NodeID, ua.AttributeID, *ua.DataValue) ua.StatusCode
}
```

The server automatically assigns namespace indices and routes requests to the correct namespace based on the `NamespaceIndex` field of each `NodeID`.

---

## Concurrency Patterns

The library uses several concurrency patterns throughout:

- **`atomic.Value`** — Lock-free reads for `secureChannel`, `session`, and `state` on the client
- **`sync.RWMutex`** — Protects concurrent access to `server.Node` attributes (read-heavy workload)
- **`sync.Mutex`** — Protects `Client.conn` during reconnect and close operations
- **Go channels** — Request/response correlation, subscription notifications, connection events
- **Goroutine-per-connection** — Server spawns a goroutine for each accepted TCP connection
- **Central dispatch** — All server messages funnel through a single `msgChan` for ordered processing
- **`sync.Once`** — Ensures the client's monitor goroutine starts exactly once
- **Condition locker** — Pauses message sending during secure channel token renewal
- **Builder pattern** — `SubscriptionBuilder` for fluent, safe subscription configuration
