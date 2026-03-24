# Architecture Guide

> Internal architecture of the `github.com/otfabric/go-opcua` Go library.

---

## Package Layering

The library follows a layered architecture aligned with the OPC-UA specification:

```
┌──────────────────────────────────────────────────┐
│              Application Layer                    │
│   opcua (client)  │  server/  │  monitor/        │
├──────────────────────────────────────────────────┤
│           Service Layer (ua/)                     │
│   Request/Response types, encoding/decoding       │
├──────────────────────────────────────────────────┤
│     Secure Conversation Layer (uasc/)             │
│   Encryption, signing, token management           │
├──────────────────────────────────────────────────┤
│     Connection Protocol Layer (uacp/)             │
│   TCP transport, HEL/ACK handshake                │
├──────────────────────────────────────────────────┤
│     Security Policies (uapolicy/)                 │
│   RSA, AES, HMAC algorithm implementations        │
└──────────────────────────────────────────────────┘
```

### Package Ownership

| Package | Responsibility |
|---------|---------------|
| `opcua` (root) | High-level client API: `Client`, `Node`, `Subscription`, `SubscriptionBuilder` |
| `server/` | High-level server: address space, service handlers, session management |
| `ua/` | OPC-UA data types, service request/response structs, binary encoding |
| `uasc/` | Secure channel management, message chunking, token renewal |
| `uacp/` | TCP transport, connection handshake, listener |
| `uapolicy/` | Cryptographic algorithms per security policy |
| `monitor/` | Convenience subscription API with callback/channel patterns |
| `errors/` | Sentinel errors and error types |
| `logger/` | Logging abstraction over `*slog.Logger` |
| `id/` | Generated OPC-UA standard node ID constants |
| `schema/` | OPC-UA NodeSet2 XML schema and parser |
| `stats/` | Metrics collection (subscriptions, errors) |
| `testutil/` | Test server/client helpers for integration tests |

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
Client.Send(ctx, req, resp)   ← Generic send with type assertion
  │
  ▼
SecureChannel.SendRequest()   ← Serialize, encrypt, sign, chunk
  │
  ▼
UACP conn.Write()             ← TCP send
  │
  ▼
  ... network ...
  │
  ▼
UACP conn.Read()              ← TCP receive
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
- `SecureChannel` correlates requests and responses by `requestID`
- Responses are delivered through Go channels to the waiting caller
- The secure channel is stored in an `atomic.Value` for lock-free reads

### Server Side

Incoming requests flow through the server's handler dispatch:

```
UACP Listener.Accept()
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

- Uses RSA encryption (1024–4096 bits depending on policy)
- Each side proves identity via certificate
- Nonces are exchanged to derive symmetric keys

### Phase 2: Symmetric Communication

After the handshake, both sides derive symmetric keys from the exchanged nonces:

```
Client nonce + Server nonce → Key derivation
  → Symmetric encryption key (AES-128 or AES-256)
  → Symmetric signing key (HMAC-SHA1 or HMAC-SHA256)
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
| Aes256_Sha256_RsaPss | AES-256 / HMAC-SHA256 | RSA-OAEP-256 | Modern |

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
| **Events** | Full support | Basic support |

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
