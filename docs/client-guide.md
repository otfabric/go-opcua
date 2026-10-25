# Client Development Guide

> Using the `github.com/otfabric/go-opcua` client to connect to OPC-UA servers.

---

## Client Service Support

| Service Set | Client Methods | Status |
|-------------|---------------|--------|
| **Discovery** | `GetEndpoints`, `FindServers`, `FindServersWithFilter`, `FindServersOnNetwork`, `FindServersOnNetworkWithFilter`, `RegisterServer`, `RegisterServer2`, `DiscoverServers` | Fully implemented |
| **Session** | Automatic via `Connect` / `Close` | Fully implemented |
| **Attribute** | `Read`, `ReadValue`, `Write`, `WriteValue` | Fully implemented (`IndexRange`, `TimestampsToReturn`) |
| **Attribute (History)** | `HistoryReadRawModified`, `HistoryReadProcessed`, `HistoryReadAtTime`, `HistoryReadEvent`, `HistoryUpdateData`, `HistoryUpdateEvents`, `HistoryDeleteRawModified`, `HistoryDeleteAtTime`, `HistoryDeleteEvents` | Fully implemented (server-dependent; go-opcua default `*Historian` covers raw/modified/at-time/processed and events + update/delete) |
| **Browse** | `Browse`, `BrowseNext` | Fully implemented (`ResultMask`, continuation release) |
| **View** | `RegisterNodes`, `UnregisterNodes` | Fully implemented |
| **Node Management** | `AddNodes`, `DeleteNodes`, `AddReferences`, `DeleteReferences` | Fully implemented |
| **Method** | `Call`, `CallMethod` | Fully implemented |
| **Subscription** | `Subscribe`, `SubscriptionBuilder`, `SetPublishingMode`, `Republish`, `TransferSubscriptions` | Fully implemented; reconnect recovery via `WithSubscriptionRecoveryHandler` |
| **Monitored Items** | `Monitor`, `ModifyMonitoredItems`, `Unmonitor`, `SetMonitoringMode`, `SetTriggering` | Fully implemented (exact queues / Overflow on go-opcua servers) |
| **Query** | `QueryFirst`, `QueryNext` | Fully implemented (server-dependent) |
| **Alarms & Conditions** (Part 9, over Method + Monitored Items) | `NewConditionEventFilter`, `ParseConditionEvent`, `Acknowledge`, `Confirm`, `AddComment`, `EnableCondition`, `DisableCondition`, `TimedShelve`, `OneShotShelve`, `Unshelve`, `ConditionRefresh`, `ConditionRefresh2`; of Part 9 1.05 `Suppress`, `Unsuppress`, `RemoveFromService`, `PlaceInService`, `Silence`, `Reset`, `Respond`, `GetGroupMemberships` and the `*2` variants; `ReadAlarmMetrics`, `ResetAlarmMetrics`; `NewAuditConditionEventFilter`, `ParseAuditConditionEvent` | Implemented; see [Alarms and Conditions](#alarms-and-conditions) |
| **Server diagnostics** (Part 5 §6.3.3, over Read / Write) | `ServerDiagnosticsSummary`, `ServerDiagnosticsEnabled`, `SetServerDiagnosticsEnabled`, `SessionDiagnostics`, `SessionSecurityDiagnostics`, `SessionDiagnosticsOf`, `SessionSecurityDiagnosticsOf`, `SubscriptionDiagnostics`, `SamplingIntervalDiagnostics`; `ReturnDiagnostics`, `*ServiceError` | Implemented; see [Server diagnostics](#server-diagnostics) |
| **Certificate management** (Part 12, over Method + Call) | package `gds`: push model (`gds.Client`: trust lists of every group, `CreateSigningRequest`, `UpdateCertificate`, `GetRejectedList`, `ApplyChanges`, `GetCertificates`, `CreateSelfSignedCertificate`, `DeleteCertificate`, `ResetToServerDefaults`, `TransactionDiagnostics`, ...); pull model (`gds.PullClient`: application directory, `StartSigningRequest`, `StartNewKeyPairRequest`, `FinishRequest`, trust lists, revocation, `Enroll`) | Implemented; see [push](#certificate-management-gds-push) and [pull](#certificate-management-gds-pull) |

For services not wrapped by a dedicated method, use `Client.Send(ctx, req, handler)` directly; the handler receives the `ua.Response`.

---

## Connecting

### Basic Connection

```go
package main

import (
    "context"
    "log"

    "github.com/otfabric/go-opcua"
    "github.com/otfabric/go-opcua/ua"
)

func main() {
    ctx := context.Background()

    c, err := opcua.NewClient("opc.tcp://localhost:4840")
    if err != nil {
        log.Fatal(err)
    }
    if err := c.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer c.Close(ctx)

    // Use client...
}
```

### With Security

```go
c, _ := opcua.NewClient("opc.tcp://server:4840",
    opcua.SecurityPolicy("Basic256Sha256"),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
    opcua.AuthUsername("user", "password"),
)
```

The ECC policies (`ECC_nistP256`, `ECC_curve25519`, `ECC_brainpoolP256r1`,
`ECC_curve448`, ...) take an ECC certificate with `PrivateKeySigner` or
`PrivateKeyFile`; see the [Security Guide](security.md#ecc-security-policies).

### With Auto-Reconnection

```go
c, _ := opcua.NewClient("opc.tcp://server:4840",
    opcua.AutoReconnect(true),
    opcua.ReconnectInterval(5 * time.Second),
)
```

### Endpoint Discovery

Discover available endpoints before connecting:

```go
endpoints, err := opcua.GetEndpoints(ctx, "opc.tcp://server:4840")
if err != nil {
    log.Fatal(err)
}

// Select the best endpoint this client can use with its certificate (DER)
ep, err := opcua.SelectEndpoint(endpoints, "Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt, cert)
if err != nil {
    log.Fatal(err)
}

// Connect with auto-configured security
c, _ := opcua.NewClient(ep.EndpointURL,
    opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous),
    opcua.Certificate(cert),
    opcua.PrivateKey(key),
)
```

### HTTPS and WebSocket endpoints

Besides `opc.tcp`, the client dials `opc.wss://` (OPC UA Secure Conversation
over a TLS WebSocket, Part 6 §7.5) and `opc.https://` / `https://` (UA Binary
requests as HTTPS POSTs, Part 6 §7.4). The endpoint URL picks the transport;
everything else (sessions, subscriptions, reconnect, security policies) works
as over `opc.tcp`.

The TLS certificate of the server is checked against `TLSConfig` (its
`RootCAs`, or the system roots) and the host name of the URL. It is not the
application instance certificate: that one is still checked as usual for the
session.

```go
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caPEM)

c, err := opcua.NewClient("opc.wss://server:4843",
    opcua.SecurityMode(ua.MessageSecurityModeNone), // TLS protects the channel
    opcua.TLSConfig(&tls.Config{RootCAs: pool}),
)
```

Over HTTPS there is no secure channel: the security policy only decides how
the session nonces are signed, and `Publish` is a POST the server holds until
it has a notification. A server usually offers user names on the None
endpoints of HTTPS (TLS protects the password). To pick the endpoint of a
transport from a GetEndpoints result, use `SelectEndpointForTransport`:

```go
eps, _ := opcua.GetEndpoints(ctx, "opc.https://server:4843", opcua.TLSConfig(tlsCfg))
ep, err := opcua.SelectEndpointForTransport(eps, ua.TransportProfileHTTPS, "None", ua.MessageSecurityModeNone, nil)
```

`SelectEndpoint` prefers `opc.tcp` endpoints when the server offers any, and
the UA Binary endpoints over the UA JSON ones otherwise.
`HTTPClient` replaces the `*http.Client` of HTTPS endpoints (for a proxy, for
example); `opc.wss` connections are always direct (no HTTP proxy).

#### UA JSON (https-uajson, wss-uajson)

Both transports also have a UA JSON mapping, with a transport profile of its
own: every service message is a JSON message (Part 6 §5.4.9, compact form)
and there is no secure conversation. Over HTTPS (Part 6 §7.4.5, profile
`ua.TransportProfileHTTPSJSON`) each request is a POST with the Content-Type
`application/json`; over a WebSocket (Part 6 §7.5.2, profile
`ua.TransportProfileWSSJSON`) the client negotiates the sub-protocol
`opcua+uajson` and sends each request as one text message. The URL scheme does
not tell the mappings apart, so the client uses JSON only when the
`TransportProfile` option says so; `SecurityFromEndpoint` sets it from the
endpoint it is given:

```go
eps, _ := opcua.GetEndpoints(ctx, "opc.wss://server:4843", opcua.TLSConfig(tlsCfg))
ep, err := opcua.SelectEndpointForTransport(eps, ua.TransportProfileWSSJSON, "None", ua.MessageSecurityModeNone, nil)
c, _ := opcua.NewClient(ep.EndpointURL,
    opcua.TLSConfig(tlsCfg),
    opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous), // selects wss-uajson
)
```

or explicitly with `opcua.TransportProfile(ua.TransportProfileHTTPSJSON)`. A
JSON profile whose scheme is not that of the URL fails `Connect` with
`errors.ErrInvalidEndpoint`.

- TLS is the only protection. A WebSocket cannot name a security policy, so
  wss-uajson is always None; over https-uajson the policy only decides how the
  session nonces are signed, as over https-uabinary.
- The client keeps up to 8 idle WebSockets to a wss-uajson server and has one
  request in flight on each, so a Publish request waiting for a notification
  holds up no other request, also with servers that answer the requests of a
  WebSocket one at a time. It checks the RequestHandle of each response.
- NodeIds of other namespaces than 0 are written with their namespace URI
  (`nsu=`, Part 6 §5.4.2.10), from the namespace array the client reads after
  connecting.
- A message is limited to `uasc.MaxWebSocketJSONMessageSize`; a larger one
  ends the WebSocket with status 1009 (Part 6 §7.5.2).
- UA-.NETStandard 2.0.1 takes JSON over HTTPS only with the (non-standard)
  Content-Type `application/opcua+uajson`. To talk to it, set that one with
  `HTTPSJSONContentType`:

```go
c, _ := opcua.NewClient(url,
    opcua.TransportProfile(ua.TransportProfileHTTPSJSON),
    opcua.HTTPSJSONContentType(uasc.HTTPSJSONContentTypeLegacy) /* ... */)
```

### Reverse Connect

When the client cannot reach the server (the server sits behind a firewall
or NAT) but the server can reach the client, let the server open the
connection. With `ReverseConnect` the client listens instead of dialling; the
server connects, announces itself with a ReverseHello message, and from then
on the connection is used like any other (OPC UA Part 6 §7.1.3).

```go
c, _ := opcua.NewClient("opc.tcp://plc-17:4840", // the endpoint URL the server announces
    opcua.ReverseConnect("0.0.0.0:4841",         // where this client listens
        opcua.ReverseServerURI("urn:acme:plc-17")), // the server's ApplicationUri
    opcua.DialTimeout(60*time.Second),           // how long to wait for the server
)
if err := c.Connect(ctx); err != nil { // returns once the server has connected
    log.Fatal(err)
}
defer c.Close(ctx)
```

The server must be configured with the address the client listens on; for a
go-opcua server see `server.WithReverseConnect` in the
[server guide](server-guide.md#reverse-connect).

What the client checks, and what it does with it:

- **ServerUri**: with `ReverseServerURI` only the server announcing that
  ApplicationUri is accepted. Without it any server is.
- **EndpointUrl**: it must denote the endpoint URL given to `NewClient`
  (host names compare case-insensitively, the port defaults to 4840, a
  trailing slash is ignored). Create the client with `""` to accept whatever
  the server announces and use that. This is the usual choice when the
  server's own idea of its address means nothing on the client's network.
- A server that fails a check is answered with an Error message and
  disconnected; the client keeps waiting for the right one. If it gives up,
  the error wraps `errors.ErrReverseHelloRejected` and says what was refused.
- With a security mode other than None, the announced ServerUri must be the
  ApplicationUri of the server certificate the client is configured with.
  See [Security](security.md#reverse-connect).

Waiting is bounded by the context passed to `Connect` and by `DialTimeout`
(default 10 s). Servers retry a reverse connection at an interval (open62541:
every 15 s by default), so choose a timeout that covers it. With
`AutoReconnect` the client goes back to waiting after a connection loss and
restores the session and the subscriptions exactly as for an outgoing
connection. `Close` stops the listener.

`GetEndpoints`, `FindServers` and `FindServersOnNetwork` take the same option
and then run over a reverse connection too:

```go
reverse := opcua.ReverseConnect("0.0.0.0:4841", opcua.ReverseServerURI("urn:acme:plc-17"))
endpoints, err := opcua.GetEndpoints(ctx, "", reverse, opcua.DialTimeout(60*time.Second))
ep, err := opcua.SelectEndpoint(endpoints, "Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt, cert)
c, _ := opcua.NewClient("", reverse, opcua.SecurityFromEndpoint(ep, ua.UserTokenTypeAnonymous) /* ... */)
```

#### One listener for several servers

A listener can be shared: create it once and give every client the ServerUri
of its server. Each incoming connection goes to the client that expects it; a
connection nobody is waiting for is kept until a client asks for it (servers
keep one idle connection open for that purpose).

```go
l, err := uacp.ListenReverse(ctx, "0.0.0.0:4841", &uacp.ReverseListenerConfig{
    // optional: admit only known servers
    Filter: func(rhe *uacp.ReverseHello) error {
        if !known[rhe.ServerURI] {
            return ua.StatusBadServerURIInvalid
        }
        return nil
    },
})
defer l.Close() // after the clients; Client.Close does not close a shared listener

a, _ := opcua.NewClient("", opcua.ReverseConnectListener(l, opcua.ReverseServerURI("urn:acme:plc-17")))
b, _ := opcua.NewClient("", opcua.ReverseConnectListener(l, opcua.ReverseServerURI("urn:acme:plc-18")))
```

`ReverseListenerConfig` also bounds what an unauthenticated peer can make the
listener hold: `HelloTimeout` (time to deliver the ReverseHello, default 10 s),
`MaxHandshakes` (connections that have not announced themselves yet, default
16) and `MaxPending` (announced connections waiting for a client, default 16).
Use `uacp.NewReverseListener` to wrap a TCP `net.Listener` of your own.

### Discovery servers

A Local Discovery Server (LDS) listens on the well-known port 4840 of a
machine and knows the servers registered with it. `DiscoverServers` asks it
for everything it knows:

```go
res, err := opcua.DiscoverServers(ctx, "plant-gateway") // opc.tcp://plant-gateway:4840
if err != nil {
    log.Fatal(err)
}
for _, app := range res.Servers { // FindServers: the LDS and its registered servers
    fmt.Println(app.ApplicationURI, app.DiscoveryURLs)
}
if res.MulticastSupported { // FindServersOnNetwork: found with mDNS
    for _, s := range res.ServersOnNetwork {
        fmt.Println(s.RecordID, s.ServerName, s.DiscoveryURL, s.ServerCapabilities)
    }
}
```

`host` may also be `host:port` or a complete `opc.tcp://` URL;
`opcua.DiscoveryURL(host)` shows what is queried. A discovery server without
the multicast extension is not an error: `MulticastSupported` is false.

The services with all their parameters are client methods. They need a
SecureChannel but no session, so `Dial` is enough:

```go
c, _ := opcua.NewClient(opcua.DiscoveryURL("plant-gateway"))
if err := c.Dial(ctx); err != nil {
    log.Fatal(err)
}
defer c.Close(ctx)

// only these servers, names in German where available
found, err := c.FindServersWithFilter(ctx, []string{"de"}, []string{"urn:factory:press7"})

// servers with historical data, 100 records at a time
var next uint32
for {
    page, err := c.FindServersOnNetworkWithFilter(ctx, next, 100, []string{"HD"})
    if err != nil || len(page.Servers) == 0 {
        break
    }
    // ... use page.Servers; start over if page.LastCounterResetTime changes
    next = page.Servers[len(page.Servers)-1].RecordID + 1
}
```

A discovered server is connected to through one of its discovery URLs:
`GetEndpoints` there, then `NewClient` with the chosen endpoint. The URL of a
server found with mDNS carries a `.local` host name, which the client machine
must be able to resolve.

**Registering a server.** `RegisterServer` and `RegisterServer2` register a
server with the discovery server, renew its registration and
(`IsOnline: false`) remove it:

```go
resp, err := c.RegisterServer2(ctx, &ua.RegisteredServer{
    ServerURI:     "urn:factory:press7",
    ServerNames:   []*ua.LocalizedText{ua.NewLocalizedText("Press 7")},
    ServerType:    ua.ApplicationTypeServer,
    DiscoveryURLs: []string{"opc.tcp://press7:4841"},
    IsOnline:      true,
}, &ua.MdnsDiscoveryConfiguration{MdnsServerName: "Press 7", ServerCapabilities: []string{"DA"}})
// resp.ConfigurationResults[0] is BadNotSupported if the discovery server has no mDNS
```

A discovery server normally only accepts this on a secured channel opened
with the certificate of the server that is being registered, and the
registration expires unless it is renewed (every 10 minutes is customary). A
go-opcua server does all of it by itself: see
`server.WithDiscoveryRegistration` in the [server guide](server-guide.md#discovery).

### Connection diagnostics (ping)

To test connectivity at different layers:

- **TCP only** — Use `uacp.DialTCP(ctx, endpoint)` to open a raw TCP connection; close the returned `net.Conn` when done. Use this to verify TCP reachability without OPC UA handshakes.
- **SecureChannel** — Call `Client.Dial(ctx)` (no session).
- **Session + Auth + Browse** — Call `Client.Connect(ctx)` then e.g. `Client.BrowseAll(ctx, ua.ObjectIDRootFolder)` to verify full stack (session, auth, browse root).

A "ping" or connection-test command can run these steps in order and report which layer failed.

### Server diagnostics

Typed helpers read the diagnostics a server exposes (Part 5 §6.3.3):

```go
sum, err := c.ServerDiagnosticsSummary(ctx)        // *ua.ServerDiagnosticsSummaryDataType
on, err := c.ServerDiagnosticsEnabled(ctx)         // EnabledFlag
sessions, err := c.SessionDiagnostics(ctx)         // SessionDiagnosticsArray
own, err := c.SessionDiagnosticsOf(ctx, nil)       // the diagnostics object of this session
sec, err := c.SessionSecurityDiagnosticsOf(ctx, nil)
subs, err := c.SubscriptionDiagnostics(ctx)        // SubscriptionDiagnosticsArray
rates, err := c.SamplingIntervalDiagnostics(ctx)
err = c.SetServerDiagnosticsEnabled(ctx, true)     // usually an administrator only; resets the counters
```

`SessionDiagnosticsOf` and `SessionSecurityDiagnosticsOf` take a SessionId
(nil for the client's own session) and resolve the variable below the
session's diagnostics object. `SessionSecurityDiagnostics` (the array) is
usually readable by a SecurityAdmin over an encrypted channel only.

### DiagnosticInfo

`opcua.ReturnDiagnostics(mask)` sets the `ReturnDiagnostics` mask of every
request, e.g. `ua.ReturnDiagnosticsAll`; a request that sets a mask in its own
`RequestHeader` keeps it. Operation diagnostics are in the `DiagnosticInfos`
of the response; resolve them against the string table with
`resp.ResponseHeader.Diagnostic(resp.DiagnosticInfos[i])`, which returns a
`*ua.Diagnostic` (SymbolicID, NamespaceURI, LocalizedText, Locale,
AdditionalInfo, InnerStatusCode, Inner). A request the server rejects as a
whole fails with a `*opcua.ServiceError` carrying the resolved service
diagnostics; it unwraps to the `ua.StatusCode`, so `errors.Is(err,
ua.StatusBadTooManyOperations)` keeps working:

```go
c, _ := opcua.NewClient(url, opcua.ReturnDiagnostics(ua.ReturnDiagnosticsAll))
...
if _, err := c.Read(ctx, req); err != nil {
    var se *opcua.ServiceError
    if errors.As(err, &se) {
        log.Printf("%v: %s", se.StatusCode, se.Diagnostic)
    }
}
```

---

## Client Options

| Option | Purpose |
|--------|---------|
| `SecurityPolicy(name)` | Security policy (`"None"`, `"Basic256Sha256"`, etc.) |
| `SecurityMode(mode)` | Message security mode |
| `Certificate(cert)` | Client certificate (DER bytes) |
| `PrivateKey(key)` | Client private key (RSA) |
| `PrivateKeySigner(key)`, `PrivateKeyFile(path)` | Client private key of any supported type: RSA, ECDSA (NIST or Brainpool), Ed25519, Ed448 (a `crypto.Signer`, e.g. an HSM) |
| `AuthAnonymous()` | Anonymous authentication |
| `AuthUsername(user, pass)` | Username/password authentication |
| `AuthCertificate(cert)` | Certificate-based authentication |
| `AutoReconnect(bool)` | Enable automatic reconnection |
| `ReconnectInterval(d)` | Time between reconnect attempts |
| `SessionTimeout(d)` | Session timeout duration |
| `ApplicationURI(uri)` | Application URI (auto-read from cert if provided) |
| `ApplicationName(name)` | Application name |
| `WithConnStateHandler(fn)` | Connection state change callback |
| `SecurityFromEndpoint(ep, auth)` | Auto-configure from discovered endpoint |
| `InsecureSkipVerify()` | Skip server certificate validation (INSECURE, dev only) |
| `TrustedCertificates(certs...)` | Add CA/self-signed certs to trust pool |
| `ReverseConnect(listenAddr, opts...)` | Wait for the server to connect instead of dialling it ([reverse connect](#reverse-connect)) |
| `ReverseConnectListener(l, opts...)` | Reverse connect through a shared `*uacp.ReverseListener` |
| `DialTimeout(d)` | Time allowed to establish the connection, or to wait for a reverse connection |
| `TLSConfig(cfg)` | TLS of `opc.wss` / `opc.https` endpoints (trusted roots, client certificate for mutual TLS) |
| `HTTPClient(c)` | `*http.Client` of `opc.https` endpoints |
| `ReturnDiagnostics(mask)` | Ask the server for DiagnosticInfos on every request ([DiagnosticInfo](#diagnosticinfo)) |

---

## Reading Values

### Single Value

```go
// High-level helper — reads the Value attribute
dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, 2258))
if err != nil {
    log.Fatal(err)
}
fmt.Println("Server time:", dv.Value.Value())
```

### Multiple Values

```go
dvs, err := c.ReadValues(ctx,
    ua.NewNumericNodeID(2, 1001),
    ua.NewNumericNodeID(2, 1002),
    ua.NewNumericNodeID(2, 1003),
)
if err != nil {
    log.Fatal(err)
}
for _, dv := range dvs {
    fmt.Println(dv.Value.Value())
}
```

### Batch read (ReadMulti)

For many node/attribute pairs (e.g. whole subtrees or bulk export), use `ReadMulti`. It chunks requests by server limits (default 32 items per request) and returns results in the same order as the input. Each result includes `DataValue` and `StatusCode`.

```go
items := []opcua.ReadItem{
    {NodeID: n1, AttributeID: ua.AttributeIDValue},
    {NodeID: n2, AttributeID: ua.AttributeIDDisplayName},
}
results, err := c.ReadMulti(ctx, items)
// optional: opcua.ReadMultiWithChunkSize(16) to override chunk size
```

### Using the Node Helper

The `Node` type provides convenience methods for common attributes:

```go
node := c.Node(ua.NewNumericNodeID(2, 1001))

// Read the value
v, err := node.Value(ctx)

// Read other attributes
name, err := node.DisplayName(ctx)
class, err := node.NodeClass(ctx)
desc, err := node.Description(ctx)
browseName, err := node.BrowseName(ctx)
accessLevel, err := node.AccessLevel(ctx)
```

### Low-Level Read

For full control over the read request:

```go
req := &ua.ReadRequest{
    MaxAge:             2000,
    TimestampsToReturn: ua.TimestampsToReturnBoth,
    NodesToRead: []*ua.ReadValueID{
        {
            NodeID:      ua.NewNumericNodeID(2, 1001),
            AttributeID: ua.AttributeIDValue,
        },
    },
}

resp, err := c.Read(ctx, req)
if err != nil {
    log.Fatal(err)
}
for _, result := range resp.Results {
    fmt.Println(result.Value.Value())
}
```

---

## Writing Values

### Single Value

```go
status, err := c.WriteValue(ctx,
    ua.NewNumericNodeID(2, 1001),
    &ua.DataValue{
        EncodingMask: ua.DataValueValue,
        Value:        ua.MustVariant(42.0),
    },
)
if err != nil {
    log.Fatal(err)
}
if status != ua.StatusOK {
    log.Fatal("write failed:", status)
}
```

### Multiple Values

```go
statuses, err := c.WriteValues(ctx,
    &ua.WriteValue{
        NodeID:      ua.NewNumericNodeID(2, 1001),
        AttributeID: ua.AttributeIDValue,
        Value: &ua.DataValue{
            EncodingMask: ua.DataValueValue,
            Value:        ua.MustVariant(42.0),
        },
    },
    &ua.WriteValue{
        NodeID:      ua.NewNumericNodeID(2, 1002),
        AttributeID: ua.AttributeIDValue,
        Value: &ua.DataValue{
            EncodingMask: ua.DataValueValue,
            Value:        ua.MustVariant("hello"),
        },
    },
)
```

---

## Browsing

### Browse All References

```go
refs, err := c.BrowseAll(ctx, ua.NewNumericNodeID(0, id.ObjectsFolder))
if err != nil {
    log.Fatal(err)
}
for _, ref := range refs {
    fmt.Printf("%s: %s (%v)\n", ref.NodeID.NodeID, ref.BrowseName.Name, ref.NodeClass)
}
```

### Node Iterator

The `Node` type provides an `iter.Seq2` iterator that handles continuation points:

```go
node := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))

for ref, err := range node.BrowseAll(ctx,
    id.HierarchicalReferences,
    ua.BrowseDirectionForward,
    ua.NodeClassAll,
    true, // Include subtypes
) {
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("%s: %s\n", ref.NodeID.NodeID, ref.BrowseName.Name)
}
```

### Low-Level Browse

```go
req := &ua.BrowseRequest{
    View: &ua.ViewDescription{},
    RequestedMaxReferencesPerNode: 100,
    NodesToBrowse: []*ua.BrowseDescription{
        {
            NodeID:          ua.NewNumericNodeID(0, id.ObjectsFolder),
            BrowseDirection: ua.BrowseDirectionForward,
            ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
            IncludeSubtypes: true,
            ResultMask:      uint32(ua.BrowseResultMaskAll),
        },
    },
}

resp, err := c.Browse(ctx, req)
```

### Recursive browse (BrowseWithDepth)

When you need a **slice** of all references up to a given depth (e.g. for filtering or batch display), use `Node.BrowseWithDepth`. It performs client-side recursion (multiple Browse calls, like `Walk`/`WalkLimit`) and returns a flat list with depth. Standard OPC UA Browse is single-level; recursion is implemented in the client.

```go
node := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
opts := opcua.BrowseWithDepthOptions{
    MaxDepth:        3,
    IncludeSubtypes: true,
}
results, err := node.BrowseWithDepth(ctx, opts)
for _, r := range results {
    fmt.Printf("depth %d: %s\n", r.Depth, r.Ref.NodeID)
}
```

---

## Resolving paths to nodes (browse path translation)

The **TranslateBrowsePathsToNodeIDs** service resolves a path of browse names to a NodeID. This is essential when you have a logical path (e.g. `"Server.ServerStatus"` or `"Objects.MyDevice.Temperature"`) and need a `Node` to read, write, or subscribe.

**Path semantics summary:**

| API | Start node | Namespace | Error |
|-----|------------|-----------|--------|
| `NodeFromPath(ctx, path)` | Objects folder (i=85) | All segments ns=0 | (nil, err) if path not found or service fails |
| `NodeFromPathInNamespace(ctx, ns, path)` | Objects folder (i=85) | All segments use ns | Same |
| `NodeFromQualifiedPath(ctx, path)` | Objects folder (i=85) | Per-segment `ns:name` (e.g. `0:Server.0:ServerStatus`) | (nil, err) if path invalid, not found, or service fails |
| `node.TranslateBrowsePathInNamespaceToNodeID(ctx, ns, path)` | Receiver node | All segments use ns | (nil, err); err may be ua.StatusCode |
| `node.TranslateBrowsePathsToNodeIDs(ctx, pathNames)` | Receiver node | Per-segment (QualifiedName.NamespaceIndex) | Same |

### High-level: resolve from Objects folder

**NodeFromPath** resolves a dot-separated path from the server's Objects folder (namespace 0):

```go
node, err := c.NodeFromPath(ctx, "Server.ServerStatus")
if err != nil {
    log.Fatal(err)
}
v, err := node.Value(ctx)
```

**NodeFromPathInNamespace** does the same but interprets all path segments in a given namespace index (e.g. for custom namespaces):

```go
node, err := c.NodeFromPathInNamespace(ctx, 1, "MyFolder.Sensor1.Temperature")
if err != nil {
    log.Fatal(err)
}
dv, err := c.ReadValue(ctx, node.ID)
```

**NodeFromQualifiedPath** uses namespace-qualified path syntax: each segment is `ns:name` (e.g. `0:Server.0:ServerStatus` or `2:DeviceSet.4:PLC_Name`). Namespace indices are decimal (0–65535). Use this when different path segments belong to different namespaces:

```go
node, err := c.NodeFromQualifiedPath(ctx, "0:Server.0:ServerStatus")
if err != nil {
    log.Fatal(err)
}
```

**Symbolic node names:** For a single well-known standard node (e.g. `CurrentTime` → i=2258, `ServerStatus` → i=2256, `Objects` → i=85), use `ua.StandardNodeID(name)` to get a `*ua.NodeID` without parsing. Useful for CLI flags like `get value -n CurrentTime`. Returns `(nil, false)` if the name is not in the standard set.

```go
if nodeID, ok := ua.StandardNodeID("CurrentTime"); ok {
    v, _ := c.Node(nodeID).Value(ctx)
}
```

### From a custom starting node

When the path does not start from the server's Objects folder, use a **Node** and **TranslateBrowsePathInNamespaceToNodeID**:

```go
root := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
nodeID, err := root.TranslateBrowsePathInNamespaceToNodeID(ctx, 0, "Server.ServerStatus")
if err != nil {
    log.Fatal(err)
}
node := c.Node(nodeID)
```

For multiple path segments in a specific namespace:

```go
root := c.Node(ua.NewStringNodeID(1, "MyDevice"))
nodeID, err := root.TranslateBrowsePathInNamespaceToNodeID(ctx, 1, "Sensors.Temperature")
if err != nil {
    log.Fatal(err)
}
node := c.Node(nodeID)
```

### Low-level: multiple paths in one request

For full control (e.g. multiple paths or custom reference types), use **TranslateBrowsePathsToNodeIDs** on a Node with a slice of [ua.QualifiedName](https://pkg.go.dev/github.com/otfabric/go-opcua/ua#QualifiedName) segments:

```go
root := c.Node(ua.NewNumericNodeID(0, id.ObjectsFolder))
names := []*ua.QualifiedName{
    {NamespaceIndex: 0, Name: "Server"},
    {NamespaceIndex: 0, Name: "ServerStatus"},
}
nodeID, err := root.TranslateBrowsePathsToNodeIDs(ctx, names)
if err != nil {
    log.Fatal(err)
}
node := c.Node(nodeID)
```

---

## Subscriptions

### Using the Builder (Recommended)

The fluent builder API is the simplest way to create subscriptions:

```go
sub, notifyCh, err := c.NewSubscription().
    Interval(100 * time.Millisecond).
    Monitor(
        ua.NewNumericNodeID(2, 1001),
        ua.NewNumericNodeID(2, 1002),
    ).
    Start(ctx)
if err != nil {
    log.Fatal(err)
}
defer sub.Cancel(ctx)

// Process notifications
for msg := range notifyCh {
    if msg.Error != nil {
        log.Println("error:", msg.Error)
        continue
    }
    switch v := msg.Value.(type) {
    case *ua.DataChangeNotification:
        for _, item := range v.MonitoredItems {
            fmt.Printf("Item %d: %v\n", item.ClientHandle, item.Value.Value.Value())
        }
    case *ua.EventNotificationList:
        for _, event := range event.Events {
            fmt.Println("Event:", event.EventFields)
        }
    }
}
```

Builder options:
- `Interval(d)` — Publishing interval (how often the server sends notifications to the client)
- `SamplingInterval(d)` — Requested sampling interval for monitored items (how often the server samples each node). Independent of publishing interval. If not set, server uses fastest practical rate.
- `DataChangeFilter(trigger, deadbandType, deadbandValue)` — Data-change filter for the items added by the `Monitor` calls that follow (see [Data-change filters](#data-change-filters))
- `LifetimeCount(n)` — Lifetime count (go-opcua servers revise so `LifetimeCount >= 3 × MaxKeepAliveCount`)
- `MaxKeepAliveCount(n)` — Max keep-alive count
- `MaxNotificationsPerPublish(n)` — Max notifications per publish (`MoreNotifications` when more remain)
- `Priority(p)` — Subscription priority
- `Monitor(nodeIDs...)` — Add nodes for data change monitoring
- `MonitorItems(items...)` — Add custom monitored item requests (set `QueueSize` / `DiscardOldest` here)
- `MonitorEvents(filter, nodeIDs...)` — Event notifier monitoring with an `EventFilter`
- `NotifyChannel(ch)` — Use a custom notification channel
- `Timestamps(ts)` — Timestamps to return on DataChange notifications (same enum as Read)

Against go-opcua servers (v1.3.0+), monitored-item queues follow Part 4: Overflow InfoBit when `QueueSize > 1` and the queue overflows; `DiscardOldest=false` keeps the oldest `QueueSize-1` samples plus the newest.

If the server closes the connection during `Subscribe` (CreateSubscription) or `Monitor` (CreateMonitoredItems)—for example when the server does not support event or alarm subscriptions—the returned error wraps `io.EOF` with a message suggesting that limitation. Use `errors.Is(err, io.EOF)` to detect it. This applies both to `Start()` (which calls both) and to direct `Subscribe`/`Monitor` calls.

### Data-change filters

A `DataChangeFilter` tells the server which changes to report. The trigger
selects what counts as a change; the deadband suppresses value changes that
stay close to the last reported value.

```go
// Report the node only when it moved by more than 0.5.
sub, notifs, err := c.NewSubscription().
    Interval(250 * time.Millisecond).
    DataChangeFilter(ua.DataChangeTriggerStatusValue, ua.DeadbandTypeAbsolute, 0.5).
    Monitor(nodeID).
    Start(ctx)
```

For a hand-built request, or with the `monitor` package, use
`opcua.NewDataChangeFilter`:

```go
req := opcua.NewMonitoredItemCreateRequestWithDefaults(nodeID, ua.AttributeIDValue, 1)
req.RequestedParameters.Filter = opcua.NewDataChangeFilter(
    ua.DataChangeTriggerStatusValueTimestamp, ua.DeadbandTypeNone, 0)

res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, req)
// res.Results[0].StatusCode tells whether the server accepted the filter.
```

| Parameter | Values |
|-----------|--------|
| Trigger | `ua.DataChangeTriggerStatus` (status only), `ua.DataChangeTriggerStatusValue` (status or value; the default without a filter), `ua.DataChangeTriggerStatusValueTimestamp` (also the source timestamp) |
| Deadband type | `ua.DeadbandTypeNone`, `ua.DeadbandTypeAbsolute` (absolute change), `ua.DeadbandTypePercent` (percentage, 0–100, of the node's `EURange`) |

A deadband needs a numeric variable, and a percent deadband one with an
`EURange` property. A server that cannot apply the filter rejects that item
with a Bad status (`BadFilterNotAllowed`, `BadMonitoredItemFilterUnsupported`,
`BadDeadbandFilterInvalid`, `BadMonitoredItemFilterInvalid`) in the per-item
result; the other items of the request are created normally. go-opcua servers
(v1.6.0+) apply triggers, deadbands, the sampling interval and a monitored
item's `IndexRange`; earlier versions reported every change.

To change the filter of a live item, send the new one with
`Subscription.ModifyMonitoredItems`.

### Manual Subscription

```go
notifyCh := make(chan *opcua.PublishNotificationData, 100)

sub, err := c.Subscribe(ctx, &opcua.SubscriptionParameters{
    Interval: 100 * time.Millisecond,
}, notifyCh)
if err != nil {
    log.Fatal(err)
}
defer sub.Cancel(ctx)

// Add monitored items
miReq := opcua.NewMonitoredItemCreateRequestWithDefaults(
    ua.NewNumericNodeID(2, 1001),
    ua.AttributeIDValue,
    0, // client handle
)

res, err := sub.Monitor(ctx, ua.TimestampsToReturnBoth, miReq)
if err != nil {
    log.Fatal(err)
}

// Process notifications
for msg := range notifyCh {
    // ...
}
```

The same EOF wrapping applies: if the server closes the connection during `Subscribe` or `Monitor`, the error wraps `io.EOF` with a hint; use `errors.Is(err, io.EOF)` to detect it.

### Alarms and Conditions

`NewConditionEventFilter` selects the ConditionId and the condition fields
of Part 9 (EventId, EventType, SourceNode, Time, Message, Severity,
ConditionName, Retain, EnabledState, AckedState, ConfirmedState,
ActiveState, Comment, ShelvingState, ...); `ParseConditionEvent` turns each
event of such an item into a `ConditionEvent`. After `ConditionRefresh` the
server sends a RefreshStartEvent, the retained conditions and a
RefreshEndEvent (Part 9 §5.5.7):

```go
sub, ch, err := c.NewSubscription().
    Interval(200*time.Millisecond).
    MonitorEvents(opcua.NewConditionEventFilter(), ua.NewNumericNodeID(0, id.Server)).
    Start(ctx)
if err != nil {
    log.Fatal(err)
}
if err := sub.ConditionRefresh(ctx); err != nil { // or sub.ConditionRefresh2(ctx, itemID)
    log.Fatal(err)
}
for msg := range ch {
    enl, ok := msg.Value.(*ua.EventNotificationList)
    if !ok {
        continue
    }
    for _, f := range enl.Events {
        ev, err := opcua.ParseConditionEvent(f)
        if err != nil || ev.ConditionID == nil { // RefreshStart / RefreshEnd have none
            continue
        }
        if ev.Acked != nil && !*ev.Acked {
            // Acknowledge the state of this event; the EventId identifies it.
            err := c.Acknowledge(ctx, ev.ConditionID, ev.EventID, "seen")
            if errors.Is(err, ua.StatusBadConditionBranchAlreadyAcked) {
                // someone else was faster
            }
        }
    }
}
```

| Helper | Part 9 |
|---|---|
| `Acknowledge`, `Confirm` (conditionID, eventID, comment) | §5.7.3, §5.7.4 |
| `AddComment` (conditionID, eventID, comment) | §5.5.6 |
| `EnableCondition`, `DisableCondition` | §5.5.4, §5.5.5 |
| `TimedShelve` (duration), `OneShotShelve`, `Unshelve`; `TimedShelve2`, `OneShotShelve2`, `Unshelve2` (with a comment) | §5.8.10 |
| `Suppress`, `Unsuppress`, `RemoveFromService`, `PlaceInService`, `Silence`, `Reset`; `Suppress2`, `Unsuppress2`, `RemoveFromService2`, `PlaceInService2`, `Reset2` (with a comment) | §5.8 |
| `Respond` (selectedResponse), `Respond2` (selectedResponse, comment) of a dialog | §5.6.3, §5.6.4 |
| `GetGroupMemberships` (the alarm groups of an alarm) | §5.8 |
| `ReadAlarmMetrics`, `ResetAlarmMetrics` (an AlarmMetricsType object) | §8.5 |
| `ConditionRefresh`, `ConditionRefresh2` (Client: server ids; Subscription: its own ids) | §5.5.7, §5.5.8 |

A refused call returns its StatusCode as the error (`errors.Is(err,
ua.StatusBadEventIDUnknown)`). The comment is sent with the first session
locale (`opcua.Locales`, "en-us" by default), because open62541 ignores a
comment without one. For your own filters, `ua.EventFilterBuilder.SelectPaths`
selects BrowsePaths such as `AckedState/Id` and `SelectConditionID` the
ConditionId; `ua.FieldPath` is the WhereClause operand of a BrowsePath.

The filter also selects BranchId and the Part 9 v1.05 fields SuppressedState,
OutOfServiceState, SilenceState, LatchedState, DialogState, Prompt and
LastResponse (`ConditionEvent.Suppressed`, `OutOfService`, `Silenced`,
`Latched`, `DialogActive`, `Prompt`, `LastResponse`; nil when the server does
not report them). `ev.IsBranch()` tells the event of a condition branch: a
previous occurrence the server keeps until it is acknowledged or confirmed.
Acknowledge and Confirm it with its own EventId like the condition.
It also selects AudibleEnabled, ReAlarmRepeatCount and FirstInGroupFlag
(`ConditionEvent.AudibleEnabled`, `ReAlarmRepeatCount`, `FirstInGroup`).
`ParseConditionEvent` still reads the shorter field lists of earlier filters.

`ReadAlarmMetrics` reads the counters of an AlarmMetricsType object (one
TranslateBrowsePathsToNodeIDs and one Read) and `ResetAlarmMetrics` calls its
Reset method:

```go
m, err := c.ReadAlarmMetrics(ctx, metricsID)
if err == nil {
    log.Printf("%d alarms since %v, %.1f per %d min", m.AlarmCount, m.StartTime, m.CurrentAlarmRate, m.RateMinutes)
}
```

Audit events: `NewAuditConditionEventFilter` selects the AuditConditionEventType
events (who called which condition method, with which arguments and result)
and `ParseAuditConditionEvent` reads them. The server must have auditing on
and grant the session the ReceiveEvents permission. `WithAuditEntryID(ctx,
id)` sets the AuditEntryId of the requests sent with that context, which the
server reports as ClientAuditEntryId:

```go
ctx := opcua.WithAuditEntryID(ctx, "ticket-4711")
if err := c.Suppress2(ctx, alarmID, "maintenance until 14:00"); err != nil {
    log.Fatal(err)
}
```

### Monitor Package (Callback-Based)

The `monitor` package provides a higher-level API with callbacks:

```go
import "github.com/otfabric/go-opcua/monitor"

m, err := monitor.NewNodeMonitor(c)
if err != nil {
    log.Fatal(err)
}

// Channel-based
ch := make(chan *monitor.DataChangeMessage, 16)
sub, err := m.ChanSubscribe(ctx, &opcua.SubscriptionParameters{
    Interval: 500 * time.Millisecond,
}, ch,
    "ns=2;s=Temperature",
    "ns=2;s=Pressure",
)

for msg := range ch {
    if msg.Error != nil {
        log.Println(msg.Error)
        continue
    }
    fmt.Printf("%s: %v\n", msg.NodeID, msg.Value)
}

// Or callback-based
sub, err := m.Subscribe(ctx, &opcua.SubscriptionParameters{
    Interval: 500 * time.Millisecond,
}, func(s *monitor.Subscription, msg *monitor.DataChangeMessage) {
    fmt.Printf("%s: %v\n", msg.NodeID, msg.Value)
},
    "ns=2;s=Temperature",
)
```

`AddMonitorItems` with a zero-value `monitor.Request.MonitoringMode` defaults to **Reporting**. To disable an item, call `SetMonitoringMode` after create.

---

## Calling Methods

### High-Level Helper

```go
result, err := c.CallMethod(ctx,
    ua.NewNumericNodeID(2, 1001),  // object node ID
    ua.NewNumericNodeID(2, 2001),  // method node ID
    42.0,                           // arguments (auto-wrapped in Variants)
    "hello",
)
if err != nil {
    log.Fatal(err)
}
if result.StatusCode != ua.StatusOK {
    log.Fatal("method failed:", result.StatusCode)
}
for _, v := range result.OutputArguments {
    fmt.Println("output:", v.Value())
}
```

### Low-Level Call

```go
req := &ua.CallMethodRequest{
    ObjectID: ua.NewNumericNodeID(2, 1001),
    MethodID: ua.NewNumericNodeID(2, 2001),
    InputArguments: []*ua.Variant{
        ua.MustVariant(42.0),
        ua.MustVariant("hello"),
    },
}

result, err := c.Call(ctx, req)
```

---

## Connection State Monitoring

Track connection state changes for monitoring and alerting:

```go
c, _ := opcua.NewClient("opc.tcp://server:4840",
    opcua.AutoReconnect(true),
    opcua.ReconnectInterval(5 * time.Second),
    opcua.WithConnStateHandler(func(state opcua.ConnState) {
        switch state {
        case opcua.Connected:
            log.Println("Connected to server")
        case opcua.Disconnected:
            log.Println("Disconnected — will attempt reconnection")
        case opcua.Reconnecting:
            log.Println("Reconnecting...")
        case opcua.Closed:
            log.Println("Connection closed")
        }
    }),
)
```

### Connection States

| State | Meaning |
|-------|---------|
| `Closed` | Not connected (initial state or permanently closed) |
| `Connecting` | First connection attempt in progress |
| `Connected` | Active session, ready for operations |
| `Disconnected` | Lost connection (auto-reconnect will trigger) |
| `Reconnecting` | Recovery in progress |

With `AutoReconnect(true)` (default), reconnect runs Transfer → Republish → Recreate
per subscription. Observe outcomes with `WithSubscriptionRecoveryHandler`:

```go
opcua.WithSubscriptionRecoveryHandler(func(ev opcua.SubscriptionRecoveryEvent) {
    log.Printf("sub %d: %s (%s)", ev.SubscriptionID, ev.Outcome, ev.Detail)
})
```

Manual protocol helpers (do not mutate subscription notify channels):

```go
resp, err := c.Republish(ctx, subscriptionID, sequenceNumber)
tr, err := c.TransferSubscriptions(ctx, []uint32{subscriptionID}, false)
```

---

## Session Management

### Session Transfer

Detach a session from one channel and reattach it to another:

```go
// Detach from current client
session, err := c1.DetachSession(ctx)
if err != nil {
    log.Fatal(err)
}

// Create new client with channel only
c2, _ := opcua.NewClient(endpoint, opts...)
c2.Dial(ctx)

// Reattach session
err = c2.ActivateSession(ctx, session)
```

This is useful for failover scenarios or migrating between connections.

---

## Historical Access

High-level helpers page raw history for you:

```go
// Single page
values, err := c.ReadHistory(ctx, nodeID, start, end, 100)

// All pages via Go 1.23 iterator
for dv, err := range c.ReadHistoryAll(ctx, nodeID, start, end) {
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(dv.SourceTimestamp, dv.Value.Value())
}
```

Low-level `HistoryReadRawModified` / `HistoryReadProcessed` / `HistoryReadAtTime` and the
HistoryUpdate helpers accept full details and continuation points. Against go-opcua servers
with the default `*Historian`, raw/modified/at-time/processed and data update/delete paths
are available after `SetHistorian` + `EnableNode`.

Historical events are read with `HistoryReadEvent` (an `EventFilter` selects the fields
and filters the events) and changed with `HistoryUpdateEvents` / `HistoryDeleteEvents`;
go-opcua servers serve them on the notifiers they historize (`EnableEventHistory`):

```go
d := &ua.ReadEventDetails{
    StartTime:        start, // two of StartTime, EndTime, NumValuesPerNode (Part 11 §6.5.2)
    EndTime:          end,
    NumValuesPerNode: 100,
    Filter:           ua.NewEventFilter().Select("EventId", "Time", "Message", "Severity").Build(),
}
var cp []byte
for {
    resp, err := c.HistoryReadEvent(ctx, []*ua.HistoryReadValueID{{NodeID: notifier, ContinuationPoint: cp}}, d)
    if err != nil {
        log.Fatal(err)
    }
    r := resp.Results[0] // Good, Good_NoData, or a Bad status of the node
    if he, ok := r.HistoryData.Value.(*ua.HistoryEvent); ok {
        for _, ev := range he.Events {
            fmt.Println(ev.EventFields[1].Value(), ev.EventFields[2].Value())
        }
    }
    if cp = r.ContinuationPoint; len(cp) == 0 {
        break
    }
}
```
Peer-proven history is raw HistoryRead (`history.read.raw`) in both directions with all six
peers, and its continuation points (`history.read.continuation`) in both directions with all
of them but the asyncua server, which returns none (see [INTEROP.md](../INTEROP.md)).

IndexRange on current Values uses the same NumericRange grammar as servers:
`"i"`, `"i:j"`, or multi-dimensional `"a:b,c:d"` via `ReadItem.IndexRange` / `ReadMulti`.

---

## Lifecycle and concurrency

- Own the client: `NewClient` → `Connect` → use → `Close`. Do not reuse after `Close`.
- One connected `*Client` is safe for concurrent ordinary service calls (see race tests).
- Subscription and recovery callbacks run on library goroutines and must not block.
- Auto-reconnect is enabled by default; watch `ConnState` / recovery handlers if the app must react to session rebuilds.

Internals (atomics, mutexes) are described in [architecture.md](architecture.md). Caller-facing contracts are also summarized in [API.md](../API.md).

## Certificate Management (GDS Push)

Package `gds` manages the certificates of a server by the push model of
Part 12 §7 — a go-opcua server with `server.WithPushManagement`, open62541
(UA_ENABLE_GDS_PUSHMANAGEMENT), UA-.NETStandard or node-opcua. The client
needs a session with the SecurityAdmin role over SignAndEncrypt:

```go
c, _ := opcua.NewClient(endpoint,
    opcua.SecurityPolicy(ua.SecurityPolicyURIBasic256Sha256),
    opcua.SecurityMode(ua.MessageSecurityModeSignAndEncrypt),
    opcua.Certificate(cert), opcua.PrivateKey(key),
    opcua.AuthUsername("secadmin", password),
)
_ = c.Connect(ctx)
g := gds.New(c)

// Trust list of the DefaultApplicationGroup (Part 12 §7.8.2).
tl, _ := g.ReadTrustList(ctx, ua.TrustListMasksAll)
tl.TrustedCertificates = append(tl.TrustedCertificates, newClientCA)
required, _ := g.WriteTrustList(ctx, tl)     // Open, Write, CloseAndUpdate
_ = g.AddCertificate(ctx, peerCert, true)     // or one certificate at a time
_ = g.RemoveCertificate(ctx, gds.Thumbprint(oldCert), true)

// A new application instance certificate (Part 12 §7.10.4, §7.10.8).
csr, _ := g.CreateSigningRequest(ctx, &gds.SigningRequest{
    CertificateType: gds.RsaSha256ApplicationCertificateType,
})
issued := myCA.Sign(csr)
required, _ = g.UpdateCertificate(ctx, &gds.CertificateUpdate{
    CertificateType:    gds.RsaSha256ApplicationCertificateType,
    Certificate:        issued,
    IssuerCertificates: [][]byte{myCA.Cert},
})
if required {
    _ = g.ApplyChanges(ctx) // or CancelChanges
}
rejected, _ := g.GetRejectedList(ctx)
props, _ := g.Properties(ctx) // SupportedPrivateKeyFormats, MaxTrustListSize, CertificateTypes, …

// Part 12 1.05 (§7.10): what the server uses, a self-signed certificate,
// the diagnostics of the last transaction, back to the defaults.
types, certs, _ := g.GetCertificates(ctx, gds.DefaultHTTPSGroup)
tlsCert, _ := g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
    CertificateGroup: gds.DefaultHTTPSGroup,
    SubjectName:      "CN=myserver/O=example",
    DNSNames:         []string{"myserver.example.com"},
})
_ = g.ApplyChanges(ctx)
diag, _ := g.TransactionDiagnostics(ctx) // Result, AffectedTrustLists, Errors, …

// Delete a certificate (it goes at ApplyChanges; a server refuses to delete
// the one its endpoints use) and fill the slot again in the same transaction.
_ = g.DeleteCertificate(ctx, gds.DefaultApplicationGroup, gds.EccNistP256ApplicationCertificateType)
_, _ = g.CreateSelfSignedCertificate(ctx, &gds.SelfSignedCertificate{
    CertificateType: gds.EccNistP256ApplicationCertificateType,
    SubjectName:     "CN=myserver/O=example",
})
_ = g.ApplyChanges(ctx)

// The certificate groups of the server, the defaults and its own, with
// their TrustLists.
groups, _ := g.CertificateGroups(ctx)
for _, cg := range groups {
    tl, _ := g.WithTrustList(cg.TrustList).ReadTrustList(ctx, ua.TrustListMasksAll)
    _ = tl
}
_ = g.ResetToServerDefaults(ctx)

// The trust lists of the DefaultUserTokenGroup and the DefaultHttpsGroup.
_ = g.WithTrustList(gds.UserTokenTrustList).AddCertificate(ctx, userCA, true)
_ = g.ApplyChanges(ctx)

// A new key with its certificate as PKCS #12; the server knows the password.
pfx, _ := uapolicy.EncodePFX(newKey, [][]byte{issued, myCA.Cert}, password)
_, _ = g.UpdateCertificate(ctx, &gds.CertificateUpdate{
    CertificateType: gds.RsaSha256ApplicationCertificateType,
    Certificate:     issued, PrivateKeyFormat: "PFX", PrivateKey: pfx,
})
```

A method that fails returns a `*gds.Error` with the method name and the
status (`errors.Is(err, ua.StatusBadUserAccessDenied)`). The methods are found
by BrowseName under the ServerConfiguration object, so servers with other
NodeIds work too; `Client.WithTrustList` (or the `Client.TrustList` field)
selects another certificate group's TrustList. `EncodeTrustList` / `DecodeTrustList` are the file format.
`Thumbprint` is the upper-case hexadecimal SHA-1 that every tested server
accepts (UA-.NETStandard compares the case).

Peers differ in details: open62541 1.5.9 serves the methods to any session on a
SignAndEncrypt channel and answers ApplyChanges without a pending change with
`Bad_NothingToDo` (as node-opcua), and the endpoints of UA-.NETStandard and
node-opcua carry the issuer chain after the certificate. Of the Part 12 1.05
additions, UA-.NETStandard serves GetCertificates, the TransactionDiagnostics,
the HTTPS and UserToken trust lists, PFX keys and the alarms, and refuses
CreateSelfSignedCertificate for an occupied slot (`Bad_InvalidState`: it wants
DeleteCertificate first). It serves DeleteCertificate but refuses to delete
its only application certificate, at once, with `Bad_InvalidState`; this
library's server accepts the deletion and refuses it at ApplyChanges.
open62541 1.5.9 and node-opcua serve the UserToken trust list only. See the interop ledgers.

The pull model is described in the next section.

## Certificate Management (GDS Pull)

`gds.PullClient` talks to a Global Discovery Server by the pull model of
Part 12 (§6, §7.9) — a go-opcua `gds/gdsserver` or any other GDS. It
finds the GDS namespace itself and wraps every Directory and
CertificateDirectory method (RegisterApplication, QueryServers,
StartSigningRequest, StartNewKeyPairRequest, FinishRequest,
RevokeCertificate, GetTrustList, CheckRevocationStatus, ...). `Enroll` does
the whole exchange: it finds or registers the application, asks for a
certificate, waits until the GDS issues it and reads the trust list:

```go
pc := gds.NewPullClient(c) // a session over SignAndEncrypt
e, err := pc.Enroll(ctx, &gds.EnrollRequest{
    Record:          &gds.ApplicationRecord{ApplicationURI: uri, ApplicationType: ua.ApplicationTypeClient, ApplicationNames: names, ProductURI: product},
    CertificateType: gds.EccNistP256ApplicationCertificateType,
    Key:             key, // nil: the GDS generates the key
})
opts, err := e.ClientOptions()   // certificate, key and trusted CAs for opcua.NewClient
sopts := e.ServerOptions()       // ApplicationIdentity and push management with the trust list
```

Registering needs the DiscoveryAdmin role and a certificate request the
CertificateAuthorityAdmin role, or a session of the application itself.
`WaitForCertificate` polls FinishRequest (`DefaultPollInterval`) while the
request waits for approval. See [examples/gds-pull](../examples/gds-pull/main.go).

`NewCertificateRequest` makes a request for a key of any certificate type
(RSA, NIST and Brainpool ECDSA, Ed25519, Ed448). A key the GDS generates
comes as PEM (encrypted when a password is given) or as PFX with the
certificate and its issuer; `DecodePrivateKey` reads both, and `Enroll`
takes the format and password:

```go
e, err := pc.Enroll(ctx, &gds.EnrollRequest{
    ApplicationID:      appID,
    PrivateKeyFormat:   gds.PrivateKeyFormatPFX,
    PrivateKeyPassword: password,
})
```

A server application asks for a TLS certificate in the DefaultHttpsGroup
(`CertificateGroup` of the request, the group's NodeId from
`GetCertificateGroups`) and reads the issuers of user certificates from the
trust list of the DefaultUserTokenGroup. The pull model is verified against
the Global Discovery Server of UA-.NETStandard 2.0.1.

---

## Error Handling

OPC-UA exposes **Go errors** (connection/session/config) and **wire `ua.StatusCode`**
(per-item service outcomes). They are not interchangeable — see the canonical guide
[ERRORS.md](../ERRORS.md).

```go
import (
    "errors"

    opcuaerrors "github.com/otfabric/go-opcua/errors"
    "github.com/otfabric/go-opcua/ua"
)

if err := c.Connect(ctx); err != nil {
    if errors.Is(err, opcuaerrors.ErrNotConnected) {
        // Handle disconnection / connect failure
    }
    return err
}

dv, err := c.ReadValue(ctx, nodeID)
if err != nil {
    return err // client/transport failure
}
if dv.Status != ua.StatusOK {
    // Server item status — not the same as a Go sentinel
    return dv.Status
}
```

### Common Status Codes

| Code | Meaning |
|------|---------|
| `StatusOK` | Success |
| `StatusBadNodeIDUnknown` | Node does not exist |
| `StatusBadAttributeIDInvalid` | Attribute not supported |
| `StatusBadUserAccessDenied` | Insufficient permissions |
| `StatusBadTimeout` | Operation timed out |
| `StatusBadSessionIDInvalid` | Session expired or invalid |
| `StatusBadSecureChannelIDInvalid` | Channel needs renewal |

---

## Complete Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/otfabric/go-opcua"
    "github.com/otfabric/go-opcua/ua"
)

func main() {
    ctx := context.Background()

    c, err := opcua.NewClient("opc.tcp://localhost:4840",
        opcua.AutoReconnect(true),
        opcua.ReconnectInterval(5 * time.Second),
        opcua.WithConnStateHandler(func(s opcua.ConnState) {
            log.Printf("State: %s", s)
        }),
    )
    if err != nil {
        log.Fatal(err)
    }
    if err := c.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer c.Close(ctx)

    // Read server time
    dv, err := c.ReadValue(ctx, ua.NewNumericNodeID(0, 2258))
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Server time:", dv.Value.Value())

    // Subscribe to value changes
    sub, notifyCh, err := c.NewSubscription().
        Interval(500 * time.Millisecond).
        Monitor(ua.NewNumericNodeID(2, 1001)).
        Start(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer sub.Cancel(ctx)

    for msg := range notifyCh {
        if msg.Error != nil {
            log.Println("error:", msg.Error)
            continue
        }
        if dcn, ok := msg.Value.(*ua.DataChangeNotification); ok {
            for _, item := range dcn.MonitoredItems {
                fmt.Printf("Value changed: %v\n", item.Value.Value.Value())
            }
        }
    }
}
```
