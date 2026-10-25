# Server Development Guide

> Building OPC-UA servers with the `github.com/otfabric/go-opcua/server` package.

---

## Service Support Matrix

| Service Set | Operations | Status |
|-------------|-----------|--------|
| **Discovery** | FindServers, GetEndpoints | Fully implemented (FindServers with `serverUris`, `localeIds` and `endpointUrl`) |
| | RegisterServer, RegisterServer2 | Local Discovery Server role, opt-in with `WithLocalDiscoveryServer`; `StatusBadServiceUnsupported` otherwise |
| | FindServersOnNetwork | Multicast extension (mDNS), opt-in with `WithMulticastDiscovery`; `StatusBadServiceUnsupported` otherwise |
| **Secure Channel** | OpenSecureChannel, CloseSecureChannel | Implemented (handled in `uasc` layer) |
| **Session** | CreateSession, ActivateSession, CloseSession, Cancel | Fully implemented |
| **Node Management** | AddNodes, DeleteNodes, AddReferences, DeleteReferences | Fully implemented |
| **View** | Browse, BrowseNext, TranslateBrowsePathsToNodeIDs, RegisterNodes, UnregisterNodes | Fully implemented |
| **Attribute** | Read, Write | Fully implemented (IndexRange / NumericRange, `TimestampsToReturn`, value-only Write) |
| | HistoryRead | Via pluggable `HistoryProvider` (`SetHistorian`); default `*Historian` supports raw, modified, at-time, and processed aggregates |
| | HistoryUpdate | Via optional historian interfaces (`HistoryDataUpdater` / deleters); default `*Historian` supports UpdateData and raw/at-time deletes |
| **Method** | Call | Fully implemented |
| **Monitored Items** | CreateMonitoredItems, ModifyMonitoredItems, SetMonitoringMode, SetTriggering, DeleteMonitoredItems | Fully implemented (exact `QueueSize` / `DiscardOldest` / Overflow, `DataChangeFilter`, sampling interval, `IndexRange`) |
| **Subscription** | CreateSubscription, ModifySubscription, SetPublishingMode, Publish, Republish, TransferSubscriptions, DeleteSubscriptions | Fully implemented (revise clamps, `MoreNotifications`, Publish ACK, lifetime expiry) |
| **Query** | QueryFirst, QueryNext | Fully implemented |

Unsupported services return consistent OPC UA status codes. Any request type
not registered with the server returns `StatusBadServiceUnsupported`.

Not implemented in the server, so plan around them:

- **Historical events**: the history interfaces cover data only (see
  [Historical Access](#historical-access-raw)).

---

## Server diagnostics

The server maintains `Server.ServerDiagnostics` (i=2274, Part 5 §6.3.3) live:

- `ServerDiagnosticsSummary` (i=2275) and its twelve component variables:
  current and cumulated sessions and subscriptions, rejected and
  security-rejected sessions and requests, session timeouts, publishing
  intervals in use. Read it in process with `srv.ServerDiagnosticsSummary()`.
- `SamplingIntervalDiagnosticsArray` (i=2289), one entry per sampling
  interval in use, and `SubscriptionDiagnosticsArray` (i=2290), one entry per
  subscription (publish, notification, republish, transfer, modify and
  enable / disable counts).
- `SessionsDiagnosticsSummary` (i=3706) with `SessionDiagnosticsArray` (i=3707)
  and `SessionSecurityDiagnosticsArray` (i=3708), and one
  `SessionDiagnosticsObject` per session, created with the session and removed
  with it. Its NodeId is the SessionId (a GUID in the namespace
  `urn:otfabric:go-opcua:diagnostics`, which the server adds when the first
  session is created, after the namespaces of the application). It holds
  `SessionDiagnostics` (with per-service request counters),
  `SessionSecurityDiagnostics`, the session's `SubscriptionDiagnosticsArray`
  and `CurrentRoleIds`.
- `EnabledFlag` (i=2294). Diagnostics are on by default;
  `server.WithServerDiagnostics(false)` starts the server with them off and
  `srv.SetServerDiagnosticsEnabled` switches them at run time, as does a
  client that writes `EnabledFlag`. While they are off the counters stand
  still, the summary keeps its last value, the arrays are empty and the
  session objects are gone. Switching them on resets the counters (the
  cumulated counts start at what exists) and recreates the session objects.

The counters are atomics bumped by the request dispatcher; reading the
diagnostics builds the values on demand, so a server that nobody asks pays a
few atomic adds per request.

Access follows the role permissions of the standard node set and
UA-.NETStandard practice, in addition to the `AccessController`:

| Node | Read / browse | Write |
|---|---|---|
| Summary, its components, the sampling interval and subscription arrays, `SessionDiagnosticsArray`, `EnabledFlag` | everyone | `EnabledFlag`: SecurityAdmin, ConfigureAdmin |
| `SessionSecurityDiagnosticsArray` | SecurityAdmin, over a SignAndEncrypt channel (its AccessRestrictions) | — |
| A session's object and its variables | the session itself, SecurityAdmin, ConfigureAdmin | — |
| A session's `SessionSecurityDiagnostics` | the session itself, SecurityAdmin | — |

Browsing `SessionsDiagnosticsSummary` shows a client only the objects it may
read. Session security diagnostics hold the user name (or the subject of the
X.509 user certificate), the authentication mechanism, the security policy
and mode and the client certificate; passwords and token data never appear.

### DiagnosticInfo (ReturnDiagnostics)

A request whose `RequestHeader.ReturnDiagnostics` asks for diagnostics gets
them (Part 4 §7.12, §7.33): for a failed service the `ServiceDiagnostics` of
the header, for failed operations one `DiagnosticInfo` per operation in the
`DiagnosticInfos` of the response (an empty array when every operation
succeeded). The strings are in the `StringTable` of the header. A
DiagnosticInfo carries what the mask asks for: the symbolic id of the status
in `http://opcfoundation.org/UA/`, its description (locale `en`), as
AdditionalInfo the operation in terms of the request (NodeId and attribute,
subscription or monitored item id, method and object), and for a failed
method call the first failed input argument as inner status, with a
DiagnosticInfo per failed argument in `InputArgumentDiagnosticInfos`. Nothing
the client did not send, no internal error text, peer address or secret.

### What is not tracked

`SessionAbortCount` stays 0: a session outlives the loss of its secure
channel and ends by CloseSession or timeout. In `SubscriptionDiagnostics`,
`CurrentKeepAliveCount`, `CurrentLifetimeCount`, `LatePublishRequestCount`,
`DiscardedMessageCount`, `MonitoringQueueOverflowCount` and
`EventQueueOverFlowCount` are 0. The arrays have no variable per element
(Part 5 lets a server omit them). Publish responses sent after the request
waited (the usual case) carry no DiagnosticInfos.

---

## Minimal Server

A working server needs at least an endpoint and a security configuration:

```go
package main

import (
    "context"
    "log"

    "github.com/otfabric/go-opcua/server"
    "github.com/otfabric/go-opcua/ua"
)

func main() {
    s, err := server.New(
        server.EndPoint("localhost", 4840),
        server.EnableSecurity("None", ua.MessageSecurityModeNone),
        server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    )
    if err != nil {
        log.Fatal(err)
    }

    if err := s.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
    defer s.Close()

    log.Println("Server running on opc.tcp://localhost:4840")
    select {} // Block forever
}
```

This creates a server with:
- Standard OPC-UA namespace (namespace 0) auto-populated with `Server`, `ServerStatus`, `CurrentTime`, etc.
- No encryption (suitable for development only)
- Anonymous authentication

### Server Options

| Option | Purpose |
|--------|---------|
| `EndPoint(host, port)` | Listen address (can be called multiple times) |
| `EnableSecurity(policy, mode)` | Register a security policy + mode combination |
| `EnableAuthMode(tokenType)` | Enable an authentication mechanism |
| `Certificate(cert)` | DER-encoded X.509 certificate |
| `PrivateKey(key)` | RSA private key |
| `ApplicationIdentity(cert, key)` | An application instance certificate per key type (RSA, ECDSA on NIST or Brainpool curves, Ed25519, Ed448) for the ECC policies |
| `ServerName(name)` | Human-readable name |
| `ManufacturerName(name)` | Manufacturer metadata |
| `ProductName(name)` | Product metadata |
| `SoftwareVersion(version)` | Version string |
| `SetLogger(l)` | `*slog.Logger`; silent by default (`nil` restores silent) |
| `WithAccessController(ac)` | Custom authorization logic |
| `ApplicationURI(uri)` | ApplicationUri of a server without a certificate (otherwise taken from the certificate) |
| `WithReverseConnect(clientURL, opts...)` | Connect to a listening client ([reverse connect](#reverse-connect)) |
| `WebSocketEndPoint(host, port)`, `ListenWebSocketOn(addr)` | An `opc.wss` endpoint and its bind address ([HTTPS and WebSocket endpoints](#https-and-websocket-endpoints)) |
| `HTTPSEndPoint(host, port)`, `ListenHTTPSOn(addr)` | An `opc.https` endpoint and its bind address |
| `TLSConfig(cfg)` | TLS certificate of the `opc.wss` / `opc.https` listeners |
| `EnableUAJSON()` | The UA JSON mappings https-uajson and wss-uajson on those listeners ([UA JSON](#ua-json-https-uajson-wss-uajson)) |
| `WithServerDiagnostics(enabled)` | Start with server diagnostics on (default) or off ([Server diagnostics](#server-diagnostics)) |
| `WithLocalDiscoveryServer`, `WithDiscoveryRegistration`, `WithMulticastDiscovery` | Discovery server role, registration with one, mDNS ([Discovery](#discovery)) |
| `WithAuditing(enabled)`, `WithAlarmClock(clock)` | Audit events of the condition methods and of the GDS; the clock of the alarm timers ([Alarms and Conditions](#alarms-and-conditions)) |
| `WithPushManagement(pm)` | ServerConfiguration push model ([Certificate Management](#certificate-management-push-model)) |
| `WithPubSub(cfg, opts...)` | PubSub runtime with the PublishSubscribe information model ([PubSub](pubsub.md)) |

The full list is in [API.md](../API.md#server-configuration-options).

---

## HTTPS and WebSocket endpoints

Next to its `opc.tcp` listener a server can serve `opc.wss` (OPC UA Secure
Conversation over a TLS WebSocket, Part 6 §7.5, transport profile
wss-uasc-uabinary) and `opc.https` (UA Binary over HTTPS POST, Part 6 §7.4,
https-uabinary), each on a listener of its own:

```go
srv, err := server.New(
    server.EndPoint("plc.example.com", 4840),
    server.WebSocketEndPoint("plc.example.com", 4843),
    server.HTTPSEndPoint("plc.example.com", 4443),
    server.TLSConfig(&tls.Config{Certificates: []tls.Certificate{tlsCert}}),
    server.EnableSecurity("None", ua.MessageSecurityModeNone),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableAuthMode(ua.UserTokenTypeAnonymous),
)
```

- **TLS.** `TLSConfig` sets the TLS certificate; it may differ from the
  application instance certificate (Part 6 §7.5.3). Without it the RSA
  application certificate serves TLS. TLS 1.2 is the minimum. Set
  `ClientAuth` / `ClientCAs` to require client TLS certificates.
- **Endpoints.** Every endpoint description carries its
  `TransportProfileUri`. opc.wss offers all enabled policies and modes, as
  opc.tcp does. opc.https offers each enabled policy that needs no secure
  conversation (`uasc.HTTPSPolicySupported`: not `ECC_nistP256_AesGcm` and
  `ECC_nistP256_ChaChaPoly`, whose SecureChannelEnhancements bind the session
  signatures to a channel thumbprint) once, in its strongest
  enabled mode; a user name is accepted on the None endpoint because TLS
  protects it.
- **HTTPS requests.** All HTTPS requests to the server share one virtual secure
  channel per policy, selected by the `OPCUA-SecurityPolicy` header (None
  without it). The body is limited to the maximum message size (413), POST
  only (405), `application/octet-stream` or `application/opcua+uabinary`
  (415); bodies must arrive within 10 s and headers are limited to 64 KiB.
  A Publish request is answered when a notification is due (long poll); one
  whose HTTP request has ended is dropped and not answered.
- **Ports.** Port 0 picks a free port; `Server.URLs()` lists the bound URLs
  and `Server.WebSocketAddr()` / `Server.HTTPSAddr()` the listener addresses.
  `ListenWebSocketOn` / `ListenHTTPSOn` bind elsewhere than the advertised
  host (for example `0.0.0.0:4843`).

### UA JSON (https-uajson, wss-uajson)

`EnableUAJSON` makes the same listeners serve the UA JSON mappings of their
transports: every service message is a JSON message (Part 6 §5.4.9) and there
is no secure conversation.

```go
srv, err := server.New(
    server.EndPoint("plc.example.com", 4840),
    server.WebSocketEndPoint("plc.example.com", 4843),
    server.HTTPSEndPoint("plc.example.com", 4443),
    server.TLSConfig(&tls.Config{Certificates: []tls.Certificate{tlsCert}}),
    server.EnableSecurity("None", ua.MessageSecurityModeNone),
    server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    server.EnableUAJSON(),
)
```

- **Endpoints.** The JSON endpoints are twins of the binary ones at the same
  URLs, with the TransportProfileUri of https-uajson or wss-uajson. https-uajson
  offers the policies of https-uabinary. A WebSocket cannot name a security
  policy, so wss-uajson is offered only with None / None (when it is enabled,
  or no security is configured at all).
- **https-uajson** (Part 6 §7.4.5). A POST with the Content-Type
  `application/json` (Part 6 §7.4.2 Table 80), or `application/opcua+uajson`
  as UA-.NETStandard sends it, carries one request; the response has the
  request's Content-Type. The body may be gzip compressed (`Content-Encoding:
  gzip`); the size limit (413) applies to the decompressed body. A body that is
  no request is answered with a ServiceFault (with the RequestHandle when it
  can be read), a bad gzip stream with 400. The `OPCUA-SecurityPolicy` header
  selects the virtual channel, as for UA Binary.
- **wss-uajson** (Part 6 §7.5.2). A WebSocket whose client offers the
  sub-protocol `opcua+uajson` carries one JSON message per WebSocket message
  (text frames; binary ones are accepted) with no HEL/ACK. Up to 64 requests of
  a connection are served at the same time and answered as they complete; the
  RequestHandle correlates them. A message over the maximum message size ends
  the connection with status 1009, invalid UTF-8 with 1007. A connection
  without a request in flight is closed after 2 minutes.
- **Encoding.** Responses use the compact form; requests may use the compact
  or the verbose form, and the 1.04 form. NodeIds of namespaces other than 0
  are written with their namespace URI (Part 6 §5.4.2.10).
- **Sessions.** The AuthenticationToken travels in the RequestHeader; the
  HTTP `Authorization: Bearer` header of Part 6 §7.4.5 is not used.

## Reverse Connect

A server behind a firewall or NAT cannot be reached by its clients, but it
can usually reach them. With reverse connect (OPC UA Part 6 §7.1.3) the
server opens the TCP connection to a client that listens for it, announces
itself with a ReverseHello message, and then serves the connection exactly
like one it had accepted: the client sends Hello, opens a secure channel with
any enabled security policy, and creates sessions and subscriptions.

```go
srv, err := server.New(
    server.EndPoint("plc-17", 4840),
    server.Certificate(cert), server.PrivateKey(key),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    // connect to the client listening at scada.example.com:4841
    server.WithReverseConnect("opc.tcp://scada.example.com:4841"),
)
```

Targets can also be managed while the server runs:

```go
rc, err := srv.AddReverseConnect("opc.tcp://scada.example.com:4841",
    server.ReverseConnectRetryInterval(time.Second, 30*time.Second),
)
fmt.Println(rc.State(), rc.Connections(), rc.Err())
_ = rc.Close() // stop connecting and close the target's connections
```

How it behaves:

- **Announcement.** The ReverseHello carries the server's ApplicationUri as
  ServerUri (from the certificate, or from `server.ApplicationURI` for a
  server without one) and the URL of the endpoint the client is to use. The
  latter defaults to the first `EndPoint`; override it per target with
  `ReverseConnectEndpointURL`. Clients such as open62541 compare it with the
  endpoint URLs returned by GetEndpoints, so announce one of those.
- **One idle connection.** As soon as the client uses a connection the
  server opens the next one, so a client can open a further channel, or
  replace a broken one, without waiting. `ReverseConnectMaxConnections`
  (default 8) limits how many connections of one target may be in use.
- **Retries.** An attempt that fails, because the client is not listening
  or refuses the server, is repeated after 500 ms, then with a doubling
  delay up to 15 s (`ReverseConnectRetryInterval`). A connection that ends is
  replaced at once. `ReverseConnect.Err` reports why the last attempt failed.
- **State.** `ReverseConnect.State` is one of `ReverseConnectConnecting`,
  `ReverseConnectWaiting` (announced, not used by the client yet),
  `ReverseConnectConnected`, `ReverseConnectBackoff` and
  `ReverseConnectClosed`.
- **Shutdown.** `Server.Close` stops all targets and closes their
  connections; `ReverseConnect.Close` does so for one target. Sessions and
  subscriptions of a closed connection time out as after any connection loss.

Everything that applies to accepted connections applies here too: response
write timeouts, back pressure, panic containment and session timeouts. The
server keeps accepting connections on its own endpoint as well.

For the client side see the [client guide](client-guide.md#reverse-connect),
for what reverse connect means for security see
[Security](security.md#reverse-connect).
| `WithLocalDiscoveryServer(opts...)` | Act as a Local Discovery Server: see [Discovery](#discovery) |
| `WithDiscoveryRegistration(url, opts...)` | Register with a discovery server and keep the registration alive |
| `WithMulticastDiscovery(opts...)` | Announce the server with mDNS and answer FindServersOnNetwork |

---

## Namespaces

The server's address space is split into namespaces. Namespace 0 is the standard OPC-UA namespace (auto-populated). Your application data lives in custom namespaces (index 1+).

Two implementations are provided:

### NodeNameSpace — Full OPC-UA Modeling

Use `NodeNameSpace` when you need the full OPC-UA information model: complex type hierarchies, custom references, methods, events.

```go
// Create a node-based namespace
ns := server.NewNodeNameSpace(s, "http://example.com/myapp")

// Create a folder to organize nodes
folder := server.NewFolderNode(
    ua.NewNumericNodeID(ns.ID(), 1001),
    "Devices",
)
ns.AddNode(folder)

// Add a reference from the Objects folder to our new folder
ns.Objects().AddRef(folder, id.HasComponent, true)

// Create a variable with a dynamic value
tempNode := server.NewVariableNode(
    ua.NewNumericNodeID(ns.ID(), 1002),
    "Temperature",
    func() *ua.DataValue {
        return server.DataValueFromValue(readSensor())
    },
)
ns.AddNode(tempNode)
folder.AddRef(tempNode, id.HasComponent, true)
```

**Best for:** Industrial automation, device models, complex type definitions, methods, events.

### MapNamespace — Simple Key-Value Mapping

Use `MapNamespace` for straightforward data mapping without OPC-UA modeling overhead. It automatically maps Go types to OPC-UA types.

```go
// Create a map-based namespace
data := server.NewMapNamespace(s, "http://example.com/sensors")

// Set values directly — types are auto-detected
data.SetValue("temperature", 23.5)      // float64
data.SetValue("pressure", int64(1013))   // int64
data.SetValue("active", true)            // bool
data.SetValue("location", "Lab-2")       // string

// Update a value (triggers change notifications to subscribers)
data.SetValue("temperature", 24.1)

// Listen for writes from OPC-UA clients
go func() {
    for key := range data.ExternalNotification {
        val := data.GetValue(key)
        log.Printf("Client changed %s to %v", key, val)
    }
}()
```

**Supported types:** `string`, `int` (stored as `int64`), `float64`, `bool`, `time.Time`

**Best for:** IoT, sensor data, edge devices, minimal overhead.

### Choosing Between Them

| Feature | NodeNameSpace | MapNamespace |
|---------|--------------|--------------|
| Node modeling | Full (objects, variables, types, references) | Auto-generated from keys |
| Methods | Supported via `RegisterMethod` | Not supported |
| Events | `EmitEvent` + `EmitBaseEvent` (EventFilter) | Basic support |
| Custom references | Yes | `HasComponent` only |
| Type system | Complete OPC-UA types | Auto-detected Go types |
| Memory | Higher (full node graph) | Lower (simple map) |
| Setup complexity | More code | Minimal |

You can mix both in the same server — use `NodeNameSpace` for complex subsystems and `MapNamespace` for simple data feeds.

---

## Adding Custom Nodes

### Variable Nodes

Variable nodes hold data values. Use a `ValueFunc` for dynamic data:

```go
node := server.NewVariableNode(
    ua.NewNumericNodeID(ns.ID(), 2001),
    "MotorSpeed",
    func() *ua.DataValue {
        return server.DataValueFromValue(motor.RPM())
    },
)
ns.AddNode(node)
```

### Folder Nodes

Folder nodes organize the address space:

```go
folder := server.NewFolderNode(
    ua.NewNumericNodeID(ns.ID(), 3001),
    "BuildingA",
)
ns.AddNode(folder)

// Attach it under the Objects folder
ns.Objects().AddRef(folder, id.HasComponent, true)
```

### Dynamic Node Management

Add and remove nodes at runtime via OPC-UA service calls:

```go
// Server-side: nodes can also be added/removed programmatically
ns.AddNode(newNode)
ns.DeleteNode(nodeID)

// Client-side: clients can use AddNodes/DeleteNodes service calls
// (if your access controller allows it)
```

---

## Methods

Register callable methods on the server. The handler has type [MethodHandler](https://pkg.go.dev/github.com/otfabric/go-opcua/server#MethodHandler): it receives `context.Context`, the object and method NodeIDs, and the input arguments, and returns output arguments and a status code.

```go
// Define the method handler: (ctx, objectID, methodID, args) -> (outputs, status)
handler := func(ctx context.Context, objectID, methodID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
    if len(args) < 1 {
        return nil, ua.StatusBadArgumentsMissing
    }
    factor, err := args[0].Float()
    if err != nil {
        return nil, ua.StatusBadTypeMismatch
    }
    result := factor * 2.0
    return []*ua.Variant{ua.MustVariant(result)}, ua.StatusOK
}

// Register: objectID is the parent object, methodID is the method node
objectID := ua.NewNumericNodeID(ns.ID(), 1001)
methodID := ua.NewNumericNodeID(ns.ID(), 1002)
s.RegisterMethod(objectID, methodID, handler)
```

Clients call the method via the standard `Call` service.

---

## NodeSet2 Import

Import standard OPC-UA companion specifications or custom information models from NodeSet2 XML files:

```go
import "os"

data, _ := os.ReadFile("my-model.xml")
if err := s.ImportNodeSetXML(data); err != nil {
    log.Fatal(err)
}
```

The importer handles:
- Namespace URI registration
- All node types (Objects, Variables, Methods, DataTypes, ObjectTypes, VariableTypes, ReferenceTypes)
- Reference relationships
- Node attributes (BrowseName, DisplayName, Description, etc.)
- For variables: the `<Value>` (decoded with `ua.DecodeXML`, see
  [JSON and XML Data Encodings](encodings.md)), `DataType` (NodeId or alias),
  `ValueRank`, `ArrayDimensions`, `AccessLevel` and `UserAccessLevel`
- Aliases

`DataType` and `ValueRank` get the defaults of the NodeSet schema
(`BaseDataType`, scalar) when the attribute is absent. `AccessLevel` and
`UserAccessLevel` are only applied when the XML has them: a variable without
them stays readable and writable. A `<Value>` that cannot be decoded - or
whose structure type is not registered - is logged and skipped; it does not
fail the import.

The standard OPC-UA NodeSet is imported automatically on server startup.

---

## Subscriptions and Monitored Items

The server handles subscriptions automatically. When a client creates a subscription and adds monitored items, the server tracks changes and sends notifications.

### Triggering Change Notifications

When you change a node value, notify the server so it can push updates to subscribers:

```go
// Using MapNamespace — automatic with SetValue()
data.SetValue("temperature", 25.0)  // Subscribers notified automatically

// Using NodeNameSpace — call ChangeNotification after updating
ns.SetAttribute(nodeID, ua.AttributeIDValue, newDataValue)
ns.ChangeNotification(nodeID)

// Or notify via the server directly
s.ChangeNotification(nodeID)
```

`ChangeNotification` means "this node may have changed": the server then
samples each monitored item on the node and reports the value only if it
passes the item's filter. By default that is a change of the value or its
status, so calling `ChangeNotification` without changing anything does not
produce a notification. A node backed by a value function is read at that
moment.

### Events

Emit events to subscribers monitoring a node for events:

```go
// Raw field list (caller owns SelectClause ordering)
fields := &ua.EventFieldList{
    EventFields: []*ua.Variant{
        ua.MustVariant("OverTemperature"),
        ua.MustVariant(time.Now()),
        ua.MustVariant("Temperature exceeded 100°C"),
    },
}
s.EmitEvent(nodeID, fields)

// BaseEventType-shaped event — applies each item's EventFilter SelectClauses / OfType
err := s.EmitBaseEvent(nodeID, &server.BaseEvent{
    EventID:    []byte{1, 2, 3},
    EventType:  ua.NewNumericNodeID(0, 2041), // BaseEventType
    SourceNode: nodeID,
    SourceName: "Motor",
    Time:       time.Now().UTC(),
    Message:    &ua.LocalizedText{Text: "Temperature exceeded 100°C"},
    Severity:   500,
})
```

### Alarms and Conditions

`Server.AddCondition` creates a condition instance (Part 9 §5.5) with the
standard components of its type: ConditionType, AcknowledgeableConditionType,
AlarmConditionType (the default) and its subtypes, including the exclusive and
non-exclusive limit alarms (level, deviation, rate of change) and the
off-normal alarms. The condition gets a HasCondition reference from its
source, the source becomes an event notifier, and the Server object reports
its events (HasNotifier) unless a notifier path already exists.

```go
src := server.NewFolderNode(ua.NewStringNodeID(ns.ID(), "Tank"), "Tank")
ns.AddNode(src)
ns.Objects().AddRef(src, server.RefTypeIDOrganizes, true)

hi, hihi := 80.0, 95.0
level, err := s.AddCondition(server.ConditionConfig{
    Type:        ua.NewNumericNodeID(0, id.ExclusiveLevelAlarmType),
    NodeID:      ua.NewStringNodeID(ns.ID(), "Tank.LevelAlarm"),
    Name:        "LevelAlarm",
    Source:      src.ID(),
    Severity:    700,
    Message:     "Tank level high",
    Confirmable: true, // ConfirmedState and Confirm
    Shelving:    true, // ShelvingState with TimedShelve / OneShotShelve / Unshelve
    Limits:      server.AlarmLimits{High: &hi, HighHigh: &hihi},
    OnAcknowledge: func(ctx context.Context, c *server.Condition, comment *ua.LocalizedText) ua.StatusCode {
        log.Printf("%s acknowledged: %v", c.Name(), comment)
        return ua.StatusOK // any other status refuses the call
    },
})

// The application drives the state; every change reports a condition event
// with a new EventId.
_ = level.EvaluateLimits(87.5)  // HighState, ActiveState true
_ = level.SetSeverity(800)      // LastSeverity takes the old value
_ = level.SetActive(false)      // alarms only
st := level.State()             // snapshot: Acked, Confirmed, Retain, Shelving, ...
```

Clients call the standard methods through the Call service, so the
`AccessController` decides who may call them like any other method:

| Method | Part 9 | Refusals |
|---|---|---|
| Enable / Disable | §5.5.4, §5.5.5 | Bad_ConditionAlreadyEnabled / Bad_ConditionAlreadyDisabled |
| AddComment | §5.5.6 | Bad_EventIdUnknown, Bad_ConditionDisabled |
| Acknowledge / Confirm | §5.7.3, §5.7.4 | Bad_EventIdUnknown (EventId not one of the condition's recent events), Bad_ConditionBranchAlreadyAcked / Bad_ConditionBranchAlreadyConfirmed, Bad_ConditionDisabled |
| TimedShelve / OneShotShelve / Unshelve (and `*2`) | §5.8.10 | Bad_ConditionAlreadyShelved, Bad_ConditionNotShelved, Bad_ShelvingTimeOutOfRange |
| Suppress / Unsuppress (and `*2`) | §5.8 | Bad_ConditionDisabled; only with `Suppressible` |
| RemoveFromService / PlaceInService (and `*2`) | §5.8 | Bad_ConditionDisabled; only with `Serviceable` |
| Silence | §5.8 | Bad_ConditionDisabled; only with `Silenceable` |
| Reset / Reset2 | §5.8 | Bad_InvalidState (the alarm is still active), Bad_ConditionDisabled; only with `Latching` |
| Respond / Respond2 | §5.6.3, §5.6.4 | Bad_DialogNotActive, Bad_DialogResponseInvalid, Bad_ConditionDisabled |
| GetGroupMemberships | §5.8 | every alarm; returns the alarm groups that list it |
| ConditionRefresh / ConditionRefresh2 | §5.5.7, §5.5.8 | Bad_SubscriptionIdInvalid (not a subscription of the caller's session), Bad_MonitoredItemIdInvalid, Bad_RefreshInProgress |

A method that is not configured for the condition answers Bad_MethodInvalid.
A call for the state the alarm is already in (Suppress of a suppressed alarm)
is Good and reports no event. The `*2` variants take a trailing Comment that
sets the Comment of the condition.

The method sets Comment (a null comment keeps it, except for AddComment) and
ClientUserId (the user name, the certificate subject, `IssuedToken` or
`Anonymous`). Retain follows the state: an acknowledgeable condition is
retained while it is unacknowledged or (if confirmable) unconfirmed, an
alarm also while it is active; a disabled condition is not retained, reports
no events and reads `Bad_ConditionDisabled` for its non-identifying
variables (§5.5.2).

ConditionRefresh sends a RefreshStartEvent, the latest event of every
retained condition the item can see (with its original EventId, so clients
can still acknowledge it) and a RefreshEndEvent. RefreshStart / RefreshEnd
bypass the item's WhereClause (§5.11.2). Event fields resolve by the full
BrowsePath (`AckedState/Id`, `ShelvingState/CurrentState/Id`), and a select
clause with an empty BrowsePath and AttributeId NodeId returns the
ConditionId.

`RemoveCondition` deletes the instance and its references;
`Server.Conditions` and `Server.Condition` list and look them up.

**Part 9 v1.05 states.** `Serviceable`, `Silenceable` and `Latching` add
OutOfServiceState, SilenceState and LatchedState to an alarm, with their
methods; `Condition.Update` sets them from the application as well. A latching
alarm latches when it becomes active and stays latched after it returns to
inactive until a client calls Reset. SuppressedOrShelved is true while the
alarm is suppressed, shelved or out of service. Silence ends when the alarm
becomes active again.

**Dialogs.** A condition of `DialogConditionType` with a `Dialog` config has
DialogState, Prompt, ResponseOptionSet, DefaultResponse, OkResponse,
CancelResponse and LastResponse. `ShowDialog` activates it with a prompt;
Respond sets LastResponse and deactivates it. A dialog is retained while it is
active.

```go
ok, cancel := int32(0), int32(1)
dlg, _ := s.AddCondition(server.ConditionConfig{
    Type:   ua.NewNumericNodeID(0, id.DialogConditionType),
    Name:   "StartPump",
    Source: src.ID(),
    Dialog: &server.DialogConfig{ResponseOptions: []string{"Ok", "Cancel"},
        OkResponse: &ok, CancelResponse: &cancel, DefaultResponse: &cancel},
    OnRespond: func(ctx context.Context, c *server.Condition, sel int32, _ *ua.LocalizedText) ua.StatusCode {
        return ua.StatusOK
    },
})
_ = dlg.ShowDialog("Start the pump?")
```

**Branches.** With `Branching`, an alarm that becomes active again while its
previous occurrence is unacknowledged (or unconfirmed) keeps that occurrence
as a branch: a copy of the state with its own BranchId and EventIds.
`CreateBranch` makes one explicitly. ConditionRefresh reports the condition
and then every retained branch; Acknowledge and Confirm find the branch by
the EventId, and a branch that needs no more action reports a last event with
Retain false and is deleted. The `On*` hooks read the branch with
`BranchIDFromContext`. A condition keeps at most 256 branches
(`ErrTooManyBranches`); disabling it ends all of them.

**Alarm groups.** `Server.AddAlarmGroup` adds an AlarmGroupType object
(AlarmGroupMember references to its alarms); `Suppression: true` makes it an
AlarmSuppressionGroupType whose `SetSuppressing` or `Evaluate` (any of the
Boolean `DigitalVariables` true) sets SuppressedState of every alarm that
lists it in `ConditionConfig.SuppressionGroups` (HasAlarmSuppressionGroup).
GetGroupMemberships returns the groups of an alarm.

**Audit events.** With `server.WithAuditing(true)` (or `SetAuditing`, which
also sets Server/Auditing) every call of a condition method reports an
AuditConditionEventType subtype (Enable, Comment, Acknowledge, Confirm,
Respond, Shelving, Suppression, OutOfService, Silence, Reset), also for a
refused call, with ActionTimeStamp, Status, ServerId, ClientAuditEntryId (the
request header's AuditEntryId), ClientUserId, MethodId, StatusCodeId,
InputArguments and OutputArguments. An access controller that implements
`EventAccessController` decides who receives them: the
`RBACAccessController` requires the ReceiveEvents permission of the event
type (namespace 0 grants it to SecurityAdmin, not to Anonymous).

**Delays and re-alarming.** `OnDelay` holds an activation (ActiveState, a
limit state or the non-exclusive limits) until it has lasted that long; an
excursion shorter than OnDelay is never reported. `OffDelay` holds the return
to normal in the same way, and an activation during OffDelay cancels it.
`State().PendingActive` / `PendingInactive` tell that a delay runs; the
other fields of an update apply at once. `ReAlarmTime` re-annunciates an
alarm that stays active: each time it ends, ReAlarmRepeatCount counts up and
the alarm needs a new acknowledgement (and confirmation), its silence ends
and a latching alarm latches; with `Branching` the previous occurrence moves
to a branch. The properties are Durations in milliseconds.

**AudibleSound.** `ConditionConfig.AudibleSound` adds AudibleEnabled (true
at the start; `ConditionUpdate.AudibleEnabled` changes it) and AudibleSound,
an AudioVariableType with the sound and its optional ListId / AgencyId /
VersionId.

**FirstInGroup.** `ConditionConfig.FirstInGroup` names an alarm group (the
alarm becomes a member). The alarm gets FirstInGroupFlag and a FirstInGroup
object (AlarmGroupType, listing the alarms that share the group). The first
alarm of the group to become active while none was active has the flag
until all of them are inactive again; a branch keeps the flag of its
occurrence.

**AlarmMetrics.** `Server.AddAlarmMetrics` adds an AlarmMetricsType object
(a component of the Server object, or of `Parent`) that counts the
activations of every alarm or of the members of `Group`: AlarmCount,
StartTime, MaximumActiveState, MaximumUnAck, MaximumReAlarmCount and the
Current / Maximum / Average alarm rates per `RateMinutes`. Its Reset method
(audited with an AuditUpdateMethodEventType) and `AlarmMetrics.Reset` start
anew.

**The alarm clock.** The shelving, delay and re-alarm timers run on the
clock of `server.WithAlarmClock` (the system clock by default). A test can
pass a manual clock and advance it, so that no test waits for a timer.

```go
g, _ := s.AddAlarmGroup(server.AlarmGroupConfig{Name: "BoilerTrip", Namespace: ns})
_, _ = s.AddCondition(server.ConditionConfig{
    Name: "FlameOut", Source: src.ID(),
    OnDelay: 2 * time.Second, OffDelay: 5 * time.Second, ReAlarmTime: 10 * time.Minute,
    FirstInGroup: g.NodeID(),
    AudibleSound: &server.AudibleSound{Sound: horn, ListID: "plant-horns"},
})
m, _ := s.AddAlarmMetrics(server.AlarmMetricsConfig{Namespace: ns, Group: g.NodeID()})
log.Printf("%+v", m.Values())
```

### Historical Access (raw)

Attach an in-memory historian (or your own `HistoryProvider`) and record samples:

```go
h := server.NewHistorian()
h.EnableNode(nodeID, 1000) // ring buffer capacity; <=0 → default 1000
s.SetHistorian(h)

// After writing a value (or from your own sampler):
h.RecordValue(nodeID, dv)
```

Clients then call HistoryRead / HistoryUpdate against the provider. Default `*Historian`
supports raw, modified, at-time, and processed aggregates (Average/Minimum/Maximum/Count),
plus UpdateData and raw/at-time deletes. Continuations are session-bound (30s TTL, max 100).
`returnBounds` is accepted but bounding/interpolation is not implemented. Historical events
are not supported. Without `SetHistorian`, HistoryRead reports unsupported / non-historized.

### Monitored-item queues and modes

- `QueueSize` is revised to `max(1, requested)` (cap 100); Overflow InfoBit `0x480` when `QueueSize > 1` and the queue overflows.
- `DiscardOldest=true` keeps the newest `QueueSize` samples; `false` keeps the oldest `QueueSize-1` plus the newest (e.g. writes `1..5` / QS=3 → `[1,2,5]`).
- `SetMonitoringMode`: Disabled = no enqueue; Sampling = enqueue only; Reporting = enqueue + Publish.
- Subscription `TimestampsToReturn` filters DataChange timestamps the same way as Read.
- A new monitored item reports its current value once; items that already exist on the same node are not notified again.

### Data-change filters, sampling and IndexRange

The server applies the `DataChangeFilter` of a monitored item on the Value
attribute (Part 4 §7.22.2). Every sample is compared with the last value that
was queued for that item.

| Filter | Behaviour |
|--------|-----------|
| No filter | Same as `StatusValue` without deadband |
| Trigger `Status` | Reported when the StatusCode changes |
| Trigger `StatusValue` | Reported when the StatusCode or the value changes |
| Trigger `StatusValueTimestamp` | As `StatusValue`, plus a change of the SourceTimestamp. With a deadband it behaves as `StatusValue` |
| Deadband `Absolute` | A value change counts when it is larger than the deadband. Arrays: any element exceeding it, or a change of size, reports the whole array. A status change is always reported |
| Deadband `Percent` | The deadband is that percentage (0–100) of the node's `EURange` property (Part 8 §7.2) |

Requests the server cannot honour are rejected per item:

| Request | StatusCode |
|---------|------------|
| Deadband on a variable that is not a Number | `BadFilterNotAllowed` |
| Any filter on an attribute other than Value, or an `EventFilter` on Value | `BadFilterNotAllowed` |
| Percent deadband on a node without an `EURange` property; `AggregateFilter` | `BadMonitoredItemFilterUnsupported` |
| Negative deadband, percent above 100 | `BadDeadbandFilterInvalid` |
| Unknown trigger or deadband type, or something that is not a monitoring filter | `BadMonitoredItemFilterInvalid` |
| Malformed `IndexRange` | `BadIndexRangeInvalid` |

`ModifyMonitoredItems` validates a new filter the same way; an item whose new
filter is rejected keeps its current parameters. A modify without a filter
restores the default.

To make a variable usable with a percent deadband, give it an `EURange`
property holding a `ua.Range`:

```go
temp := ns.AddNewVariableStringNode("Temperature", float64(20))
rng := &ua.DataValue{
    EncodingMask: ua.DataValueValue,
    Value:        ua.MustVariant(ua.NewExtensionObject(&ua.Range{Low: -40, High: 120})),
}
prop := server.NewNode(
    ua.NewStringNodeID(ns.ID(), "Temperature.EURange"),
    map[ua.AttributeID]*ua.DataValue{
        ua.AttributeIDNodeClass:   server.DataValueFromValue(uint32(ua.NodeClassVariable)),
        ua.AttributeIDBrowseName:  server.DataValueFromValue(attrs.BrowseName("EURange")),
        ua.AttributeIDDisplayName: server.DataValueFromValue(attrs.DisplayName("EURange", "EURange")),
        ua.AttributeIDDataType:    server.DataValueFromValue(ua.NewNumericExpandedNodeID(0, id.Range)),
    },
    nil,
    func() *ua.DataValue { return rng },
)
ns.AddNode(prop)
temp.AddRef(prop, id.HasProperty, true)
```

**Sampling interval.** The server is exception based: it samples when the
application reports a change, it does not poll.

- Requested `0` is revised to `0`: every change is sampled as it happens.
- A negative request selects the publishing interval of the subscription.
- Other values are clamped to 1 ms – 1 h and returned as `RevisedSamplingInterval`.
- With an interval above 0 an item is sampled at most once per interval. A
  value that changes faster is sampled at the end of the interval, so the queue
  holds the latest value of each interval. One timer serves all items; there is
  no goroutine per monitored item.
- Event items are not sampled; their revised interval is `0`.

**IndexRange.** A monitored item with an `IndexRange` (for example `"2:4"` or
`"1,0:1"` for a matrix) reports only that part of the array, and a change
outside the range does not trigger a notification. If the array has no data in
the range the item reports `BadIndexRangeNoData` until it does.

### Subscription Lifecycle

The server manages subscriptions with these services:
- **CreateSubscription** / **ModifySubscription** — revise publishing interval; enforce `LifetimeCount >= 3 × MaxKeepAliveCount`
- **CreateMonitoredItems** — client adds nodes (or event notifiers) to watch
- **Publish** — notifications, keepalives, `MoreNotifications`, ACK / AvailableSequenceNumbers
- **SetPublishingMode** — pause holds queues; resume delivers queued windows
- **SetMonitoringMode** — Disabled / Sampling / Reporting per item
- **Republish** / **TransferSubscriptions** — retransmission and ownership transfer
- **DeleteSubscriptions** — remove subscriptions; lifetime expiry also removes idle subs

---

## Discovery

Clients find servers in three steps of growing reach: `GetEndpoints` on a
server they already know, `FindServers` on the **Local Discovery Server**
(LDS) of a machine, which lists the servers registered with it, and
`FindServersOnNetwork` on a discovery server with the **multicast extension**
(LDS-ME), which lists what was announced with mDNS on the network segment
(OPC UA Part 4 §5.4 and Part 12). A go-opcua server can take each of these
roles. All of them are opt-in.

### Local Discovery Server

```go
lds, _ := server.New(
    server.EndPoint("plant-gateway", 4840), // the well-known discovery port
    server.Certificate(cert), server.PrivateKey(key),
    server.EnableSecurity("None", ua.MessageSecurityModeNone), // for FindServers / GetEndpoints
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.WithLocalDiscoveryServer(
        server.LDSApplicationType(ua.ApplicationTypeDiscoveryServer),
    ),
)
```

The server now accepts `RegisterServer` and `RegisterServer2` and returns the
registered servers from `FindServers`, after itself.

| Behaviour | Detail |
|-----------|--------|
| Registration | `ServerUri`, at least one server name and one to 16 discovery URLs are required: `BadServerUriInvalid`, `BadServerNameMissing`, `BadDiscoveryUrlMissing`, `BadTooManyOperations`. A client application cannot register (`BadInvalidArgument`). A second registration of the same `ServerUri` replaces the first. |
| Unregistration | `IsOnline = false` removes the registration; `BadNothingToDo` if there is none. |
| Expiry | A registration that is not renewed is removed after `LDSRegistrationTimeout` (default one hour, as in open62541; `0` disables the expiry). |
| Semaphore file | A registration with a `SemaphoreFilePath` needs the file to exist (`BadSemaphoreFileMissing`), does not time out, and ends when the file is deleted. |
| Who may register | Only a SecureChannel with Sign or SignAndEncrypt (`BadSecurityModeInsufficient` otherwise), and only for the `ServerUri` of the certificate the channel was opened with (`BadServerUriInvalid`). `LDSAllowInsecureRegistration()` and `LDSSkipServerURICheck()` lift the two rules for labs and gateways. See [security.md](security.md#discovery). |
| Discovery configurations | Of the `DiscoveryConfiguration` list of RegisterServer2 the first `MdnsDiscoveryConfiguration` is used, if the server has the multicast extension. Every other entry gets `BadNotSupported` in `ConfigurationResults`; the server is registered regardless. |
| FindServers | `serverUris` restricts the result, `localeIds` selects the server name, and `endpointUrl` selects which of the discovery server's own URLs are returned (those on the host the client used; all of them if the host is not recognised). The URLs of registered servers are returned as registered. |
| Limits | `LDSMaxRegisteredServers` (1024): `BadResourceUnavailable` beyond it. |

`Server.RegisteredServers()` returns the current table and
`LDSRegistrationCallback` reports every accepted request.

### Registering with a discovery server

```go
srv, _ := server.New(
    server.EndPoint("press7", 4841),
    server.Certificate(cert), server.PrivateKey(key),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.WithDiscoveryRegistration("opc.tcp://localhost:4840",
        server.RegisterServerCapabilities("DA", "HD"),
    ),
)
```

From `Start` on the server registers in the background: `RegisterServer2`
with its mDNS server name and capabilities, `RegisterServer` if the discovery
server answers `BadServiceUnsupported`, `BadNotSupported` or
`BadNotImplemented`. It renews the registration every `RegisterInterval`
(10 minutes), retries with an exponential back-off (`RegisterBackoff`, one
second to one minute) while the discovery server cannot be reached, and
unregisters in `Close`. A discovery server that is down delays neither `Start`
nor, beyond `RegisterRequestTimeout` (10 seconds), `Close`.

The channel to the discovery server is secured with the server's own
certificate, using the endpoint with the highest security level the discovery
server offers. `RegisterSecurity` pins policy and mode, `RegisterInsecure`
allows a channel without security (needed for a server without a
certificate), and `RegisterCertificateValidator` decides whether the discovery
server's certificate is trusted. `RegisterEventHandler` reports every attempt.
Other options: `RegisterDiscoveryURLs` (the URLs to register, e.g. the address
outside a container), `RegisterMdnsServerName`, `RegisterSemaphoreFile`.

An application that wants to do this by hand can use `Client.RegisterServer`
and `Client.RegisterServer2` ([client guide](client-guide.md#discovery-servers)).

### Multicast discovery (mDNS)

```go
srv, _ := server.New(
    // ...
    server.WithMulticastDiscovery(
        server.MulticastCapabilities("DA", "HD"),
        server.MulticastInterfaces("eth0"),
    ),
)
```

The server announces itself as a DNS-SD service of type `_opcua-tcp._tcp`
(instance `<server name>-<host name>`, SRV target `<host name>.local`, TXT
keys `path` and `caps`), browses for the announcements of others and answers
`FindServersOnNetwork` from the resulting table: record ids that count up
from 0 and are never reused, `startingRecordId` / `maxRecordsToReturn` for
paging, a case-insensitive capability filter, and `lastCounterResetTime`.
`Server.ServersOnNetwork()` returns the table.

Combined with `WithLocalDiscoveryServer` this is an LDS-ME: every registered
server is announced as well, one instance per discovery URL with a host name,
under its `MdnsServerName` and capabilities (or its first server name and
`NA` when it registered without an mDNS configuration). A registered server
that already announces itself under the same name is not announced a second
time, so a server should either register with an LDS-ME or run its own
multicast discovery, not both under different names.

The mDNS implementation is part of the library (`internal/mdns`): no Avahi,
Bonjour or other dependency is needed, and it shares UDP port 5353 with a
system responder. By default it uses every interface that is up and
multicast capable, except loopback and point-to-point interfaces, with IPv4
(224.0.0.251) and IPv6 (ff02::fb); `MulticastInterfaces` and
`MulticastIPv4Only` restrict it. `Start` fails if no interface can be used.

| RFC 6762 / 6763 | |
|---|---|
| Implemented | Announcements on start (two, one second apart); answers to PTR, SRV, TXT, A, AAAA and ANY questions and to the service type enumeration; additional records; known-answer suppression; legacy unicast responses; cache-flush bit; one-second rate limit per record and interface; goodbye packets on unregistration and `Close`; continuous queries with exponential back-off; TTL expiry with refresh at 80 % and 90 %; goodbye grace period of one second; source-address check (on-link only); name compression. |
| Not implemented | Probing and conflict resolution (a conflict is logged); the random response delay; truncated (TC) queries; the unicast-response (QU) bit; NSEC; address records of other hosts (a discovered server is reported with the host name of its SRV record, e.g. `opc.tcp://press7.local:4841`, which the client must be able to resolve). |
| Deviation | Responses and queries from a UDP source port other than 5353 are accepted as multicast traffic: open62541 sends from an ephemeral port. |

Things to know:

- Multicast does not cross routers, and Docker Desktop does not forward it
  between the host and containers. Use a discovery server per segment and
  `WithDiscoveryRegistration` across segments.
- A discovery URL with an IP address cannot be expressed in DNS-SD; such a
  registered server is listed by `FindServers` but not announced.

---

## Certificate Management (Push Model)

`WithPushManagement` lets a certificate manager — package [`gds`](client-guide.md#certificate-management-gds-push),
or the push client of another stack — manage the server's trust list and
application instance certificate at run time, by the push model of Part 12 §7.
The server then exposes the ServerConfiguration object (Part 12 §7.10.3) as a
component of the Server object:

| Node | Content |
|------|---------|
| ServerConfiguration properties | ServerCapabilities, SupportedPrivateKeyFormats (`PEM`, `PFX`), MaxTrustListSize, MulticastDnsEnabled |
| CertificateGroups / DefaultApplicationGroup | CertificateTypes (the types of the application identities), the TrustList, the CertificateExpired and TrustListOutOfDate alarms (with `Alarms`) |
| CertificateGroups / DefaultHttpsGroup | CertificateTypes (HttpsCertificateType: the TLS certificate of the opc.https / opc.wss endpoints), its own TrustList, CertificateExpired and TrustListOutOfDate |
| CertificateGroups / DefaultUserTokenGroup | its own TrustList for X.509 user identity tokens, TrustListOutOfDate |
| CertificateGroups / <name> | a certificate group of the application (`PushManagement.CertificateGroups`): its CertificateTypes, TrustList, CertificateExpired and TrustListOutOfDate, in the namespace `server.CertificateAlarmsNamespaceURI` |
| <group> / TrustList | TrustListType file (Part 12 §7.8.2): Open, OpenWithMasks, Read, Write, GetPosition, SetPosition, Close, CloseAndUpdate, AddCertificate, RemoveCertificate; Size, LastUpdateTime, UpdateFrequency (with `TrustListUpdateFrequency`) |
| Methods | UpdateCertificate, CreateSigningRequest, GetRejectedList, ApplyChanges, CancelChanges, GetCertificates, CreateSelfSignedCertificate, DeleteCertificate, ResetToServerDefaults (the nodeset of the library lacks a DeleteCertificate instance; the server adds it) |
| TransactionDiagnostics | StartTime, EndTime, Result, AffectedTrustLists, AffectedCertificateGroups, Errors of the last or current transaction (SecurityAdmin only) |

```go
srv, _ := server.New(
    server.Certificate(cert), server.PrivateKey(key),
    server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
    server.EnableAuthMode(ua.UserTokenTypeUserName),
    server.WithUsernameValidator(checkPassword),
    server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
        if u, ok := tok.(*ua.UserNameIdentityToken); ok && u.UserName == "secadmin" {
            return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(), ua.RoleSecurityAdmin.NodeID()}
        }
        return server.DefaultRoleMapper(tok)
    }),
    server.WithPushManagement(server.PushManagement{
        // the CA (or the certificate) of the clients, the manager's among them
        TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{caDER}},
    }),
)
```

| Behaviour | Detail |
|-----------|--------|
| Validation | New channels and sessions validate the client application certificate against the trust list (Part 4 §6.1.3): a chain to a trusted certificate, issuer certificates as intermediates, CRLs of the CAs (`Bad_CertificateRevoked`, `Bad_CertificateIssuerRevoked`). It replaces `WithClientCertificateTrustList` (`New` refuses both) |
| Trust list input | CloseAndUpdate decodes the TrustListDataType exactly; every certificate and CRL must parse, a CRL must be signed by a CA of the lists; at most 1024 entries and `MaxTrustListSize` bytes (default 1 MiB; `Bad_EncodingLimitsExceeded` beyond) |
| Transactions | AddCertificate, RemoveCertificate, CloseAndUpdate and UpdateCertificate collect their changes in a transaction of the calling session (Part 12 §7.10.2); they take effect at ApplyChanges, CancelChanges drops them, another session gets `Bad_TransactionPending`. `ApplyImmediately` applies every change when its method returns |
| UpdateCertificate | Replaces the certificate of its group and type: an application instance certificate (RSA, ECDSA on NIST and Brainpool curves, Ed25519, Ed448) or the HTTPS certificate of the DefaultHttpsGroup. The key is the one of the last CreateSigningRequest or CreateSelfSignedCertificate, the current key, or a `PEM` or `PFX` (PKCS #12, password from `PFXPassword`; a wrong one is `Bad_SecurityChecksFailed`) private key. The certificate must carry the server's ApplicationUri and be issued by one of the issuer certificates when they are given |
| After ApplyChanges | New channels and the endpoints use the new certificate, new TLS handshakes the new HTTPS certificate; channels and connections already open keep theirs and keep working |
| CreateSigningRequest | PKCS #10 for the current key or, with `regeneratePrivateKey`, a new key of the certificate type: RSA (2048, 3072 or 4096 bits), ECDSA P-256 / P-384, brainpoolP256r1 / brainpoolP384r1, Ed25519 or Ed448 (nonce of at least 32 bytes) |
| CreateSelfSignedCertificate | A new key and a self-signed certificate for a group and type (subject, DNS names and IP addresses default to those of the current certificate, 365 days by default, the ApplicationUri as SAN); it takes effect at ApplyChanges |
| DeleteCertificate | Removes the certificate of a group and type at ApplyChanges (Part 12 1.05 §7.10); `Bad_InvalidState` if there is none, counting the transaction. ApplyChanges refuses (`Bad_InvalidState`, in the TransactionDiagnostics) to delete the certificate the endpoints advertise, or the HTTPS certificate while there are opc.https / opc.wss endpoints. A deleted type stays in CertificateTypes: CreateSigningRequest with a new key, UpdateCertificate or CreateSelfSignedCertificate fill it again, also in the same transaction. A `CertificateDeleteStore` persists deletions |
| GetCertificates | The certificate types and certificates of a group |
| ResetToServerDefaults | Back to the trust lists, certificates and keys the server started with (stored through `Store`), the groups of the application included; certificates the server did not start with are deleted. `Bad_TransactionPending` while another session has a transaction |
| Group trust lists | The DefaultUserTokenGroup trust list validates X.509 user tokens before a `WithX509UserValidator` is asked; the DefaultHttpsGroup trust list validates TLS client certificates when `HTTPSClientCertificates` is `HTTPSClientCertificatesVerifyIfGiven` or `HTTPSClientCertificatesRequire` |
| Alarms | `Alarms: &server.CertificateAlarms{ExpirationLimit, CheckInterval}` adds CertificateExpired (active from `ExpirationLimit`, default 14 days, before the group certificate expires; severity 900 once expired) and TrustListOutOfDate (active when a trust list was not updated for `TrustListUpdateFrequency`) conditions in the namespace `server.CertificateAlarmsNamespaceURI`, evaluated every `CheckInterval` (default 1 minute) and on every change |
| GetRejectedList | The most recent `MaxRejectedCertificates` (default 64) client certificates validation rejected |
| Access | SignAndEncrypt only (`Bad_SecurityModeInsufficient`), and the SecurityAdmin role (`Bad_UserAccessDenied`), unless `Authorizer` decides otherwise |
| Persistence | None by default: the server writes no files. A `CertificateStore` gets the trust list and the new certificate with its issuers and key at ApplyChanges, before they take effect; an error fails ApplyChanges with `Bad_InternalError` and keeps the change pending |

`Server.TrustList()`, `Server.GroupTrustList(group)`,
`Server.HTTPSCertificate()` and `Server.RejectedCertificates()` return the
trust lists in effect, the HTTPS certificate and the rejected certificates.

### Certificate groups of the application

`PushManagement.CertificateGroups` adds certificate groups next to the three
default ones (Part 12 §7.5), for certificates and trust lists the
application uses itself: the client certificate and CA list of an MQTT or
HTTPS connection to a broker, say. Each has a name (its BrowseName), the
certificate types it holds (application certificate types, HttpsCertificateType,
UserCertificateType, TlsServerCertificateType, TlsClientCertificateType), a
trust list and optionally its first certificates with their keys. A
certificate manager handles them like the default groups: the TrustList,
UpdateCertificate, CreateSigningRequest, CreateSelfSignedCertificate,
DeleteCertificate, GetCertificates, ResetToServerDefaults, the transactions
and the alarms.

```go
server.WithPushManagement(server.PushManagement{
    TrustList: &ua.TrustListDataType{TrustedCertificates: [][]byte{caDER}},
    CertificateGroups: []server.CertificateGroup{{
        Name:             "Broker",
        CertificateTypes: []*ua.NodeID{ua.NewNumericNodeID(0, id.TLSClientCertificateType)},
        TrustList:        &ua.TrustListDataType{TrustedCertificates: [][]byte{brokerCA}},
        Certificates: []server.GroupCertificate{{
            CertificateType: ua.NewNumericNodeID(0, id.TLSClientCertificateType),
            Certificate:     clientDER,
            PrivateKey:      clientKey,
        }},
    }},
})

group := srv.CertificateGroupID("Broker")
cert, issuers, key := srv.GroupCertificate(group, nil) // what ApplyChanges installed last
err := srv.VerifyGroupCertificate(group, brokerChain)  // against the group's trust list
```

The groups are String NodeIds (`CertificateGroups.<Name>` and
`CertificateGroups.<Name>.TrustList`) in the namespace
`server.CertificateAlarmsNamespaceURI`; `gds.Client.CertificateGroups` finds
them. The server itself does not use them. A `CertificateStore` gets their
changes through `StoreGroupTrustList` and `StoreGroupCertificate` (a
`CertificateGroupStore`).

A Global Discovery Server (the pull model) is the subject of the next section.

## Global Discovery Server (Pull Model)

Package `gds/gdsserver` adds a Global Discovery Server (Part 12 §6 and §7.9)
to a server: the `Directory` object (CertificateDirectoryType) in the GDS
namespace `http://opcfoundation.org/UA/GDS/` with its DefaultApplicationGroup,
DefaultHttpsGroup and DefaultUserTokenGroup and their TrustLists, an
application directory, and a CA per key type that issues certificates and
CRLs. Call `Attach` before `Start`:

```go
var g atomic.Pointer[gdsserver.GDS]
srv, _ := server.New(
    server.ApplicationIdentity(cert, key),
    server.EnableSecurity(ua.SecurityPolicyURIECCNistP256, ua.MessageSecurityModeSignAndEncrypt),
    server.EnableAuthMode(ua.UserTokenTypeUserName),
    server.WithUsernameValidator(checkUser),
    server.WithRoleMapper(func(tok ua.IdentityToken) []*ua.NodeID {
        if isAdmin(tok) {
            return []*ua.NodeID{ua.RoleAuthenticatedUser.NodeID(),
                g.Load().DiscoveryAdminRole(), g.Load().CertificateAuthorityAdminRole()}
        }
        return server.DefaultRoleMapper(tok)
    }),
)
gd, err := gdsserver.Attach(srv, gdsserver.Config{
    Store:            store,    // nil: a MemoryStore; gdsserver.NewFileStore(dir) for a directory
    CertificateTypes: []*ua.NodeID{gds.RsaSha256ApplicationCertificateType, gds.EccNistP256ApplicationCertificateType},
})
g.Store(gd)
srv.Start(ctx)
defer gd.Close() // before srv.Close; makes later calls fail with Bad_Shutdown
```

| Topic | Behaviour |
|-------|-----------|
| Directory | FindApplications, RegisterApplication, UpdateApplication, UnregisterApplication (revokes the application's certificates), GetApplication, QueryApplications, QueryServers; records are validated (URIs, names, at most 32 discovery URLs and capabilities) |
| Certificate requests | StartSigningRequest (a CSR of any key type — RSA, NIST and Brainpool ECDSA, Ed25519, Ed448 — whose URI must be the application's), StartNewKeyPairRequest (the GDS generates the key; PEM, encrypted with a password, or PFX with the certificate and its issuer), FinishRequest; a request waits for `GDS.ApproveRequest` (`GDS.Requests` lists them) unless `Config.AutoApprove`; at most `MaxRequests` open requests per application |
| CA | One issuer per key type (RSA, NistP256, NistP384, BrainpoolP256r1, BrainpoolP384r1, Curve25519, Curve448), generated or given in `Config.Issuers`; DNS names and IP addresses from the discovery URLs or DomainNames; the CRL is re-signed on every revocation and before its NextUpdate |
| Certificate groups | DefaultApplicationGroup (`Config.CertificateTypes`; trust list: every CA), DefaultHttpsGroup (HttpsCertificateType, RSA or ECDSA P-256 / P-384 TLS certificates, when the GDS has such a CA; a request may leave out the ApplicationUri; trust list: those CAs), DefaultUserTokenGroup (issues nothing; trust list: what a CertificateAuthorityAdmin adds). A client gets the application group, a server all three |
| Trust list | GetCertificateGroups, GetCertificates, GetTrustList and the TrustList object of each group (the CA certificates and their CRLs, plus the certificates a CertificateAuthorityAdmin adds), GetCertificateStatus, RevokeCertificate, CheckRevocationStatus; `GDS.TrustList`, `GDS.GroupTrustList` |
| Authorization | Directory queries are open; register / update / unregister need DiscoveryAdmin; certificate requests, revocation and the trust list need CertificateAuthorityAdmin over SignAndEncrypt, or the application itself (a certificate the GDS issued to it, or one `Config.SelfAdmin` accepts); the TrustList object needs SecurityAdmin to write |
| RolePermissions | The methods carry the RolePermissions of the GDS NodeSet (Call for DiscoveryAdmin, CertificateAuthorityAdmin, ...); the GDS refuses a session none of whose roles may call a method, except an application calling the self-administration methods for itself. `server.RBACAccessController` applies them too, before the GDS, and so refuses self-administration by an application without a role |
| Audit events | With `server.WithAuditing(true)`: ApplicationRegistrationChangedAuditEventType, CertificateRequestedAuditEventType, CertificateDeliveredAuditEventType and CertificateRevokedAuditEventType of the GDS NodeSet, on the Server object and the Directory, without passwords and private keys; an `EventAccessController` filters them (RBAC: ReceiveEvents for SecurityAdmin) |
| Persistence | `Config.Store` (`gdsserver.Store`): applications, requests, issuers with their keys and CRLs, the trust list additions; `NewMemoryStore` keeps them in memory, `NewFileStore(dir)` in a directory (one JSON file per record, written to a temporary file, synced and renamed; files 0600, directories 0700). A GDS attached again to the same Store continues with its state |

The pull model is verified against the Global Discovery Server and the GDS
client of UA-.NETStandard 2.0.1 (INTEROP.md).
[examples/gds-pull](../examples/gds-pull/main.go) runs a GDS and enrolls a
server and a client.

---

## Access Control

Implement fine-grained authorization by providing a custom `AccessController`:

```go
type MyAccessController struct {
    readOnlyNodes map[string]bool
}

func (ac *MyAccessController) CheckRead(ctx context.Context, sess *server.Session, nodeID *ua.NodeID) ua.StatusCode {
    return ua.StatusOK // Allow all reads
}

func (ac *MyAccessController) CheckWrite(ctx context.Context, sess *server.Session, nodeID *ua.NodeID) ua.StatusCode {
    if ac.readOnlyNodes[nodeID.String()] {
        return ua.StatusBadUserAccessDenied
    }
    return ua.StatusOK
}

func (ac *MyAccessController) CheckBrowse(ctx context.Context, sess *server.Session, nodeID *ua.NodeID) ua.StatusCode {
    return ua.StatusOK
}

func (ac *MyAccessController) CheckCall(ctx context.Context, sess *server.Session, methodID *ua.NodeID) ua.StatusCode {
    return ua.StatusOK
}

// Apply to server
s, err := server.New(
    server.WithAccessController(&MyAccessController{
        readOnlyNodes: map[string]bool{"ns=1;i=1001": true},
    }),
    // ... other options
)
```

The `DefaultAccessController` allows all operations.

---

## Complete Example

A production-ready server with security, custom namespace, and methods:

```go
package main

import (
    "context"
    "crypto/rsa"
    "crypto/tls"
    "log"
    "log/slog"
    "os"
    "time"

    "github.com/otfabric/go-opcua/server"
    "github.com/otfabric/go-opcua/ua"
)

func main() {
    // Load certificates
    tlsCert, _ := tls.LoadX509KeyPair("cert.pem", "key.pem")
    pk := tlsCert.PrivateKey.(*rsa.PrivateKey)
    cert := tlsCert.Certificate[0]

    // Configure server
    s, err := server.New(
        server.EndPoint("0.0.0.0", 4840),
        server.Certificate(cert),
        server.PrivateKey(pk),
        server.EnableSecurity("Basic256Sha256", ua.MessageSecurityModeSignAndEncrypt),
        server.EnableSecurity("None", ua.MessageSecurityModeNone),
        server.EnableAuthMode(ua.UserTokenTypeAnonymous),
        server.EnableAuthMode(ua.UserTokenTypeUserName),
        server.ServerName("My OPC-UA Server"),
        server.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil))),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create application namespace
    ns := server.NewNodeNameSpace(s, "http://example.com/myapp")

    // Add a folder
    folder := server.NewFolderNode(
        ua.NewNumericNodeID(ns.ID(), 1000),
        "Process",
    )
    ns.AddNode(folder)

    // Add a variable
    var temperature float64 = 22.0
    tempNode := server.NewVariableNode(
        ua.NewNumericNodeID(ns.ID(), 1001),
        "Temperature",
        func() *ua.DataValue {
            return server.DataValueFromValue(temperature)
        },
    )
    ns.AddNode(tempNode)

    // Register a method (handler: ctx, objectID, methodID, args -> outputs, status)
    s.RegisterMethod(
        ua.NewNumericNodeID(ns.ID(), 1000),  // object
        ua.NewNumericNodeID(ns.ID(), 2001),  // method
        func(ctx context.Context, objectID, methodID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
            return nil, ua.StatusOK
        },
    )

    // Start
    if err := s.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
    defer s.Close()

    // Simulate data changes
    go func() {
        for {
            time.Sleep(time.Second)
            temperature += 0.1
            s.ChangeNotification(ua.NewNumericNodeID(ns.ID(), 1001))
        }
    }()

    select {}
}
```
