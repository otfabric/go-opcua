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

- **Alarms & Conditions** (Part 9): no condition state machines, Acknowledge,
  Confirm or ConditionRefresh (`AlarmsConditionsSupported()` reports false).
  Emit `BaseEventType` or your own event types and keep condition state in
  the application.
- **Diagnostics**: no live `ServerDiagnosticsSummary` or session diagnostics
  counters, and responses carry an empty `DiagnosticInfo` even when the
  request sets `ReturnDiagnostics`. Use the metrics callbacks and `log/slog`
  ([OBSERVABILITY.md](../OBSERVABILITY.md)).
- **Historical events**: the history interfaces cover data only (see
  [Historical Access](#historical-access-raw)).
- **Certificate management** (Part 12 GDS push and pull): certificates and
  trust lists are configured in code (`server.Certificate`, `server.PrivateKey`,
  `WithClientCertificateTrustList`).

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
  conversation (`uasc.HTTPSPolicySupported`: not the AEAD ECC policies, whose
  session signatures are bound to a channel thumbprint) once, in its strongest
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
