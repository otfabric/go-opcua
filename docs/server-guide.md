# Server Development Guide

> Building OPC-UA servers with the `github.com/otfabric/go-opcua/server` package.

---

## Service Support Matrix

| Service Set | Operations | Status |
|-------------|-----------|--------|
| **Discovery** | FindServers, GetEndpoints | Fully implemented |
| | FindServersOnNetwork, RegisterServer, RegisterServer2 | Unsupported (`StatusBadServiceUnsupported`) |
| **Secure Channel** | OpenSecureChannel, CloseSecureChannel | Implemented (handled in `uasc` layer) |
| **Session** | CreateSession, ActivateSession, CloseSession, Cancel | Fully implemented |
| **Node Management** | AddNodes, DeleteNodes, AddReferences, DeleteReferences | Fully implemented |
| **View** | Browse, BrowseNext, TranslateBrowsePathsToNodeIDs, RegisterNodes, UnregisterNodes | Fully implemented |
| **Attribute** | Read, Write | Fully implemented (IndexRange / NumericRange, `TimestampsToReturn`, value-only Write) |
| | HistoryRead | Via pluggable `HistoryProvider` (`SetHistorian`); default `*Historian` supports raw, modified, at-time, and processed aggregates |
| | HistoryUpdate | Via optional historian interfaces (`HistoryDataUpdater` / deleters); default `*Historian` supports UpdateData and raw/at-time deletes |
| **Method** | Call | Fully implemented |
| **Monitored Items** | CreateMonitoredItems, ModifyMonitoredItems, SetMonitoringMode, SetTriggering, DeleteMonitoredItems | Fully implemented (exact `QueueSize` / `DiscardOldest` / Overflow) |
| **Subscription** | CreateSubscription, ModifySubscription, SetPublishingMode, Publish, Republish, TransferSubscriptions, DeleteSubscriptions | Fully implemented (revise clamps, `MoreNotifications`, Publish ACK, lifetime expiry) |
| **Query** | QueryFirst, QueryNext | Fully implemented |

Unsupported services return consistent OPC UA status codes. Any request type
not registered with the server returns `StatusBadServiceUnsupported`.

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
    s := server.New(
        server.EndPoint("localhost", 4840),
        server.EnableSecurity("None", ua.MessageSecurityModeNone),
        server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    )

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
| `SetLogger(l)` | `*slog.Logger`; defaults to `slog.Default()` |
| `WithAccessController(ac)` | Custom authorization logic |

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
- Node attributes (BrowseName, DisplayName, Description, DataType, etc.)
- Aliases

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
s := server.New(
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
    s := server.New(
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
