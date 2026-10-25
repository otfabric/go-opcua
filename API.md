# API Reference

Complete reference for all public types, functions, and interfaces in `github.com/otfabric/go-opcua`.

---

## Table of Contents

- [Package `opcua` (root)](#package-opcua-root)
  - [Client](#client)
    - [Connection](#connection)
    - [Session management](#session-management)
    - [Namespace helpers](#namespace-helpers)
    - [Security info](#security-info)
    - [Read](#read)
    - [Write](#write)
    - [Browse](#browse)
    - [Browse path translation (path to NodeID)](#browse-path-translation-path-to-nodeid)
    - [History](#history)
    - [History update](#history-update)
    - [Method calls](#method-calls)
    - [Query](#query)
    - [Node registration](#node-registration)
    - [Node management](#node-management)
    - [Node access](#node-access)
    - [Discovery](#discovery)
    - [Subscriptions](#subscriptions)
    - [Low-level send](#low-level-send)
  - [Node](#node)
    - [Attribute helpers](#attribute-helpers)
    - [Summary](#summary)
    - [Browse](#browse-1)
    - [Browse path translation](#browse-path-translation)
    - [Walk](#walk)
  - [Subscription](#subscription)
    - [SubscriptionParameters](#subscriptionparameters)
    - [PublishNotificationData](#publishnotificationdata)
  - [SubscriptionBuilder](#subscriptionbuilder)
  - [Session](#session)
  - [ConnState](#connstate)
  - [Subscription recovery](#subscription-recovery)
  - [RetryPolicy](#retrypolicy)
  - [ClientMetrics](#clientmetrics)
  - [Discovery (standalone functions)](#discovery-standalone-functions)
  - [Reverse connect (client)](#reverse-connect-client)
  - [Logger](#logger)
  - [Configuration Options](#configuration-options)
  - [Helper](#helper)
  - [Constants](#constants)
- [Package `ua`](#package-ua)
  - [Variant](#variant)
  - [ExtensionObject](#extensionobject)
  - [TypeID](#typeid)
  - [NodeID](#nodeid)
  - [ExpandedNodeID](#expandednodeid)
  - [QualifiedName](#qualifiedname)
  - [LocalizedText](#localizedtext)
  - [DataValue](#datavalue)
  - [NumericRange](#numericrange)
  - [StatusCode](#statuscode)
  - [DiagnosticInfo](#diagnosticinfo)
  - [EventFilterBuilder](#eventfilterbuilder)
  - [Enums and constants](#enums-and-constants)
  - [ReferenceDescription](#referencedescription)
  - [Service message types (selection)](#service-message-types-selection)
  - [Notification types](#notification-types)
  - [Display name and endpoint helpers](#display-name-and-endpoint-helpers)
  - [Buffer](#buffer)
  - [JSON and XML DataEncoding](#json-and-xml-dataencoding)
- [Package `server`](#package-server)
  - [Server](#server)
  - [Server configuration options](#server-configuration-options)
  - [Reverse connect (server)](#reverse-connect-server)
  - [NameSpace (interface)](#namespace-interface)
  - [Node (server-side)](#node-server-side)
  - [AccessController](#accesscontroller)
  - [Authentication validators](#authentication-validators)
  - [EventEmitter](#eventemitter)
  - [Alarms & Conditions](#alarms--conditions)
  - [Registered Custom DataTypes](#registered-custom-datatypes)
  - [HistoryProvider](#historyprovider)
  - [ServerMetrics](#servermetrics)
  - [Push certificate management (server)](#push-certificate-management-server)
- [Package `gds`](#package-gds)
- [Package `monitor`](#package-monitor)
  - [NodeMonitor](#nodemonitor)
  - [Subscription (monitor)](#subscription-monitor)
  - [Request and Item](#request-and-item)
  - [DataChangeMessage](#datachangemessage)
  - [Types](#types)
- [Package `errors`](#package-errors)
  - [Sentinel errors](#sentinel-errors)
  - [Utility functions](#utility-functions)
- [Package `uacp`](#package-uacp)
  - [Endpoint parsing](#endpoint-parsing)
  - [Conn](#conn)
  - [Dialer](#dialer)
  - [Listener](#listener)
  - [Reverse connect (transport)](#reverse-connect-transport)
- [Package `uapolicy`](#package-uapolicy)
- [Package `uasc`](#package-uasc)
  - [SecureChannel](#securechannel)
  - [Config](#config)
  - [SessionConfig](#sessionconfig)
- [Package `id`](#package-id)

---

## Package `opcua` (root)

The root package provides the high-level client, node, subscription, and server APIs.

### Client

```go
func NewClient(endpoint string, opts ...Option) (*Client, error)
```

Creates a new OPC-UA client for the given endpoint URL. Apply configuration
with [Option] functions.

#### Connection

```go
func (c *Client) Connect(ctx context.Context) error
func (c *Client) Dial(ctx context.Context) error
func (c *Client) Close(ctx context.Context) error
func (c *Client) State() ConnState
```

`Connect` establishes a secure channel **and** creates/activates a session.
When `AutoReconnect` is enabled (default), `Connect` also starts a background
goroutine that recovers the session and subscriptions after a disconnect — see
[Subscription recovery](#subscription-recovery).
`Dial` establishes a secure channel only (no session; TCP + HEL/ACK + OpenSecureChannel).
For TCP-only reachability checks (e.g. connection diagnostics or "ping" without creating a session), use [uacp.DialTCP](uacp package); the CLI can infer TCP failure from connection errors if that helper is not used.
`Close` tears down session, secure channel, and TCP connection.

#### Lifecycle and concurrency

- The caller owns the `*Client`: create with `NewClient`, `Connect` when ready, `Close` when finished.
- After `Close`, do not reuse the client; create a new one.
- A single `*Client` is safe for concurrent use from multiple goroutines for ordinary service calls (reads, writes, browse, method calls) once connected. Race tests cover concurrent reads and subscription create/cancel.
- Subscription notification delivery and recovery handlers run on library goroutines; handlers must not block (see `WithSubscriptionRecoveryHandler`).
- Auto-reconnect (default on) may recreate sessions and subscriptions after disconnect; observe `ConnState` / recovery events if your application needs to react.

Errors: [ERRORS.md](ERRORS.md). Observability: [OBSERVABILITY.md](OBSERVABILITY.md).

#### Session management

```go
func (c *Client) CreateSession(ctx context.Context, cfg *uasc.SessionConfig) (*Session, error)
func (c *Client) ActivateSession(ctx context.Context, s *Session) error
func (c *Client) CloseSession(ctx context.Context) error
func (c *Client) DetachSession(ctx context.Context) (*Session, error)
func (c *Client) Session() *Session
func (c *Client) SecureChannel() *uasc.SecureChannel
```

#### Namespace helpers

```go
func (c *Client) Namespaces() []string
func (c *Client) UpdateNamespaces(ctx context.Context) error
func (c *Client) NamespaceURI(ctx context.Context, idx uint16) (string, error)
func (c *Client) FindNamespace(ctx context.Context, name string) (uint16, error)
func (c *Client) NamespaceArray(ctx context.Context) ([]string, error)
```

#### Security info

```go
func (c *Client) SecurityPolicy() string
func (c *Client) SecurityMode() ua.MessageSecurityMode
func (c *Client) ServerStatus(ctx context.Context) (*ua.ServerStatusDataType, error)
```

#### Server diagnostics

```go
func (c *Client) ServerDiagnosticsSummary(ctx context.Context) (*ua.ServerDiagnosticsSummaryDataType, error)
func (c *Client) ServerDiagnosticsEnabled(ctx context.Context) (bool, error)
func (c *Client) SetServerDiagnosticsEnabled(ctx context.Context, on bool) error
func (c *Client) SessionDiagnostics(ctx context.Context) ([]*ua.SessionDiagnosticsDataType, error)
func (c *Client) SessionSecurityDiagnostics(ctx context.Context) ([]*ua.SessionSecurityDiagnosticsDataType, error)
func (c *Client) SessionDiagnosticsOf(ctx context.Context, sessionID *ua.NodeID) (*ua.SessionDiagnosticsDataType, error)
func (c *Client) SessionSecurityDiagnosticsOf(ctx context.Context, sessionID *ua.NodeID) (*ua.SessionSecurityDiagnosticsDataType, error)
func (c *Client) SubscriptionDiagnostics(ctx context.Context) ([]*ua.SubscriptionDiagnosticsDataType, error)
func (c *Client) SamplingIntervalDiagnostics(ctx context.Context) ([]*ua.SamplingIntervalDiagnosticsDataType, error)

func ReturnDiagnostics(mask uint32) Option

type ServiceError struct {
    StatusCode ua.StatusCode
    Diagnostic *ua.Diagnostic
}
func (e *ServiceError) Error() string
func (e *ServiceError) Unwrap() error // the StatusCode
```

Typed reads of `Server.ServerDiagnostics` (Part 5 §6.3.3). The `...Of` helpers
read below the diagnostics object of a session (nil: the client's own).
`ReturnDiagnostics` sets the `ReturnDiagnostics` mask of every request (a
request with a mask of its own keeps it); a request the server rejects then
fails with a `*ServiceError` when the server returned service diagnostics.
See the [client guide](docs/client-guide.md#server-diagnostics).

#### Read

```go
func (c *Client) Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error)
func (c *Client) ReadValue(ctx context.Context, nodeID *ua.NodeID) (*ua.DataValue, error)
func (c *Client) ReadValues(ctx context.Context, nodeIDs ...*ua.NodeID) ([]*ua.DataValue, error)
func (c *Client) ReadMulti(ctx context.Context, items []ReadItem, opts ...ReadMultiOption) ([]ReadResult, error)
```

`ReadMulti` performs a batch read of N node/attribute pairs in one or more Read calls, chunking by `DefaultReadMultiChunkSize` (32) or by the size given via `ReadMultiWithChunkSize`. Results are in the same order as `items`; each result has `DataValue` and `StatusCode`. Use for large subtrees or bulk export to minimize round-trips. Empty or nil `items` returns `(nil, nil)` without a request.

```go
type ReadItem struct {
    NodeID      *ua.NodeID
    AttributeID ua.AttributeID
    IndexRange  string
}
type ReadResult struct {
    DataValue  *ua.DataValue
    StatusCode ua.StatusCode
}
const DefaultReadMultiChunkSize = 32
func ReadMultiWithChunkSize(n uint32) ReadMultiOption
```

#### Write

```go
func (c *Client) Write(ctx context.Context, req *ua.WriteRequest) (*ua.WriteResponse, error)
func (c *Client) WriteValue(ctx context.Context, nodeID *ua.NodeID, value *ua.DataValue) (ua.StatusCode, error)
func (c *Client) WriteValues(ctx context.Context, writes ...*ua.WriteValue) ([]ua.StatusCode, error)
func (c *Client) WriteAttribute(ctx context.Context, nodeID *ua.NodeID, attrID ua.AttributeID, value *ua.DataValue) (ua.StatusCode, error)
func (c *Client) WriteNodeValue(ctx context.Context, nodeID *ua.NodeID, value any) (ua.StatusCode, error)
```

`WriteNodeValue` wraps a plain Go value into a `DataValue` and writes it to
the node's `Value` attribute.

#### Browse

```go
func (c *Client) Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error)
func (c *Client) BrowseNext(ctx context.Context, req *ua.BrowseNextRequest) (*ua.BrowseNextResponse, error)
func (c *Client) BrowseAll(ctx context.Context, nodeID *ua.NodeID) ([]*ua.ReferenceDescription, error)
```

#### Browse path translation (path to NodeID)

| Method | Start node | Namespace | Error behavior |
|--------|------------|-----------|----------------|
| `NodeFromPath(ctx, path)` | Objects folder (i=85) | All segments ns=0 | (nil, err) if path not found, service fails, or not connected |
| `NodeFromPathInNamespace(ctx, ns, path)` | Objects folder (i=85) | All segments use ns | Same |
| `NodeFromQualifiedPath(ctx, path)` | Objects folder (i=85) | Per-segment `ns:` prefix | (nil, err) if path invalid, not found, service fails, or not connected |

```go
func (c *Client) NodeFromPath(ctx context.Context, path string) (*Node, error)
func (c *Client) NodeFromPathInNamespace(ctx context.Context, ns uint16, path string) (*Node, error)
func (c *Client) NodeFromQualifiedPath(ctx context.Context, path string) (*Node, error)
```

Path: `NodeFromPath` / `NodeFromPathInNamespace` use dot-separated browse names (e.g. `"Server.ServerStatus"`). `NodeFromQualifiedPath` uses namespace-qualified segments `ns:name` (e.g. `"0:Server.0:ServerStatus"` or `"2:DeviceSet.4:PLC_Name"`). For a custom start node, use the Node methods `TranslateBrowsePathInNamespaceToNodeID` or `TranslateBrowsePathsToNodeIDs` below. See [Resolving paths to nodes](docs/client-guide.md#resolving-paths-to-nodes-browse-path-translation) in the client guide.

#### History

```go
func (c *Client) HistoryReadEvent(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadEventDetails) (*ua.HistoryReadResponse, error)
func (c *Client) HistoryReadRawModified(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadRawModifiedDetails) (*ua.HistoryReadResponse, error)
func (c *Client) HistoryReadProcessed(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadProcessedDetails) (*ua.HistoryReadResponse, error)
func (c *Client) HistoryReadAtTime(ctx context.Context, nodes []*ua.HistoryReadValueID, details *ua.ReadAtTimeDetails) (*ua.HistoryReadResponse, error)
func (c *Client) ReadHistory(ctx context.Context, nodeID *ua.NodeID, start, end time.Time, maxValues uint32) ([]*ua.DataValue, error)
func (c *Client) ReadHistoryAll(ctx context.Context, nodeID *ua.NodeID, start, end time.Time) iter.Seq2[*ua.DataValue, error]
```

`ReadHistoryAll` returns a Go 1.23 iterator that pages through all historical
values automatically.

#### History update

```go
func (c *Client) HistoryUpdateData(ctx context.Context, details ...*ua.UpdateDataDetails) (*ua.HistoryUpdateResponse, error)
func (c *Client) HistoryUpdateEvents(ctx context.Context, details ...*ua.UpdateEventDetails) (*ua.HistoryUpdateResponse, error)
func (c *Client) HistoryDeleteRawModified(ctx context.Context, details ...*ua.DeleteRawModifiedDetails) (*ua.HistoryUpdateResponse, error)
func (c *Client) HistoryDeleteAtTime(ctx context.Context, details ...*ua.DeleteAtTimeDetails) (*ua.HistoryUpdateResponse, error)
func (c *Client) HistoryDeleteEvents(ctx context.Context, details ...*ua.DeleteEventDetails) (*ua.HistoryUpdateResponse, error)
```

Each method wraps the typed details into `ExtensionObject` entries for the
underlying `HistoryUpdateRequest`.

#### Method calls

```go
func (c *Client) Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error)
func (c *Client) CallMethod(ctx context.Context, objectID, methodID *ua.NodeID, args ...any) (*ua.CallMethodResult, error)
func (c *Client) MethodArguments(ctx context.Context, objectID, methodID *ua.NodeID) (inputs, outputs []*ua.Argument, err error)
```

#### Query

```go
func (c *Client) QueryFirst(ctx context.Context, req *ua.QueryFirstRequest) (*ua.QueryFirstResponse, error)
func (c *Client) QueryNext(ctx context.Context, req *ua.QueryNextRequest) (*ua.QueryNextResponse, error)
```

#### Node registration

```go
func (c *Client) RegisterNodes(ctx context.Context, req *ua.RegisterNodesRequest) (*ua.RegisterNodesResponse, error)
func (c *Client) UnregisterNodes(ctx context.Context, req *ua.UnregisterNodesRequest) (*ua.UnregisterNodesResponse, error)
```

#### Node management

```go
func (c *Client) AddNodes(ctx context.Context, req *ua.AddNodesRequest) (*ua.AddNodesResponse, error)
func (c *Client) DeleteNodes(ctx context.Context, req *ua.DeleteNodesRequest) (*ua.DeleteNodesResponse, error)
func (c *Client) AddReferences(ctx context.Context, req *ua.AddReferencesRequest) (*ua.AddReferencesResponse, error)
func (c *Client) DeleteReferences(ctx context.Context, req *ua.DeleteReferencesRequest) (*ua.DeleteReferencesResponse, error)
```

#### Node access

```go
func (c *Client) Node(id *ua.NodeID) *Node
func (c *Client) NodeFromExpandedNodeID(id *ua.ExpandedNodeID) *Node
func (c *Client) NodeFromPath(ctx context.Context, path string) (*Node, error)
func (c *Client) NodeFromPathInNamespace(ctx context.Context, ns uint16, path string) (*Node, error)
func (c *Client) NodeFromQualifiedPath(ctx context.Context, path string) (*Node, error)
```

#### Discovery

```go
func (c *Client) FindServers(ctx context.Context) (*ua.FindServersResponse, error)
func (c *Client) FindServersWithFilter(ctx context.Context, localeIDs, serverURIs []string) (*ua.FindServersResponse, error)
func (c *Client) FindServersOnNetwork(ctx context.Context) (*ua.FindServersOnNetworkResponse, error)
func (c *Client) FindServersOnNetworkWithFilter(ctx context.Context, startingRecordID, maxRecordsToReturn uint32, capabilityFilter []string) (*ua.FindServersOnNetworkResponse, error)
func (c *Client) GetEndpoints(ctx context.Context) (*ua.GetEndpointsResponse, error)
func (c *Client) RegisterServer(ctx context.Context, server *ua.RegisteredServer) (*ua.RegisterServerResponse, error)
func (c *Client) RegisterServer2(ctx context.Context, server *ua.RegisteredServer, configurations ...any) (*ua.RegisterServer2Response, error)
```

The discovery services need a SecureChannel but no session: `Dial` is enough.
`RegisterServer` registers, renews or (`IsOnline` false) removes a server at a
discovery server; `RegisterServer2` adds discovery configurations, typically a
`*ua.MdnsDiscoveryConfiguration`, and returns one result per configuration.

#### Subscriptions

```go
func (c *Client) Subscribe(ctx context.Context, params *SubscriptionParameters, notifyCh chan<- *PublishNotificationData) (*Subscription, error)
func (c *Client) SubscriptionIDs() []uint32
func (c *Client) SetPublishingMode(ctx context.Context, publishingEnabled bool, subscriptionIDs ...uint32) (*ua.SetPublishingModeResponse, error)
func (c *Client) Republish(ctx context.Context, subscriptionID, sequenceNumber uint32) (*ua.RepublishResponse, error)
func (c *Client) TransferSubscriptions(ctx context.Context, subscriptionIDs []uint32, sendInitialValues bool) (*ua.TransferSubscriptionsResponse, error)
func (c *Client) NewSubscription() *SubscriptionBuilder
```

`Subscribe` is the ergonomic CreateSubscription path and returns a live `*Subscription`, not `*ua.CreateSubscriptionResponse`. Callers that need the raw protocol response should use `Client.Send` with `ua.CreateSubscriptionRequest`. Mutation APIs on `*Subscription` (`Monitor`, `Unmonitor`, `Modify*`, `Set*`) and `Client.Republish` / `TransferSubscriptions` return full `ua.*Response` values.

`Republish` returns the protocol response without mutating subscription delivery state — callers must handle the returned notification themselves. Automatic reconnect recovery (when `AutoReconnect(true)`, the default) separately runs Transfer → Republish → Recreate and may dispatch recovered notifications through the normal subscription pipeline; see [Subscription recovery](#subscription-recovery). Manual `Republish` / `TransferSubscriptions` do not emit `SubscriptionRecoveryEvent`s.

If the server closes the connection during CreateSubscription, the returned error may wrap `io.EOF` with a message suggesting the server may not support subscriptions; use `errors.Is(err, io.EOF)` to detect it.

#### Low-level send

```go
func (c *Client) Send(ctx context.Context, req ua.Request, h func(ua.Response) error) error
```

---

### Node

High-level object to interact with a node in the address space.

```go
type Node struct {
    ID *ua.NodeID
}
```

#### Attribute helpers

```go
func (n *Node) NodeClass(ctx context.Context) (ua.NodeClass, error)
func (n *Node) BrowseName(ctx context.Context) (*ua.QualifiedName, error)
func (n *Node) Description(ctx context.Context) (*ua.LocalizedText, error)
func (n *Node) DisplayName(ctx context.Context) (*ua.LocalizedText, error)
func (n *Node) AccessLevel(ctx context.Context) (ua.AccessLevelType, error)
func (n *Node) HasAccessLevel(ctx context.Context, mask ua.AccessLevelType) (bool, error)
func (n *Node) UserAccessLevel(ctx context.Context) (ua.AccessLevelType, error)
func (n *Node) HasUserAccessLevel(ctx context.Context, mask ua.AccessLevelType) (bool, error)
func (n *Node) Value(ctx context.Context) (*ua.Variant, error)
func (n *Node) TypeDefinition(ctx context.Context) (*ua.NodeID, error)
func (n *Node) DataType(ctx context.Context) (*ua.NodeID, error)
func (n *Node) Attribute(ctx context.Context, attrID ua.AttributeID) (*ua.Variant, error)
func (n *Node) Attributes(ctx context.Context, attrID ...ua.AttributeID) ([]*ua.DataValue, error)
```

#### Summary

```go
func (n *Node) Summary(ctx context.Context) (*NodeSummary, error)
```

Reads all common attributes of a node in a single request:

```go
type NodeSummary struct {
    NodeID          *ua.NodeID
    NodeClass       ua.NodeClass
    BrowseName      *ua.QualifiedName
    DisplayName     *ua.LocalizedText
    Description     *ua.LocalizedText
    DataType        *ua.NodeID
    Value           *ua.DataValue
    AccessLevel     ua.AccessLevelType
    UserAccessLevel ua.AccessLevelType
    TypeDefinition  *ua.NodeID
}
```

#### Browse

```go
func (n *Node) Children(ctx context.Context, refs uint32, mask ua.NodeClass) ([]*Node, error)
func (n *Node) ReferencedNodes(ctx context.Context, refs uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*Node, error)
func (n *Node) References(ctx context.Context, refs uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*ua.ReferenceDescription, error)
func (n *Node) BrowseAll(ctx context.Context, refs uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) iter.Seq2[*ua.ReferenceDescription, error]
```

#### Browse path translation

Resolve a path of browse names to a NodeID (TranslateBrowsePathsToNodeIDs service):

| Method | Start node | Namespace | Error behavior |
|--------|------------|-----------|----------------|
| `TranslateBrowsePathInNamespaceToNodeID(ctx, ns, browsePath)` | Receiver n | All segments use ns | (nil, err) if path not found, service fails, or not connected; err may be ua.StatusCode |
| `TranslateBrowsePathsToNodeIDs(ctx, pathNames)` | Receiver n | Per-segment (pathNames[i].NamespaceIndex) | Same |

```go
func (n *Node) TranslateBrowsePathsToNodeIDs(ctx context.Context, pathNames []*ua.QualifiedName) (*ua.NodeID, error)
func (n *Node) TranslateBrowsePathInNamespaceToNodeID(ctx context.Context, ns uint16, browsePath string) (*ua.NodeID, error)
```

`TranslateBrowsePathInNamespaceToNodeID` splits `browsePath` on "." and builds a path of [QualifiedName](https://pkg.go.dev/github.com/otfabric/go-opcua/ua#QualifiedName) segments in the given namespace. Use when the path starts from this node (e.g. custom root). For paths from the server's Objects folder, use `Client.NodeFromPath` or `Client.NodeFromPathInNamespace` instead.

#### Walk

```go
func (n *Node) Walk(ctx context.Context) iter.Seq2[WalkResult, error]
func (n *Node) WalkLimit(ctx context.Context, maxDepth int) iter.Seq2[WalkResult, error]
func (n *Node) WalkLimitDedup(ctx context.Context, maxDepth int) iter.Seq2[WalkResult, error]
```

`Walk` recursively descends through the node's hierarchical references with no depth limit. `WalkLimit` is like `Walk` but stops recursing when depth reaches `maxDepth`; the node at depth `maxDepth` is still yielded. If `maxDepth < 0`, depth is unlimited (same as `Walk`). Use `WalkLimit` for "find node", "find type", or "browse tree" style tools to avoid unbounded traversal (e.g. pass a `-depth` flag from the CLI). The same node may be yielded more than once if reachable via multiple paths; use `WalkLimitDedup` to yield each node at most once (deduplication by NodeID).

`BrowseWithDepth` performs a client-side recursive browse up to `opts.MaxDepth` and returns a flat slice of references with depth (no iterator). Uses the same Browse calls as Walk; useful when a slice is preferred over an iterator. Standard OPC UA Browse is single-level; recursion is implemented client-side.

```go
func (n *Node) BrowseWithDepth(ctx context.Context, opts BrowseWithDepthOptions) ([]BrowseWithDepthResult, error)
type BrowseWithDepthOptions struct {
    MaxDepth        int
    RefType         uint32
    Direction       ua.BrowseDirection
    NodeClassMask   ua.NodeClass
    IncludeSubtypes bool
}
type BrowseWithDepthResult struct {
    Ref   *ua.ReferenceDescription
    Depth int
}
```

Each yielded `WalkResult` contains:

```go
type WalkResult struct {
    Depth int
    Ref   *ua.ReferenceDescription
}
```

---

### Subscription

```go
type Subscription struct {
    SubscriptionID              uint32
    RevisedPublishingInterval   time.Duration
    RevisedLifetimeCount        uint32
    RevisedMaxKeepAliveCount    uint32
    Notifs                      chan<- *PublishNotificationData
}
```

```go
func (s *Subscription) Cancel(ctx context.Context) error
func (s *Subscription) ModifySubscription(ctx context.Context, params SubscriptionParameters) (*ua.ModifySubscriptionResponse, error)
func (s *Subscription) SetPublishingMode(ctx context.Context, publishingEnabled bool) (*ua.SetPublishingModeResponse, error)
func (s *Subscription) Monitor(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemCreateRequest) (*ua.CreateMonitoredItemsResponse, error)
func (s *Subscription) Unmonitor(ctx context.Context, monitoredItemIDs ...uint32) (*ua.DeleteMonitoredItemsResponse, error)
func (s *Subscription) ModifyMonitoredItems(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemModifyRequest) (*ua.ModifyMonitoredItemsResponse, error)
func (s *Subscription) SetMonitoringMode(ctx context.Context, monitoringMode ua.MonitoringMode, monitoredItemIDs ...uint32) (*ua.SetMonitoringModeResponse, error)
func (s *Subscription) SetTriggering(ctx context.Context, triggeringItemID uint32, add, remove []uint32) (*ua.SetTriggeringResponse, error)
func (s *Subscription) Stats(ctx context.Context) (*ua.SubscriptionDiagnosticsDataType, error)
```

If the server closes the connection during CreateMonitoredItems (e.g. it does not support event or alarm subscriptions), the error may wrap `io.EOF` with a message suggesting that; use `errors.Is(err, io.EOF)` to detect it.

`Monitor` returns the full server response; individual item results are in `Response.Results`. `ModifyMonitoredItems` adjusts parameters (e.g. sampling interval) on already-monitored items. `SetMonitoringMode` enables or disables sampling for a set of items. `SetTriggering` links items so that one item's data change triggers publishing of dependent items. `Stats` returns the server's subscription diagnostics for this subscription.

**Server queue semantics (v1.3.0+):** `RequestedParameters.QueueSize` is revised to `max(1, requested)` (capped at 100) and returned as `RevisedQueueSize`. When the queue overflows and `QueueSize > 1`, the DataValue Overflow InfoBit is set (`StatusCode` `0x480`). With `DiscardOldest=true`, the newest `QueueSize` samples are kept; with `false`, the oldest `QueueSize-1` samples plus the newest are kept (Part 4 — e.g. writes `1..5` / QS=3 → `[1,2,5]`). `SubscriptionBuilder.Timestamps` is applied to DataChange notifications (same enum as Read).

**IndexRange:** one-dimensional (`"i"`, `"i:j"`) and multidimensional (`"a:b,c:d"`) NumericRange are supported for Value Read/Write via `ua.SliceVariantRead` / `ua.MergeVariantWrite`. Dimension count must match the array; scalar ByteString IndexRange slices bytes.

#### SubscriptionParameters

```go
type SubscriptionParameters struct {
    Interval                    time.Duration
    LifetimeCount               uint32
    MaxKeepAliveCount           uint32
    MaxNotificationsPerPublish  uint32
    Priority                    uint8
}
```

#### PublishNotificationData

```go
type PublishNotificationData struct {
    SubscriptionID uint32
    Error          error
    Value          ua.Notification  // *ua.DataChangeNotification | *ua.EventNotificationList | *ua.StatusChangeNotification
}
```

---

### SubscriptionBuilder

Fluent API for constructing subscriptions. Obtain via `client.NewSubscription()`.

```go
func (b *SubscriptionBuilder) Interval(d time.Duration) *SubscriptionBuilder
func (b *SubscriptionBuilder) LifetimeCount(n uint32) *SubscriptionBuilder
func (b *SubscriptionBuilder) MaxKeepAliveCount(n uint32) *SubscriptionBuilder
func (b *SubscriptionBuilder) MaxNotificationsPerPublish(n uint32) *SubscriptionBuilder
func (b *SubscriptionBuilder) Priority(p uint8) *SubscriptionBuilder
func (b *SubscriptionBuilder) Timestamps(ts ua.TimestampsToReturn) *SubscriptionBuilder
func (b *SubscriptionBuilder) SamplingInterval(d time.Duration) *SubscriptionBuilder  // requested sampling interval for Monitor/MonitorEvents items (ms on wire)
func (b *SubscriptionBuilder) DataChangeFilter(trigger ua.DataChangeTrigger, deadbandType ua.DeadbandType, deadbandValue float64) *SubscriptionBuilder  // filter for the items added by subsequent Monitor calls
func (b *SubscriptionBuilder) NotifyChannel(ch chan *PublishNotificationData) *SubscriptionBuilder
func (b *SubscriptionBuilder) Monitor(nodeIDs ...*ua.NodeID) *SubscriptionBuilder
func (b *SubscriptionBuilder) MonitorItems(items ...*ua.MonitoredItemCreateRequest) *SubscriptionBuilder
func (b *SubscriptionBuilder) MonitorEvents(filter *ua.EventFilter, nodeIDs ...*ua.NodeID) *SubscriptionBuilder
func (b *SubscriptionBuilder) Start(ctx context.Context) (*Subscription, chan *PublishNotificationData, error)
```

`Start` calls `Subscribe` then `Monitor`; if the server closes the connection during either step, the returned error may wrap `io.EOF` with a message suggesting the server may not support subscriptions or event/alarm monitoring.

Example (data change):

```go
sub, notifyCh, err := client.NewSubscription().
    Interval(500 * time.Millisecond).
    Monitor(ua.MustParseNodeID("ns=2;s=Temperature")).
    Start(ctx)
```

Example (events):

```go
filter := ua.NewEventFilter().
    Select("EventType", "SourceName", "Message", "Severity", "Time").
    Where(ua.OfType(ua.NewNumericNodeID(0, id.BaseEventType))).
    Build()
sub, notifyCh, err := client.NewSubscription().
    MonitorEvents(filter, ua.MustParseNodeID("ns=2;s=Events.Source")).
    Start(ctx)
```

---

### Session

```go
func (s *Session) RevisedTimeout() time.Duration
func (s *Session) SessionID() *ua.NodeID
func (s *Session) ServerEndpoints() []*ua.EndpointDescription
func (s *Session) MaxRequestMessageSize() uint32
```

---

### ConnState

Connection state of a client.

| Constant        | Description                                 |
|-----------------|---------------------------------------------|
| `Closed`        | Not connected (initial / final state)        |
| `Connected`     | Active session, ready for operations         |
| `Connecting`    | Establishing first connection                |
| `Disconnected`  | Connection lost (may be reconnecting)        |
| `Reconnecting`  | Attempting recovery of a lost connection      |

```go
func WithConnStateHandler(f func(ConnState)) Option
func WithConnStateChan(ch chan<- ConnState) Option
```

For per-subscription reconnect recovery outcomes, see [Subscription recovery](#subscription-recovery).

---

### Subscription recovery

When `AutoReconnect` is enabled (default), a lost connection triggers background
recovery that attempts, per subscription:

1. **TransferSubscriptions** onto the new session
2. **Republish** of available sequence numbers
3. **Recreate** the subscription if transfer fails

Applications observe the result via `WithSubscriptionRecoveryHandler`:

```go
func WithSubscriptionRecoveryHandler(f func(SubscriptionRecoveryEvent)) Option
```

The handler is called synchronously from the reconnect goroutine and must not
block — a slow handler stalls recovery for every remaining subscription. Prefer
enqueueing work (channel / goroutine) and returning immediately. The handler is
invoked once per subscription after each recovery attempt.

```go
type SubscriptionRecoveryOutcome string

const (
    SubscriptionRecoveryTransferred      SubscriptionRecoveryOutcome = "transferred"
    SubscriptionRecoveryRepublished      SubscriptionRecoveryOutcome = "republished"
    SubscriptionRecoveryRecreated        SubscriptionRecoveryOutcome = "recreated"
    SubscriptionRecoveryPartial          SubscriptionRecoveryOutcome = "partially_recovered"
    SubscriptionRecoveryUnrecoverableGap SubscriptionRecoveryOutcome = "unrecoverable_gap"
)

type SubscriptionRecoveryEvent struct {
    SubscriptionID           uint32
    Outcome                  SubscriptionRecoveryOutcome
    AvailableSequenceNumbers []uint32 // empty when recreated / transfer failed
    Detail                   string   // never empty; suitable for logging
}
```

| Outcome | Meaning |
|---------|---------|
| `SubscriptionRecoveryTransferred` | Transfer succeeded; nothing needed to republish |
| `SubscriptionRecoveryRepublished` | Transfer succeeded and buffered notifications were republished |
| `SubscriptionRecoveryRecreated` | Transfer failed; a new subscription was created |
| `SubscriptionRecoveryPartial` | Some sequence numbers republished; a gap remains |
| `SubscriptionRecoveryUnrecoverableGap` | Expected next sequence is absent from the server retransmission buffer; notifications are permanently lost |

Manual `Client.Republish` / `Client.TransferSubscriptions` do not emit these events.

---

### RetryPolicy

Controls retry behaviour for failed client requests.

```go
type RetryPolicy interface {
    // ShouldRetry is called after each failed attempt.
    // attempt is zero-based (0 = first failure).
    // Return (true, delay) to retry after delay, or (false, 0) to stop.
    ShouldRetry(attempt int, err error) (bool, time.Duration)
}
```

Built-in implementations:

```go
func NoRetry() RetryPolicy
func ExponentialBackoff(base, maxDelay time.Duration, maxAttempts int) RetryPolicy
func NewExponentialBackoff(cfg ExponentialBackoffConfig) RetryPolicy
```

```go
type ExponentialBackoffConfig struct {
    BaseDelay      time.Duration  // default 100ms
    MaxDelay       time.Duration  // default 30s
    MaxAttempts    int            // 0 = unlimited
    RetryOnTimeout bool           // default false
}
```

Attach via:

```go
func WithRetryPolicy(p RetryPolicy) Option
```

---

### ClientMetrics

Callbacks for client-side service instrumentation.

```go
type ClientMetrics interface {
    OnRequest(service string)
    OnResponse(service string, duration time.Duration)
    OnError(service string, duration time.Duration, err error)
    OnTimeout(service string, duration time.Duration)
}
```

The `service` parameter is the OPC-UA service name (e.g. `"Read"`, `"Write"`,
`"Browse"`, `"Call"`, `"CreateSubscription"`).

Attach via:

```go
func WithMetrics(m ClientMetrics) Option
```

---

### Discovery (standalone functions)

```go
func FindServers(ctx context.Context, endpoint string, opts ...Option) ([]*ua.ApplicationDescription, error)
func FindServersOnNetwork(ctx context.Context, endpoint string, opts ...Option) ([]*ua.ServerOnNetwork, error)
func GetEndpoints(ctx context.Context, endpoint string, opts ...Option) ([]*ua.EndpointDescription, error)

const DiscoveryPort = 4840
func DiscoveryURL(host string) string
func DiscoverServers(ctx context.Context, host string, opts ...Option) (*DiscoveryResult, error)

type DiscoveryResult struct {
    DiscoveryServerURL   string
    Servers              []*ua.ApplicationDescription // FindServers
    ServersOnNetwork     []*ua.ServerOnNetwork        // FindServersOnNetwork; nil without the multicast extension
    LastCounterResetTime time.Time
    MulticastSupported   bool
}
```

The helpers accept [`ReverseConnect`](#reverse-connect-client) and then run
over a connection the server opened.

---

### Reverse connect (client)

OPC UA reverse connect (Part 6 §7.1.3): the client listens and the server
opens the connection, announcing itself with a ReverseHello message. See the
[client guide](docs/client-guide.md#reverse-connect) and
[Security](docs/security.md#reverse-connect).

```go
func ReverseConnect(listenAddr string, opts ...ReverseConnectOption) Option
func ReverseConnectListener(l *uacp.ReverseListener, opts ...ReverseConnectOption) Option

type ReverseConnectOption func(*reverseConfig)

func ReverseServerURI(uri string) ReverseConnectOption
```

- `ReverseConnect` makes the client listen on `listenAddr` (`"host:port"` or
  `"opc.tcp://host:port"`) from the first `Connect`/`Dial` until `Close`.
- `ReverseConnectListener` takes the connection from a shared listener
  (`uacp.ListenReverse`), which is not closed by `Client.Close`. One listener
  serves any number of servers and clients.
- `ReverseServerURI` accepts only the server announcing that ApplicationUri.
- The announced EndpointUrl must denote the endpoint URL passed to
  `NewClient`; a client created with `""` accepts and uses any.
- A server failing these checks is refused and the client keeps waiting. With
  security, the ServerUri must also be the ApplicationUri of the configured
  server certificate, otherwise `Connect` fails. Both wrap
  `errors.ErrReverseHelloRejected`.
- Waiting is bounded by the context and by `DialTimeout`. `AutoReconnect`
  goes back to waiting after a connection loss.

`DiscoveryURL` returns the well-known URL of the Local Discovery Server of a
host (`opc.tcp://<host>:4840`; a port or a complete URL is kept).
`DiscoverServers` queries it with FindServers and FindServersOnNetwork; a
discovery server without the multicast extension is not an error.

---

### Logger

Logging uses `*slog.Logger` from the standard library. **Logging is disabled by
default** (silent discard handler). Pass `WithLogger` to enable output.
See [OBSERVABILITY.md](OBSERVABILITY.md).

```go
func WithLogger(l *slog.Logger) Option // nil restores silent default
```

---

### Configuration Options

All option functions return `Option` and are passed to `NewClient`:

| Function | Description |
|----------|-------------|
| `ApplicationName(s string)` | Application name in session |
| `ApplicationURI(s string)` | Application URI |
| `AutoReconnect(b bool)` | Enable/disable auto reconnect (default `true`). When enabled, reconnect runs Transfer → Republish → Recreate and may emit [SubscriptionRecoveryEvent](#subscription-recovery) |
| `ReconnectInterval(d time.Duration)` | Interval between reconnect attempts |
| `Lifetime(d time.Duration)` | Secure channel lifetime |
| `Locales(locale ...string)` | Preferred locales |
| `ProductURI(s string)` | Product URI |
| `RandomRequestID()` | Random initial request ID |
| `RemoteCertificate(cert []byte)` | Server certificate (DER) |
| `RemoteCertificateFile(filename string)` | Load server certificate from file |
| `SecurityMode(m ua.MessageSecurityMode)` | Security mode |
| `SecurityModeString(s string)` | Security mode by name |
| `SecurityPolicy(s string)` | Security policy URI |
| `SecurityFromEndpoint(ep *ua.EndpointDescription, authType ua.UserTokenType)` | Derive security mode, policy, and auth token type from a discovered endpoint |
| `SessionName(s string)` | Session name |
| `SessionTimeout(d time.Duration)` | Session timeout |
| `SkipNamespaceUpdate()` | Skip automatic namespace table update on connect |
| `Certificate(cert []byte)` | Client application certificate (DER) |
| `CertificateFile(filename string)` | Load client application certificate from file |
| `PrivateKey(key *rsa.PrivateKey)` | RSA private key for the client certificate |
| `PrivateKeySigner(key crypto.Signer)` | Private key for the client certificate of any supported type: `*rsa.PrivateKey`, or an ECDSA (NIST or Brainpool), Ed25519 or Ed448 key (any `crypto.Signer`, e.g. an HSM) for the ECC policies |
| `PrivateKeyFile(filename string)` | Load an RSA, ECDSA (NIST or Brainpool), Ed25519 or Ed448 private key from a PEM or DER file (PKCS #1, PKCS #8, SEC 1) |
| `AuthAnonymous()` | Use anonymous identity token (default) |
| `AuthUsername(user, pass string)` | Username/password identity token |
| `AuthCertificate(cert []byte)` | X.509 user certificate identity token (DER) |
| `AuthPrivateKey(key *rsa.PrivateKey)` | Private key for the X.509 user certificate |
| `AuthPrivateKeySigner(key crypto.Signer)` | Private key for the X.509 user certificate of any supported type (RSA, ECDSA, Ed25519 or Ed448) |
| `AuthIssuedToken(tokenData []byte)` | Issued (e.g. JWT/SAML) identity token |
| `AuthPolicyID(policy string)` | Override the UserTokenPolicy ID used during ActivateSession |
| `DialTimeout(d time.Duration)` | TCP + HEL/ACK handshake timeout (default `DefaultDialTimeout`); with reverse connect, how long to wait for the server |
| `Dialer(d *uacp.Dialer)` | Custom UACP dialer (e.g. to set `ClientACK` parameters) |
| `ReverseConnect(listenAddr string, opts ...ReverseConnectOption)` | Wait for the server to connect instead of dialling it; see [Reverse connect (client)](#reverse-connect-client) |
| `ReverseConnectListener(l *uacp.ReverseListener, opts ...ReverseConnectOption)` | Reverse connect through a shared listener |
| `RequestTimeout(t time.Duration)` | Per-request timeout |
| `MaxMessageSize(n uint32)` | Maximum OPC UA message size in bytes |
| `MaxChunkCount(n uint32)` | Maximum number of chunks per message |
| `ReceiveBufferSize(n uint32)` | TCP receive buffer size |
| `SendBufferSize(n uint32)` | TCP send buffer size |
| `WithConnStateHandler(f func(ConnState))` | Connection state callback |
| `WithConnStateChan(ch chan<- ConnState)` | Connection state channel |
| `WithSubscriptionRecoveryHandler(f func(SubscriptionRecoveryEvent))` | Per-subscription reconnect recovery callback (must not block; see [Subscription recovery](#subscription-recovery)) |
| `WithMetrics(m ClientMetrics)` | Metrics handler |
| `WithRetryPolicy(p RetryPolicy)` | Retry policy |
| `WithLogger(l *slog.Logger)` | Logger (`*slog.Logger`; silent by default; `nil` restores silent) |
| `InsecureSkipVerify()` | Skip server certificate validation (INSECURE) |
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA/self-signed certs to the trust pool |
| `TLSConfig(c *tls.Config)` | TLS of `opc.wss` and `opc.https` endpoints: `RootCAs` for the server's TLS certificate (system roots when nil), `Certificates` for mutual TLS. TLS 1.2 is the minimum. Separate from the application instance certificate |
| `HTTPClient(c *http.Client)` | The `*http.Client` of `opc.https` endpoints (proxies, transports); `TLSConfig` is then not used for them |

Server certificates may be presented as a **DER chain** (leaf followed by intermediates); validation parses the full chain and verifies the leaf against the trust pool.

### Helper

```go
func NewMonitoredItemCreateRequestWithDefaults(nodeID *ua.NodeID, attributeID ua.AttributeID, clientHandle uint32) *ua.MonitoredItemCreateRequest

// NewDataChangeFilter returns a DataChangeFilter ready to be assigned to
// MonitoringParameters.Filter (create or modify) of an item on the Value attribute.
func NewDataChangeFilter(trigger ua.DataChangeTrigger, deadbandType ua.DeadbandType, deadbandValue float64) *ua.ExtensionObject
```

**Server data-change semantics (v1.6.0+):** the go-opcua server applies the `DataChangeFilter` of a monitored item: triggers `Status`, `StatusValue` (the default without a filter) and `StatusValueTimestamp`; `DeadbandTypeAbsolute` on numeric scalars and arrays; `DeadbandTypePercent` on variables with an `EURange` property. Unusable filters are rejected per item (`BadFilterNotAllowed`, `BadMonitoredItemFilterUnsupported`, `BadDeadbandFilterInvalid`, `BadMonitoredItemFilterInvalid`). `SamplingInterval` is revised (0 stays 0 = every change, negative = publishing interval, otherwise 1 ms – 1 h) and an item is sampled at most once per interval. `ItemToMonitor.IndexRange` restricts both what is reported and what triggers. See [docs/server-guide.md](docs/server-guide.md).

---

### Constants

```go
const (
    DefaultSubscriptionMaxNotificationsPerPublish = 10000
    DefaultSubscriptionLifetimeCount              = 10000
    DefaultSubscriptionMaxKeepAliveCount           = 3000
    DefaultSubscriptionInterval                    = 100 * time.Millisecond
    DefaultSubscriptionPriority                    = 0
    DefaultDialTimeout                             = 10 * time.Second
)
```

---

## Package `ua`

OPC-UA data types, enums, status codes, and service message types.

### Variant

Union of OPC-UA built-in types.

```go
func NewVariant(v interface{}) (*Variant, error)
func MustVariant(v interface{}) *Variant
func ParseVariant(s string, typeID TypeID) (*Variant, error)
func VariantAs[T any](v *Variant) (T, error)
```

```go
func (v *Variant) Type() TypeID
func (v *Variant) Value() interface{}
func (v *Variant) ArrayLength() int32
func (v *Variant) ArrayDimensions() []int32
func (v *Variant) IsArray() bool
func (v *Variant) EncodingMask() byte
func (v *Variant) Has(mask byte) bool
func (v *Variant) Decode(b []byte) (int, error)
func (v *Variant) Encode() ([]byte, error)
```

`ParseVariant` parses a string into a typed variant (used by CLI tools).

### ExtensionObject

Register application-defined structure types so they encode/decode as OPC UA
`ExtensionObject` values (Variable Value, method arguments, etc.):

```go
func RegisterExtensionObject(typeID *NodeID, v interface{})
```

Call once per type (typically from `init()`), passing a zero value of the Go
type. Unknown `ExtensionObject` bodies are preserved as opaque bytes (dynamic
structure decoding is not implemented). See also
[Registered Custom DataTypes](#registered-custom-datatypes).

### TypeID

```go
type TypeID byte

const (
    TypeIDNull           TypeID = 0
    TypeIDBoolean        TypeID = 1
    TypeIDSByte          TypeID = 2
    TypeIDByte           TypeID = 3
    TypeIDInt16          TypeID = 4
    TypeIDUint16         TypeID = 5
    TypeIDInt32          TypeID = 6
    TypeIDUint32         TypeID = 7
    TypeIDInt64          TypeID = 8
    TypeIDUint64         TypeID = 9
    TypeIDFloat          TypeID = 10
    TypeIDDouble         TypeID = 11
    TypeIDString         TypeID = 12
    TypeIDDateTime       TypeID = 13
    TypeIDGUID           TypeID = 14
    TypeIDByteString     TypeID = 15
    TypeIDXMLElement     TypeID = 16
    TypeIDNodeID         TypeID = 17
    TypeIDExpandedNodeID TypeID = 18
    TypeIDStatusCode     TypeID = 19
    TypeIDQualifiedName  TypeID = 20
    TypeIDLocalizedText  TypeID = 21
    TypeIDExtensionObject TypeID = 22
    TypeIDDataValue      TypeID = 23
    TypeIDVariant        TypeID = 24
    TypeIDDiagnosticInfo TypeID = 25
)
```

---

### NodeID

Identifier for a node in the address space.

#### Constructors

```go
func NewTwoByteNodeID(id uint8) *NodeID
func NewFourByteNodeID(ns uint8, id uint16) *NodeID
func NewNumericNodeID(ns uint16, id uint32) *NodeID
func NewStringNodeID(ns uint16, id string) *NodeID
func NewGUIDNodeID(ns uint16, id string) *NodeID
func NewByteStringNodeID(ns uint16, id []byte) *NodeID
func NewNodeIDFromExpandedNodeID(id *ExpandedNodeID) *NodeID
func ParseNodeID(s string) (*NodeID, error)
func MustParseNodeID(s string) *NodeID
```

`ParseNodeID` accepts `ns=<ns>;{i,s,b,g}=<value>` and shorthand `i=<n>`.

#### Methods

```go
func (n *NodeID) Type() NodeIDType
func (n *NodeID) Namespace() uint16
func (n *NodeID) SetNamespace(v uint16) error
func (n *NodeID) IntID() uint32
func (n *NodeID) SetIntID(v uint32) error
func (n *NodeID) StringID() string
func (n *NodeID) SetStringID(v string) error
func (n *NodeID) String() string
func (n *NodeID) Equal(other *NodeID) bool
func (n *NodeID) EncodingMask() NodeIDType
func (n *NodeID) URIFlag() bool
func (n *NodeID) SetURIFlag()
func (n *NodeID) IndexFlag() bool
func (n *NodeID) SetIndexFlag()
func (n *NodeID) Decode(b []byte) (int, error)
func (n *NodeID) Encode() ([]byte, error)
```

`String()` returns the canonical form: `i=<id>`, `s=<id>`, `g=<id>`, or `b=<id>` for namespace 0; `ns=<n>;...` for ns ≠ 0. Namespace 0 is omitted so round-trip with ParseNodeID is consistent (e.g. `"i=85"` not `"ns=0;i=85"`).

---

### ExpandedNodeID

Extended node ID with optional namespace URI and server index.

```go
func NewExpandedNodeID(hasURI bool, uri string, hasIndex bool, index uint32, nodeID *NodeID) *ExpandedNodeID
func NewNumericExpandedNodeID(ns uint16, id uint32) *ExpandedNodeID
func NewStringExpandedNodeID(ns uint16, id string) *ExpandedNodeID
func NewTwoByteExpandedNodeID(id uint8) *ExpandedNodeID
func NewFourByteExpandedNodeID(ns uint8, id uint16) *ExpandedNodeID

func (e *ExpandedNodeID) HasNamespaceURI() bool
func (e *ExpandedNodeID) HasServerIndex() bool
func (e *ExpandedNodeID) NodeID() *NodeID
```

---

### QualifiedName

```go
type QualifiedName struct {
    NamespaceIndex uint16
    Name           string
}
```

---

### LocalizedText

```go
type LocalizedText struct {
    EncodingMask byte
    Locale       string
    Text         string
}
```

Encoding mask constants: `LocalizedTextLocale`, `LocalizedTextText`.

---

### DataValue

```go
type DataValue struct {
    EncodingMask      byte
    Value             *Variant
    Status            StatusCode
    SourceTimestamp    time.Time
    SourcePicoseconds uint16
    ServerTimestamp    time.Time
    ServerPicoseconds uint16
}
```

```go
func (d *DataValue) NodeID() *NodeID
func (d *DataValue) StatusOK() bool
func (d *DataValue) Decode(b []byte) (int, error)
func (d *DataValue) Encode() ([]byte, error)
```

Encoding mask constants: `DataValueValue`, `DataValueStatusCode`,
`DataValueSourceTimestamp`, `DataValueServerTimestamp`,
`DataValueSourcePicoseconds`, `DataValueServerPicoseconds`.

---

### NumericRange

Helpers for OPC UA IndexRange / NumericRange on Variants (used by server Read/Write and available to callers).

```go
type NumericRange struct {
    Start int // inclusive
    End   int // inclusive
}

func ParseNumericRange(s string) (NumericRange, error)
func ParseNumericRanges(s string) ([]NumericRange, error)
func (r NumericRange) Len() int

func SliceVariantRead(v *Variant, rangeStr string) (*Variant, StatusCode)
func MergeVariantWrite(current *Variant, rangeStr string, newVal *Variant) (*Variant, StatusCode)
func ApplyTimestampsToReturn(dv *DataValue, ts TimestampsToReturn) StatusCode
```

`ParseNumericRange` accepts `"i"` or `"i:j"`. `ParseNumericRanges` accepts comma-separated dimensions (`"a:b,c:d"`).

`SliceVariantRead` / `MergeVariantWrite` return Part 4 status codes (`BadIndexRangeInvalid`, `BadIndexRangeNoData`, `BadIndexRangeDataMismatch`, …). `ApplyTimestampsToReturn` filters or synthesizes DataValue timestamp fields for Read and monitored-item delivery; invalid enum → `BadTimestampsToReturnInvalid`.

---

### Transport profiles

```go
const TransportProfileUATCP = "http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary"
const TransportProfileWSS   = "http://opcfoundation.org/UA-Profile/Transport/wss-uasc-uabinary"
const TransportProfileHTTPS = "http://opcfoundation.org/UA-Profile/Transport/https-uabinary"

func TransportProfileForURL(endpointURL string) string // by scheme; "" for an unknown scheme
```

### StatusCode

32-bit OPC-UA status code.

```go
type StatusCode uint32
```

#### Common constants

```go
const (
    StatusOK                        StatusCode = 0x00000000
    StatusBad                       StatusCode = 0x80000000
    StatusUncertain                 StatusCode = 0x40000000
    StatusGood                      StatusCode = 0x00000000
    StatusBadNodeIDInvalid          StatusCode = ...
    StatusBadSessionIDInvalid       StatusCode = ...
    StatusBadSubscriptionIDInvalid  StatusCode = ...
    StatusBadUnexpectedError        StatusCode = ...
    StatusBadTimeout                StatusCode = ...
    StatusBadUserAccessDenied       StatusCode = ...
    StatusBadNodeIDUnknown          StatusCode = ...
    // ... hundreds more from the OPC-UA specification
)
```

#### Methods

```go
func (s StatusCode) Error() string
func (s StatusCode) Symbol() string
func (s StatusCode) Uint32() uint32
func (s StatusCode) IsGood() bool
func (s StatusCode) IsBad() bool
func (s StatusCode) IsUncertain() bool
```

`Uint32()` returns the raw 32-bit value for consistent CSV/JSON serialization. `Error()` returns a verbose message (e.g. "The operation succeeded. StatusGood (0x0)"); `Symbol()` returns the short symbolic name only (e.g. "Good", "BadServiceUnsupported", "BadUserAccessDenied"), stripping the "Status" prefix. Use `Symbol()` for compact status rendering.

---

### DiagnosticInfo

```go
type DiagnosticInfo struct {
    EncodingMask        uint8
    SymbolicID          int32
    NamespaceURI        int32
    LocalizedText       int32
    Locale              int32
    AdditionalInfo      string
    InnerStatusCode     StatusCode
    InnerDiagnosticInfo *DiagnosticInfo
}
```

```go
func (d *DiagnosticInfo) Has(mask byte) bool
func (d *DiagnosticInfo) UpdateMask()
func (d *DiagnosticInfo) Decode(b []byte) (int, error)
func (d *DiagnosticInfo) Encode() ([]byte, error)
```

Mask constants: `DiagnosticInfoSymbolicID`, `DiagnosticInfoNamespaceURI`,
`DiagnosticInfoLocalizedText`, `DiagnosticInfoLocale`,
`DiagnosticInfoAdditionalInfo`, `DiagnosticInfoInnerStatusCode`,
`DiagnosticInfoInnerDiagnosticInfo`.

The members of a DiagnosticInfo are indexes into the `StringTable` of the
response header. `Resolve` returns them as strings:

```go
type Diagnostic struct {
    SymbolicID, NamespaceURI, LocalizedText, Locale, AdditionalInfo string
    InnerStatusCode StatusCode
    Inner           *Diagnostic
}
func (d *DiagnosticInfo) Resolve(table []string) *Diagnostic // nil for an empty DiagnosticInfo
func (d *Diagnostic) String() string
func (h *ResponseHeader) ServiceDiagnostic() *Diagnostic  // the resolved ServiceDiagnostics
func (h *ResponseHeader) Diagnostic(d *DiagnosticInfo) *Diagnostic
```

---

### EventFilterBuilder

Fluent API for constructing event filters.

```go
func NewEventFilter() *EventFilterBuilder
```

```go
func (b *EventFilterBuilder) TypeDefinition(typeID *NodeID) *EventFilterBuilder
func (b *EventFilterBuilder) Select(names ...string) *EventFilterBuilder
func (b *EventFilterBuilder) SelectOperand(op *SimpleAttributeOperand) *EventFilterBuilder
func (b *EventFilterBuilder) Where(cond *ContentFilterElement) *EventFilterBuilder
func (b *EventFilterBuilder) Build() *EventFilter
```

#### FieldOperand (where-clause helpers)

```go
func Field(name string) *FieldOperand
func (f *FieldOperand) TypeDefinition(typeID *NodeID) *FieldOperand
func (f *FieldOperand) Equals(value interface{}) *ContentFilterElement
func (f *FieldOperand) GreaterThan(value interface{}) *ContentFilterElement
func (f *FieldOperand) LessThan(value interface{}) *ContentFilterElement
func (f *FieldOperand) GreaterThanOrEqual(value interface{}) *ContentFilterElement
func (f *FieldOperand) LessThanOrEqual(value interface{}) *ContentFilterElement
func (f *FieldOperand) Like(value string) *ContentFilterElement
func OfType(typeNodeID *NodeID) *ContentFilterElement
```

There are no fluent helpers for compound `And` / `Or` / `Not` operators. Build
those as `*ContentFilterElement` values with the corresponding
`FilterOperator*` constants and pass them to `Where`. The Go server evaluates
`And`, `Or`, and `Not` in EventFilter WhereClauses; peer stacks may support a
subset.

Example:

```go
filter := ua.NewEventFilter().
    Select("EventType", "SourceName", "Message", "Severity", "Time").
    Where(ua.Field("Severity").GreaterThanOrEqual(uint16(500))).
    Build()
```

---

### Enums and constants

#### AttributeID

```go
type AttributeID uint32

const (
    AttributeIDNodeID                  AttributeID = 1
    AttributeIDNodeClass               AttributeID = 2
    AttributeIDBrowseName              AttributeID = 3
    AttributeIDDisplayName             AttributeID = 4
    AttributeIDDescription             AttributeID = 5
    AttributeIDWriteMask               AttributeID = 6
    AttributeIDUserWriteMask           AttributeID = 7
    AttributeIDIsAbstract              AttributeID = 8
    AttributeIDSymmetric               AttributeID = 9
    AttributeIDInverseName             AttributeID = 10
    AttributeIDContainsNoLoops         AttributeID = 11
    AttributeIDEventNotifier           AttributeID = 12
    AttributeIDValue                   AttributeID = 13
    AttributeIDDataType                AttributeID = 14
    AttributeIDValueRank               AttributeID = 15
    AttributeIDArrayDimensions         AttributeID = 16
    AttributeIDAccessLevel             AttributeID = 17
    AttributeIDUserAccessLevel         AttributeID = 18
    AttributeIDMinimumSamplingInterval AttributeID = 19
    AttributeIDHistorizing             AttributeID = 20
    AttributeIDExecutable              AttributeID = 21
    AttributeIDUserExecutable          AttributeID = 22
    AttributeIDAccessLevelEx           AttributeID = 27
)
```

#### BrowseDirection

```go
type BrowseDirection uint32

const (
    BrowseDirectionForward BrowseDirection = 0
    BrowseDirectionInverse BrowseDirection = 1
    BrowseDirectionBoth    BrowseDirection = 2
)
```

#### NodeClass

```go
type NodeClass uint32

const (
    NodeClassUnspecified   NodeClass = 0
    NodeClassObject        NodeClass = 1
    NodeClassVariable      NodeClass = 2
    NodeClassMethod        NodeClass = 4
    NodeClassObjectType    NodeClass = 8
    NodeClassVariableType  NodeClass = 16
    NodeClassReferenceType NodeClass = 32
    NodeClassDataType      NodeClass = 64
    NodeClassView          NodeClass = 128
    NodeClassAll           NodeClass = 255
)
```

#### MessageSecurityMode

```go
type MessageSecurityMode uint32

const (
    MessageSecurityModeInvalid        MessageSecurityMode = 0
    MessageSecurityModeNone           MessageSecurityMode = 1
    MessageSecurityModeSign           MessageSecurityMode = 2
    MessageSecurityModeSignAndEncrypt MessageSecurityMode = 3
)
```

#### AccessLevelType

```go
type AccessLevelType uint8

const (
    AccessLevelTypeCurrentRead      AccessLevelType = 0x01
    AccessLevelTypeCurrentWrite     AccessLevelType = 0x02
    AccessLevelTypeHistoryRead      AccessLevelType = 0x04
    AccessLevelTypeHistoryWrite     AccessLevelType = 0x08
    AccessLevelTypeSemanticChange   AccessLevelType = 0x10
    AccessLevelTypeStatusWrite      AccessLevelType = 0x20
    AccessLevelTypeTimestampWrite   AccessLevelType = 0x40
)
```

#### TimestampsToReturn

```go
type TimestampsToReturn uint32

const (
    TimestampsToReturnSource  TimestampsToReturn = 0
    TimestampsToReturnServer  TimestampsToReturn = 1
    TimestampsToReturnBoth    TimestampsToReturn = 2
    TimestampsToReturnNeither TimestampsToReturn = 3
)
```

#### PerformUpdateType

Used by HistoryUpdate `UpdateDataDetails` / `HistoryDataUpdater.UpdateData`:

```go
type PerformUpdateType uint32

const (
    PerformUpdateTypeInsert  PerformUpdateType = 1
    PerformUpdateTypeReplace PerformUpdateType = 2
    PerformUpdateTypeUpdate  PerformUpdateType = 3
    PerformUpdateTypeRemove  PerformUpdateType = 4
)
```

#### Security policy URIs

```go
const (
    SecurityPolicyURINone                = "http://opcfoundation.org/UA/SecurityPolicy#None"
    SecurityPolicyURIBasic128Rsa15       = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    SecurityPolicyURIBasic256            = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
    SecurityPolicyURIBasic256Sha256      = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
    SecurityPolicyURIAes128Sha256RsaOaep = "http://opcfoundation.org/UA/SecurityPolicy#Aes128Sha256RsaOaep"
    SecurityPolicyURIAes256Sha256RsaPss  = "http://opcfoundation.org/UA/SecurityPolicy#Aes256Sha256RsaPss"
)
```

---

### ReferenceDescription

```go
type ReferenceDescription struct {
    ReferenceTypeID *NodeID
    IsForward       bool
    NodeID          *ExpandedNodeID
    BrowseName      *QualifiedName
    DisplayName     *LocalizedText
    NodeClass       NodeClass
    TypeDefinition  *ExpandedNodeID
}
```

---

### Service message types (selection)

The `ua` package contains all OPC-UA request/response types generated from the
specification. Key pairs include:

| Request | Response |
|---------|----------|
| `ReadRequest` | `ReadResponse` |
| `WriteRequest` | `WriteResponse` |
| `BrowseRequest` | `BrowseResponse` |
| `BrowseNextRequest` | `BrowseNextResponse` |
| `CallRequest` | `CallResponse` |
| `CreateSubscriptionRequest` | `CreateSubscriptionResponse` |
| `ModifySubscriptionRequest` | `ModifySubscriptionResponse` |
| `DeleteSubscriptionsRequest` | `DeleteSubscriptionsResponse` |
| `PublishRequest` | `PublishResponse` |
| `CreateMonitoredItemsRequest` | `CreateMonitoredItemsResponse` |
| `DeleteMonitoredItemsRequest` | `DeleteMonitoredItemsResponse` |
| `FindServersRequest` | `FindServersResponse` |
| `GetEndpointsRequest` | `GetEndpointsResponse` |
| `CreateSessionRequest` | `CreateSessionResponse` |
| `ActivateSessionRequest` | `ActivateSessionResponse` |
| `CloseSessionRequest` | `CloseSessionResponse` |
| `HistoryReadRequest` | `HistoryReadResponse` |
| `QueryFirstRequest` | `QueryFirstResponse` |
| `QueryNextRequest` | `QueryNextResponse` |
| `RegisterNodesRequest` | `RegisterNodesResponse` |
| `UnregisterNodesRequest` | `UnregisterNodesResponse` |
| `TranslateBrowsePathsToNodeIDsRequest` | `TranslateBrowsePathsToNodeIDsResponse` |
| `AddNodesRequest` | `AddNodesResponse` |
| `DeleteNodesRequest` | `DeleteNodesResponse` |
| `AddReferencesRequest` | `AddReferencesResponse` |
| `DeleteReferencesRequest` | `DeleteReferencesResponse` |
| `SetPublishingModeRequest` | `SetPublishingModeResponse` |
| `SetMonitoringModeRequest` | `SetMonitoringModeResponse` |
| `ModifyMonitoredItemsRequest` | `ModifyMonitoredItemsResponse` |
| `RepublishRequest` | `RepublishResponse` |
| `TransferSubscriptionsRequest` | `TransferSubscriptionsResponse` |
| `HistoryUpdateRequest` | `HistoryUpdateResponse` |

---

### Notification types

```go
type DataChangeNotification struct { ... }
type EventNotificationList struct { ... }
type StatusChangeNotification struct { ... }
```

These are the concrete types delivered in `PublishNotificationData.Value`.

---

### Endpoint selection for a client certificate

```go
func SelectEndpoint(endpoints []*ua.EndpointDescription, policy string, mode ua.MessageSecurityMode, certificate []byte) (*ua.EndpointDescription, error)
func SelectEndpointForTransport(endpoints []*ua.EndpointDescription, transportProfileURI, policy string, mode ua.MessageSecurityMode, certificate []byte) (*ua.EndpointDescription, error)
```

`opcua.SelectEndpoint` returns the endpoint with the highest security level that the client can use with its application instance certificate (DER) and that matches `policy` and `mode` (`""` / `ua.MessageSecurityModeInvalid` match anything). Unlike `ua.SelectEndpoint` it leaves out endpoints with a security policy the library does not implement and secured endpoints whose policy does not fit the key type of the certificate (RSA vs. ECC, and the curve); with an empty certificate only unsecured endpoints remain. Endpoints the server gives the same security level are ranked by `uapolicy.SecurityLevel`, which puts the AEAD policies first. When the list has `opc.tcp` endpoints, `SelectEndpoint` only considers those; `SelectEndpointForTransport` selects among the endpoints of one transport profile (`ua.TransportProfileUATCP`, `ua.TransportProfileWSS`, `ua.TransportProfileHTTPS`; an endpoint without a profile counts as `opc.tcp`).

### Display name and endpoint helpers

```go
func SelectEndpoint(endpoints []*EndpointDescription, policy string, mode MessageSecurityMode) (*EndpointDescription, error)
func ReferenceTypeDisplayName(refTypeID *NodeID) string
func TypeDefinitionDisplayName(typeDefID *NodeID) string
func DataTypeDisplayName(dataTypeID *NodeID) string
func StandardNodeID(name string) (*NodeID, bool)
```

`SelectEndpoint` filters endpoints by security policy and mode, returning the best match or an error if none match.

`ReferenceTypeDisplayName` returns the standard name for a reference type NodeID in namespace 0 (e.g. "HasComponent", "Organizes"), or the NodeID string for unknown types.

`TypeDefinitionDisplayName` returns a display string for a type definition NodeID (VariableType or ObjectType in namespace 0): tries VariableTypeName then ObjectTypeName (e.g. i=68 → "PropertyType", i=61 → "FolderType"); otherwise the NodeID string. Returns the empty string if typeDefID is nil.

`DataTypeDisplayName` returns the standard name for a DataType NodeID in namespace 0 (e.g. "Float", "String", "UtcTime"), or the NodeID string for unknown types.

`StandardNodeID` returns the namespace-0 NodeID for a well-known standard node name (e.g. "CurrentTime" → i=2258, "ServerStatus" → i=2256, "Objects" → i=85). Returns (nil, false) if the name is not found.

---

### Buffer

Low-level helper for reading/writing OPC-UA binary protocol data.

```go
func NewBuffer(b []byte) *Buffer
```

Selected methods:

```go
func (b *Buffer) ReadBool() bool
func (b *Buffer) ReadInt16() int16
func (b *Buffer) ReadInt32() int32
func (b *Buffer) ReadUint16() uint16
func (b *Buffer) ReadUint32() uint32
func (b *Buffer) ReadFloat32() float32
func (b *Buffer) ReadFloat64() float64
func (b *Buffer) ReadString() string
func (b *Buffer) ReadBytes() []byte
func (b *Buffer) ReadTime() time.Time
func (b *Buffer) ReadStruct(v interface{}) error
func (b *Buffer) WriteBool(v bool)
func (b *Buffer) WriteInt16(v int16)
func (b *Buffer) WriteInt32(v int32)
func (b *Buffer) WriteUint16(v uint16)
func (b *Buffer) WriteUint32(v uint32)
func (b *Buffer) WriteFloat32(v float32)
func (b *Buffer) WriteFloat64(v float64)
func (b *Buffer) WriteString(s string)
func (b *Buffer) WriteBytes(v []byte)
func (b *Buffer) WriteTime(t time.Time)
func (b *Buffer) Pos() int
func (b *Buffer) Len() int
func (b *Buffer) Error() error
```

### JSON and XML DataEncoding

The OPC UA JSON (Part 6 §5.4) and XML (Part 6 §5.3) DataEncodings of values.
These are encodings of data - for tooling, gateways, PubSub-style payloads
and NodeSet2 values - not a transport: the wire stays UA-TCP with the binary
encoding. See [JSON and XML Data Encodings](docs/encodings.md) for the forms,
examples and the interoperability notes.

```go
func EncodeJSON(v interface{}, opts ...CodecOption) ([]byte, error)
func DecodeJSON(data []byte, v interface{}, opts ...CodecOption) error
func EncodeXML(v interface{}, opts ...CodecOption) ([]byte, error)
func DecodeXML(data []byte, v interface{}, opts ...CodecOption) error
```

`v` is a value of a built-in type (`bool`, `int32`, `string`, `time.Time`,
`[]byte`, `*NodeID`, `*Variant`, `*DataValue`, `*ExtensionObject`, ...), a
pointer to a generated or registered structure, an enumeration, or a slice of
these; the decoders take a non-nil pointer to it. Errors wrap a `StatusCode`
(`StatusBadDecodingError`, `StatusBadEncodingLimitsExceeded`,
`StatusBadEncodingError`).

`EncodeJSON` is unrelated to `encoding/json`: `json.Marshal` on the types of
this package keeps using their `MarshalJSON` methods, a display format that is
unchanged.

```go
type JSONForm int

const (
    JSONCompact             JSONForm = iota // 1.05.04 Compact (default; what open62541 1.5 reads and writes)
    JSONVerbose                             // 1.05.04 Verbose
    JSONLegacyReversible                    // 1.04 reversible
    JSONLegacyNonReversible                 // 1.04 non-reversible, encode only
)
```

`DecodeJSON` accepts Compact, Verbose and the 1.04 reversible form without
being told which one it is given.

```go
type CodecOption func(*codecOptions)

func WithJSONForm(f JSONForm) CodecOption        // form written by EncodeJSON
func WithNamespaceArray(uris []string) CodecOption // write/read namespace URIs instead of indexes
func WithServerArray(uris []string) CodecOption    // same for the ServerIndex of an ExpandedNodeId
func WithIndent(indent string) CodecOption         // pretty-print
func WithMaxDepth(n int) CodecOption               // nesting limit, default DefaultCodecMaxDepth (100)
func WithMaxArrayLength(n int) CodecOption         // Variant array limit, default MaxVariantArrayLength
func WithXMLRootName(name string) CodecOption      // name of the outermost XML element
func WithoutXMLNamespace() CodecOption             // omit the xmlns declaration

const XMLTypesNamespace = "http://opcfoundation.org/UA/2008/02/Types.xsd"
const DefaultCodecMaxDepth = 100
```

Custom structures registered with `RegisterExtensionObject` work as they are
(fields are named after the Go fields or their `opcua:"Name"` tag).
`RegisterDataTypeInfo` adds the NodeIds JSON and XML use to identify the
structure, which makes the documents portable to other stacks:

```go
type DataTypeInfo struct {
    Name           string  // DataType name; XML element name of the structure
    DataTypeID     *NodeID // JSON UaTypeId
    XMLEncodingID  *NodeID // XML ExtensionObject TypeId
    JSONEncodingID *NodeID // accepted when decoding
}

func RegisterDataTypeInfo(v interface{}, info DataTypeInfo)
```

`StatusCodeDesc` (the values of `StatusCodes`) has a `Symbol` field with the
name of the code in the specification (`"BadNodeIdUnknown"`), which is the
`Symbol` of a StatusCode in the Verbose JSON form.

---

## Package `server`

### Server

```go
func New(opts ...Option) (*Server, error)
```

#### Lifecycle

```go
func (s *Server) Start(ctx context.Context) error
func (s *Server) Close() error
```

#### Namespace management

```go
func (s *Server) AddNamespace(ns NameSpace) int
func (s *Server) Namespace(id int) (NameSpace, error)
func (s *Server) Namespaces() []NameSpace
```

#### Method registration

```go
type MethodHandler func(ctx context.Context, objectID, methodID *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode)

func (s *Server) RegisterMethod(objectID, methodID *ua.NodeID, handler MethodHandler)
```

#### Custom service handlers

Handlers process incoming service requests by TypeID. The context is request-scoped and supports cancellation and timeouts.

```go
type Handler func(ctx context.Context, sc *uasc.SecureChannel, req ua.Request, reqID uint32) (ua.Response, error)

func (s *Server) RegisterHandler(typeID uint16, h Handler)
```

#### NodeSet import

```go
func (s *Server) ImportNodeSetXML(data []byte) error
```

Parses OPC UA NodeSet2 XML data and imports nodes, references, and namespaces
into the server's address space. Use this to load custom information models.
For `UAVariable` elements the `<Value>` (the OPC UA XML DataEncoding, decoded
with `ua.DecodeXML`), `DataType`, `ValueRank`, `ArrayDimensions`,
`AccessLevel` and `UserAccessLevel` are applied; see the
[Server Guide](docs/server-guide.md#nodeset2-import) for the defaults.

#### Info

```go
func (s *Server) Endpoints() []*ua.EndpointDescription
func (s *Server) URLs() []string
func (s *Server) Status() *ua.ServerStatusDataType
func (s *Server) Node(nid *ua.NodeID) *Node
func (s *Server) ChangeNotification(n *ua.NodeID)
func (s *Server) Port() int
func (s *Server) RegisteredServers() []*ua.RegisteredServer // Local Discovery Server: the registered servers
func (s *Server) ServersOnNetwork() []*ua.ServerOnNetwork   // multicast discovery: the ServerOnNetwork table
func (s *Server) ServerDiagnosticsSummary() *ua.ServerDiagnosticsSummaryDataType
func (s *Server) ServerDiagnosticsEnabled() bool
func (s *Server) SetServerDiagnosticsEnabled(on bool) // true resets the counters
```

---

### Server configuration options

| Function | Description |
|----------|-------------|
| `EndPoint(host string, port int)` | Listen address |
| `ListenOn(addr string)` | Override the TCP bind address (e.g. `"0.0.0.0:4840"`) |
| `Certificate(cert []byte)` | Server certificate (DER) |
| `PrivateKey(key *rsa.PrivateKey)` | Server private key (RSA) |
| `ApplicationIdentity(cert []byte, key crypto.Signer)` | Add an application instance certificate with its key; repeat per key type (RSA, ECDSA P-256 / P-384 / brainpoolP256r1 / brainpoolP384r1, Ed25519, Ed448). The server uses, and each endpoint advertises, the certificate that fits the security policy |
| `EnableSecurity(policy string, mode ua.MessageSecurityMode)` | Enable a security policy/mode combination (returns error for unsupported or duplicate). An ECC policy needs a matching `ApplicationIdentity` |
| `EnableAuthMode(tokenType ua.UserTokenType)` | Enable an authentication token type (returns error for duplicate). `UserName`, `Certificate` and `IssuedToken` also need their validator: without it every token of that type is rejected and `New` logs a warning |
| `AllowUsernameOnNone()` | Advertise `UserName` token on unencrypted (`None/None`) endpoints — for test deployments only |
| `WithUsernameValidator(v UsernameValidator)` | Callback `func(username, password string) error` called during `ActivateSession` for `UserNameIdentityToken`; without one, username tokens are rejected with `BadUserAccessDenied` |
| `WithX509UserValidator(v X509UserValidator)` | Callback `func(certDER []byte) error` called during `ActivateSession` for `X509IdentityToken`; must also call `EnableAuthMode(ua.UserTokenTypeCertificate)`; without one, X.509 user tokens are rejected |
| `WithIssuedTokenValidator(v IssuedTokenValidator)` | Callback `func(tok *ua.IssuedIdentityToken) error` called during `ActivateSession` for `IssuedIdentityToken` (token data decrypted where the policy encrypts it); must also call `EnableAuthMode(ua.UserTokenTypeIssuedToken)`; without one, issued tokens are rejected with `BadIdentityTokenRejected` |
| `WithClientCertificateTrustList(caCertDER ...[]byte)` | Verify the client application certificate (DER) at `OpenSecureChannel` (and again at `CreateSession`) against the provided CA pool; rejects untrusted certs with `BadCertificateUntrusted` |
| `ServerName(name string)` | Application name |
| `ManufacturerName(s string)` | Manufacturer name |
| `ProductName(s string)` | Product name |
| `SoftwareVersion(s string)` | Software version string |
| `SetLogger(l *slog.Logger)` | Logger (`*slog.Logger`; silent by default; `nil` restores silent) |
| `WithMetrics(m ServerMetrics)` | Metrics handler |
| `WithAccessController(ac AccessController)` | Access controller |
| `WithServerDiagnostics(enabled bool)` | Collect server diagnostics (`Server.ServerDiagnostics`, default true); see the [server guide](docs/server-guide.md#server-diagnostics) |
| `WithRoleMapper(rm RoleMapper)` | Maps a session to a `ua.UserRole`; used by the default access controller |
| `ApplicationURI(uri string)` | ApplicationUri of the server; only needed without a certificate (`Certificate` sets it from the URI SAN) |
| `WithReverseConnect(clientURL string, opts ...ReverseConnectOption)` | Open reverse connections to the client listening at `clientURL`; see [Reverse connect (server)](#reverse-connect-server) |
| `WebSocketEndPoint(host string, port int)` | Add an `opc.wss://host:port` endpoint (Part 6 §7.5, wss-uasc-uabinary); the server listens on the first one, port 0 picks a free port |
| `ListenWebSocketOn(addr string)` | Bind address of the WebSocket listener |
| `HTTPSEndPoint(host string, port int)` | Add an `opc.https://host:port` endpoint (Part 6 §7.4, https-uabinary): each enabled policy without SecureChannelEnhancements, in its strongest enabled mode |
| `ListenHTTPSOn(addr string)` | Bind address of the HTTPS listener |
| `TLSConfig(cfg *tls.Config)` | TLS certificate (and client authentication) of the `opc.wss` / `opc.https` listeners; default: the RSA application instance certificate. TLS 1.2 minimum |
| `WithPushManagement(pm PushManagement)` | Push certificate management (Part 12 §7): the ServerConfiguration object with the DefaultApplicationGroup (client application certificates), DefaultHttpsGroup (TLS) and DefaultUserTokenGroup (X.509 user tokens), their trust lists and alarms; see [Push certificate management (server)](#push-certificate-management-server) |

`Server.URLs()` lists the `opc.tcp`, then the `opc.wss` and the `opc.https` endpoint URLs; `Server.WebSocketAddr()` and `Server.HTTPSAddr()` return the bound listener addresses. Each `EndpointDescription` carries the `TransportProfileUri` of its transport.

---

### Reverse connect (server)

The server connects to a listening client, announces itself with ReverseHello
(ServerUri = its ApplicationUri, EndpointUrl = the endpoint to use) and serves
the connection like an accepted one. See the
[server guide](docs/server-guide.md#reverse-connect).

```go
func (s *Server) AddReverseConnect(clientURL string, opts ...ReverseConnectOption) (*ReverseConnect, error)
func (s *Server) ReverseConnects() []*ReverseConnect

type ReverseConnect struct { ... }

func (rc *ReverseConnect) ClientURL() string
func (rc *ReverseConnect) State() ReverseConnectState
func (rc *ReverseConnect) Connections() int // connections the client has in use
func (rc *ReverseConnect) Err() error       // why the last attempt failed, or nil
func (rc *ReverseConnect) Close() error     // remove the target, close its connections
```

`clientURL` is `"opc.tcp://host:port"`. A target added before `Start` (or
configured with `WithReverseConnect`) becomes active when the server starts;
`Server.Close` stops all targets.

```go
type ReverseConnectState int

const (
    ReverseConnectConnecting ReverseConnectState = iota // opening a connection
    ReverseConnectWaiting                               // announced, not used by the client yet
    ReverseConnectConnected                             // at least one connection in use
    ReverseConnectBackoff                               // last attempt failed, waiting to retry
    ReverseConnectClosed                                // target removed or server closed
)

func (s ReverseConnectState) String() string
```

| Option | Description |
|--------|-------------|
| `ReverseConnectEndpointURL(url string)` | EndpointUrl announced to the client (default: the first `EndPoint`) |
| `ReverseConnectRetryInterval(initial, max time.Duration)` | Delay before the first retry and the bound it doubles up to (defaults `DefaultReverseConnectRetryInterval` = 500 ms, `DefaultReverseConnectMaxRetryInterval` = 15 s) |
| `ReverseConnectMaxConnections(n int)` | Connections of the target that may be in use at a time (default `DefaultReverseConnectMaxConnections` = 8) |
| `WithLocalDiscoveryServer(opts ...LDSOption)` | Local Discovery Server: accept RegisterServer / RegisterServer2 and return the registered servers from FindServers |
| `WithDiscoveryRegistration(discoveryServerURL string, opts ...RegistrationOption)` | Register with a discovery server in the background, renew, retry and unregister on `Close`; repeatable |
| `WithMulticastDiscovery(opts ...MulticastOption)` | mDNS: announce the server, discover others, answer FindServersOnNetwork |

#### Discovery options

| `LDSOption` | Description |
|-------------|-------------|
| `LDSRegistrationTimeout(d time.Duration)` | Lifetime of a registration that is not renewed (default `DefaultRegistrationTimeout`, one hour; `<= 0` disables) |
| `LDSAllowInsecureRegistration()` | Accept registrations on channels without security (tests, lab) |
| `LDSSkipServerURICheck()` | Do not require the `ServerUri` to be the application URI of the channel's certificate |
| `LDSMaxRegisteredServers(n int)` | Bound of the table (default 1024) |
| `LDSApplicationType(t ua.ApplicationType)` | ApplicationType reported by the server, e.g. `ua.ApplicationTypeDiscoveryServer` |
| `LDSRegistrationCallback(fn func(server *ua.RegisteredServer))` | Called for every accepted registration and unregistration |

| `RegistrationOption` | Description |
|----------------------|-------------|
| `RegisterInterval(d time.Duration)` | Renewal interval (default `DefaultRegisterInterval`, 10 minutes) |
| `RegisterRequestTimeout(d time.Duration)` | Bound of one attempt and of the unregistration on `Close` (default 10 s) |
| `RegisterBackoff(minDelay, maxDelay time.Duration)` | Retry delay after a failure (default 1 s doubling to 1 min) |
| `RegisterInsecure()` | Allow a channel without security (a secured endpoint is still preferred) |
| `RegisterSecurity(policy string, mode ua.MessageSecurityMode)` | Pin policy and mode instead of the most secure endpoint |
| `RegisterCertificateValidator(fn func(certDER []byte) error)` | Trust decision for the discovery server's certificate (default: accept) |
| `RegisterDiscoveryURLs(urls ...string)` | Discovery URLs to register instead of the endpoint URLs |
| `RegisterMdnsServerName(name string)` | mDNS server name sent with RegisterServer2 |
| `RegisterServerCapabilities(caps ...string)` | Capabilities sent with RegisterServer2 (default `NA`) |
| `RegisterSemaphoreFile(path string)` | Semaphore file path of the registration |
| `RegisterEventHandler(fn func(RegistrationEvent))` | Called after every attempt |

```go
type RegistrationEvent struct {
    DiscoveryServerURL   string
    Service              string // "RegisterServer2" or "RegisterServer"
    Online               bool   // false: the unregistration on Close
    SecurityPolicyURI    string
    SecurityMode         ua.MessageSecurityMode
    ConfigurationResults []ua.StatusCode
    Err                  error
}
```

| `MulticastOption` | Description |
|-------------------|-------------|
| `MulticastServerName(name string)` | mDNS server name; the instance is `<name>-<hostname>` (default: the application name) |
| `MulticastCapabilities(caps ...string)` | `caps` of the TXT record (default `LDS` for a discovery server, else `NA`) |
| `MulticastInterfaces(names ...string)` | Restrict mDNS to these interfaces |
| `MulticastHostname(hostname string)` | Host name to announce (default: the machine's) |
| `MulticastIPv4Only()` | Do not use IPv6 |
| `MulticastMaxServersOnNetwork(n int)` | Bound of the discovered servers (default 1024) |

---

### NameSpace (interface)

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

Implementations:

```go
func NewNodeNameSpace(srv *Server, name string) *NodeNameSpace
func NewMapNamespace(srv *Server, name string) *MapNamespace
```

`NewNodeNameSpace` provides a full OPC-UA node graph with references and type
definitions. `NewMapNamespace` provides a simple key-value store for IoT/sensor
data. Both constructors register the namespace with the server automatically.

Both implementations also expose a node-enumeration accessor used by the Query
service (a namespace is scanned by QueryFirst only if it provides this method):

```go
func (as *NodeNameSpace) Nodes() []*Node
func (ns *MapNamespace) Nodes() []*Node
```

`NodeNameSpace` has helpers that create a variable node and add it to the
namespace in one step:

```go
func (as *NodeNameSpace) AddNewVariableNode(name string, value any) *Node       // numeric NodeID from the namespace sequence
func (as *NodeNameSpace) AddNewVariableStringNode(name string, value any) *Node // string NodeID equal to name
```

---

### Node (server-side)

```go
type Attributes map[ua.AttributeID]*ua.DataValue
type References []*ua.ReferenceDescription
type ValueFunc  func() *ua.DataValue
```

```go
func NewNode(id *ua.NodeID, attr Attributes, refs References, val ValueFunc) *Node
func NewFolderNode(nodeID *ua.NodeID, name string) *Node
func NewVariableNode(nodeID *ua.NodeID, name string, value any) *Node
```

#### Methods

```go
func (n *Node) ID() *ua.NodeID
func (n *Node) Value() *ua.DataValue
func (n *Node) Attribute(id ua.AttributeID) (*AttrValue, error)
func (n *Node) SetAttribute(id ua.AttributeID, val *ua.DataValue) error
func (n *Node) BrowseName() *ua.QualifiedName
func (n *Node) SetBrowseName(s string)
func (n *Node) DisplayName() *ua.LocalizedText
func (n *Node) SetDisplayName(text, locale string)
func (n *Node) Description() *ua.LocalizedText
func (n *Node) SetDescription(text, locale string)
func (n *Node) DataType() *ua.ExpandedNodeID
func (n *Node) NodeClass() ua.NodeClass
func (n *Node) SetNodeClass(nc ua.NodeClass)
func (n *Node) AddObject(o *Node) *Node
func (n *Node) AddVariable(o *Node) *Node
func (n *Node) AddRef(o *Node, rt RefType, forward bool)
func (n Node) Access(flag ua.AccessLevelType) bool
```

```go
type AttrValue struct {
    Value           *ua.DataValue
    SourceTimestamp time.Time
}
```

---

### AccessController

```go
type AccessController interface {
    CheckRead(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
    CheckWrite(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
    CheckBrowse(ctx context.Context, session *session, nodeID *ua.NodeID) ua.StatusCode
    CheckCall(ctx context.Context, session *session, methodID *ua.NodeID) ua.StatusCode
}
```

Return `ua.StatusOK` to allow, or a status like `ua.StatusBadUserAccessDenied`
to deny.

```go
type DefaultAccessController struct{}  // allows all operations
```

---

### Authentication validators

```go
// UsernameValidator is called during ActivateSession for UserNameIdentityToken.
// Return nil to accept, or an error (e.g. ua.StatusBadUserAccessDenied) to reject.
type UsernameValidator func(username, password string) error

// IssuedTokenValidator is called during ActivateSession for IssuedIdentityToken
// (a JWT, SAML or Kerberos token); TokenData is decrypted where the security
// policy encrypts it. Return nil to accept, or ua.StatusBadIdentityTokenRejected.
type IssuedTokenValidator func(tok *ua.IssuedIdentityToken) error

// Without a configured validator the server rejects every UserName, X.509 and
// issued identity token: credentials nobody checks are never accepted.

// X509UserValidator is called during ActivateSession for X509IdentityToken.
// certDER is the DER-encoded client user certificate.
// Return nil to accept, or ua.StatusBadIdentityTokenRejected to reject.
type X509UserValidator func(certDER []byte) error

// ClientCertificateValidator is called during OpenSecureChannel (and again
// during CreateSession) to verify the client's application certificate
// against the server's trust store.
// Return nil to accept, or ua.StatusBadCertificateUntrusted to reject.
// Configured via WithClientCertificateTrustList.
type ClientCertificateValidator func(certDER []byte) error
```

---

### EventEmitter

```go
type EventEmitter interface {
    EmitEvent(nodeID *ua.NodeID, fields *ua.EventFieldList) error
}

func (s *Server) EmitEvent(nodeID *ua.NodeID, fields *ua.EventFieldList) error
func (s *Server) EmitBaseEvent(nodeID *ua.NodeID, event *BaseEvent) error
```

```go
type BaseEvent struct {
    EventID    []byte
    EventType  *ua.NodeID
    SourceNode *ua.NodeID
    SourceName string
    Time       interface{} // time.Time
    Message    *ua.LocalizedText
    Severity   uint16
    // Fields holds user-defined event properties resolved by name via SelectClauses.
    // Example: Fields: map[string]*ua.Variant{"AlarmLevel": ua.MustVariant(int32(3))}
    Fields     map[string]*ua.Variant
}
```

`EmitEvent` delivers a pre-built `EventFieldList` to event-monitored items.
`EmitBaseEvent` delivers a `BaseEventType`-shaped event, applying each item's full
EventFilter — including `OfType`, `Equals`, `GreaterThan(OrEqual)`, `LessThan(OrEqual)`,
`And`, `Or`, and `Not` WhereClause operators — before selecting and delivering fields.

**Custom event subtypes:** Register any `NodeClassObjectType` node in the server
address space (any namespace) and pass its NodeID as the `OfType` operand. The server
validates and accepts it in `CreateMonitoredItems`. Emit events with `EventType` set to
that NodeID; the `eventTypeMatches` hierarchy walk correctly routes them.

**Custom event fields:** Populate `BaseEvent.Fields` with a `map[string]*ua.Variant`.
Any `SelectClause` BrowsePath name that matches a key in `Fields` resolves to that value.
Unknown field names resolve to null (as per Part 4).

**Monitored-item modification:** `ModifyMonitoredItems` re-validates and applies an
updated `EventFilter` to an existing event item when a new filter is supplied.

Peer EventFilter / event-subscription interoperability against opcua-interop v0.6.0:
`event.subscription`, SelectClauses, OfType, and severity-threshold filters are
verified in all applicable directions. Broad WhereClause and custom emission remain
deferred. Go↔Go covered.

---

### Alarms & Conditions

Condition instances (Part 9 §5.5) with their standard components and state
machines. The standard methods (Enable, Disable, AddComment, Acknowledge,
Confirm, TimedShelve, OneShotShelve, Unshelve, ConditionRefresh,
ConditionRefresh2) are served through the Call service and the
`AccessController`. Guide: [server-guide.md](docs/server-guide.md#alarms-and-conditions).

```go
var AcknowledgeableConditionTypeNodeID = ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)

func AlarmsConditionsSupported() bool // true

func (s *Server) AddCondition(cfg ConditionConfig) (*Condition, error)
func (s *Server) Condition(conditionID *ua.NodeID) (*Condition, bool)
func (s *Server) Conditions() []*Condition
func (s *Server) RemoveCondition(conditionID *ua.NodeID) error

type ConditionConfig struct {
    Type               *ua.NodeID // ConditionType or a subtype; default AlarmConditionType
    NodeID             *ua.NodeID // the ConditionId; default a new numeric NodeId
    Namespace          *NodeNameSpace
    Name               string     // BrowseName and ConditionName
    Source             *ua.NodeID // required: gets HasCondition, becomes a notifier
    SourceName         string
    Notifiers          []*ua.NodeID
    ConditionClassID   *ua.NodeID
    ConditionClassName string
    Severity           uint16 // 1..1000, 0 = 500
    Message            string
    Retain             bool // ConditionType only; derived for the others
    Disabled           bool
    Confirmable        bool // ConfirmedState + Confirm
    Suppressible       bool // SuppressedState + Suppress / Unsuppress (and *2)
    Shelving           bool // ShelvingState + TimedShelve / OneShotShelve / Unshelve (and *2)
    Serviceable        bool // OutOfServiceState + RemoveFromService / PlaceInService (and *2)
    Silenceable        bool // SilenceState + Silence
    Latching           bool // LatchedState + Reset / Reset2
    Branching          bool // keep an unacknowledged / unconfirmed occurrence as a branch
    Dialog             *DialogConfig // DialogConditionType: Prompt, ResponseOptionSet, ...
    SuppressionGroups  []*ua.NodeID  // AlarmSuppressionGroups (HasAlarmSuppressionGroup)
    MaxTimeShelved     time.Duration
    InputNode          *ua.NodeID
    NormalState        *ua.NodeID // OffNormalAlarmType
    Limits             AlarmLimits

    // Called before the change, after the state checks; a non-Good status
    // refuses the call. They run without locks held.
    OnAcknowledge func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
    OnConfirm     func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
    OnAddComment  func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
    OnEnable      func(ctx context.Context, c *Condition, enable bool) ua.StatusCode
    OnShelve      func(ctx context.Context, c *Condition, state ShelvingState, shelvingTime time.Duration) ua.StatusCode
    OnSuppress    func(ctx context.Context, c *Condition, suppress bool, comment *ua.LocalizedText) ua.StatusCode
    OnService     func(ctx context.Context, c *Condition, inService bool, comment *ua.LocalizedText) ua.StatusCode
    OnSilence     func(ctx context.Context, c *Condition) ua.StatusCode
    OnReset       func(ctx context.Context, c *Condition, comment *ua.LocalizedText) ua.StatusCode
    OnRespond     func(ctx context.Context, c *Condition, selectedResponse int32, comment *ua.LocalizedText) ua.StatusCode
}

type DialogConfig struct {
    Prompt                                          string
    ResponseOptions                                 []string
    DefaultResponse, OkResponse, CancelResponse     *int32
    Active                                          bool
}

func (c *Condition) ShowDialog(prompt string) error
func (c *Condition) CloseDialog() error

// Branches (Part 9 §5.5.2 BranchId, Annex B)
func (c *Condition) CreateBranch() (*ua.NodeID, error) // copy of the current state
func (c *Condition) Branches() []ConditionState
func (c *Condition) Branch(branchID *ua.NodeID) (ConditionState, bool)
func (c *Condition) DeleteBranch(branchID *ua.NodeID) error
func BranchIDFromContext(ctx context.Context) *ua.NodeID // in the On* hooks
var ErrBranchUnknown, ErrTooManyBranches error

// Alarm groups (AlarmGroupType, AlarmSuppressionGroupType)
type AlarmGroupConfig struct {
    NodeID           *ua.NodeID
    Namespace        *NodeNameSpace
    Name             string
    Parent           *ua.NodeID // default the Objects folder
    Suppression      bool       // an AlarmSuppressionGroup
    DigitalVariables []*ua.NodeID
}
func (s *Server) AddAlarmGroup(cfg AlarmGroupConfig) (*AlarmGroup, error)
func (s *Server) AlarmGroup(groupID *ua.NodeID) (*AlarmGroup, bool)
func (s *Server) RemoveAlarmGroup(groupID *ua.NodeID) error
func (g *AlarmGroup) AddMember(c *Condition) error
func (g *AlarmGroup) RemoveMember(c *Condition) error
func (g *AlarmGroup) Members() []*ua.NodeID
func (g *AlarmGroup) SetSuppressing(on bool) error // suppression groups
func (g *AlarmGroup) Evaluate() error              // from the DigitalVariables

// Audit events (AuditConditionEventType and subtypes); off by default
func WithAuditing(enabled bool) Option
func (s *Server) SetAuditing(enabled bool)
func (s *Server) Auditing() bool
type EventAccessController interface { // RBACAccessController: ReceiveEvents
    CheckReceiveEvents(ctx context.Context, session *session, eventType *ua.NodeID) ua.StatusCode
}

type AlarmLimits struct{ HighHigh, High, Low, LowLow *float64 }
type NonExclusiveLimits struct{ HighHigh, High, Low, LowLow bool }
type LimitState int    // LimitNone, LimitHighHigh, LimitHigh, LimitLow, LimitLowLow
type ShelvingState int // Unshelved, TimedShelved, OneShotShelved

func (c *Condition) NodeID() *ua.NodeID
func (c *Condition) Name() string
func (c *Condition) TypeID() *ua.NodeID
func (c *Condition) Source() *ua.NodeID
func (c *Condition) State() ConditionState // snapshot
func (c *Condition) Update(u ConditionUpdate) error // nil fields unchanged; reports an event
func (c *Condition) Report() error
func (c *Condition) SetActive(active bool) error
func (c *Condition) SetSeverity(severity uint16) error
func (c *Condition) SetMessage(msg string) error
func (c *Condition) SetQuality(q ua.StatusCode) error
func (c *Condition) SetRetain(retain bool) error
func (c *Condition) SetSuppressed(s bool) error
func (c *Condition) SetLimitState(l LimitState) error
func (c *Condition) SetNonExclusiveLimits(l NonExclusiveLimits) error
func (c *Condition) EvaluateLimits(v float64) error
func (c *Condition) Enable() error  // Bad_ConditionAlreadyEnabled
func (c *Condition) Disable() error // Bad_ConditionAlreadyDisabled

var ErrConditionRemoved, ErrConditionNotAlarm, ErrConditionUnsupport error
```

Event fields resolve by "/"-joined BrowsePath (`AckedState/Id`); a select
clause with an empty BrowsePath and AttributeId NodeId returns the
ConditionId. Not implemented: AudibleSound, OnDelay / OffDelay, ReAlarmTime,
FirstInGroup and the AlarmMetrics of Part 9 v1.05.

Client side (package `opcua`):

```go
func ConditionEventFields() []string
func NewConditionEventFilter() *ua.EventFilter
func ParseConditionEvent(ev *ua.EventFieldList) (*ConditionEvent, error)
func (e *ConditionEvent) IsRefreshStart() bool
func (e *ConditionEvent) IsRefreshEnd() bool

func (c *Client) Acknowledge(ctx context.Context, conditionID *ua.NodeID, eventID []byte, comment string) error
func (c *Client) Confirm(ctx context.Context, conditionID *ua.NodeID, eventID []byte, comment string) error
func (c *Client) AddComment(ctx context.Context, conditionID *ua.NodeID, eventID []byte, comment string) error
func (c *Client) EnableCondition(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) DisableCondition(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) TimedShelve(ctx context.Context, conditionID *ua.NodeID, d time.Duration) error
func (c *Client) OneShotShelve(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) Unshelve(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) ConditionRefresh(ctx context.Context, subscriptionID uint32) error
func (c *Client) ConditionRefresh2(ctx context.Context, subscriptionID, monitoredItemID uint32) error
func (s *Subscription) ConditionRefresh(ctx context.Context) error
func (s *Subscription) ConditionRefresh2(ctx context.Context, monitoredItemID uint32) error
func (e *ConditionEvent) IsBranch() bool

// Part 9 v1.05: the *2 variants take a Comment
func (c *Client) Suppress(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) Suppress2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) Unsuppress(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) Unsuppress2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) RemoveFromService(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) RemoveFromService2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) PlaceInService(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) PlaceInService2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) Silence(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) Reset(ctx context.Context, conditionID *ua.NodeID) error
func (c *Client) Reset2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) TimedShelve2(ctx context.Context, conditionID *ua.NodeID, d time.Duration, comment string) error
func (c *Client) OneShotShelve2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) Unshelve2(ctx context.Context, conditionID *ua.NodeID, comment string) error
func (c *Client) Respond(ctx context.Context, conditionID *ua.NodeID, selectedResponse int32) error
func (c *Client) Respond2(ctx context.Context, conditionID *ua.NodeID, selectedResponse int32, comment string) error
func (c *Client) GetGroupMemberships(ctx context.Context, conditionID *ua.NodeID) ([]*ua.NodeID, error)

// audit events
func NewAuditConditionEventFilter() *ua.EventFilter
func ParseAuditConditionEvent(ev *ua.EventFieldList) (*AuditConditionEvent, error)
func WithAuditEntryID(ctx context.Context, auditEntryID string) context.Context

// package ua
func (b *EventFilterBuilder) SelectPaths(paths ...string) *EventFilterBuilder
func (b *EventFilterBuilder) SelectConditionID() *EventFilterBuilder
func FieldPath(path string) *FieldOperand
```

A refused method call returns its StatusCode as the error. Guide:
[client-guide.md](docs/client-guide.md#alarms-and-conditions).

---

### Registered Custom DataTypes

Go types can be encoded as OPC UA `ExtensionObject` values and round-tripped through the
server without any NodeSet2 XML. Register a Go type once (typically in `init()`) with:

```go
ua.RegisterExtensionObject(dataTypeNodeID, new(MyStruct))
```

After registration the codec automatically encodes/decodes `*MyStruct` values inside any
`ExtensionObject`, including Variable read/write and method in/out arguments.

**Fixture package** – `internal/testutil/customtypes` provides four fixture types:

| Type | Description |
|---|---|
| `MyEnum` | `int32` enumeration (Off/Idle/Running) |
| `FlatStruct` | Flat structure with float32, int32, and string scalar fields |
| `ArrayStruct` | Structure with a `Name` string and `Values []int32` array field |
| `NestedStruct` | Structure embedding a `FlatStruct` with an additional `bool` field |

All four are registered in `init()` against DataType NodeIDs in namespace 2 (IDs 3001-3004).

**Server nodes** – `customtypes.AddNodes(ns, parent)` adds one writable Variable node per
type under `parent` and returns a `map[string]*ua.NodeID`. `customtypes.AddMethodNode(srv,
ns, parent)` adds a `ProcessFlat` method that accepts a `FlatStruct` argument and returns
an `ArrayStruct`, exercising the codec through the method call path.

**Tests** – `conformance/customtypes_test.go` (Go↔Go, no peer adapter) verifies:
- Read of each custom type decodes to the correct Go struct value.
- Write of a `FlatStruct` round-trips through the server and reads back correctly.
- Method call with `FlatStruct` input returns the expected `ArrayStruct` output.

**Dynamic structure decoding** – not implemented (deferred). Unknown `ExtensionObject`
bodies are preserved opaquely and passed through as raw bytes.

---

### HistoryProvider

Baseline server-facing HistoryRead surface. Optional capabilities are discovered
via type assertion on the same value; missing interfaces return
`BadHistoryOperationUnsupported` from the History services.

```go
type HistoryProvider interface {
    ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
    ReleaseContinuation(continuationPoint []byte)
}

type HistoryDataUpdater interface {
    UpdateData(nodeID *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult
}

type RawHistoryDeleter interface {
    DeleteRawModified(nodeID *ua.NodeID, isDeleteModified bool, startTime, endTime time.Time) *ua.HistoryUpdateResult
}

type AtTimeHistoryDeleter interface {
    DeleteAtTime(nodeID *ua.NodeID, reqTimes []time.Time) *ua.HistoryUpdateResult
}

// Default *Historian: for each requested time, return the nearest previous
// sample (or exact match); otherwise a DataValue with StatusBadNoData.
type AtTimeHistoryReader interface {
    ReadAtTime(nodeID *ua.NodeID, reqTimes []time.Time, useSimpleBounds bool) (*ua.HistoryReadResult, error)
}

type ModifiedHistoryReader interface {
    ReadModified(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, continuationPoint []byte) (*ua.HistoryReadResult, error)
}

type ProcessedHistoryReader interface {
    ReadProcessed(nodeID *ua.NodeID, startTime, endTime time.Time, processingInterval float64, aggregateType *ua.NodeID, aggregateConfiguration *ua.AggregateConfiguration) (*ua.HistoryReadResult, error)
}

type Historian struct { /* in-memory implementation */ }

func NewHistorian() *Historian
func (h *Historian) EnableNode(nodeID *ua.NodeID, maxSamples int)
func (h *Historian) RecordValue(nodeID *ua.NodeID, dv *ua.DataValue)
func (h *Historian) IsEnabled(nodeID *ua.NodeID) bool

// *Historian implements HistoryProvider plus all optional interfaces above:
func (h *Historian) ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
func (h *Historian) ReleaseContinuation(continuationPoint []byte)
func (h *Historian) UpdateData(nodeID *ua.NodeID, perform ua.PerformUpdateType, values []*ua.DataValue) *ua.HistoryUpdateResult
func (h *Historian) DeleteRawModified(nodeID *ua.NodeID, isDeleteModified bool, startTime, endTime time.Time) *ua.HistoryUpdateResult
func (h *Historian) DeleteAtTime(nodeID *ua.NodeID, reqTimes []time.Time) *ua.HistoryUpdateResult
func (h *Historian) ReadAtTime(nodeID *ua.NodeID, reqTimes []time.Time, useSimpleBounds bool) (*ua.HistoryReadResult, error)
func (h *Historian) ReadModified(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, continuationPoint []byte) (*ua.HistoryReadResult, error)
func (h *Historian) ReadProcessed(nodeID *ua.NodeID, startTime, endTime time.Time, processingInterval float64, aggregateType *ua.NodeID, aggregateConfiguration *ua.AggregateConfiguration) (*ua.HistoryReadResult, error)

func (s *Server) SetHistorian(h HistoryProvider)
```

Default `*Historian` is process-lifetime only with a per-node ring buffer
(default 1000 samples when `maxSamples <= 0`). Continuations are session-bound
opaque ByteStrings owned by the server (expire after 30s; max 100 active).

Supported by default `*Historian`:
- UpdateData Insert / Replace / Update semantics
- DeleteRawModified with `isDeleteModified=false`; `true` → `BadHistoryOperationUnsupported`
- DeleteAtTime
- ReadAtTime (nearest previous)
- ReadModified
- ReadProcessed aggregates Average / Minimum / Maximum / Count

Limitations:
- `returnBounds` is accepted and stored on continuation points, but interpolated /
  bounding values are not implemented for raw reads
- Without `SetHistorian`, HistoryRead returns unsupported / non-historized results

Peer HistoryRead raw interoperability: all four directions verified
(`history.read.raw`) against opcua-interop v0.6.0; continuation points verified
open62541→Go and Milo→Go. Go↔Go covered.

---

### ServerMetrics

```go
type ServerMetrics interface {
    OnRequest(service string)
    OnResponse(service string, duration time.Duration)
    OnError(service string, duration time.Duration, err error)
}
```

---

## Package `pubsub`

OPC UA PubSub (Part 14). The guide is [docs/pubsub.md](docs/pubsub.md); the
configuration is the generated `ua.PubSubConfigurationDataType` model.

### Runtime

```go
func New(cfg *ua.PubSubConfigurationDataType, opts ...Option) (*PubSub, error)
func (p *PubSub) Start(ctx context.Context) error
func (p *PubSub) Close() error
func (p *PubSub) Running() bool

// Components: connections, groups, writers, readers, published data sets.
func (p *PubSub) AddPublishedDataSet(cfg *ua.PublishedDataSetDataType) (ComponentID, error)
func (p *PubSub) AddConnection(cfg *ua.PubSubConnectionDataType) (ComponentID, error)
func (p *PubSub) AddWriterGroup(conn ComponentID, cfg *ua.WriterGroupDataType) (ComponentID, error)
func (p *PubSub) AddReaderGroup(conn ComponentID, cfg *ua.ReaderGroupDataType) (ComponentID, error)
func (p *PubSub) AddDataSetWriter(group ComponentID, cfg *ua.DataSetWriterDataType) (ComponentID, error)
func (p *PubSub) AddDataSetReader(group ComponentID, cfg *ua.DataSetReaderDataType) (ComponentID, error)
// Remove*, Enable, Disable, State, Status, Components, Component, Lookup,
// Configuration, SetKeySource, KeySource.

// Part 14 §9.1.11 diagnostics objects: counters, totals, SubError, LiveValues.
func (p *PubSub) Diagnostics(id ComponentID) (Diagnostics, error)
func (p *PubSub) ResetDiagnostics(id ComponentID) error
func (p *PubSub) SetDiagnosticsLevel(id ComponentID, l ua.DiagnosticsLevel) error
```

Options: `WithDataSource`, `WithEventSource`, `WithDataSetHandler`,
`WithTargetWriter`, `WithEventHandler`, `WithKeySource`,
`WithKeySourceLookup`, `WithTransportConfig`, `WithRetryInterval`,
`WithDiagnosticsLevel`, `WithLogger`.

Builders: `NewConfiguration`, `UDPConnection`, `EthernetConnection`,
`MQTTConnection` (`MappingUADP`, `MappingJSON`), `AttachWriterGroups`, `AttachReaderGroups`, `WriterGroup`,
`JSONWriterGroup`, `Secure`, `DataSetWriter`, `SetWriterQueue`,
`PublishedDataItems` / `Var`, `MetaData` / `Field`, `DataSetMetaDataOf`,
`ReaderGroup`, `DataSetReader`, `SetReaderQueue`, `Target`,
`SetTargetVariables`, `SetMirror`, `PublisherIDVariant`; `Validate` checks a
configuration (`*ConfigError`), `NewMemoryDataSource` holds values to publish.

### Sub-packages

| Package | Main API |
|---------|----------|
| `pubsub/message` | `NetworkMessage`, `DataSetMessage`, `Field`, `PublisherID`, `MetaDataLookup` |
| `pubsub/uadp` | `Encode(nm, *EncodeOptions)`, `Decode(b, *DecodeOptions)`; errors `ErrFiltered`, `ErrMalformed`, `ErrUnsupported`, `ErrSecurityMode`, `ErrSecurityChecksFailed`, `ErrNoMetaData` |
| `pubsub/jsonmsg` | `Encode`, `Decode`, `DecodeAny`, `EncodeMetaData` / `DecodeMetaData`, `EncodeStatus` / `DecodeStatus`, `MessageType` |
| `pubsub/transport` | `Open(ctx, Config)`, `Connection`, `Register`; `udp` registers `opc.udp`, `eth` registers `opc.eth` (`ParseURL`, `Address`, `EtherType`, `MaxPayload`, `ErrNotSupported`, `Supported`), `mqtt` registers `mqtt` and `mqtts` |
| `pubsub/security` | `Aes128CTR()`, `Aes256CTR()`, `PolicyByURI`, `KeyRing`, `KeyRings`, `KeyService` (`AddSecurityGroup`, `GetSecurityKeys`, `KeySource`) |
| `pubsub/sks` | `GetSecurityKeys`, `SetSecurityKeys`, `Push`, `NewKeySource(ctx, Config)` |
| `pubsub/remote` | `New(*opcua.Client)`; `AddConnection`, `AddWriterGroup`, `AddReaderGroup`, `AddDataSetWriter`, `AddDataSetReader`, `AddPublishedDataItems`, `AddPublishedDataItemsTemplate`, `Remove*`, `Enable`, `Disable`, `State`, `Property`, `Connections`, `WriterGroups`, `ReaderGroups`, `DataSetWriters`, `DataSetReaders`, `PublishedDataSets` |

### Server integration

```go
func WithPubSub(cfg *ua.PubSubConfigurationDataType, opts ...pubsub.Option) Option
func WithPubSubAuthorizer(a PubSubAuthorizer) Option
func (s *Server) PubSub() *pubsub.PubSub
func (s *Server) PubSubNodeID(c pubsub.ComponentID) (*ua.NodeID, bool)
func (s *Server) PubSubComponentID(nodeID *ua.NodeID) (pubsub.ComponentID, bool)
func (s *Server) EnableSecurityKeyService(ks *security.KeyService, opts ...SKSOption) (*SecurityKeyService, error)
func (s *Server) EnableSecurityKeyPush(rings *security.KeyRings, opts ...SKSOption) error
func MethodCallerFromContext(ctx context.Context) (*MethodCaller, bool)
```

### Push certificate management (server)

```go
type PushManagement struct {
    TrustList                *ua.TrustListDataType // initial trust list of the DefaultApplicationGroup (nil: empty)
    HTTPSTrustList           *ua.TrustListDataType // DefaultHttpsGroup (TLS client certificates)
    UserTokenTrustList       *ua.TrustListDataType // DefaultUserTokenGroup (X.509 user tokens)
    HTTPSClientCertificates  HTTPSClientAuth       // Ignore (default), VerifyIfGiven, Require
    MaxTrustListSize         uint32                // 0: 1 MiB
    MaxRejectedCertificates  int                   // 0: 64
    ApplyImmediately         bool                  // no transactions: changes apply when their method returns
    Authorizer               PushAuthorizer        // nil: SecurityAdmin role (always SignAndEncrypt)
    Store                    CertificateStore      // nil: nothing is persisted; a CertificateGroupStore gets every group
    PFXPassword              func(ctx context.Context, certificateGroup, certificateType *ua.NodeID) (string, error)
    TrustListUpdateFrequency time.Duration         // UpdateFrequency; drives TrustListOutOfDate
    Alarms                   *CertificateAlarms    // CertificateExpired and TrustListOutOfDate alarms
}
type HTTPSClientAuth int // HTTPSClientCertificatesIgnore, …VerifyIfGiven, …Require
type CertificateAlarms struct {
    ExpirationLimit time.Duration // 0: 14 days
    CheckInterval   time.Duration // 0: 1 minute
}
const CertificateAlarmsNamespaceURI = "urn:otfabric:go-opcua:certificates"
type PushAuthorizer func(ctx context.Context, caller *MethodCaller, method string) ua.StatusCode
type CertificateStore interface {
    StoreTrustList(ctx context.Context, tl *ua.TrustListDataType) error
    StoreCertificate(ctx context.Context, certificateType *ua.NodeID, cert []byte, issuers [][]byte, key crypto.Signer) error
}
type CertificateGroupStore interface {
    CertificateStore
    StoreGroupTrustList(ctx context.Context, certificateGroup *ua.NodeID, tl *ua.TrustListDataType) error
    StoreGroupCertificate(ctx context.Context, certificateGroup, certificateType *ua.NodeID, cert []byte, issuers [][]byte, key crypto.Signer) error
}
func WithPushManagement(pm PushManagement) Option
func (s *Server) TrustList() *ua.TrustListDataType    // the trust list in effect (nil without push management)
func (s *Server) GroupTrustList(certificateGroup *ua.NodeID) *ua.TrustListDataType
func (s *Server) HTTPSCertificate() []byte            // the TLS certificate of opc.https / opc.wss
func (s *Server) RejectedCertificates() [][]byte      // the most recently rejected client certificates
```

See [docs/server-guide.md](docs/server-guide.md#certificate-management-push-model).

## Package `gds`

Certificate management clients of Part 12: the push model (§7.10) against
any server's ServerConfiguration object and the pull model (§6, §7.9)
against a Global Discovery Server.

```go
func New(c *opcua.Client) *Client                     // Client.TrustList: the TrustList object (default DefaultTrustList)
func (g *Client) ReadTrustList(ctx context.Context, masks ua.TrustListMasks) (*ua.TrustListDataType, error)
func (g *Client) WriteTrustList(ctx context.Context, tl *ua.TrustListDataType) (applyChangesRequired bool, err error)
func (g *Client) AddCertificate(ctx context.Context, cert []byte, trusted bool) error
func (g *Client) RemoveCertificate(ctx context.Context, thumbprint string, trusted bool) error
func (g *Client) CreateSigningRequest(ctx context.Context, req *SigningRequest) ([]byte, error)
func (g *Client) UpdateCertificate(ctx context.Context, u *CertificateUpdate) (applyChangesRequired bool, err error)
func (g *Client) GetRejectedList(ctx context.Context) ([][]byte, error)
func (g *Client) ApplyChanges(ctx context.Context) error
func (g *Client) CancelChanges(ctx context.Context) error
func (g *Client) Properties(ctx context.Context) (*Properties, error)
func (g *Client) WithTrustList(tl *ua.NodeID) *Client // another group's TrustList (HTTPSTrustList, UserTokenTrustList)
func (g *Client) GetCertificates(ctx context.Context, group *ua.NodeID) ([]*ua.NodeID, [][]byte, error)
func (g *Client) CreateSelfSignedCertificate(ctx context.Context, req *SelfSignedCertificate) ([]byte, error)
func (g *Client) ResetToServerDefaults(ctx context.Context) error
func (g *Client) TransactionDiagnostics(ctx context.Context) (*TransactionDiagnostics, error)
func Thumbprint(cert []byte) string                  // upper-case hex SHA-1, for RemoveCertificate
func EncodeTrustList(tl *ua.TrustListDataType) ([]byte, error)
func DecodeTrustList(b []byte) (*ua.TrustListDataType, error)
type Error struct{ Method string; Status ua.StatusCode } // errors.Is(err, ua.StatusBad…)
```

`SigningRequest{CertificateGroup, CertificateType, SubjectName, RegeneratePrivateKey, Nonce}`,
`CertificateUpdate{CertificateGroup, CertificateType, Certificate, IssuerCertificates, PrivateKeyFormat, PrivateKey}` (`PEM` or `PFX`, see `uapolicy.EncodePFX`),
`SelfSignedCertificate{CertificateGroup, CertificateType, SubjectName, DNSNames, IPAddresses, LifetimeInDays, KeySizeInBits}`,
`TransactionDiagnostics{StartTime, EndTime, Result, AffectedTrustLists, AffectedCertificateGroups, Errors}`;
NodeIds `ServerConfiguration`, `DefaultApplicationGroup`, `DefaultTrustList`, `DefaultHTTPSGroup`, `HTTPSTrustList`,
`DefaultUserTokenGroup`, `UserTokenTrustList`, `HTTPSCertificateType` and the
`…ApplicationCertificateType` variables. See [docs/client-guide.md](docs/client-guide.md#certificate-management-gds-push).

Pull model:

```go
func NewPullClient(c *opcua.Client) *PullClient
func (p *PullClient) Namespace(ctx) (uint16, error)              // the GDS namespace index
func (p *PullClient) DefaultApplicationGroup(ctx) (*ua.NodeID, error)
func (p *PullClient) FindApplications(ctx, applicationURI string) ([]*ApplicationRecord, error)
func (p *PullClient) RegisterApplication(ctx, r *ApplicationRecord) (*ua.NodeID, error)
func (p *PullClient) UpdateApplication(ctx, r *ApplicationRecord) error
func (p *PullClient) UnregisterApplication(ctx, applicationID *ua.NodeID) error
func (p *PullClient) GetApplication(ctx, applicationID *ua.NodeID) (*ApplicationRecord, error)
func (p *PullClient) QueryApplications(ctx, q *ApplicationQuery) (*ApplicationQueryResult, error)
func (p *PullClient) QueryServers(ctx, q *ServerQuery) (*ServerQueryResult, error)
func (p *PullClient) StartSigningRequest(ctx, applicationID, group, certificateType *ua.NodeID, csr []byte) (*ua.NodeID, error)
func (p *PullClient) StartNewKeyPairRequest(ctx, applicationID *ua.NodeID, r *NewKeyPairRequest) (*ua.NodeID, error)
func (p *PullClient) FinishRequest(ctx, applicationID, requestID *ua.NodeID) (*IssuedCertificate, error) // Bad_NothingToDo while pending
func (p *PullClient) WaitForCertificate(ctx, applicationID, requestID *ua.NodeID, interval time.Duration) (*IssuedCertificate, error)
func (p *PullClient) RevokeCertificate(ctx, applicationID *ua.NodeID, cert []byte) error
func (p *PullClient) GetCertificateGroups / GetCertificates / GetTrustList / ReadTrustList / GetCertificateStatus / CheckRevocationStatus
func (p *PullClient) Enroll(ctx, r *EnrollRequest) (*Enrollment, error)
func (e *Enrollment) ClientOptions() ([]opcua.Option, error)
func (e *Enrollment) ServerOptions() []server.Option
func NewCertificateRequest(key crypto.Signer, applicationURI, subject string, hosts []string) ([]byte, error)
```

See [docs/client-guide.md](docs/client-guide.md#certificate-management-gds-pull).

## Package `gds/gdsserver`

Global Discovery Server of the pull model (Part 12 §6, §7.9).

```go
func Attach(srv *server.Server, cfg Config) (*GDS, error)       // before srv.Start
func (g *GDS) Close()                                           // later calls: Bad_Shutdown
func (g *GDS) Namespace() uint16
func (g *GDS) DiscoveryAdminRole() / CertificateAuthorityAdminRole() *ua.NodeID
func (g *GDS) DefaultApplicationGroup() *ua.NodeID
func (g *GDS) Requests() []*PendingRequest
func (g *GDS) ApproveRequest(ctx context.Context, requestID string, approve bool) error // ErrUnknownRequest, ErrClosed
func (g *GDS) RequestID(n *ua.NodeID) string
func (g *GDS) IssuerCertificates() [][]byte
func (g *GDS) TrustList() *ua.TrustListDataType
type Store interface{ ... }                                      // NewMemoryStore
```

`Config{Store, CertificateTypes, Issuers, CAName, CALifetime, CertificateLifetime, CRLLifetime, RSAKeySize, AutoApprove, RequestLifetime, MaxRequests, MaxApplications, SelfAdmin, Now, Logger}`.
See [docs/server-guide.md](docs/server-guide.md#global-discovery-server-pull-model).

## Package `monitor`

High-level subscription management with callback and channel APIs.

### NodeMonitor

```go
func NewNodeMonitor(client *opcua.Client) (*NodeMonitor, error)
```

```go
func (m *NodeMonitor) SetErrorHandler(cb ErrHandler)
func (m *NodeMonitor) Subscribe(ctx context.Context, params *opcua.SubscriptionParameters, cb MsgHandler, nodes ...string) (*Subscription, error)
func (m *NodeMonitor) ChanSubscribe(ctx context.Context, params *opcua.SubscriptionParameters, ch chan<- *DataChangeMessage, nodes ...string) (*Subscription, error)
```

### Subscription (monitor)

```go
func (s *Subscription) Unsubscribe(ctx context.Context) error
func (s *Subscription) Subscribed() int
func (s *Subscription) SubscriptionID() uint32
func (s *Subscription) AddNodes(ctx context.Context, nodes ...string) error
func (s *Subscription) AddNodeIDs(ctx context.Context, nodes ...*ua.NodeID) error
func (s *Subscription) AddMonitorItems(ctx context.Context, nodes ...Request) ([]Item, error)
func (s *Subscription) RemoveNodes(ctx context.Context, nodes ...string) error
func (s *Subscription) RemoveNodeIDs(ctx context.Context, nodes ...*ua.NodeID) error
func (s *Subscription) RemoveMonitorItems(ctx context.Context, items ...Item) error
func (s *Subscription) Modify(ctx context.Context, params *opcua.SubscriptionParameters) error
func (s *Subscription) ModifyMonitorItems(ctx context.Context, nodes ...Request) error
func (s *Subscription) SetMonitoringMode(ctx context.Context, monitoringMode ua.MonitoringMode, items ...Item) error
func (s *Subscription) SetMonitoringModeForNodes(ctx context.Context, monitoringMode ua.MonitoringMode, nodes ...string) error
func (s *Subscription) SetMonitoringModeForNodeIDs(ctx context.Context, monitoringMode ua.MonitoringMode, nodes ...*ua.NodeID) error
func (s *Subscription) Stats(ctx context.Context) (*ua.SubscriptionDiagnosticsDataType, error)
func (s *Subscription) Delivered() uint64
func (s *Subscription) Dropped() uint64
```

`AddMonitorItems` succeeds for valid nodes in a batch even when some items are rejected. Per-item failures are returned as `*ItemError` values joined into the error (recover with `errors.As`). `errors.Is(err, ua.StatusBad…)` works via `ItemError.Unwrap`.

Zero-value `Request.MonitoringMode` (`MonitoringModeDisabled` = 0) means **use default Reporting** — it does not create a Disabled item. Call `SetMonitoringMode` after create to disable sampling/reporting.

`RemoveNodes` removes by string node ID; `RemoveNodeIDs` by `*ua.NodeID`; `RemoveMonitorItems` by `Item` handle (as returned by `AddMonitorItems`).

```go
type ItemError struct {
    NodeID     *ua.NodeID
    StatusCode ua.StatusCode
}
func (e *ItemError) Error() string
func (e *ItemError) Unwrap() error
```

### Request and Item

```go
// Request describes a node to monitor or modify.
type Request struct {
    NodeID               *ua.NodeID
    MonitoringMode       ua.MonitoringMode // zero = Reporting default
    MonitoringParameters *ua.MonitoringParameters
}

// Item is a handle to an active monitored item returned by AddMonitorItems.
type Item struct{ /* opaque */ }
func (m *Item) ID() uint32       // server-assigned MonitoredItemID
func (m *Item) NodeID() *ua.NodeID
```

### DataChangeMessage

```go
type DataChangeMessage struct {
    *ua.DataValue
    Error  error
    NodeID *ua.NodeID
}
```

### Types

```go
// ErrHandler is called when a transport or subscription error occurs.
type ErrHandler func(c *opcua.Client, sub *Subscription, err error)

// MsgHandler is called for each incoming data-change notification.
type MsgHandler func(sub *Subscription, msg *DataChangeMessage)
```

`DefaultCallbackBufferLen` controls the internal channel buffer size for `ChanSubscribe`:

```go
var DefaultCallbackBufferLen = 8192
```

---

## Package `errors`

### Sentinel errors

Grouped by category:

**Connection**

```go
var (
    ErrAlreadyConnected    = errors.New("opcua: already connected")
    ErrNotConnected        = errors.New("opcua: not connected")
    ErrSecureChannelClosed = errors.New("opcua: secure channel closed")
    ErrSessionClosed       = errors.New("opcua: session closed")
    ErrSessionNotActivated = errors.New("opcua: session not activated")
    ErrReconnectAborted    = errors.New("opcua: reconnect aborted")
)
```

**Configuration**

```go
var (
    ErrInvalidEndpoint    = errors.New("opcua: invalid endpoint")
    ErrNoCertificate      = errors.New("opcua: no certificate")
    ErrInvalidPrivateKey  = errors.New("opcua: invalid private key")
    ErrInvalidCertificate = errors.New("opcua: invalid certificate")
    ErrNoMatchingEndpoint = errors.New("opcua: no matching endpoint")
    ErrNoEndpoints        = errors.New("opcua: no endpoints available")
)
```

**Subscription**

```go
var (
    ErrSubscriptionNotFound  = errors.New("opcua: subscription not found")
    ErrMonitoredItemNotFound = errors.New("opcua: monitored item not found")
    ErrInvalidSubscriptionID = errors.New("opcua: invalid subscription ID")
    ErrSlowConsumer          = errors.New("opcua: slow consumer: messages may be dropped")
)
```

**Namespace**

```go
var (
    ErrNamespaceNotFound    = errors.New("opcua: namespace not found")
    ErrInvalidNamespaceType = errors.New("opcua: invalid namespace array type")
)
```

**Codec**

```go
var (
    ErrUnsupportedType = errors.New("opcua: unsupported type")
    ErrArrayTooLarge   = errors.New("opcua: array too large")
    ErrUnbalancedArray = errors.New("opcua: unbalanced multi-dimensional array")
)
```

**Response**

```go
var (
    ErrInvalidResponseType = errors.New("opcua: invalid response type")
    ErrEmptyResponse       = errors.New("opcua: empty response")
)
```

**Security**

```go
var (
    ErrUnsupportedSecurityPolicy = errors.New("opcua: unsupported security policy")
    ErrInvalidSecurityConfig     = errors.New("opcua: invalid security configuration")
    ErrSignatureValidationFailed = errors.New("opcua: signature validation failed")
    ErrInvalidCiphertext         = errors.New("opcua: invalid ciphertext")
    ErrInvalidPlaintext          = errors.New("opcua: invalid plaintext")
)
```

**Protocol**

```go
var (
    ErrInvalidMessageType = errors.New("opcua: invalid message type")
    ErrMessageTooLarge    = errors.New("opcua: message too large")
    ErrMessageTooSmall    = errors.New("opcua: message too small")
    ErrTooManyChunks      = errors.New("opcua: too many chunks")
    ErrInvalidState       = errors.New("opcua: invalid state")
    ErrDuplicateHandler   = errors.New("opcua: duplicate handler registration")
    ErrUnknownService     = errors.New("opcua: unknown service")

    // a ReverseHello was refused: unexpected ServerUri or EndpointUrl, or a
    // ServerUri that is not the ApplicationUri of the server certificate
    ErrReverseHelloRejected = errors.New("opcua: reverse hello rejected")
)
```

**Node ID**

```go
var (
    ErrInvalidNodeID         = errors.New("opcua: invalid node ID")
    ErrInvalidNamespace      = errors.New("opcua: invalid namespace")
    ErrTypeAlreadyRegistered = errors.New("opcua: type already registered")
)
```

### Utility functions

```go
func Is(err error, target error) bool
func As(err error, target any) bool
func Unwrap(err error) error
func Join(errs ...error) error
```

---

## Package `uacp`

OPC-UA Connection Protocol over TCP (`opc.tcp`) and over a TLS WebSocket
(`opc.wss`, Part 6 §7.5: sub-protocol `opcua+uacp`, one MessageChunk per binary
frame).

### Endpoint parsing

```go
const DefaultDialTimeout = 10 * time.Second

func ParseEndpoint(endpoint string) (network string, u *url.URL, err error)
```

`ParseEndpoint` parses and validates an `opc.tcp://` URL without DNS lookup. The host must be present; an explicit port must be numeric. Hostname resolution is deferred to `net.Dialer` at dial time.

### Conn

`Conn` adds OPC-UA Connection Protocol framing to a TCP connection or a
WebSocket. The embedded `*net.TCPConn` is nil for an `opc.wss` connection; the
`net.Conn` methods of `Conn` work on either transport.

```go
type Conn struct { ... }

func NewConn(c *net.TCPConn, ack *Acknowledge) (*Conn, error)
```

#### `net.Conn` methods

```go
func (c *Conn) Read(b []byte) (int, error)
func (c *Conn) Write(b []byte) (int, error)
func (c *Conn) Close() error
func (c *Conn) LocalAddr() net.Addr
func (c *Conn) RemoteAddr() net.Addr
func (c *Conn) SetDeadline(t time.Time) error
func (c *Conn) SetReadDeadline(t time.Time) error
func (c *Conn) SetWriteDeadline(t time.Time) error
```

#### UACP methods

```go
func (c *Conn) ID() uint32
func (c *Conn) Version() uint32
func (c *Conn) ReceiveBufSize() uint32
func (c *Conn) SendBufSize() uint32
func (c *Conn) MaxMessageSize() uint32
func (c *Conn) MaxChunkCount() uint32
func (c *Conn) SetLogger(l *slog.Logger)
func (c *Conn) Handshake(ctx context.Context, endpoint string) error
func (c *Conn) AcceptHello(ctx context.Context, endpoint string) error
func (c *Conn) Receive() ([]byte, error)
func (c *Conn) Send(typ string, msg interface{}) error
func (c *Conn) SendError(code ua.StatusCode)
```

### Dialer

```go
type Dialer struct {
    Dialer    *net.Dialer
    ClientACK *Acknowledge
    Logger    *slog.Logger
}

func (d *Dialer) Dial(ctx context.Context, endpoint string) (*Conn, error)
```

`Dial` performs TCP connect, OPC UA HEL/ACK handshake, and returns a UACP `*Conn`. For TCP-only reachability (e.g. ping or diagnostics without HEL/ACK), use `DialTCP`.

`Dialer.TLSConfig` (`*tls.Config`) is the TLS configuration of `opc.wss` endpoints: `Dial` then connects over TLS (1.2 minimum), upgrades to a WebSocket with the `opcua+uacp` sub-protocol and runs HEL/ACK over it, all within the dial timeout.

```go
const SchemeWebSocket = "opc.wss"
const WebSocketSubprotocol = "opcua+uacp"

func IsWebSocketEndpoint(endpoint string) bool
func ParseWebSocketEndpoint(endpoint string) (*url.URL, error)
func ListenWebSocket(ctx context.Context, endpoint string, tlsConfig *tls.Config, ack *Acknowledge) (*Listener, error)
```

`ListenWebSocket` returns a `Listener` whose `Accept` yields connections that completed TLS, the WebSocket upgrade and HEL/ACK.

```go
func Dial(ctx context.Context, endpoint string) (*Conn, error)
func DialWithTimeout(ctx context.Context, endpoint string, timeout time.Duration) (*Conn, error)
func DialTCP(ctx context.Context, endpoint string) (net.Conn, error)
func DialTCPWithTimeout(ctx context.Context, endpoint string, timeout time.Duration) (net.Conn, error)
```

`Dial` and `DialTCP` use `DefaultDialTimeout`. `DialWithTimeout` / `DialTCPWithTimeout` accept an explicit timeout; zero means no dial timeout (only any deadline on `ctx`).

### Listener

```go
func Listen(ctx context.Context, endpoint string, ack *Acknowledge) (*Listener, error)
```

```go
func (l *Listener) Accept(ctx context.Context) (*Conn, error)
func (l *Listener) Close() error
func (l *Listener) Addr() net.Addr
func (l *Listener) Endpoint() string
```

A `Listener` answers a ReverseHello message with `BadTcpMessageTypeInvalid`: a
server never receives one.

### Reverse connect (transport)

Reverse connect (Part 6 §7.1.3) swaps the TCP roles: the server dials, the
client listens. Applications normally use `server.WithReverseConnect` and
`opcua.ReverseConnect`; these are the building blocks.

Server side:

```go
type ReverseDialer struct {
    Dialer *net.Dialer  // default: DefaultDialTimeout
    ACK    *Acknowledge // default: DefaultServerACK
    Logger *slog.Logger
}

func (d *ReverseDialer) Dial(ctx context.Context, clientURL string, rhe *ReverseHello) (*Conn, error)
func (c *Conn) AcceptHello(ctx context.Context, endpoint string) error
```

`Dial` connects to the client and sends the ReverseHello message.
`AcceptHello` then waits, until `ctx` is done, for the client's Hello, checks
its endpoint URL and answers with Acknowledge.

Client side:

```go
type ReverseListenerConfig struct {
    Filter        func(*ReverseHello) error // admit or refuse a server; nil admits all
    HelloTimeout  time.Duration             // default DefaultReverseHelloTimeout (10 s)
    MaxHandshakes int                       // default DefaultMaxReverseHandshakes (16)
    MaxPending    int                       // default DefaultMaxPendingReverse (16)
    Logger        *slog.Logger
}

func ListenReverse(ctx context.Context, addr string, cfg *ReverseListenerConfig) (*ReverseListener, error)
func NewReverseListener(l net.Listener, cfg *ReverseListenerConfig) *ReverseListener

func (l *ReverseListener) Accept(ctx context.Context, match func(*ReverseHello) error) (*net.TCPConn, *ReverseHello, error)
func (l *ReverseListener) Pending() int
func (l *ReverseListener) Addr() net.Addr
func (l *ReverseListener) Close() error

func (d *Dialer) AcceptReverse(ctx context.Context, l *ReverseListener, endpoint string, match func(*ReverseHello) error) (*Conn, *ReverseHello, error)
```

- `ListenReverse` takes `"host:port"` or `"opc.tcp://host:port"`;
  `NewReverseListener` wraps a TCP listener of the caller.
- The listener reads one ReverseHello per connection, of at most 8208 bytes
  (`MaxReverseHelloURILength` = 4096 per string), within `HelloTimeout`.
  Anything else is answered with an Error message and closed.
- `Accept` returns the most recent pending connection whose ReverseHello
  satisfies `match` (nil: any), or waits for one. Connections nobody waits for
  stay pending, up to `MaxPending`; a newer connection of the same server
  replaces the older, and a pending connection the server closes is dropped.
- `AcceptReverse` is the reverse-connect counterpart of `Dial`: `Accept` plus
  the HEL/ACK handshake, bounded by the dial timeout. The Hello names the
  announced EndpointUrl (`endpoint` if the server announced none).

---

## Package `uapolicy`

OPC-UA security policy implementations.

```go
func SupportedPolicies() []string
```

Returns all supported security policy URIs:
- `http://opcfoundation.org/UA/SecurityPolicy#None`
- `http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15`
- `http://opcfoundation.org/UA/SecurityPolicy#Basic256`
- `http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256`
- `http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep`
- `http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_ChaChaPoly`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP256r1`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_brainpoolP384r1`
- `http://opcfoundation.org/UA/SecurityPolicy#ECC_curve448`

The `ua` package has a constant for each (`ua.SecurityPolicyURIECCNistP256AesGcm`, `ua.SecurityPolicyURIECCNistP256ChaChaPoly`, `ua.SecurityPolicyURIECCCurve25519`, `ua.SecurityPolicyURIECCBrainpoolP256r1`, `ua.SecurityPolicyURIECCBrainpoolP384r1`, `ua.SecurityPolicyURIECCCurve448`, ...) and the short names `ECCNistP256AesGcm`, `ECCNistP256ChaChaPoly`, `ECCCurve25519`, `ECCBrainpoolP256r1`, `ECCBrainpoolP384r1` and `ECCCurve448` in `ua.SecurityPolicyURIs`; the spelling of the specification (`ECC_nistP256_AesGcm`, ...) works everywhere a policy is named.

```go
func SecurityLevel(policy string, mode ua.MessageSecurityMode) uint8
func IsSupported(uri string) bool // the policy is implemented (one of SupportedPolicies)
func IsECC(uri string) bool
func IsAEAD(uri string) bool                    // authenticated encryption: the four policies of OPC UA 1.05.07
func SecureChannelEnhancements(uri string) bool // ChannelThumbprint, key chaining, channel bound signatures
func LegacySequenceNumbers(uri string) bool

// Algorithms
func Asymmetric(uri string, localKey *rsa.PrivateKey, remoteKey *rsa.PublicKey) (*EncryptionAlgorithm, error)
func AsymmetricKeys(uri string, localKey crypto.PrivateKey, remoteKey crypto.PublicKey) (*EncryptionAlgorithm, error)
func Symmetric(uri string, localNonce, remoteNonce []byte) (*EncryptionAlgorithm, error) // RSA policies
func (e *EncryptionAlgorithm) SignOnly() bool

// Authenticated encryption (AES-GCM, ChaCha20-Poly1305): one call secures a chunk
func (e *EncryptionAlgorithm) AEAD() bool
func (e *EncryptionAlgorithm) SealChunk(chunk []byte, headerLength int, tokenID, lastSequenceNumber uint32, encrypt bool) ([]byte, error)
func (e *EncryptionAlgorithm) OpenChunk(chunk []byte, headerLength int, tokenID, lastSequenceNumber uint32, encrypted bool) ([]byte, error)

// Key negotiation of one OpenSecureChannel exchange, for every policy
type Role int // RoleClient, RoleServer
func NewKeyExchange(uri string, role Role) (*KeyExchange, error)
func (k *KeyExchange) Nonce() []byte
func (k *KeyExchange) Symmetric(remoteNonce []byte) (*EncryptionAlgorithm, error)
func (k *KeyExchange) SymmetricChained(remoteNonce, chain []byte) (algo *EncryptionAlgorithm, next []byte, err error)

// Certificates and keys
func CertificatePublicKey(cert []byte) (crypto.PublicKey, error)
func PublicKey(cert []byte) (*rsa.PublicKey, error)
func Thumbprint(cert []byte) []byte
func CheckCertificate(uri string, cert []byte) error
func CheckPublicKey(uri string, key crypto.PublicKey) error
func CertificateHash(uri string, cert []byte) ([]byte, error) // in channel bound signatures
func KeyMatchesCertificate(key crypto.Signer, cert []byte) bool
func ParsePrivateKey(data []byte) (crypto.Signer, error) // RSA, ECDSA (NIST, Brainpool), Ed25519, Ed448
func MarshalPrivateKey(key crypto.Signer) ([]byte, error) // PKCS #8, every key type

// Certificates crypto/x509 cannot handle: Brainpool keys, Ed448 keys and signatures
func ParseCertificate(der []byte) (*x509.Certificate, error)
func ParseCertificates(der []byte) ([]*x509.Certificate, error)
func CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) ([]byte, error)
func VerifyCertificate(certs []*x509.Certificate, roots *x509.CertPool, anchors []*x509.Certificate) error
func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, priv crypto.Signer) ([]byte, error)
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error)
func CheckCertificateRequestSignature(csr *x509.CertificateRequest) error
func CreateRevocationList(rand io.Reader, template *x509.RevocationList, issuer *x509.Certificate, priv crypto.Signer) ([]byte, error)
func ParseRevocationList(der []byte) (*x509.RevocationList, error)
func CheckRevocationListSignature(crl *x509.RevocationList, issuer *x509.Certificate) error

// PKCS #12 (PFX): PBES2 / PKCS #12 PBEs, HMAC or PBMAC1 integrity
func ParsePFX(data []byte, password string) (crypto.Signer, []*x509.Certificate, error) // ErrPFXPassword: wrong password
func EncodePFX(key crypto.Signer, certs [][]byte, password string) ([]byte, error)

// ECC: ephemeral keys and the EccEncryptedSecret of user identity tokens
func NewEphemeralKey(uri string) (*EphemeralKey, error)
func (k *EphemeralKey) PolicyURI() string
func (k *EphemeralKey) PublicKey() []byte
func (k *EphemeralKey) DecryptSecret(data []byte, signerKey func(certificate []byte) (crypto.PublicKey, error)) (*Secret, error)
func EncryptSecret(uri string, signingKey crypto.PrivateKey, signingCertificate, receiverPublicKey, nonce, secret []byte, signingTime time.Time) ([]byte, error)
```

`AsymmetricKeys` is the key-type independent form of `Asymmetric`: RSA policies take `*rsa.PrivateKey` / `*rsa.PublicKey`, the ECC policies a `crypto.Signer` with an ECDSA public key and an `*ecdsa.PublicKey`, `ECC_curve25519` a `crypto.Signer` with an `ed25519.PublicKey` and an `ed25519.PublicKey`, and `ECC_curve448` the same with `ed448.PublicKey` (`github.com/cloudflare/circl/sign/ed448`). The asymmetric algorithm of an ECC policy is `SignOnly`: OpenSecureChannel messages are signed, not encrypted. `ECDSA`, `EdDSA` and `Ed448` are the signature algorithms themselves.

`ParseCertificate` is `x509.ParseCertificate` that also takes certificates with a Brainpool key (returned as an `*ecdsa.PublicKey` on its curve) or an Ed448 key (an `ed448.PublicKey`); `ParseCertificates` likewise for a concatenation. `CreateCertificate` is `x509.CreateCertificate` for such keys, as subject or issuer key (the signature algorithm follows the issuer key; `template.SignatureAlgorithm` must be unset). `VerifyCertificate` verifies `certs[0]` with `certs[1:]` as intermediates: with `crypto/x509` against `roots`, or, when a certificate is signed with Ed448, with the library's own chain builder against `anchors` (see [Security](docs/security.md#brainpool-and-curve448) for the rules). The client and the server use these wherever they read a certificate.

A `KeyExchange` creates the nonce a side sends in OpenSecureChannel and, given the peer's nonce, the symmetric algorithm of the new SecurityToken. For RSA policies the nonce is random and the keys come from P_SHA; for ECC policies the nonce is an ephemeral public key and the keys come from HKDF over the ECDH shared secret. `Symmetric` alone cannot serve the ECC policies and returns an error for them.

The symmetric algorithm of `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` and `ECC_curve25519` is an AEAD cipher (`AEAD()` is true). It has no separate `Encrypt` and `Signature` (they fail); `SealChunk` and `OpenChunk` secure a whole message chunk: the header stays readable and is authenticated, the rest is encrypted in `SignAndEncrypt` mode, and a 16 byte tag is appended. The nonce is the derived IV masked with the TokenId and the sequence number of the previous chunk; `SealChunk` fails rather than use a nonce twice under a key, `OpenChunk` returns `ErrInvalidCiphertext` for anything that was modified, truncated, replayed or secured with other keys.

`SymmetricChained` is `Symmetric` for a channel with `SecureChannelEnhancements`: it takes the value the previous exchange on the channel returned (nil for the first one) and returns the one for the next renewal. The value is key material and must stay secret. For all other policies it is ignored and nil.

`CheckCertificate` reports whether a certificate's key can be used with a policy (RSA for the RSA policies; P-256 or P-384 for `ECC_nistP256`, `ECC_nistP256_AesGcm` and `ECC_nistP256_ChaChaPoly`; P-384 for `ECC_nistP384`; brainpoolP256r1 or brainpoolP384r1 for `ECC_brainpoolP256r1`; brainpoolP384r1 for `ECC_brainpoolP384r1`; Ed25519 for `ECC_curve25519`; Ed448 for `ECC_curve448`).

---

## Package `uasc`

Secure conversation layer.

### HTTPS (Part 6 §7.4)

`NewHTTPSChannel` returns a `SecureChannel` for an `opc.https://` (or `https://`)
endpoint. There is no secure conversation: every request is an HTTP/1.1 POST
of the UA Binary encoded message (`Content-Type: application/octet-stream`)
and the response is the body of its answer; TLS protects the messages. The
security policy of `cfg` only selects how the session nonces are signed and is
sent in the `OPCUA-SecurityPolicy` header. `Open` and `Renew` do nothing. A
lost connection is reported on `errCh` as an error wrapping `io.EOF`.

```go
const SchemeHTTPS = "opc.https"
const HTTPSContentType = "application/octet-stream"
const HTTPSContentTypeLegacy = "application/opcua+uabinary"
const HTTPSSecurityPolicyHeader = "OPCUA-SecurityPolicy"
const MaxHTTPSMessageSize = 16 << 20

func IsHTTPSEndpoint(endpoint string) bool
func HTTPSURL(endpoint string) (string, error)         // the https:// URL to post to
func HTTPSPolicySupported(policyURI string) bool        // None, or a policy without SecureChannelEnhancements
func NewHTTPSClient(tlsConfig *tls.Config) *http.Client // HTTP/1.1, TLS 1.2 minimum, no redirects
func EncodeServiceMessage(v any) ([]byte, error)        // TypeId + UA Binary body
```

### SecureChannel

```go
func NewSecureChannel(endpoint string, conn *uacp.Conn, cfg *Config, errCh chan<- error) (*SecureChannel, error)
func NewHTTPSChannel(endpoint string, httpClient *http.Client, cfg *Config, errCh chan<- error) (*SecureChannel, error)
func (s *SecureChannel) IsHTTPS() bool
func (s *SecureChannel) RemoteCertificate() []byte // DER certificate of the peer; nil without security
```

```go
func (s *SecureChannel) Open(ctx context.Context) error
func (s *SecureChannel) Close() error
func (s *SecureChannel) SendRequest(ctx context.Context, req ua.Request, authToken *ua.NodeID, handler ResponseHandler) error
func (s *SecureChannel) SendRequestWithTimeout(ctx context.Context, req ua.Request, authToken *ua.NodeID, timeout time.Duration, handler ResponseHandler) error
func (s *SecureChannel) VerifySessionSignature(serverCert []byte, nonce []byte, sig []byte) error
func (s *SecureChannel) NewSessionSignature(serverCert []byte, nonce []byte) (sig []byte, alg string, err error)
func (s *SecureChannel) NewUserTokenSignature(authPolicyURI string, serverCert []byte, serverNonce []byte) ([]byte, string, error)
func (s *SecureChannel) EncryptUserPassword(authPolicyURI string, password string, serverCert []byte, serverNonce []byte) ([]byte, string, error)

// ECC policies
func (s *SecureChannel) UserTokenPolicyIsECC(policyURI string) bool
func (s *SecureChannel) EncryptUserSecret(policyURI string, secret, serverEphemeralKey, nonce []byte) ([]byte, error)
func (s *SecureChannel) NewEphemeralKeySignature(policyURI string, publicKey []byte) ([]byte, error)
func (s *SecureChannel) VerifyEphemeralKeySignature(policyURI string, certificate, publicKey, signature []byte) error
func (s *SecureChannel) LocalCertificate() []byte
func (s *SecureChannel) RemoteCertificate() []byte
func DecryptUserSecret(key *uapolicy.EphemeralKey, data, signerCertificate, nonce []byte) ([]byte, error)

// Session signatures, channel bound where the policy has SecureChannelEnhancements
func (s *SecureChannel) ChannelThumbprint() []byte
func (s *SecureChannel) NewCreateSessionSignature(clientCertificate, clientNonce, serverNonce []byte) ([]byte, string, error)
func (s *SecureChannel) VerifyCreateSessionSignature(serverCertificate, clientNonce, serverNonce, signature []byte) error
func (s *SecureChannel) NewActivateSessionSignature(serverCertificate, serverNonce, clientNonce []byte) ([]byte, string, error)
func (s *SecureChannel) VerifyActivateSessionSignature(clientCertificate, serverNonce, clientNonce, signature []byte) error
func (s *SecureChannel) NewSessionUserTokenSignature(policyURI string, serverCertificate, serverNonce, clientNonce []byte) ([]byte, string, error)
func (s *SecureChannel) VerifySessionUserTokenSignature(policyURI string, userCertificate, serverCertificate, serverNonce, clientNonce, signature []byte) error

// Ephemeral key exchange in the AdditionalHeader of CreateSession / ActivateSession
func NewECDHPolicyHeader(policyURI string) *ua.ExtensionObject
func NewECDHKeyHeader(policyURI string, key *ua.EphemeralKeyType) *ua.ExtensionObject
func ECDHPolicyFromHeader(header *ua.ExtensionObject) (string, bool)
func ECDHKeyFromHeader(header *ua.ExtensionObject) (*ua.EphemeralKeyType, error)
```

With an ECC security policy the password of a user name token and the data of an issued token are protected with an `EccEncryptedSecret` (`EncryptUserSecret` / `DecryptUserSecret`) instead of `EncryptUserPassword`. The client asks for the server's ephemeral key with an `ECDHPolicyUri` entry in the request's `AdditionalHeader`; the server returns it, signed, as `ECDHKey`. `opcua.Client` and `server.Server` do all of this themselves.

`NewCreateSessionSignature`, `NewActivateSessionSignature` and `NewSessionUserTokenSignature` (with their `Verify` counterparts) create the signatures of CreateSession and ActivateSession for every policy. For the policies with `SecureChannelEnhancements` (`ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly`) the signed data is bound to the channel: `ChannelThumbprint | nonce | certificate hashes | nonce` (Part 4 §6.1.8), with the `ChannelThumbprint` being the signature of the first OpenSecureChannel response. For all other policies they are the classic `certificate | nonce` signatures of `NewSessionSignature`, `VerifySessionSignature` and `NewUserTokenSignature`, which remain for those policies.

### Config

```go
type Config struct {
    SecurityPolicyURI string
    SecurityMode      ua.MessageSecurityMode
    Certificate       []byte
    LocalKey          *rsa.PrivateKey   // RSA key of Certificate
    LocalPrivateKey   crypto.Signer     // key of Certificate, any type; takes precedence over LocalKey
    UserKey           *rsa.PrivateKey   // RSA key of the X.509 user certificate
    UserPrivateKey    crypto.Signer     // key of the X.509 user certificate, any type
    LocalIdentity     func(securityPolicyURI string) (certificate []byte, key crypto.Signer, err error) // server: certificate per policy
    RemoteCertificate []byte
    Lifetime          uint32          // milliseconds
    RequestTimeout    time.Duration
    RequestIDSeed     uint32
    AutoReconnect     bool
    ReconnectInterval time.Duration
    Logger            *slog.Logger
}
```

### SessionConfig

```go
type SessionConfig struct {
    SessionName        string
    SessionTimeout     time.Duration
    ClientDescription  *ua.ApplicationDescription
    LocaleIDs          []string
    UserIdentityToken  ua.UserIdentityToken
    AuthPolicyURI      string
    AuthPassword       string
    UserTokenSignature *ua.SignatureData
}
```

---

## Package `id`

Generated constants for all standard OPC-UA node IDs from the specification.

Contains ~14,600 constants organised by node class:
- Object IDs (e.g. `id.Server`, `id.ServerServerStatus`)
- Variable IDs (e.g. `id.ServerServerStatusCurrentTime`)
- ObjectType IDs (e.g. `id.BaseObjectType`, `id.FolderType`)
- VariableType IDs
- DataType IDs (e.g. `id.BaseDataType`, `id.Boolean`, `id.String`)
- ReferenceType IDs (e.g. `id.References`, `id.HasTypeDefinition`, `id.HasComponent`, `id.Organizes`, `id.HierarchicalReferences`)
- Method IDs

These constants are used as arguments to browse and read operations to refer
to well-known nodes in the address space.

```go
func ReferenceTypeName(id uint32) string
```

`ReferenceTypeName` returns the standard OPC UA name for a well-known reference type in namespace 0 (e.g. 47 → "HasComponent", 35 → "Organizes"), or "" if unknown. Use when displaying reference type NodeIDs (e.g. browse refs) to show names instead of raw NodeIDs. For a single call that accepts a NodeID and returns either the name or the NodeID string, use `ua.ReferenceTypeDisplayName`.

```go
func DataTypeName(id uint32) string
```

`DataTypeName` returns the standard OPC UA name for a well-known DataType in namespace 0 (e.g. 10 → "Float", 12 → "String", 294 → "UtcTime"), or "" if unknown. Use when displaying DataType NodeIDs to normalize type rendering. For a NodeID-based helper, use `ua.DataTypeDisplayName`.

```go
func NodeIDByName(name string) (uint32, bool)
```

`NodeIDByName` is the reverse of `Name`: it maps well-known standard node names (namespace 0 only) to numeric IDs. Names include full spec names (e.g. "Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime") and short aliases "CurrentTime" (→ 2258), "ServerStatus" (→ 2256), "Objects" (→ 85). Returns (0, false) if not found. For a `*ua.NodeID` use `ua.StandardNodeID`.

```go
func VariableTypeName(id uint32) string
func ObjectTypeName(id uint32) string
```

`VariableTypeName` returns the standard OPC UA name for a well-known VariableType in namespace 0 (e.g. 68 → "PropertyType", 63 → "BaseDataVariableType"), or "" if unknown. `ObjectTypeName` does the same for ObjectTypes (e.g. 58 → "BaseObjectType", 61 → "FolderType"). For a NodeID-based display helper use `ua.TypeDefinitionDisplayName`.

```go
func ObjectName(id uint32) string
func VariableName(id uint32) string
func MethodName(id uint32) string
```

`ObjectName` returns the standard name for a well-known Object node in namespace 0 (e.g. 84 → "RootFolder", 85 → "ObjectsFolder", 2253 → "Server"). `VariableName` does the same for Variable nodes (e.g. 2256 → "Server_ServerStatus", 2258 → "Server_ServerStatus_CurrentTime"). `MethodName` does the same for Method nodes (e.g. 11492 → "Server_GetMonitoredItems"). Each returns "" if the id is not in that category. The generic [Name](id package) function looks up across all categories.

```go
func AggregateType(name string) (uint32, bool)
```

`AggregateType` returns the numeric node ID for a well-known aggregate name (e.g. "Average" → 2342, "Count" → 2352). Returns (0, false) if the name is not found.
