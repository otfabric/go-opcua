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
- [Package `server`](#package-server)
  - [Server](#server)
  - [Server configuration options](#server-configuration-options)
  - [NameSpace (interface)](#namespace-interface)
  - [Node (server-side)](#node-server-side)
  - [AccessController](#accesscontroller)
  - [Authentication validators](#authentication-validators)
  - [EventEmitter](#eventemitter)
  - [Alarms & Conditions (deferred)](#alarms--conditions-deferred)
  - [Registered Custom DataTypes](#registered-custom-datatypes)
  - [HistoryProvider](#historyprovider)
  - [ServerMetrics](#servermetrics)
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
func (c *Client) FindServersOnNetwork(ctx context.Context) (*ua.FindServersOnNetworkResponse, error)
func (c *Client) GetEndpoints(ctx context.Context) (*ua.GetEndpointsResponse, error)
```

#### Subscriptions

```go
func (c *Client) Subscribe(ctx context.Context, params *SubscriptionParameters, notifyCh chan<- *PublishNotificationData) (*Subscription, error)
func (c *Client) SubscriptionIDs() []uint32
func (c *Client) SetPublishingMode(ctx context.Context, publishingEnabled bool, subscriptionIDs ...uint32) (*ua.SetPublishingModeResponse, error)
func (c *Client) Republish(ctx context.Context, subscriptionID, sequenceNumber uint32) (*ua.RepublishResponse, error)
func (c *Client) TransferSubscriptions(ctx context.Context, subscriptionIDs []uint32, sendInitialValues bool) (*ua.TransferSubscriptionsResponse, error)
func (c *Client) NewSubscription() *SubscriptionBuilder
```

`Republish` returns the protocol response without mutating subscription delivery state — callers must handle the returned notification themselves. Automatic reconnect recovery (when `AutoReconnect(true)`, the default) separately runs Transfer → Republish → Recreate and may dispatch recovered notifications through the normal subscription pipeline; see [Subscription recovery](#subscription-recovery).

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
block. It is invoked once per subscription after each recovery attempt.

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
```

---

### Logger

Logging uses `*slog.Logger` from the standard library. The default logger is `slog.Default()`.

```go
func WithLogger(l *slog.Logger) Option
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
| `PrivateKeyFile(filename string)` | Load private key from file |
| `AuthAnonymous()` | Use anonymous identity token (default) |
| `AuthUsername(user, pass string)` | Username/password identity token |
| `AuthCertificate(cert []byte)` | X.509 user certificate identity token (DER) |
| `AuthPrivateKey(key *rsa.PrivateKey)` | Private key for the X.509 user certificate |
| `AuthIssuedToken(tokenData []byte)` | Issued (e.g. JWT/SAML) identity token |
| `AuthPolicyID(policy string)` | Override the UserTokenPolicy ID used during ActivateSession |
| `DialTimeout(d time.Duration)` | TCP + HEL/ACK handshake timeout (default `DefaultDialTimeout`) |
| `Dialer(d *uacp.Dialer)` | Custom UACP dialer (e.g. to set `ClientACK` parameters) |
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
| `WithLogger(l *slog.Logger)` | Logger (`*slog.Logger`; defaults to `slog.Default()`) |
| `InsecureSkipVerify()` | Skip server certificate validation (INSECURE) |
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA/self-signed certs to the trust pool |

Server certificates may be presented as a **DER chain** (leaf followed by intermediates); validation parses the full chain and verifies the leaf against the trust pool.

### Helper

```go
func NewMonitoredItemCreateRequestWithDefaults(nodeID *ua.NodeID, attributeID ua.AttributeID, clientHandle uint32) *ua.MonitoredItemCreateRequest
```

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

#### Info

```go
func (s *Server) Endpoints() []*ua.EndpointDescription
func (s *Server) URLs() []string
func (s *Server) Status() *ua.ServerStatusDataType
func (s *Server) Node(nid *ua.NodeID) *Node
func (s *Server) ChangeNotification(n *ua.NodeID)
```

---

### Server configuration options

| Function | Description |
|----------|-------------|
| `EndPoint(host string, port int)` | Listen address |
| `ListenOn(addr string)` | Override the TCP bind address (e.g. `"0.0.0.0:4840"`) |
| `Certificate(cert []byte)` | Server certificate (DER) |
| `PrivateKey(key *rsa.PrivateKey)` | Server private key |
| `EnableSecurity(policy string, mode ua.MessageSecurityMode)` | Enable a security policy/mode combination (returns error for unsupported or duplicate) |
| `EnableAuthMode(tokenType ua.UserTokenType)` | Enable an authentication token type (returns error for duplicate) |
| `AllowUsernameOnNone()` | Advertise `UserName` token on unencrypted (`None/None`) endpoints — for test deployments only |
| `WithUsernameValidator(v UsernameValidator)` | Callback `func(username, password string) error` called during `ActivateSession` for `UserNameIdentityToken` |
| `WithX509UserValidator(v X509UserValidator)` | Callback `func(certDER []byte) error` called during `ActivateSession` for `X509IdentityToken`; must also call `EnableAuthMode(ua.UserTokenTypeCertificate)` |
| `WithClientCertificateTrustList(caCertDER ...[]byte)` | Verify the client application certificate (DER) at `OpenSecureChannel` (and again at `CreateSession`) against the provided CA pool; rejects untrusted certs with `BadCertificateUntrusted` |
| `ServerName(name string)` | Application name |
| `ManufacturerName(s string)` | Manufacturer name |
| `ProductName(s string)` | Product name |
| `SoftwareVersion(s string)` | Software version string |
| `SetLogger(l *slog.Logger)` | Logger (`*slog.Logger`; defaults to `slog.Default()`) |
| `WithMetrics(m ServerMetrics)` | Metrics handler |
| `WithAccessController(ac AccessController)` | Access controller |
| `WithRoleMapper(rm RoleMapper)` | Maps a session to a `ua.UserRole`; used by the default access controller |

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

Peer EventFilter / event-subscription interoperability: open62541→Go and
Milo→Go verified (`event.subscription`) against opcua-interop v0.5.0.
Go↔Go covered.

---

### Alarms & Conditions (deferred)

Full Alarms & Conditions (Part 9) state machines, Acknowledge/Confirm methods,
and alarm catalogs are not implemented. The library exposes the standard type
NodeId and an explicit capability probe so applications and coverage tooling
can treat A&C as optional / deferred:

```go
var AcknowledgeableConditionTypeNodeID = ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)

func AlarmsConditionsSupported() bool // always false in the current library
```

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

Peer HistoryRead raw interoperability: open62541→Go and Milo→Go verified
(`history.read.raw`). Go↔Go covered.

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

TCP transport layer (OPC-UA Connection Protocol).

### Endpoint parsing

```go
const DefaultDialTimeout = 10 * time.Second

func ParseEndpoint(endpoint string) (network string, u *url.URL, err error)
```

`ParseEndpoint` parses and validates an `opc.tcp://` URL without DNS lookup. The host must be present; an explicit port must be numeric. Hostname resolution is deferred to `net.Dialer` at dial time.

### Conn

`Conn` embeds `*net.TCPConn` and adds OPC-UA Connection Protocol framing.

```go
type Conn struct { ... }

func NewConn(c *net.TCPConn, ack *Acknowledge) (*Conn, error)
```

#### Inherited from `*net.TCPConn`

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
- `http://opcfoundation.org/UA/SecurityPolicy#Aes128Sha256RsaOaep`
- `http://opcfoundation.org/UA/SecurityPolicy#Aes256Sha256RsaPss`

---

## Package `uasc`

Secure conversation layer.

### SecureChannel

```go
func NewSecureChannel(endpoint string, conn *uacp.Conn, cfg *Config, errCh chan<- error) (*SecureChannel, error)
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
```

### Config

```go
type Config struct {
    SecurityPolicyURI string
    SecurityMode      ua.MessageSecurityMode
    Certificate       []byte
    LocalKey          *rsa.PrivateKey
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
