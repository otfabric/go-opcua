# API Reference

Complete reference for all public types, functions, and interfaces in `github.com/otfabric/opcua`.

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
func (c *Client) NewSubscription() *SubscriptionBuilder
```

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
func (n *Node) Browse(ctx context.Context, refs uint32, dir ua.BrowseDirection, mask ua.NodeClass, includeSubtypes bool) ([]*ua.ReferenceDescription, error)
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

`TranslateBrowsePathInNamespaceToNodeID` splits `browsePath` on "." and builds a path of [QualifiedName](https://pkg.go.dev/github.com/otfabric/opcua/ua#QualifiedName) segments in the given namespace. Use when the path starts from this node (e.g. custom root). For paths from the server's Objects folder, use `Client.NodeFromPath` or `Client.NodeFromPathInNamespace` instead.

#### Walk

```go
func (n *Node) Walk(ctx context.Context) iter.Seq2[WalkResult, error]
func (n *Node) WalkLimit(ctx context.Context, maxDepth int) iter.Seq2[WalkResult, error]
func (n *Node) WalkLimitDedup(ctx context.Context, maxDepth int) iter.Seq2[WalkResult, error]
```

`Walk` recursively descends through the node's hierarchical references with no depth limit. `WalkLimit` is like `Walk` but stops recursing when depth reaches `maxDepth`; the node at depth `maxDepth` is still yielded. If `maxDepth < 0`, depth is unlimited (same as `Walk`). Use `WalkLimit` for "find node", "find type", or "browse tree" style tools to avoid unbounded traversal (e.g. pass a `-depth` flag from the CLI). The same node may be yielded more than once if reachable via multiple paths; use `WalkLimitDedup` to yield each node at most once (deduplication by NodeID).

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
func (s *Subscription) Monitor(ctx context.Context, ts ua.TimestampsToReturn, items ...*ua.MonitoredItemCreateRequest) ([]*ua.MonitoredItemCreateResult, error)
func (s *Subscription) Unmonitor(ctx context.Context, ids ...uint32) ([]ua.StatusCode, error)
```

If the server closes the connection during CreateMonitoredItems (e.g. it does not support event or alarm subscriptions), the error may wrap `io.EOF` with a message suggesting that; use `errors.Is(err, io.EOF)` to detect it.

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

Example:

```go
sub, notifyCh, err := client.NewSubscription().
    Interval(500 * time.Millisecond).
    Monitor(ua.MustParseNodeID("ns=2;s=Temperature")).
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
func SelectEndpoint(endpoints []*ua.EndpointDescription, policy string, mode ua.MessageSecurityMode) (*ua.EndpointDescription, error)
```

---

### Logger

```go
type Logger = logger.Logger  // re-exported alias
```

See the `logger` package below.

```go
func WithLogger(l Logger) Option
```

---

### Configuration Options

All option functions return `Option` and are passed to `NewClient`:

| Function | Description |
|----------|-------------|
| `ApplicationName(s string)` | Application name in session |
| `ApplicationURI(s string)` | Application URI |
| `AutoReconnect(b bool)` | Enable/disable auto reconnect |
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
| `SessionName(s string)` | Session name |
| `SessionTimeout(d time.Duration)` | Session timeout |
| `SkipNamespaceUpdate()` | Skip automatic namespace table update on connect |
| `PrivateKey(key *rsa.PrivateKey)` | RSA private key |
| `PrivateKeyFile(filename string)` | Load private key from file |
| `WithConnStateHandler(f func(ConnState))` | Connection state callback |
| `WithConnStateChan(ch chan<- ConnState)` | Connection state channel |
| `WithMetrics(m ClientMetrics)` | Metrics handler |
| `WithRetryPolicy(p RetryPolicy)` | Retry policy |
| `WithLogger(l Logger)` | Logger |
| `InsecureSkipVerify()` | Skip server certificate validation (INSECURE) |
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA/self-signed certs to the trust pool |

### Helper

```go
func NewMonitoredItemCreateRequestWithDefaults(nodeID *ua.NodeID, attributeID ua.AttributeID, clientHandle uint32) *ua.MonitoredItemCreateRequest
func ReferenceTypeDisplayName(refTypeID *ua.NodeID) string
func DataTypeDisplayName(dataTypeID *ua.NodeID) string
func TypeDefinitionDisplayName(typeDefID *ua.NodeID) string
func StandardNodeID(name string) (*ua.NodeID, bool)
```

`TypeDefinitionDisplayName` returns a display string for a type definition NodeID (VariableType or ObjectType in namespace 0): tries VariableTypeName then ObjectTypeName (e.g. i=68 → "PropertyType", i=61 → "FolderType"); otherwise the NodeID string. Use when displaying type definition columns in browse. Returns the empty string if typeDefID is nil.

`StandardNodeID` returns the namespace-0 NodeID for a well-known standard node name (e.g. "CurrentTime" → i=2258, "ServerStatus" → i=2256, "Objects" → i=85). Use for CLI or config that accepts symbolic names like `-n CurrentTime` instead of `-n i=2258`. Uses [id.NodeIDByName](id package) under the hood. Returns (nil, false) if the name is not found.

`ReferenceTypeDisplayName` returns a display string for a reference type NodeID: the standard name (e.g. "HasComponent", "Organizes") for well-known types in namespace 0, otherwise the NodeID string. Use when displaying the reference type column in browse refs.

`DataTypeDisplayName` returns a display string for a DataType NodeID: the standard name (e.g. "Float", "String", "UtcTime") for well-known types in namespace 0, otherwise the NodeID string. Use when displaying DataType attributes or type columns to normalize type rendering.

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
func New(opts ...Option) *Server
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
| `Certificate(cert []byte)` | Server certificate (DER) |
| `PrivateKey(key *rsa.PrivateKey)` | Server private key |
| `EnableSecurity(policy string, mode ua.MessageSecurityMode)` | Enable a security policy/mode combination |
| `EnableAuthMode(tokenType ua.UserTokenType)` | Enable an authentication token type |
| `ApplicationName(s string)` | Application name |
| `ApplicationURI(s string)` | Application URI |
| `ManufacturerName(s string)` | Manufacturer name |
| `ProductName(s string)` | Product name |
| `SoftwareVersion(s string)` | Software version string |
| `WithLogger(l Logger)` | Logger |
| `WithMetrics(m ServerMetrics)` | Metrics handler |
| `WithAccessController(ac AccessController)` | Access controller |

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
func NodeNameSpace(uri string, generator NodeGenerator) NameSpace
func MapNamespace(uri string) *MapNamespace
```

`NodeNameSpace` provides a full OPC-UA node graph with references and type
definitions. `MapNamespace` provides a simple key-value store for IoT/sensor
data.

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

### EventEmitter

```go
type EventEmitter interface {
    EmitEvent(nodeID *ua.NodeID, fields *ua.EventFieldList) error
}

func (s *Server) EmitEvent(nodeID *ua.NodeID, fields *ua.EventFieldList) error
```

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
func (s *Subscription) AddNodes(ctx context.Context, nodes ...string) error
func (s *Subscription) RemoveNodes(ctx context.Context, nodeIDs ...*ua.NodeID) error
func (s *Subscription) RemoveNodeByHandle(handle uint32) error
func (s *Subscription) Delivered() uint64
func (s *Subscription) Dropped() uint64
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
type ErrHandler func(err error)
type MsgHandler func(msg *DataChangeMessage)
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

## Package `logger`

```go
type Logger interface {
    Debugf(format string, args ...any)
    Infof(format string, args ...any)
    Warnf(format string, args ...any)
    Errorf(format string, args ...any)
}
```

Built-in implementations:

```go
func Default() Logger                  // delegates to slog.Default()
func NewStdLogger(l *log.Logger) Logger
func NewSlogLogger(h slog.Handler) Logger
func NopLogger() Logger                // discards all output
```

---

## Package `uacp`

TCP transport layer (OPC-UA Connection Protocol).

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
func (c *Conn) SetLogger(l logger.Logger)
func (c *Conn) Handshake(ctx context.Context, endpoint string) error
func (c *Conn) Receive() ([]byte, error)
func (c *Conn) Send(typ string, msg interface{}) error
func (c *Conn) SendError(code ua.StatusCode)
```

### Dialer

```go
type Dialer struct {
    Dialer    *net.Dialer
    ClientACK *ClientACK
    Logger    Logger
}

func (d *Dialer) Dial(ctx context.Context, endpoint string) (*Conn, error)
```

`Dial` performs TCP connect, OPC UA HEL/ACK handshake, and returns a UACP `*Conn`. For TCP-only reachability (e.g. ping or diagnostics without HEL/ACK), use `DialTCP`.

```go
func DialTCP(ctx context.Context, endpoint string) (net.Conn, error)
```

`DialTCP` parses the endpoint URL and opens a raw TCP connection to the host:port. No OPC UA protocol is performed. The caller must close the returned connection. Use for TCP reachability tests when fine-grained diagnostics are needed.

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
func NewSecureChannel(endpoint string, conn *uacp.Conn, cfg *Config, errCh chan error) (*SecureChannel, error)
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
    Logger            Logger
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

## Package `stats`

Runtime statistics via `expvar`.

```go
func Reset()
func Client() *expvar.Map
func Error() *expvar.Map
func Subscription() *expvar.Map
func RecordError(err error)
```

---

## Package `id`

Generated constants for all standard OPC-UA node IDs from the specification.

Contains ~10,000 constants organised by node class:
- Object IDs (e.g. `id.Server`, `id.Server_ServerStatus`)
- Variable IDs (e.g. `id.Server_ServerStatus_CurrentTime`)
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

`ReferenceTypeName` returns the standard OPC UA name for a well-known reference type in namespace 0 (e.g. 47 → "HasComponent", 35 → "Organizes"), or "" if unknown. Use when displaying reference type NodeIDs (e.g. browse refs) to show names instead of raw NodeIDs. For a single call that accepts a NodeID and returns either the name or the NodeID string, use [ReferenceTypeDisplayName](opcua package) in the root package.

```go
func DataTypeName(id uint32) string
```

`DataTypeName` returns the standard OPC UA name for a well-known DataType in namespace 0 (e.g. 10 → "Float", 12 → "String", 294 → "UtcTime"), or "" if unknown. Use when displaying DataType NodeIDs to normalize type rendering. For a NodeID-based helper, use [DataTypeDisplayName](opcua package) in the root package.

```go
func NodeIDByName(name string) (uint32, bool)
```

`NodeIDByName` is the reverse of `Name`: it maps well-known standard node names (namespace 0 only) to numeric IDs. Names include full spec names (e.g. "Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime") and short aliases "CurrentTime" (→ 2258), "ServerStatus" (→ 2256), "Objects" (→ 85). Returns (0, false) if not found. For a `*ua.NodeID` use [StandardNodeID](opcua package) in the root package.

```go
func VariableTypeName(id uint32) string
func ObjectTypeName(id uint32) string
```

`VariableTypeName` returns the standard OPC UA name for a well-known VariableType in namespace 0 (e.g. 68 → "PropertyType", 63 → "BaseDataVariableType"), or "" if unknown. `ObjectTypeName` does the same for ObjectTypes (e.g. 58 → "BaseObjectType", 61 → "FolderType"). For a NodeID-based display helper use [TypeDefinitionDisplayName](opcua package) in the root package.

```go
func ObjectName(id uint32) string
func VariableName(id uint32) string
func MethodName(id uint32) string
```

`ObjectName` returns the standard name for a well-known Object node in namespace 0 (e.g. 84 → "RootFolder", 85 → "ObjectsFolder", 2253 → "Server"). `VariableName` does the same for Variable nodes (e.g. 2256 → "Server_ServerStatus", 2258 → "Server_ServerStatus_CurrentTime"). `MethodName` does the same for Method nodes (e.g. 11492 → "Server_GetMonitoredItems"). Each returns "" if the id is not in that category. The generic [Name](id package) function looks up across all categories.
