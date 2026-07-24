# go-opcua Releases

## v1.3.0

**Date:** 2026-07-24
**Previous release:** v1.2.0

### Summary

Minor release focused on **Part 4 correctness** for Read/Write/Browse, **subscription and monitored-item semantics**, **event subscriptions**, **subscription recovery**, and **historical access** — with matching public APIs and a large expansion of open62541 / Milo interop coverage ([opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0)). Also absorbs race-detector test timeout fixes that were prepared as an unreleased v1.2.1 patch.

Highlights:
- **IndexRange** on array and matrix Values, with Part 4 status codes and helpers in `ua`
- **Monitored-item queues** that honor `QueueSize`, `DiscardOldest`, and the Overflow InfoBit
- **Subscription lifecycle** — revise clamps, monitoring/publishing modes, `MoreNotifications`, Publish ACK, delete and lifetime expiry
- **Events** — `EventFilter` (SelectClauses / OfType / comparison WhereClauses), `EmitBaseEvent` with custom `Fields`
- **Republish / TransferSubscriptions** on server and client (`Client.Republish`, `Client.TransferSubscriptions`) plus `WithSubscriptionRecoveryHandler`
- **HistoryRead / HistoryUpdate** via pluggable `HistoryProvider`; default `*Historian` also covers update/delete/at-time/modified/processed aggregates
- **~330** interop tests against digest-pinned adapter images
- **Server test suite under `-race`** no longer times out in CI (nodeset import cache + Query subtype recursion guard)

No intentional breaking changes for correct callers. Servers that previously ignored queue or monitoring-mode parameters now follow Part 4 — notification batches may differ.

### Read, Write, and Browse

- **IndexRange / NumericRange** — 1D (`"i"`, `"i:j"`) and multi-dimensional (`"a:b,c:d"`) Value Read/Write; ByteString IndexRange slices bytes. Scalar + IndexRange → `BadIndexRangeInvalid`; empty/out-of-range → `BadIndexRangeNoData`; write size mismatch → `BadIndexRangeDataMismatch`.
- **TimestampsToReturn** — Read and DataChange notifications honor Source / Server / Both / Neither; invalid enum → `BadTimestampsToReturnInvalid`.
- **Write EncodingMask** — value-only Writes succeed; status and/or timestamp bits → `BadWriteNotSupported`.
- **Browse ResultMask** — omitted fields are cleared on `ReferenceDescription`s (`NodeID` always kept).
- **BrowseNext** — early `ReleaseContinuationPoints` invalidates the token (`BadContinuationPointInvalid`).
- **Client certificate trust** — `WithClientCertificateTrustList` is enforced at `OpenSecureChannel` (CreateSession retained as defense-in-depth).

### Subscriptions and monitored items

- **QueueSize** revised to `max(1, requested)` (cap 100), returned as `RevisedQueueSize`.
- **DiscardOldest** — `true` keeps the newest `QueueSize` samples; `false` keeps the oldest `QueueSize-1` plus the newest (e.g. writes `1..5` / QS=3 → `[1,2,5]`).
- **Overflow** — InfoBit `0x480` when `QueueSize > 1` and the queue overflows; queues are per-item.
- **SetMonitoringMode** — Disabled (no enqueue) / Sampling (enqueue only) / Reporting (Publish).
- **SetPublishingMode** — disable holds queues; re-enable delivers the queued window.
- **Create/ModifySubscription revise** — publishing interval clamped; `RevisedLifetimeCount >= 3 × RevisedMaxKeepAliveCount`.
- **MoreNotifications** — honors `MaxNotificationsPerPublish` with partial drain.
- **Publish ACK** — Results + AvailableSequenceNumbers; keepalives do not fabricate DataChange.
- **Delete / lifetime expiry** — second delete → `BadSubscriptionIdInvalid` / `BadMonitoredItemIdInvalid`; idle lifetime removes the subscription.
- **monitor package** — zero-value `Request.MonitoringMode` means Reporting (use `SetMonitoringMode` for Disabled/Sampling).

### Events

- Event monitored items accept `EventFilter` SelectClauses and WhereClause operators (`OfType`, comparisons, `And`/`Or`/`Not`); invalid filters are rejected.
- `EmitBaseEvent` delivers a `BaseEventType`-shaped event (optional custom `Fields`) and applies each item’s filter.
- `EmitEvent` remains for raw `EventFieldList` delivery.
- `ModifyMonitoredItems` can update a live EventFilter.
- Event queues are bounded (max 50). Alarms/Conditions, historical events, and shelving are not included.

### Subscription recovery

- **Server Republish / TransferSubscriptions** — returns available sequences; missing → `BadMessageNotAvailable`; transfer reassigns session/channel under lock.
- **Client helpers** — `Client.Republish` (protocol response only; does not mutate notify channels) and `Client.TransferSubscriptions`.
- **`WithSubscriptionRecoveryHandler`** — observes Transfer → Republish → Recreate outcomes during `AutoReconnect`.
- ACK removes sequences from the retransmission set.
- `SendInitialValues` is accepted but currently a no-op. Durable subscriptions are not included.

### Historical Access

- Pluggable `HistoryProvider`; default in-memory `*Historian` (per-node ring buffer, default 1000 samples, process-lifetime only).
- Raw `ReadRawModifiedDetails` with session-bound continuation points (30s TTL, max 100 active).
- Optional interfaces on the same provider (implemented by `*Historian`): UpdateData, DeleteRawModified (`isDeleteModified=false`), DeleteAtTime, ReadAtTime, ReadModified, ReadProcessed (Average/Minimum/Maximum/Count).
- `returnBounds` is accepted but bounding/interpolation is not implemented for raw reads. Historical events are not included. HistoryRead stays unsupported until `SetHistorian` is configured.

### New and changed public APIs

#### `ua` — NumericRange and timestamp helpers

```go
type NumericRange struct {
    Start int // inclusive
    End   int // inclusive
}

func ParseNumericRange(s string) (NumericRange, error)
func ParseNumericRanges(s string) ([]NumericRange, error)
func SliceVariantRead(v *Variant, rangeStr string) (*Variant, StatusCode)
func MergeVariantWrite(current *Variant, rangeStr string, newVal *Variant) (*Variant, StatusCode)
func ApplyTimestampsToReturn(dv *DataValue, ts TimestampsToReturn) StatusCode
```

Used by the server for Value IndexRange and timestamp filtering; safe to call directly.

#### `opcua` — client recovery helpers

```go
func (c *Client) Republish(ctx context.Context, subscriptionID, sequenceNumber uint32) (*ua.RepublishResponse, error)
func (c *Client) TransferSubscriptions(ctx context.Context, subscriptionIDs []uint32, sendInitialValues bool) (*ua.TransferSubscriptionsResponse, error)
func WithSubscriptionRecoveryHandler(f func(SubscriptionRecoveryEvent)) Option
```

#### `server` — BaseEvent emission

```go
type BaseEvent struct {
    EventID    []byte
    EventType  *ua.NodeID
    SourceNode *ua.NodeID
    SourceName string
    Time       interface{} // time.Time
    Message    *ua.LocalizedText
    Severity   uint16
    Fields     map[string]*ua.Variant // custom SelectClause fields
}

func (s *Server) EmitBaseEvent(nodeID *ua.NodeID, event *BaseEvent) error
```

#### `server` — HistoryProvider / Historian

```go
type HistoryProvider interface {
    ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
    ReleaseContinuation(continuationPoint []byte)
}

// Optional capabilities (type-assert; *Historian implements all):
// HistoryDataUpdater, RawHistoryDeleter, AtTimeHistoryDeleter,
// AtTimeHistoryReader, ModifiedHistoryReader, ProcessedHistoryReader

func NewHistorian() *Historian
func (h *Historian) EnableNode(nodeID *ua.NodeID, maxSamples int)
func (h *Historian) RecordValue(nodeID *ua.NodeID, dv *ua.DataValue)
func (h *Historian) IsEnabled(nodeID *ua.NodeID) bool
func (s *Server) SetHistorian(h HistoryProvider)
```

### Interoperability

Verified four-direction against open62541 and Milo for IndexRange, timestamps, Write EncodingMask, Browse ResultMask / BrowseNext release, queue windows, subscription timestamps, and subscription lifecycle (revise / publishing-mode / monitoring-mode / delete), plus peer capability rows on [opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0):

- `event.subscription` — open62541→Go and Milo→Go
- `history.read.raw` — open62541→Go and Milo→Go
- `subscription.server.republish` — open62541→Go
- `subscription.server.transfer` — Milo→Go
- `subscription.client.republish` — Go→open62541

| Image | Pin |
|-------|-----|
| open62541 | `ghcr.io/otfabric/opcua-interop-open62541@sha256:d9650e1b63fd0df1c840335d1951c848437530de0670c279ef905440a3bc77d6` |
| Milo | `ghcr.io/otfabric/opcua-interop-milo@sha256:af502530b7043763220474d6dcf0deef62215e0b3c112cc8eab9849ec1d4e321` |

Digests are fix-forwarded on the same `v0.5.0` tag when opcua-interop requirements change (no RC / `v0.5.1` pins). See [INTEROP.md](INTEROP.md) and [`interop/COVERAGE.md`](interop/COVERAGE.md) for the full matrix. Docs updated in `API.md`, `README.md`, and `docs/*`.

### Bug fixes and test infrastructure

Absorbed from the skipped v1.2.1 patch:

- **`server` tests: nodeset import cached across tests** — `newTestServer()` was calling `New()` (full built-in XML nodeset import, ~0.4 s each under `-race`) for every server-package test case, exceeding the 120 s CI per-package timeout. A `sync.Once` cache (`warmNS0Cache`) imports once per test binary; later servers copy the cached nodes in microseconds. Server package time under `-race`: **>120 s → ~11 s**.
- **`getSubRefs` infinite recursion guard** — `HasSubtype` expansion for `QueryFirst`/`QueryNext` could loop on the cyclic built-in type hierarchy. A `visited` map (`getSubRefsVisited`) prevents re-traversal; individual query tests now run in <50 ms instead of 41+ s.
- **`newServerNoNS()`** (package-private) — lightweight `Server` constructor that skips nodeset import; used by the test helper.

### Known limitations

- Broader EventFilter peer rows (SelectClauses / OfType / Where) and history edges beyond raw O→S/M→S remain unverified in the ledger
- No Alarms/Conditions, historical events, durable subscriptions, or full bounding/interpolation for raw HistoryRead `returnBounds`

---

## v1.2.0

**Date:** 2026-07-22
**Previous release:** v1.1.1

### Summary

Minor release focused on **X.509 security hardening**, **server API correctness**, and a large step forward in **test coverage** (50% → 81%).

Highlights:
- **ApplicationURI SAN verification** — the client now binds the server certificate to the `ApplicationURI` advertised in its `ApplicationDescription`, closing an OPC UA PKI identity gap.
- **Strict key-usage enforcement** — server certificates that declare a `KeyUsage` extension must include `DigitalSignature` (and `KeyEncipherment` for SignAndEncrypt); verification is now a hard failure instead of a warning.
- **Server-side X.509 user token validation** — the server validates the `UserTokenSignature` (signature over `serverCertificate || serverNonce`) and calls an application-provided `X509UserValidator` for trust decisions.
- **Critical server nil-pointer fixes** — 14 distinct nil-pointer panic paths in `server/` were found and fixed; the entire subscription/monitored-item service set now handles unauthenticated or malformed requests without crashing.
- **`AddObject` / `AddVariable` API fixed** — both methods were silently broken (nil back-reference on every registered node); they now work correctly and are covered by tests.
- **New documentation** — `API.md` (full public API reference with table of contents) and `INTEROP.md` (compatibility matrix against open62541 and Eclipse Milo).
- **Coverage** reaches 81%, well above the 75% threshold enforced by `make coverage`.

No breaking changes for correct existing callers. Minor version bump.

### Security hardening

#### Client — ApplicationURI SAN verification (OPC UA Part 6 §6.2.2)

`SecurityFromEndpoint` now stores the server's `ApplicationURI` from the endpoint `ApplicationDescription`. `validateServerCertificate` compares the certificate's URI SANs against this stored value. Trusting the CA alone is insufficient: the URI SAN is the OPC UA identity binding that ties a certificate to a specific application instance.

```go
// Automatic when using SecurityFromEndpoint — no API change required.
// InsecureSkipVerify() bypasses this check as before.
```

#### Client — Strict key-usage validation (OPC UA Part 6 §6.2.4)

Certificates that declare a `KeyUsage` extension are now required to include `DigitalSignature` (and additionally `KeyUsageKeyEncipherment` for `SignAndEncrypt` mode). Previously a missing bit produced a warning; it is now a rejected connection. Certificates that do not declare any `KeyUsage` extension are still accepted for interoperability with legacy deployments.

#### Server — X.509 user token validation

The server now fully validates `X509IdentityToken` presented in `ActivateSession`:
1. The token certificate must be parseable.
2. The `UserTokenSignature` (signature over `serverCertificate ‖ serverNonce`) is verified with the token certificate's public key — this prevents certificate-replay attacks.
3. An application-supplied `X509UserValidator` hook is called for trust-store and policy decisions.

```go
v := server.X509UserValidator(func(certDER []byte) error {
    // parse certDER, check trust store, enforce your policy
    return nil // or ua.StatusBadIdentityTokenRejected
})
srv, _ := server.New(
    server.WithX509UserValidator(v),
    // ...
)
```

### New server API

#### `ListenOn(addr string) Option`

Binds the server to a specific host/port without going through `EndPoint`:

```go
srv, _ := server.New(server.ListenOn("0.0.0.0:4840"))
```

#### `UsernameValidator` and `WithUsernameValidator`

Previously an internal type; now a first-class exported type and option:

```go
v := server.UsernameValidator(func(user, pass string) error {
    if user != "admin" || pass != secret {
        return ua.StatusBadUserAccessDenied
    }
    return nil
})
srv, _ := server.New(server.WithUsernameValidator(v))
```

#### `X509UserValidator` and `WithX509UserValidator`

New type and option for server-side X.509 user token trust decisions (see Security hardening above).

#### `AllowUsernameOnNone() Option`

Permits username/password authentication on `SecurityModeNone` endpoints (opt-in; disabled by default for safety).

### Bug fixes

#### Server — `AddObject` / `AddVariable` always panicked

Every node registered via `NodeNameSpace.AddNode` had its `ns` back-reference left `nil`. Any subsequent call to `Node.AddObject` or `Node.AddVariable` on that node immediately panicked. Both methods now work correctly:
- `AddNode` sets `n.ns = as`.
- `AddVariable` registers the new child node in the namespace (previously it returned the cloned child without inserting it).

#### Server — `AddNamespace` did not inject server reference

`NewNameSpace(name)` creates a `NodeNameSpace` with `srv = nil`. `AddNamespace` now sets `nns.srv = s` on any `*NodeNameSpace` instance that arrives without a server reference, so `Browse`, `ChangeNotification`, and `SetAttribute` work correctly on namespaces registered after construction.

#### Server — `Browse` nil type definition

`NodeNameSpace.Browse` called `td.DataType()` on the result of `as.srv.Node(...)` without a nil check. Any reference pointing to a node that does not exist in the server's address space panicked. The nil case is now handled gracefully.

#### Server — `node.DataType()` nil `ReferenceTypeID`

The method logged a warning about a nil `ReferenceTypeID` but then immediately called `.IntID()` on it in the next statement. The warning is now followed by a `continue`.

#### Server — `nodeset2_import.go` — nil node before `AddRef` (7 sites)

All six node-type sections of `refsImportNodeSet` called `node.AddRef(...)` after a `Warn`-but-no-`continue` nil check, or with no nil check at all. All seven call sites now skip the reference loop when the node cannot be resolved.

#### Server — subscription / monitored-item service nil panics (7 critical paths)

All service handlers that compare session tokens against a nil `Session()` result now guard with `sess == nil`:

| Method | Symptom |
|---|---|
| `SetMonitoringMode` | `!ok` check came *after* the nil dereference |
| `DeleteMonitoredItems` | Missing `continue` after `!ok`; nil `item` used on fallthrough |
| `CreateMonitoredItems` | `sess` nil, used immediately |
| `ModifyMonitoredItems` | `sess` nil, used immediately |
| `SetTriggering` | `sess` nil, used immediately |
| `DeleteSubscriptions` | `session` nil, used immediately |
| `CloseSession` | `SubscriptionService` nil before `Start()` |

#### Server — `Subscription.run()` goroutine nil session / channel panic

`CreateSubscription` sets `sub.Session = srv.Session(...)` which returns `nil` for an invalid token. The background `run()` goroutine then panicked on `s.Session.PublishRequests`. Both `Session` and `Channel` are now checked at the start of `run()` with an immediate clean shutdown. `keepalive()` also guards against a nil `Channel`.

#### Server — `ChangeNotification` before `Start()`

`MonitoredItemService` is `nil` until `initHandlers()` is called inside `Start()`. Any call to `ChangeNotification` (or `SetAttribute`, which calls it) during pre-`Start()` namespace population panicked. The method now returns early when `MonitoredItemService == nil`.

#### `uasc.SecureChannel` — new `SecurityPolicyURI()` accessor

The field was private and inaccessible to callers that need to inspect the negotiated policy URI without access to the internal `Config`. A public accessor is now exported.

### Documentation

- **`API.md`** — comprehensive public API reference for the `opcua`, `server`, `ua`, `uasc`, `uacp`, `uapolicy`, `monitor`, and `errors` packages, with a full table of contents.
- **`INTEROP.md`** — compatibility matrix showing verified behavior against open62541 and Eclipse Milo across all security policies, authentication methods, and service operations.

### Testing

Test coverage increased from ~50% to **81%** (threshold enforced at 75% via `make coverage`).

New test files and significant additions include:
- `ua/enums_all_values_test.go`, `ua/enums_string_methods_test.go` — 100% branch coverage for all generated enum `FromString` / `String` methods.
- `ua/extobjs_header_test.go` — `Header` / `SetHeader` for all generated request/response types.
- `server/server_config_options_test.go` — all server `Option` constructors.
- `server/channel_broker_test.go`, `server/query_service_test.go` — previously 0% covered.
- `server/subscription_service_test.go`, `server/monitored_item_service_test.go` — regression tests for all nil-panic fixes.
- `server/namespace_node_test.go` — `AddObject`, `AddVariable`, `AddNamespace` back-reference, `Browse` nil td, `DataType()` nil ref.
- `uasc/secure_channel_test.go` — accessors, `conditionLocker`, `mergeChunks`, `notifyMonitor`, `isReconnectTrigger`, `getActiveChannelInstance`.
- `uacp/conn_test.go` — `minNonZero`, `defaultNetDialer`, live connection accessors.
- `config_test.go` — `setCertificate` URI extraction, `loadPrivateKey` PEM/DER/PKCS#8 branches.
- `conformance/` — cross-package coverage of `uasc` and `opcua` root via in-process client/server tests.

### Compatibility

All additions are backward-compatible. The stricter certificate validation (ApplicationURI SAN, key usage) is a security fix; callers with correctly configured certificates are unaffected. `InsecureSkipVerify()` bypasses both new checks. Minor version bump.

---

## v1.1.1

**Date:** 2026-07-09
**Previous release:** v1.1.0

### Summary

Patch release focused on **interop hardening** with strict OPC UA clients and servers (certificate chains, encrypted-channel handshakes, large responses), plus **monitoring ergonomics** and **transport-layer improvements** in `uacp`.

Highlights:
- **Certificate chains** (leaf + intermediate) are parsed correctly on connect; thumbprints use the leaf certificate only.
- **Server secure-channel handshake** now includes `ReceiverCertificateThumbprint` on OpenSecureChannel responses.
- **Large server responses** (e.g. Browse of a big folder) are split across multiple chunks instead of dropping the connection.
- **`monitor.ItemError`** — batch monitored-item creation succeeds for valid nodes and reports per-item failures individually.
- **`uacp.ParseEndpoint`** and default dial timeouts for direct `uacp` package users; DNS resolution delegated to `net.Dialer`.

No breaking API changes. Patch version bump.

### Bug fixes

#### Certificate chains on connect

Servers that present their application instance certificate as a **leaf plus intermediate chain** (e.g. Siemens WinCC Unified Runtime) previously failed validation because `x509.ParseCertificate` rejects trailing DER. The client now uses `x509.ParseCertificates`, validates the leaf against the trust pool with intermediates, and `uapolicy.PublicKey` / `Thumbprint` extract the **leaf** certificate only. Session signature paths use the same chain-aware helpers.

#### Server OpenSecureChannel response missing client thumbprint

The server recorded the client's certificate on incoming OPN requests but never set `cfg.Thumbprint`, so OpenSecureChannel responses carried an empty `ReceiverCertificateThumbprint`. Strict clients (UaExpert, Prosys) reject encrypted channels against the server. The thumbprint is now derived from the client's `SenderCertificate` when the OPN request is processed.

#### Server large responses dropped the connection

`sendResponseWithContext` encoded the entire response as a single chunk. Responses larger than the negotiated buffer (common when browsing folders with many nodes) overflowed the client's receive buffer and closed the connection. Server responses now use `EncodeChunks(maxBodySize)` with per-chunk sign/encrypt/write, mirroring the client request path. `SetMaximumBodySize` is called on the server after symmetric keys are established. The UACP server handshake also negotiates send/receive buffer sizes to the **minimum** of what each side advertises.

#### Monitor batch failed on first bad node

`monitor.Subscription.AddMonitorItems` returned immediately on the first per-item `StatusCode` failure, abandoning valid items in the same batch. It now collects `ItemError` values for rejected items (recoverable via `errors.As`), cleans up speculatively registered handles, and still returns successfully created items. The server's `CreateMonitoredItems` handler rejects unknown nodes individually with `BadNodeIDUnknown` instead of failing the whole request.

### New features / improvements

#### `monitor.ItemError`

```go
type ItemError struct {
    NodeID     *ua.NodeID
    StatusCode ua.StatusCode
}
```

`AddMonitorItems` returns `(items, errors.Join(itemErrors...))` when some items fail. `errors.Is(err, ua.StatusBadNodeIDUnknown)` works via `Unwrap`.

#### `uacp` endpoint parsing and dial timeouts

- `ParseEndpoint(endpoint)` — parse and validate `opc.tcp://` URLs **without DNS**; requires a host and validates explicit ports. Hostname resolution is deferred to `net.Dialer` / `net.Listen` (standard library happy eyeballs).
- `uacp.DefaultDialTimeout` (10s); `Dial` / `DialTCP` use it by default.
- `DialWithTimeout` / `DialTCPWithTimeout` for explicit timeouts (zero = no dial timeout beyond `ctx`).
- `opcua.DefaultDialTimeout` is now an alias of `uacp.DefaultDialTimeout`.

### Testing

- `uapolicy/cert_utils_test.go` — chain thumbprint and public-key extraction.
- `config_test.go` — leaf+intermediate chain validation.
- `conformance/monitor_chunk_test.go` — partial-batch monitor (`ItemError`), multi-chunk browse with small negotiated buffer.
- `uacp/dial_timeout_test.go` — default dial timeout and zero-timeout behavior.
- `monitor/subscription_test.go` — `ItemError` unit test.

### Compatibility

No breaking API changes. All additions are new types/functions or relaxed behavior (partial monitor success, chain parsing). Patch version bump.

---

## v1.1.0

**Date:** 2026-07-09
**Previous release:** v1.0.2

### Summary

Feature and hardening release, and the first release prepared for open-source distribution under the MIT license.

Highlights:
- New **server-side Query service** (QueryFirst/QueryNext) with a full Part 4 `ContentFilter` evaluator.
- A new **client↔server conformance test suite** (conformance, adversarial, concurrency, and property-based tiers) covering the client/server API surface over a real `opc.tcp` loopback.
- **Correctness fixes** in the binary codec, the client's fault handling, and the server's fault routing.
- **Open-source preparation**: SPDX license headers across the codebase and licensing/documentation updates.

No breaking API changes. Minor version bump.

### New features

#### Server-side Query service (QueryFirst / QueryNext)

The server now implements the Query Service Set. Previously `QueryFirst`/`QueryNext` returned `Bad_ServiceUnsupported`.

- `QueryFirst` matches candidate nodes by `TypeDefinition` (with `IncludeSubTypes` via the type tree), applies the `ContentFilter` WhereClause, and builds `QueryDataSet`s by resolving each `QueryDataDescription` (`RelativePath` + attribute read). It honors `MaxDataSetsToReturn` and reports per-NodeType `ParsingResults` and a `FilterResult`.
- `QueryNext` supports pagination via a continuation-point store, releasing continuation points, and returns `Bad_ContinuationPointInvalid` for unknown tokens.
- A specified but unknown `View` returns `Bad_ViewIdUnknown`; a null view scans the whole address space. Empty `NodeTypes` returns `Bad_NothingToDo`.

The Service Support Matrix in the README now lists QueryFirst/QueryNext as supported on both client and server.

#### Full ContentFilter evaluator

New self-contained `ContentFilter` evaluator (`server/content_filter.go`) implementing full Part 4 semantics:

- All 18 `FilterOperator`s: `Equals`, `IsNull`, `GreaterThan`, `LessThan`, `GreaterThanOrEqual`, `LessThanOrEqual`, `Like`, `Not`, `Between`, `InList`, `And`, `Or`, `Cast`, `InView`, `OfType`, `RelatedTo`, `BitwiseAnd`, `BitwiseOr`.
- Three-valued logic (TRUE/FALSE/NULL) for the logical operators.
- Operand resolution for `LiteralOperand`, `ElementOperand` (with forward-only, cycle-checked element references), `AttributeOperand`, and `SimpleAttributeOperand`.
- Implicit numeric/string comparison, the OPC UA `Like` grammar (`%`, `_`, `[]`, `[^]`, `\` escaping) translated to a Go regexp, and a `Cast` conversion for the common built-in scalar types.
- A structural validation pass producing a `ContentFilterResult` with per-element/per-operand status codes.

#### Node enumeration API

New optional `Nodes()` accessors return a snapshot of a namespace's nodes:

```go
func (as *NodeNameSpace) Nodes() []*Node
func (ns *MapNamespace) Nodes() []*Node
```

The Query service uses these to scan candidate nodes; custom namespaces that implement the same signature participate automatically.

#### New and modernized examples

New runnable examples: `readmulti` (auto-chunked batch read), `history-read-simple` (`ReadHistoryAll` iterator), `serverstatus`, `metrics` (`WithMetrics`/`WithRetryPolicy`), `node-summary` (`Node.Summary`), `regread` (register-nodes), and dedicated server examples `server/node_server`, `server/map_server`, `server/NodeSet2_server`, and `server/method_server`. Existing `read`/`write`/`subscribe`/`method`/`translate`/`history-read` examples were reworked to demonstrate both the high-level convenience wrappers and the low-level service calls.

### Bug fixes

#### Binary encoder nil-pointer asymmetry

`ua/encode.go` wrote zero bytes for a nil pointer field, but the decoder always allocates and reads pointer fields. Any message that left a pointer field nil produced a stream that could not be decoded symmetrically. The encoder now writes the zero value for a nil pointer, matching decode (a nil `*NodeID` encodes as the null NodeID `0x00 0x00`). Existing messages that fully populate their pointers are unaffected. Added round-trip idempotence tests covering empty `QueryFirstRequest`/`QueryNextRequest`, `ContentFilter` with each operand type, and nil `*NodeID`.

#### Operation-level ServiceFaults no longer disconnect the client

The client's read dispatcher forwarded every failed message to the connection monitor, which treats any notification as a connection failure. A normal operation-level ServiceFault (a decoded response carrying a non-OK `ServiceResult`, e.g. a bad NodeID or an invalid filter) therefore tore down the whole connection. The dispatcher now forwards only connection/transport-level failures and the faults that actually require the channel, session, or subscriptions to be recreated (`Bad_SecureChannelIdInvalid`, `Bad_SessionIdInvalid`, `Bad_SubscriptionIdInvalid`, `Bad_NoSubscription`, `Bad_CertificateInvalid`). Ordinary faults are returned to the caller with the connection left usable. Auto-reconnect behavior is unchanged.

#### Server no longer tears down the secure channel on a per-request error

When a single request failed to decode/process, the server's channel broker closed the entire secure channel without replying, so the client blocked until its full `RequestTimeout` (and `Client.Close` then blocked too). The broker now returns a `ServiceFault` correlated to the offending `RequestID` and keeps serving the channel; only connection-level failures close it.

#### Node.Description panic

`Node.Description` could panic because the server's node constructors stored the wrong value type (a numeric NodeClass instead of a `LocalizedText`) under the Description attribute. The server constructors now store a `LocalizedText`, and the client-side `Node.Description` performs a checked type assertion and returns an error instead of panicking on unexpected types.

### Testing

#### New conformance test suite (`conformance/` package)

A new in-process client↔server test suite exercises the full client/server API surface over a real `opc.tcp` loopback:

- **Conformance** per service set (attribute, view, method, node management, subscription, events, history, query, misc).
- **Adversarial** tests for malformed/hostile inputs and edge cases.
- **Concurrency** tests (safe under `-race`).
- **Property-based** round-trip/invariance tests using `pgregory.net/rapid` (added as a dependency).
- An **API coverage matrix** (`matrix_test.go`) that reflects over the client/server APIs to guard against untested surface.
- Shared harness and a rich node `Fixture` in `internal/testutil` (scalars of every common type, arrays, access-controlled nodes, a callable method, an event source, and a typed/subtyped `VariableType` hierarchy for Query).

Unit tests were also added for the ContentFilter evaluator (`server/content_filter_test.go`: operator matrix, three-valued logic, `Like` grammar, `Cast`, validation).

### Open-source preparation / licensing

- **SPDX headers**: every first-party Go file now begins with `// SPDX-License-Identifier: MIT`. Code-generator templates (`cmd/*`) and the generation orchestrator (`internal/cmd/gen`) emit the SPDX header, and `stringer` output is post-processed so generated files stay consistent with `go generate ./...`.
- **LICENSE**: added the OT Fabric copyright line; the project remains MIT-licensed.
- **Documentation**: `README.md` badges refreshed (pkg.go.dev reference, Codecov, release), the examples table expanded, and the Query rows updated; `API.md` documents the client Query API and the new `Nodes()` accessors.

### Compatibility

No breaking API changes. All additions are new methods/behavior; the encoder change only affects previously-undecodable output; SPDX headers and licensing updates are non-functional. Minor version bump.

---

## v1.0.2

**Date:** 2026-03-24
**Previous release:** v1.0.1

### Summary

Production-grade hardening release. Makes the library fully slog-native, removes the custom logger abstraction, hardens NodeSet2 XML import against malformed input, adds generator tests and CI drift detection, and finishes the panic audit.

### Breaking changes

#### Logger package removed

The `logger/` package and `logger_alias.go` re-exports have been deleted. The library is now slog-native internally — all logging uses `*slog.Logger` directly.

```go
// Before
import "github.com/otfabric/go-opcua/logger"
opcua.WithLogger(logger.NewSlogLogger(handler))

// After
import "log/slog"
opcua.WithLogger(slog.New(handler))
```

#### `WithLogger` accepts `*slog.Logger`

The client option `WithLogger` now takes `*slog.Logger` directly instead of the former `logger.Logger` interface. The separate `WithSlogLogger` option has been removed (merged into `WithLogger`).

```go
// Before
opcua.WithSlogLogger(myLogger)

// After
opcua.WithLogger(myLogger)
```

#### `SetLogger` accepts `*slog.Logger` (server)

The server option `SetLogger` now takes `*slog.Logger` directly instead of `logger.Logger`.

#### `uacp.Dialer.Logger` and `uasc.Config.Logger` type changed

The exported `Logger` fields on `uacp.Dialer` and `uasc.Config` have changed from `logger.Logger` to `*slog.Logger`.

#### `uacp.Conn.SetLogger` accepts `*slog.Logger`

The `SetLogger` method now takes `*slog.Logger`.

#### `TypeRegistry.New(nil)` returns nil instead of panicking

`TypeRegistry.New` with a nil NodeID now returns nil instead of panicking. This protects runtime paths processing incoming messages with potentially malformed type IDs.

#### Stricter NodeSet2 XML import validation

`ImportNodeSetXML` now returns contextual errors instead of panicking when NodeSet2 XML contains invalid node IDs, reference targets, or reference types. All 29 uses of `ua.MustParseNodeID` on XML-derived data have been replaced with `ua.ParseNodeID` and error propagation.

Error messages include the import phase, node type, and offending value:
```
nodeset import: variable: parse node id "not-valid": ...
nodeset import: reference type "ns=1;i=1": parse reference target "bad-ref": ...
nodeset import: data type "ns=1;i=2": unknown reference type "NonExistent"
```

### New features

#### Slog-native logging

All internal logging now uses `*slog.Logger` with structured key-value fields. No `Debugf`/`Infof`/`Warnf`/`Errorf` format-string logging remains in production code.

The default logger is `slog.Default()`, which means the library respects any global slog configuration set by the application.

#### Generator test coverage

`internal/cmd/gen` now has focused tests covering:
- Enum type discovery (sorted, deduplicated)
- Generated file list validation (no duplicates)
- File cleanup behavior
- Missing file tolerance

#### CI generation drift detection

A new `gen-drift` CI job runs `go generate ./...` and fails if the working tree becomes dirty, ensuring generated files stay in sync with source changes.

A new `check-gen` Makefile target provides the same check locally: `make check-gen`.

#### NodeSet2 import regression tests

New test suite `TestImportNodeSetXML_BadInput` covers 12 malformed XML scenarios including invalid node IDs for each node type, invalid alias references, invalid reference targets, unknown reference types, and malformed XML.

### Improvements

#### All logging converted to structured slog

243+ log call sites across all packages (`client`, `server`, `uacp`, `uasc`) converted from printf-style format strings to structured slog calls with meaningful key-value fields.

#### Deterministic generator targets

`discoverEnumTypes` now deduplicates discovered types using `slices.Compact` after sorting, and returns errors instead of calling `log.Fatalf`.

#### Generator error propagation

All generator functions (`clean`, `generate`, `stringer`, `run`) now return errors instead of calling `log.Fatalf`, making failures actionable and testable.

#### Nil-safe map lookups in NodeSet import

Reference type lookups in NodeSet import now use the comma-ok pattern and return descriptive errors for unknown reference types instead of nil-pointer panics.

### Migration guide

1. **Logger package** — remove all imports of `"github.com/otfabric/go-opcua/logger"`. Use `*slog.Logger` directly.
2. **`WithLogger`** — change argument from `logger.Logger` to `*slog.Logger`. Remove calls to `WithSlogLogger` (use `WithLogger` instead).
3. **`SetLogger` (server)** — change argument from `logger.Logger` to `*slog.Logger`.
4. **`uacp`/`uasc` Logger fields** — update any direct assignments of `Dialer.Logger` or `Config.Logger` to use `*slog.Logger`.
5. **NodeSet import errors** — callers of `ImportNodeSetXML` should handle more granular errors from stricter validation.
6. **CI** — the new `gen-drift` job will fail PRs that modify generator inputs without regenerating. Run `make gen` before committing generated file changes.

---

## v1.0.1

**Date:** 2026-03-24
**Previous release:** v1.0.0

### Summary

Production hardening and maintainability release. Replaces shell-driven code generation with a Go-based driver, tightens package boundaries, unifies configuration patterns, eliminates avoidable panics, internalizes non-public packages, documents service support, and reduces root package sprawl.

### Breaking changes

#### `server.New` returns `(*Server, error)`

`server.New` now returns an error instead of panicking on bootstrap failures. All server option functions also return `error`, matching the client's `Option func(*Config) error` pattern.

```go
// Before
srv := server.New(opts...)

// After
srv, err := server.New(opts...)
```

#### Server options return errors instead of logging warnings

`EnableSecurity` and `EnableAuthMode` now return `fmt.Errorf` for invalid or duplicate configurations instead of silently logging warnings.

#### `schema` package moved to `internal/schema`

The `schema` package (NodeSet2 XML types and embedded spec data) is now internal. Use `server.ImportNodeSetXML(data []byte)` instead of unmarshaling into `schema.UANodeSet` directly.

```go
// Before
import "github.com/otfabric/go-opcua/schema"
var nodes schema.UANodeSet
xml.Unmarshal(data, &nodes)
srv.ImportNodeSet(&nodes)

// After
srv.ImportNodeSetXML(data)
```

#### `stats` package moved to `internal/stats`

The experimental `stats` package is now internal. It was not intended for downstream use.

#### `testutil` package moved to `internal/testutil`

The test helper package is now internal. It was not intended for downstream use.

#### Root package helpers removed

The following functions have been removed from the root `opcua` package and moved to their canonical locations:

| Function | New location |
|----------|-------------|
| `AggregateType` | `id.AggregateType` (returns `(uint32, bool)` instead of `*ua.NodeID`) |
| `ReferenceTypeDisplayName` | `ua.ReferenceTypeDisplayName` |
| `TypeDefinitionDisplayName` | `ua.TypeDefinitionDisplayName` |
| `DataTypeDisplayName` | `ua.DataTypeDisplayName` |
| `StandardNodeID` | `ua.StandardNodeID` |
| `SelectEndpoint` | `ua.SelectEndpoint` |

### New features

#### Go-based code generation driver

`generate.sh` has been replaced by `internal/cmd/gen/main.go`. The new driver:
- Cleans an explicit list of generated files (no shell globs).
- Runs each generator in dependency order.
- Discovers enum types via Go's `go/ast` parser and runs `stringer`.
- Uses `go tool stringer` (version pinned in `go.mod` via the `tool` directive).
- Does not install tools or run `go mod tidy`.

Generation is invoked via `go generate ./...` or `make gen`.

#### Pinned stringer version

`stringer` is now declared as a tool dependency in `go.mod` (`golang.org/x/tools v0.43.0`) and invoked via `go tool stringer` instead of `go install ...@latest`.

#### `server.ImportNodeSetXML`

New public API for importing custom NodeSet2 XML data without depending on schema types:

```go
data, _ := os.ReadFile("my-model.xml")
if err := srv.ImportNodeSetXML(data); err != nil {
    log.Fatal(err)
}
```

#### `WithSlogLogger` option

Both client and server now accept `WithSlogLogger(*slog.Logger)` as a convenience option for configuring structured logging without manually wrapping a handler.

#### Service support matrices

Comprehensive service support matrices added to:
- `docs/server-guide.md` — server-side service status
- `docs/client-guide.md` — client-side method coverage
- `README.md` — combined matrix with accurate unsupported-service markers

### Improvements

#### Package tiering

All packages are now explicitly classified into three tiers in `docs/architecture.md`:
- **Tier 1 (stable public):** `opcua`, `server`, `ua`, `id`, `monitor`, `errors`
- **Tier 2 (advanced public):** `uacp`, `uasc`, `uapolicy`, `logger`, `schema/` (data files), `server/attrs`, `server/refs`
- **Tier 3 (internal):** `internal/schema`, `internal/stats`, `internal/testutil`, `internal/goname`, `internal/cmd/gen`

#### Panic discipline

- Three panics in `server.New` replaced with error returns (XML unmarshal, namespace assertion, node set import).
- Panic in `monitor/subscription.go` goroutine replaced with `sendError`.
- All remaining panics audited and documented as justified (`Must*` helpers, init-time registration, or internal invariants).

#### Unified config semantics

Client and server option patterns now follow the same model: `type Option func(*config) error` with error aggregation. Invalid configurations fail explicitly instead of being silently ignored.

#### Code generation documentation

Generation flow documented in `CONTRIBUTING.md` with a table mapping each generator to its inputs and outputs.

### Migration guide

1. **`server.New`** — add error handling: `srv, err := server.New(opts...)`.
2. **`schema` import** — replace `schema.UANodeSet` + `xml.Unmarshal` + `ImportNodeSet` with `srv.ImportNodeSetXML(data)`.
3. **`stats` import** — remove direct imports of `stats`; the package is now internal.
4. **`testutil` import** — remove direct imports of `testutil`; the package is now internal.
5. **Relocated helpers** — update imports to use `id.AggregateType`, `ua.SelectEndpoint`, `ua.ReferenceTypeDisplayName`, etc. The root package wrappers have been removed.

---

## v1.0.0

**Date:** 2026-03-24
**Previous release:** v0.1.15

### Summary

Makes all generated Go identifiers fully idiomatic by removing spec-derived underscore names from exported constants, fields, and symbols. This is a **breaking change** — all exported identifiers containing underscores have been renamed to CamelCase, and `id.Name()` now returns OPC UA spec names instead of Go identifier spellings.

### Breaking changes

#### Identifier renames

All exported generated identifiers now use idiomatic Go CamelCase without underscores. Approximately 14,600 `id` package constants, plus status code constants and schema struct fields, have been renamed.

Common rename patterns:

| Old name | New name |
|----------|----------|
| `id.ServerType_ServerArray` | `id.ServerTypeServerArray` |
| `id.Server_ServerStatus_CurrentTime` | `id.ServerServerStatusCurrentTime` |
| `id.AggregateFunction_Average` | `id.AggregateFunctionAverage` |
| `id.WellKnownRole_Anonymous` | `id.WellKnownRoleAnonymous` |
| `id.FindServersRequest_Encoding_DefaultBinary` | `id.FindServersRequestEncodingDefaultBinary` |
| `StatusGoodEdited_DependentValueChanged` | `StatusGoodEditedDependentValueChanged` |

#### Go initialism normalization

Standard Go initialisms are now consistently applied across all generators:

| Token | Normalized |
|-------|-----------|
| `Id` | `ID` |
| `Uri` | `URI` |
| `Url` | `URL` |
| `Xml` | `XML` |
| `Json` | `JSON` |
| `Guid` | `GUID` |
| `Tcp` | `TCP` |
| `Tls` | `TLS` |
| `Http` | `HTTP` |
| `Https` | `HTTPS` |
| `Dns` | `DNS` |
| `Uadp` | `UADP` |

#### `id.Name()` returns spec names

`id.Name()` now returns the original OPC UA specification name (with underscores) instead of the Go identifier spelling:

```go
id.Name(2005) == "ServerType_ServerArray"  // was: "ServerTypeServerArray"
```

#### Schema struct field renames

`schema/uaNodeSet.go` struct fields and types updated to use Go initialisms:
- `NodeIdAttr` → `NodeIDAttr`
- `TransactionIdAttr` → `TransactionIDAttr`
- `UriTable` → `URITable`
- `NodeId` → `NodeID`
- `NodeIdAlias` → `NodeIDAlias`

XML tags are unchanged — wire format compatibility is preserved.

### New features

#### Shared naming formatter (`internal/goname`)

All code generators now use a single shared naming formatter (`internal/goname.Format`) that:
- Removes underscores and applies CamelCase conversion.
- Normalizes all standard Go initialisms.
- Validates generated identifiers.

#### Collision detection

The `cmd/id` generator now detects naming collisions (where distinct spec names would normalize to the same Go identifier) and fails with a clear error. No collisions exist in the current OPC UA specification.

### Lint and quality

- **ST1003 exclusion removed** — The `.golangci.yml` exclusion for `ST1003` on generated files and `schema/` has been removed. All generated code now passes staticcheck without exceptions.
- **ST1016** — Fixed inconsistent receiver name `n` → `s` on `StatusCode.Error()`.
- **ST1021** — Fixed `AttributeID` type comment format.

### Migration guide

This release contains no compatibility aliases. Update all references mechanically:

1. Replace `id.Foo_Bar_Baz` with `id.FooBarBaz` (remove all underscores).
2. Replace `StatusFoo_Bar` with `StatusFooBar`.
3. Update any code using `id.Name()` that expected Go-style names — it now returns spec-style names with underscores.
4. Update `schema.NodeIdAttr` → `schema.NodeIDAttr` and similar field references.

---

## v0.1.15

**Date:** 2026-03-24
**Previous release:** v0.1.14

## Summary

Renames the Go module from `github.com/otfabric/opcua` to `github.com/otfabric/go-opcua`, migrates CI and release workflows to shared reusable workflows, upgrades Go and all dependencies, expands the linter configuration, and fixes all lint issues across the codebase.

## Module rename

- **Go module** — `github.com/otfabric/opcua` → `github.com/otfabric/go-opcua`. All import paths across the entire codebase (source, tests, examples, commands, documentation) are updated accordingly.
- **Retract directives removed** — The `retract` block referencing old `otfabric/opcua` tags (v0.7.2, v0.2.4, v0.2.5) has been dropped since it no longer applies to the new module path.

## Go and dependency upgrades

- **Go version** — `go 1.23` → `go 1.25.0`.
- **testify** — v1.10.0 → v1.11.1.
- **golang.org/x/exp** — updated to 2026-03-12 snapshot.
- **golang.org/x/term** — v0.27.0 → v0.41.0.
- **golang.org/x/sys** — v0.28.0 → v0.42.0.

## GitHub workflows

- **CI** (`ci.yml`) — Replaced the inline multi-job workflow (test matrix, coverage, lint, integration) with a single call to the shared reusable workflow `otfabric/.github/.github/workflows/go-ci.yml@v2`. Test matrix now targets Go 1.25 and 1.26. Triggers on pushes and PRs to all branches.
- **Release** (`release.yml`) — Replaced the inline release workflow (version detection, tag creation, release notes extraction, GitHub release creation) with a call to the shared reusable workflow `otfabric/.github/.github/workflows/go-package-release.yml@v2`. Supports a `release-name-prefix` parameter (`go-opcua`).
- **goreleaser** — Removed `.goreleaser.yml` and the `make release` target. Release is now handled entirely by the shared workflow.

## Linting and code quality

- **golangci-lint** (`.golangci.yml`) — Expanded from 2 linters (`govet`, `unparam`) to 8 linters with all checks enabled: `errcheck`, `govet`, `ineffassign`, `staticcheck` (full SA/S/ST/QF), `misspell`, `godot`, `nilerr`, `exhaustive`. Added `gofmt` and `goimports` formatters. No exclusions except ST1003 on generated code (OPC UA spec names use underscores). All issues fixed at the source across code, tests, examples, and cmd/.
- **errcheck** — All unchecked error returns resolved across the entire codebase: `defer` calls wrapped in `defer func() { _ = ... }()`, cleanup `Close()`/`SetDeadline()`/`WriteByte()` calls prefixed with `_ =`, and `xml.Unmarshal`/`ImportNodeSet` in server init now panic on error.
- **godot** — Trailing periods added to all comments (production code, tests, examples, generated template).
- **misspell** — `occured` → `occurred`, `taht` → `that`.
- **ineffassign** — Removed 3 dead assignments to `action` in `client.go` reconnect logic.
- **exhaustive** — Added missing switch cases for `reconnectAction`, `ConnState`, and `crypto.Hash`.
- **goimports** — Fixed import grouping in `cmd/id/main.go` and `uacp/endpoint_test.go`.
- **staticcheck QF** — Applied 44 quickfix suggestions: removed redundant embedded field selectors (`.Header.`, `.PublicKey.`, `.MessageHeader.`, `.SequenceHeader.`, `.TCPConn.`), replaced `strings.Replace(..., -1)` with `strings.ReplaceAll`, converted untagged switches to tagged switches, and lifted loop conditions.
- **staticcheck ST1003** — Renamed 25 underscore-named variables and methods to camelCase across `client_sub.go`, `subscription.go`, `server/`, and examples (e.g. `recreate_delete` → `recreateDelete`, `matching_endpoints` → `matchingEndpoints`).
- **staticcheck ST1016** — Standardized inconsistent receiver names across 10 files (`server/namespace_map.go`, `server/namespace_node.go`, `server/nodeset2_import.go`, `ua/expanded_node_id.go`, `ua/status_gen.go`, `uapolicy/`, `uasc/`).
- **staticcheck ST1020/ST1021** — Fixed 48 exported method comments to start with the method name and 5 exported type comments to start with the type name, following Go doc conventions.
- **staticcheck ST1000** — Added package doc comments to all 11 packages that lacked them (`id`, `logger`, `monitor`, `schema`, `server`, `server/attrs`, `server/refs`, `testutil`, `tests/go`, `tests/python`, `cmd/service/goname`).
- **.gitignore** — Reorganized with categories (Python, binaries, IDE, coverage, certificates). Added `/bin/`, `cover.*`, `coverage.*`, `*.out`. Removed `vendor/`, `build/`, `dist/`, `__debug*`.
- **Makefile** — Removed the `release` target (goreleaser). Added `coverage` to the `check` target.

## Documentation

All references to `otfabric/opcua` updated to `otfabric/go-opcua` across:

- **README.md** — Title, badges, `go get` command, import paths, overview text.
- **API.md** — Module path and `pkg.go.dev` links.
- **CONTRIBUTING.md** — Title and `git clone` URL.
- **docs/architecture.md**, **docs/client-guide.md**, **docs/security.md**, **docs/server-guide.md** — Module path references and import paths in code examples.

## Files changed

196 files changed, +1130 / -1235 lines.

---

## v0.1.14

**Date:** 2026-03-12
**Previous release:** v0.1.13

## Summary

New unified github release flow.

---

## v0.1.13

**Date:** 2026-03-11
**Previous release:** v0.1.12

## Summary

Implements `fmt.Stringer` for `*ua.LocalizedText` and `*ua.QualifiedName` so that `fmt.Sprintf("%v", v)` and logging print readable text instead of struct literals (e.g. `&{3 en-US Siemens AG}`).

## LocalizedText and QualifiedName display

- **`(*ua.LocalizedText).String() string`** — Returns the text; if locale is set, returns `"locale: text"` (e.g. `"en-US: Siemens AG"`). Nil receiver returns `""`.
- **`(*ua.QualifiedName).String() string`** — Returns the name only when namespace is 0, otherwise `"ns:name"` (e.g. `"2:Temperature"`). Nil receiver returns `""`.

CLI and tools that print variant values, display names, or browse names no longer need custom formatting for these types; `%v` and default logging use the new methods.

---

## v0.1.12

**Date:** 2026-03-11
**Previous release:** v0.1.11

## Summary

Adds batch read (`ReadMulti`) and client-side recursive browse (`BrowseWithDepth`) APIs, with tests and documentation updates.

## ReadMulti (batch read)

- **`Client.ReadMulti(ctx, items []ReadItem, opts ...ReadMultiOption) ([]ReadResult, error)`** — Batch read of N node/attribute pairs in one or more OPC UA Read calls. Chunks by `DefaultReadMultiChunkSize` (32) or by `ReadMultiWithChunkSize(n)`. Results match input order; each result has `DataValue` and `StatusCode`. Use for large subtrees or bulk export to reduce round-trips.
- **`ReadItem`** — NodeID, AttributeID, optional IndexRange.
- **`ReadResult`** — DataValue and StatusCode per item.
- Empty or nil `items` returns `(nil, nil)` without sending a request.

## BrowseWithDepth (client-side recursive browse)

- **`Node.BrowseWithDepth(ctx, opts BrowseWithDepthOptions) ([]BrowseWithDepthResult, error)`** — Client-side recursive browse up to `opts.MaxDepth`. Returns a flat slice of references with depth (no iterator). Options: MaxDepth, RefType, Direction, NodeClassMask, IncludeSubtypes. Standard OPC UA Browse is single-level; recursion is implemented via multiple Browse calls (same as Walk/WalkLimit).
- **`BrowseWithDepthOptions`** — MaxDepth (-1 = unlimited), RefType (0 = HierarchicalReferences), Direction, NodeClassMask, IncludeSubtypes.
- **`BrowseWithDepthResult`** — Ref (*ua.ReferenceDescription) and Depth.

## Tests and documentation

- **Tests:** `TestReadMulti`, `TestReadMultiChunking`, `TestReadMultiEmptyItems`, `TestReadMultiMixedAttributes`, `TestNodeBrowseWithDepth`, `TestNodeBrowseWithDepthMaxDepthZero`, `TestNodeBrowseWithDepthInverse`.
- **API.md:** ReadMulti and BrowseWithDepth types and behavior; empty-items note.
- **README.md:** Reading and Browsing rows mention ReadMulti and BrowseWithDepth.
- **docs/client-guide.md:** "Batch read (ReadMulti)" and "Recursive browse (BrowseWithDepth)" sections with examples.

---

## v0.1.11

**Date:** 2026-03-11
**Previous release:** v0.1.10

## Summary

Exposes the remaining standard-node name lookups in the `id` package and adds
a type-definition display helper so browse UIs can show "PropertyType",
"FolderType", and other well-known names instead of raw NodeIDs.

## Type definition display

- **`id.VariableTypeName(id uint32) string`** — Standard name for well-known VariableTypes in namespace 0 (e.g. 68 → "PropertyType", 63 → "BaseDataVariableType"), or "" if unknown.
- **`id.ObjectTypeName(id uint32) string`** — Same for ObjectTypes (e.g. 58 → "BaseObjectType", 61 → "FolderType").
- **`TypeDefinitionDisplayName(typeDefID *ua.NodeID) string`** — Root package: tries VariableTypeName then ObjectTypeName; otherwise returns the NodeID string. Use when displaying type definition columns (e.g. browse) so "PropertyType" is shown instead of "i=68".

## id package: Object, Variable, Method names

All seven name maps used by `id.Name(id)` are now exposed as dedicated helpers:

- **`id.ObjectName(id uint32) string`** — Well-known Object nodes (e.g. 84 → "RootFolder", 85 → "ObjectsFolder", 2253 → "Server").
- **`id.VariableName(id uint32) string`** — Well-known Variable nodes (e.g. 2256 → "Server_ServerStatus", 2258 → "Server_ServerStatus_CurrentTime").
- **`id.MethodName(id uint32) string`** — Well-known Method nodes (e.g. 11492 → "Server_GetMonitoredItems").

Together with existing `DataTypeName`, `ReferenceTypeName`, `VariableTypeName`, and `ObjectTypeName`, callers can resolve standard names by node class when displaying NodeIDs (e.g. in browse or diagnostics).

---

## v0.1.10

**Date:** 2026-03-11
**Previous release:** v0.1.9

## Summary

Adds type and status display helpers, namespace-qualified path resolution,
symbolic node name lookup, TCP-only dial for diagnostics, and documentation
improvements for path semantics and CSV/JSON consistency.

## DataType display names

- **`id.DataTypeName(id uint32) string`** — Returns the standard OPC UA name for well-known DataTypes in namespace 0 (e.g. 10 → "Float", 12 → "String", 294 → "UtcTime"), or "" if unknown.
- **`DataTypeDisplayName(dataTypeID *ua.NodeID) string`** — Convenience in the root package: standard name for known ns=0 DataTypes, otherwise the NodeID string. Use to normalize type rendering (e.g. "Float" instead of "i=10").

## Status code helpers

- **`StatusCode.Symbol() string`** — Short symbolic name only (e.g. "Good", "BadServiceUnsupported"), stripping the "Status" prefix. Use for compact status rendering instead of `Error()`.
- **`StatusCode.Uint32() uint32`** — Raw 32-bit value for consistent CSV/JSON serialization.

## Variant array

- **`Variant.IsArray() bool`** — Returns true if the variant value is an array (one- or multi-dimensional). `ArrayDimensions()` was already present (returns `[]int32`).

## Connection diagnostics

- **`uacp.DialTCP(ctx, endpoint) (net.Conn, error)`** — TCP-only connect to the endpoint host:port; no OPC UA HEL/ACK or secure channel. Caller must close the returned connection. Use for TCP reachability checks (e.g. ping) without creating a session.

## Path resolution

- **Path semantics docs** — Godoc and API.md/client-guide now state start node, namespace handling, and error behavior for `NodeFromPath`, `NodeFromPathInNamespace`, `Node.TranslateBrowsePathInNamespaceToNodeID`, and `Node.TranslateBrowsePathsToNodeIDs`.
- **`Client.NodeFromQualifiedPath(ctx, path) (*Node, error)`** — Parses namespace-qualified path syntax `ns:segment.ns:segment` (e.g. `0:Server.0:ServerStatus`, `2:DeviceSet.4:PLC_Name`) and calls TranslateBrowsePathsToNodeIDs with per-segment namespace indices. Start node is Objects folder.

## Symbolic node names

- **`id.NodeIDByName(name string) (uint32, bool)`** — Reverse lookup from well-known standard node names (namespace 0) to numeric ID. Names include full spec names ("Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime") and short aliases: "CurrentTime" → 2258, "ServerStatus" → 2256, "Objects" → 85.
- **`StandardNodeID(name string) (*ua.NodeID, bool)`** — Root package helper: returns `ua.NewNumericNodeID(0, id)` when `id.NodeIDByName(name)` succeeds. Use for CLI or config that accepts symbolic names (e.g. `get value -n CurrentTime` instead of `-n i=2258`).

## CSV/JSON and canonical form

- **`ua.NodeID.String()`** — Godoc and API.md now state that output is canonical (namespace 0 omitted; round-trip with `ParseNodeID`).
- **`StatusCode.Uint32()`** — See above; supports consistent numeric serialization.

## Endpoint troubleshooting

- **Verification** — `EndpointDescription` fields `TransportProfileURI`, `ServerCertificate`, and `Server.ApplicationURI` are already exposed and used; no code change; documented for endpoint output tooling.

## Documentation

- README.md path resolution row updated with `NodeFromQualifiedPath` and symbolic names (`StandardNodeID`, `id.NodeIDByName`). Quickstart comment added for `StandardNodeID("CurrentTime")`.
- docs/client-guide.md: connection diagnostics (ping) section, path semantics table with `NodeFromQualifiedPath`, and symbolic node names (`StandardNodeID`) subsection.
- API.md: all new functions and tables (path semantics, DataType/StatusCode/Variant, uacp.DialTCP, id.NodeIDByName, StandardNodeID, NodeID canonical, StatusCode.Uint32).

---

## v0.1.9

**Date:** 2026-03-11
**Previous release:** v0.1.8

## Summary

Adds an API to resolve well-known reference type NodeIDs to their standard
names (e.g. "HasComponent", "Organizes") so tools like `opcuactl browse refs` can
show names instead of raw NodeIDs (i=47, i=46) in the reference type column.

## Reference type display names

- **`id.ReferenceTypeName(id uint32) string`** — Returns the standard OPC UA
  name for a well-known reference type in namespace 0 (e.g. 47 → "HasComponent",
  35 → "Organizes"), or "" if unknown.
- **`ReferenceTypeDisplayName(refTypeID *ua.NodeID) string`** — Convenience
  helper in the root package: returns the standard name when the NodeID is in
  namespace 0 and known, otherwise returns the NodeID string. Use when
  displaying the reference type column in browse refs or similar UIs.

Clients can call `ReferenceTypeDisplayName(ref.ReferenceTypeID)` when rendering
`ReferenceDescription` rows to show "HasComponent" instead of "i=47".

---

## v0.1.8

**Date:** 2026-03-11
**Previous release:** v0.1.7

## Summary

Adds subscription sampling interval control and a deduplicating walk API:
callers can set the server-side sampling rate for monitored items independently
of the publishing interval, and can walk the address space with each node
yielded at most once.

## Client: Subscription sampling interval

- **`SubscriptionBuilder.SamplingInterval(d time.Duration)`** — Sets the
  requested sampling interval for monitored items added by `Monitor` or
  `MonitorEvents`. The server samples at this rate (converted to milliseconds
  on the wire); the subscription's publishing interval still controls how often
  notifications are sent to the client. If not set or zero, the server uses
  the fastest practical rate (unchanged from before).

## Browsing: WalkLimitDedup

- **`Node.WalkLimitDedup(ctx, maxDepth)`** — Same as `WalkLimit` but yields
  each node at most once, keyed by NodeID. When a node is reachable via
  multiple hierarchical paths, only the first occurrence (by traversal order) is
  yielded. Callers no longer need to maintain their own visited set to avoid
  duplicate nodes.

---

## v0.1.7

**Date:** 2026-03-11
**Previous release:** v0.1.6

## Summary

Fixes a **regression introduced in v0.1.5** that broke connection establishment
(e.g. `opcuactl browse` or any client connecting with `--security-mode None`).
The generic encoder no longer skips nil optional fields; nil is now encoded as
the correct OPC UA null representation so message layout stays valid.

## Bug fix: Encoder regression (nil optional fields)

In v0.1.5 we changed `ua/encode.go` to skip nil pointer fields entirely
(return `nil, nil`) to avoid calling `BinaryEncoder.Encode()` on a nil receiver.
That broke the OPC UA binary wire format: the server expects **all fields at
fixed offsets**. Omitting bytes for nil optional fields corrupted the message
layout and caused "failed to open a new secure channel" / EOF during connect.

- **`ua/encode.go`** — Reverted the early-exit that returned no bytes for any
  nil pointer. Nil optional fields are no longer skipped.
- **`ua/qualified_name.go`** — When the receiver is nil, `Encode()` now
  returns the OPC UA null QualifiedName encoding (namespace 0 + string length
  -1), i.e. 6 bytes, so struct field offsets are preserved.
- **`ua/node_id.go`** — When the receiver is nil, `Encode()` now returns the
  OPC UA null NodeID (two-byte form, id=0), i.e. 2 bytes, so optional NodeID
  fields keep a fixed layout.

Connection establishment and all messages with optional `*QualifiedName` or
`*NodeID` fields now encode correctly.

## Other changes

- **testutil**: Test client uses longer `DialTimeout` and `RequestTimeout`
  (30s) so tests have time to connect under load (e.g. race detector).
- **examples/browse**: Test uses `testutil.NewTestServer` / `NewTestClient`
  (dynamic port, shared timeouts); removed unused `join` helper (lint).

---

## v0.1.6

**Date:** 2026-03-11
**Previous release:** v0.1.5

## Summary

Improves error messages when the server closes the connection (EOF) during
subscription or monitored-item creation. Callers (e.g. `monitor event` /
`monitor alarm` against servers that do not support event subscriptions) now
see a clear hint instead of a raw "EOF".

## Client: EOF handling in subscription path

When the server closes the connection instead of returning a service fault
(e.g. WAGO PLC not supporting OPC UA event or alarm subscriptions), the SDK
previously surfaced **io.EOF** with no context.

- **`Subscription.Monitor()`** — If the request returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  monitored items (server may not support event or alarm subscriptions)".
  Callers can still use `errors.Is(err, io.EOF)`.
- **`Client.Subscribe()`** — If `CreateSubscription` returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  subscription (server may not support subscriptions)".

Documentation and doc comments for `Monitor` and `SubscriptionBuilder.Start`
note that connection-close errors may wrap `io.EOF` with this hint.

---

## v0.1.5

**Date:** 2026-03-11
**Previous release:** v0.1.4

## Summary

Adds the depth-limited `WalkLimit` API for browsing the address space and fixes a
nil pointer dereference when encoding `HistoryReadRequest` with optional
`DataEncoding` (e.g. `history value` / `history event` commands).

## Client: WalkLimit (depth-limited walk)

- **`Node.WalkLimit(ctx, maxDepth)`** — Same as `Walk` but stops recursing when
  depth reaches `maxDepth`. The node at `maxDepth` is still yielded. Use for
  "find node", "find type", or "browse tree" style tools to avoid unbounded
  traversal (e.g. a `-depth` flag on the CLI). If `maxDepth < 0`, depth is
  unlimited (equivalent to `Walk`).
- **`Node.Walk(ctx)`** — Unchanged; now implemented via `WalkLimit(ctx, -1)`.

## Bug fix: HistoryReadRequest encoding with nil DataEncoding

Encoding a `HistoryReadRequest` whose `HistoryReadValueID` entries had
`DataEncoding == nil` caused a panic in `QualifiedName.Encode()` (nil pointer
dereference). This affected `HistoryReadRawModified`, `HistoryReadEvent`, and
other history read calls when the optional `DataEncoding` field was omitted.

- **`ua/encode.go`** — Nil pointer fields that implement `BinaryEncoder` are
  now encoded as no bytes instead of calling `Encode()` on a nil receiver.
- **`ua/qualified_name.go`** — `QualifiedName.Encode()` guards against a nil
  receiver and returns `(nil, nil)`.

---

## v0.1.4

**Date:** 2026-03-11
**Previous release:** v0.1.3

## Summary

Adds server certificate validation infrastructure and two new client options:
`InsecureSkipVerify()` and `TrustedCertificates()`. When `SecurityMode` is
`Sign` or `SignAndEncrypt`, the client now validates the server certificate by
default. Use `TrustedCertificates()` to trust self-signed servers or private
CAs, or `InsecureSkipVerify()` to disable validation for development.

## Client: Server Certificate Validation

The SDK previously performed no X.509 trust-chain validation of the server's
certificate — it parsed the certificate only to extract the RSA public key for
signing and encryption. This release adds opt-in validation and a deprecation
path toward secure-by-default behavior.

### New Options

| Option | Description |
|--------|-------------|
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA or self-signed certificates to the trust pool. Merged with the system CA pool. Enables full validation (chain, expiry, key usage). |
| `InsecureSkipVerify()` | Disable all server certificate validation. Certificate is still parsed for its public key. **INSECURE — development only.** |

### Validation Checks (when `TrustedCertificates` is configured)

| Check | Description |
|-------|-------------|
| **Trust chain** | Verifies the certificate chains to a trusted root CA (system pool + user-supplied certs) |
| **Expiration** | Rejects expired or not-yet-valid certificates |
| **Key usage** | Warns if `DigitalSignature` / `KeyEncipherment` bits are missing |

### Validation Points

Server certificate validation runs at two points in the connection flow:

- **`Dial()`** — validates `RemoteCertificate` (set via `SecurityFromEndpoint`
  or `RemoteCertificate` option) after `OpenSecureChannel`
- **`CreateSession()`** — validates `ServerCertificate` from the
  `CreateSessionResponse` after verifying the session signature

### Behavioral Summary

| Scenario | Certificate check | How to configure |
|----------|------------------|------------------|
| `SecurityMode == None` | No certificate exchanged, nothing to validate | Default |
| `Sign` or `SignAndEncrypt` (default) | Full validation: chain, expiry, key usage | Default |
| `Sign` or `SignAndEncrypt` + self-signed server | Fails unless cert added to trust pool | `TrustedCertificates(serverCACert)` |
| `Sign` or `SignAndEncrypt` + skip verify | No validation, just parse for public key | `InsecureSkipVerify()` |

### Config Changes

Added `serverCertValidator` to the internal `Config` struct:

```go
type serverCertValidator struct {
    insecureSkipVerify bool
    trustedCerts       *x509.CertPool
    trustedCertsList   []*x509.Certificate
}
```

## Documentation

- **API.md** — added `InsecureSkipVerify()` and `TrustedCertificates()` to the
  options table
- **docs/security.md** — new "Server Certificate Validation" section with
  usage examples, trust configuration, and dev-mode skip
- **docs/client-guide.md** — added new options to the client options table
- **README.md** — updated security feature description

## Files Changed

6 files changed. Hand-written Go: 3 files (config.go, client.go, config_test.go).

---

## v0.1.3

**Date:** 2026-03-11
**Previous release:** v0.1.2

## Summary

Patch release with a small improvement for anonymous authentication when using
the client (e.g. `--auth anonymous` in example CLIs).

## Client: anonymous auth without pre-set PolicyID

When `AuthAnonymous()` is applied before the server's endpoints are known (for
example when using `--auth anonymous` on the command line), the
`AnonymousIdentityToken` is created without a policy ID. The client now
resolves the correct anonymous user token policy from the server's advertised
endpoints after `CreateSession` and sets it on the token, so anonymous
authentication works correctly without requiring endpoint or security options
to be applied first.

---

## v0.1.2

**Date:** 2026-03-11
**Previous release:** v0.1.1

## Summary

This release brings the OPC UA schema files up to the latest OPC Foundation
specification and adds a security layer to the server: access restrictions,
role-based access control (RBAC), and session identity-to-role mapping. Three
new code generators were added and the existing service generator was hardened
to skip JSON-only types.

## Schema Update

Updated all schema files from the OPC Foundation UA-Nodeset repository:

- **NodeIds.csv** — refreshed; thousands of new/renamed node identifiers
- **StatusCode.csv** — new status codes added
- **Opc.Ua.Types.bsd** — new structured types and enumerations
- **Opc.Ua.NodeSet2.xml** — expanded node set with role permissions
- **Opc.Ua.PredefinedNodes.xml** — added (new file, used by .NET tooling)
- **AttributeIds.csv** — added (new file, 27 attribute IDs)
- **ServerCapabilities.csv** — added (new file, 39 capability identifiers)
- **Opc.Ua.NodeIds.permissions.csv** — added (new file, 557 default permission entries)

## New Code Generators

| Generator | Input | Output | Description |
|-----------|-------|--------|-------------|
| `cmd/attrid` | `AttributeIds.csv` | `ua/enums_attribute_id_gen.go` | AttributeID enum constants (replaces hand-maintained block) |
| `cmd/capability` | `ServerCapabilities.csv` | `ua/server_capabilities_gen.go` | 39 `ServerCapability*` constants, `KnownCapabilities` map, `ValidateCapability()` |
| `cmd/permissions` | `Opc.Ua.NodeIds.permissions.csv` | `server/default_permissions_gen.go` | 557 default node permission entries for RBAC |

## Code Generation Fixes

- **Service generator** (`cmd/service`): added `-nodeids` flag and
  `filterByBinaryEncoding()` to skip types that only have a JSON encoding in
  the spec — prevents generating codec registrations for types that cannot be
  serialized over OPC UA Binary.
- **`generate.sh`**: updated to run the three new generators; added descriptive
  header comment; fixed shellcheck warnings (SC2035, SC2086).

## Server Security & RBAC

### Access Restrictions (OPC UA Part 3 §5.2.11)

- `checkAccessRestrictions()` enforces `SigningRequired` and
  `EncryptionRequired` bits against the secure channel's security mode.
- `checkAccessRestrictionsForBrowse()` only enforces restrictions when the
  `ApplyRestrictionsToBrowse` bit is set.
- Wired into Read, Write, Browse, and Call service handlers.
- Added `SecurityMode()` getter on `SecureChannel`.

### Role-Based Access Control

- **`RBACAccessController`** — checks node `rolePermissions` against the
  session's assigned roles for Read, Write, Browse, and Call operations.
  Nodes without role permissions are unrestricted.
- **`RoleMapper`** function type and `DefaultRoleMapper` — maps identity tokens
  to well-known role NodeIDs (anonymous → `Anonymous`, others →
  `AuthenticatedUser`). Configurable via `WithRoleMapper()` server option.
- **Session identity tracking** — `ActivateSession` now extracts the
  `UserIdentityToken` and resolves roles through the configured `RoleMapper`.

### Well-Known Roles

- New `ua/well_known_role.go`: 12 well-known roles from the spec (Anonymous,
  AuthenticatedUser, Observer, Operator, Engineer, Supervisor, ConfigureAdmin,
  SecurityAdmin, SecurityKeyServer, SecurityKeyServerAdmin,
  SecurityKeyServerAccess, SecurityKeyServerPush).
- Each role has `String()`, `NodeID()` methods and lookup via `RoleByName` map.

### Node RolePermissions

- Server `Node` stores `[]*ua.RolePermissionType` resolved from the generated
  default permissions at import time via `resolveRolePermissions()`.
- `AttributeIDRolePermissions` and `AttributeIDUserRolePermissions` are served
  from the node as `[]*ua.ExtensionObject`.

## Server Capabilities Expansion

- `OperationalLimits` expanded from 1 field to 12 (all defaulting to 32):
  `MaxNodesPerRead`, `MaxNodesPerWrite`, `MaxNodesPerBrowse`,
  `MaxNodesPerMethodCall`, `MaxNodesPerRegisterNodes`,
  `MaxNodesPerTranslateBrowsePathsToNodeIDs`, `MaxNodesPerNodeManagement`,
  `MaxMonitoredItemsPerCall`, `MaxNodesPerHistoryReadData`,
  `MaxNodesPerHistoryReadEvents`, `MaxNodesPerHistoryUpdateData`,
  `MaxNodesPerHistoryUpdateEvents`.
- Server capability nodes generated dynamically from the struct.

## Code Quality

- Enabled `unparam` linter in `.golangci.yml` — `make check` now catches
  unused parameters.
- Fixed 4 genuine unused-parameter issues in `secure_channel.go` and
  `race_test.go`:
  - `newSecureChannel`: removed 3 dead parameters (`secureChannelID`,
    `sequenceNumber`, `securityTokenID`) — values were only used by
    `NewServerSecureChannel` which sets them on `openingInstance` directly.
  - `sendResponseWithContext`: wired up `ctx` for cancellation checks and
    write deadlines.
  - `mergeChunks`: removed always-nil error return.
  - `race_test.go`: removed unused goroutine parameter.

## Generated Code Changes

All generated files were regenerated from the updated schema:

- `id/` — NodeID constants (DataType, Method, Object, ObjectType, ReferenceType,
  Variable, VariableType)
- `ua/enums_gen.go` — updated/new enum types
- `ua/enums_strings_gen.go` — stringer output for all enums
- `ua/extobjs_gen.go` — extension object codecs
- `ua/register_extobjs_gen.go` — filtered to binary-encoded types only
- `ua/status_gen.go` — new status codes
- `connstate_strings_gen.go` — regenerated

## Files Changed

52 files changed, ~232k insertions, ~53k deletions (bulk is schema XML and
generated code). Hand-written Go: 19 files, +866 / -73 lines.
