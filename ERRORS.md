# Errors: otfabric/go-opcua

How go-opcua reports failures. For method signatures see [API.md](API.md).
Client usage examples: [docs/client-guide.md](docs/client-guide.md).

OPC-UA has two related but distinct error surfaces:

1. **Go `error` values** — connection, session, configuration, and transport failures from this library (package [`errors`](errors/)).
2. **Wire `ua.StatusCode`** — outcomes returned by the peer for individual service items (reads, writes, browse results, method calls, …).

Do not treat them as interchangeable.

## Quick reference

| Situation | How it is reported |
|-----------|--------------------|
| Not connected / session or channel closed | Go sentinel (`errors.ErrNotConnected`, `ErrSecureChannelClosed`, …) |
| Bad endpoint, cert, or security config | Go sentinel (`errors.ErrInvalidEndpoint`, …) |
| Transport / dial / timeout at client layer | Go `error` (often wrapping or related to timeout sentinels) |
| Read/write/browse/call item rejected by server | `ua.StatusCode` on the result (`DataValue.Status`, browse status, …) — top-level `error` may still be `nil` |
| Service-level Bad status as a Go error | Some paths return `ua.StatusCode` as an `error` (it implements `error`) |

Prefer:

```go
import (
    "errors"

    "github.com/otfabric/go-opcua"
    opcuaerrors "github.com/otfabric/go-opcua/errors"
    "github.com/otfabric/go-opcua/ua"
)

c, err := opcua.NewClient(endpoint)
if err != nil {
    return err
}
if err := c.Connect(ctx); err != nil {
    if errors.Is(err, opcuaerrors.ErrNotConnected) {
        // reconnect / retry policy
    }
    return err
}

dv, err := c.ReadValue(ctx, nodeID)
if err != nil {
    return err // client/transport failure
}
if dv.Status != ua.StatusOK {
    // server reported a Bad/Uncertain status for this item
    return dv.Status
}
```

## Go sentinel errors

Definitions live in [`errors/sentinel.go`](errors/sentinel.go). Match with `errors.Is`; most are returned wrapped with detail. When wrapping, use `%w`.

### Connection and session

| Sentinel | Meaning |
|----------|---------|
| `ErrAlreadyConnected` | `Connect` or `Dial` on a client that already has a connection |
| `ErrNotConnected` | No secure channel is open to carry the request |
| `ErrSecureChannelClosed` | The secure channel ended while the operation was under way |
| `ErrSessionClosed`, `ErrSessionNotActivated`, `ErrReconnectAborted` | Defined for API stability; the library does not return them at present |

### Configuration

| Sentinel | Meaning |
|----------|---------|
| `ErrInvalidEndpoint` | Endpoint URL does not parse, has an unsupported scheme, no host or a bad port, or does not suit the transport profile |
| `ErrNoCertificate` | The server presented no certificate, or a reverse connection's server certificate is unknown |
| `ErrInvalidPrivateKey` | Private key cannot be parsed or does not suit the policy |
| `ErrInvalidCertificate` | Certificate cannot be parsed, is not a CERTIFICATE PEM block, or fails validation |
| `ErrNoMatchingEndpoint` | No endpoint has the requested policy, mode or transport profile |
| `ErrNoEndpoints` | The endpoint list is empty |
| `ErrInsecureNotAllowed` | No message security without the `InsecureNoSecurity` option |

### Subscriptions

| Sentinel | Meaning |
|----------|---------|
| `ErrSubscriptionNotFound` | Monitor request on a subscription that no longer exists |
| `ErrMonitoredItemNotFound` | Notification or request for an item `monitor` does not hold |
| `ErrInvalidSubscriptionID` | Subscription ID is zero or does not match the notification |
| `ErrSlowConsumer` | A subscriber's channel is full and messages may be dropped; also exported by `monitor` |

### Namespaces and node IDs

| Sentinel | Meaning |
|----------|---------|
| `ErrNamespaceNotFound` | Namespace URI is not in the server's NamespaceArray |
| `ErrInvalidNamespaceType` | The NamespaceArray value is not a string array |
| `ErrInvalidNodeID` | Node ID text or value is malformed |
| `ErrInvalidNamespace` | Namespace in a node ID is out of range, or a URI needs a NamespaceArray that was not given |
| `ErrTypeAlreadyRegistered` | An extension object or type ID is registered twice |

### Codec and responses

| Sentinel | Meaning |
|----------|---------|
| `ErrUnsupportedType` | Value has a Go type the codec or `Variant` does not handle |
| `ErrArrayTooLarge` | Array length exceeds the limit of the codec |
| `ErrUnbalancedArray` | Multi-dimensional Variant slice is not rectangular |
| `ErrInvalidResponseType` | Response has an unexpected type or length |
| `ErrEmptyResponse` | Response carries no results where the request needs one |

### Security

| Sentinel | Meaning |
|----------|---------|
| `ErrUnsupportedSecurityPolicy` | Security policy URI is unknown, or the policy lacks the operation |
| `ErrInvalidSecurityConfig` | Security configuration cannot work, for example a WebSocket listener without a TLS certificate |
| `ErrSignatureValidationFailed` | A signature does not verify |
| `ErrInvalidCiphertext` | Ciphertext has an invalid length or fails authentication |
| `ErrInvalidPlaintext` | Plaintext does not fit the cipher's block or size rules |

### Protocol

| Sentinel | Meaning |
|----------|---------|
| `ErrInvalidMessageType` | UACP or secure channel message type is unknown or unexpected |
| `ErrMessageTooLarge` | Message or chunk exceeds the negotiated or configured limit |
| `ErrMessageTooSmall` | Message is shorter than its header requires |
| `ErrTooManyChunks` | Chunk count exceeds `MaxChunkCount` |
| `ErrInvalidState` | An internal or protocol invariant does not hold: an unsupported ACK version, a sequence number that would reuse a nonce, an inconsistent encrypted secret, a channel without its expected instance or thumbprint |
| `ErrDuplicateHandler` | A response handler is already registered for the request ID |
| `ErrUnknownService` | Request or response type has no service encoding |
| `ErrReverseHelloRejected` | The announced ServerUri or EndpointUrl is not what the client expects, or does not match the server certificate |

### Other packages

| Sentinel | Meaning |
|----------|---------|
| `uapolicy.ErrPFXPassword` | PKCS #12 MAC does not verify or the contents do not decrypt: in practice a wrong password. Also matches `ErrInvalidPrivateKey` |
| `pubsub.ErrActionTimeout` | An Action call got no Done response within its timeout; wraps `ua.StatusBadTimeout` |
| `pubsub.ErrNotRunning` | `PubSub.Ready` on a runtime that is not started or stopped while waiting |
| `pubsub/jsonmsg.ErrDecode` | Malformed input |
| `pubsub/security.ErrPolicyMismatch` | Keys offered for a SecurityGroup with another policy; wraps `ua.StatusBadSecurityPolicyRejected` |
| `pubsub/security.ErrUnknownPolicy` | `PolicyByURI` for an unsupported SecurityPolicyUri |
| `pubsub/security.ErrInvalidKey` | Key material of the wrong length |
| `pubsub/security.ErrInvalidNonce` | MessageNonce of the wrong length |
| `pubsub/security.ErrSignature` | `Verify`: the signature does not match |
| `pubsub/security.ErrNoKeys` | No key for this security token |
| `pubsub/sks.ErrBadResponse` | GetSecurityKeys response without the method's output arguments |
| `pubsub/sks.ErrEndpoint` | `EndpointDialer.Dial` of an element of SecurityKeyServices that is not a pull SKS: nil, no Server, an ApplicationType other than SERVER, or no DiscoveryUrl or EndpointUrl. The errors of its URLs are joined: GetEndpoints, no SignAndEncrypt endpoint of the SecurityPolicyUri, an ApplicationUri other than the ServerUri (`ua.StatusBadServerURIInvalid`), the client or the connect. `NewPuller` fails without a runtime or a Dial |
| `pubsub/transport/eth.ErrNotSupported` | `Open` on an OS other than Linux, macOS or FreeBSD; wraps `errors.ErrUnsupported` |
| `pubsub/uadp.ErrChunkRejected` | `Reassembler.Add` discards a chunk: outside its message, wrong size, duplicate, beyond the limits, or no room. Wrapped with the reason |
| `pubsub/uadp.ErrFiltered` | The Accept callback rejected the message after its header was decoded |
| `pubsub/uadp.ErrMalformed` | Message does not follow the UADP encoding, or `Encode` cannot encode the NetworkMessage |
| `pubsub/uadp.ErrUnsupported` | Valid UADP feature this package does not implement: discovery messages of PubSub Actions, reserved DataSetMessage types |
| `pubsub/uadp.ErrSecurityMode` | Message security weaker than required, or a secured message with no keys to verify it |
| `pubsub/uadp.ErrSecurityChecksFailed` | Invalid security header, bad signature or failed decryption; or `Encode` could not sign or encrypt |
| `pubsub/uadp.ErrNoMetaData` | RawData DataSetMessage whose DataSetMetaData the MetaData callback does not supply |
| `uafx.ErrInspect` | `Inspect` ended because a service call failed, or a node it must browse has a bad status; wraps the error or the status. Deviations of the model are `Report.Findings`, not errors |
| `uafx.ErrCall` | `EstablishConnections` or `CloseConnections` failed: no UAFX Data and AC namespaces, no such Method on the AutomationComponent, a failed service call, a Bad status of the call (wrapped: `errors.As` with a `ua.StatusCode` finds it), or output arguments that do not decode |
| `uafx.ErrCodec` | The arguments of EstablishConnections do not encode or decode: a wrong number or type of arguments, an ExtensionObject of another type, or a body that does not decode |
| `uafx/fxcm.ErrConfig` | A ConnectionConfigurationSet is not valid (`*fxcm.ConfigError` with its Findings, `ua.StatusBadConfigurationError` in the chain), or a file does not decode (`ua.StatusBadTypeMismatch`, Table F.40) or a set does not encode (`ua.StatusBadInvalidArgument`) |
| `uafx/fxcm.ErrManager` | An operation the state of a set does not allow: an edit by another `LockOwner` or a set in Processing (`ua.StatusBadInvalidState`), no `LockOwner` (`ua.StatusBadInvalidArgument`). From a `Manager`: `New` without a Dialer or ApplicationURI (`ua.StatusBadInvalidArgument`); a key without a set (`ua.StatusBadNodeIDUnknown` from `Process`, `ua.StatusBadNoMatch` from `Replace`, `Remove` and `Settle`); `Add` of an existing key (`ua.StatusBadBrowseNameDuplicated`) or beyond MaxConnectionConfigurationSets (`ua.StatusBadResourceUnavailable`); an action outside FxProcessEnum (`ua.StatusBadNotSupported`); `Replace` or `Remove` whose close failed (the StatusCode of the close); a closed Manager (`ua.StatusBadShutdown`). `fxcm.StatusOf` returns the StatusCode. A run does not return errors: its `RunResult` has a `Failure` (FxError and StatusCode, §10.19) per failed endpoint |
| `uafx/fxcm` store | With `Options.Store`: `New` wraps the error of the store (`fxcm: the store: ...`; `fxstore.ErrForeignOwner`, `fxstore.ErrSchema` in the chain). A set change (`Add`, `Replace`, `Remove`, `Update`, `CommitEdit`) whose write definitely did not commit is `ua.StatusBadResourceUnavailable` (also while the store is fenced, `fxstore.ErrFenced` in the chain), one with an unknown outcome `ua.StatusBadInternalError` (library interpretation C3-D13); `Add` of a key a record that does not decode or is not valid holds, or an owed set change adds, is `ua.StatusBadInvalidState`. While a set owes work (`Status.Recovery.Owed`), `Replace`, `Remove` and an `Update` that names it are `ua.StatusBadInvalidState`, and so is every `Process` action while it owes a set change (a `Reconcile` completes it); a run whose owed rollback or owed run end fails is not executed and ends with a `Failure` FxErrorRuntimeError, `ua.StatusBadInvalidState`; so do the endpoints of a run on a server where a call of an earlier run of the set has an unknown outcome (nothing is sent there until it is proven or settled), a call whose intent the fence refuses when it is rechecked, and an endpoint that is not the incarnation its record was made with (CreationTime or ConnectionManagerApplicationUri), which is not closed, adopted or enabled. While a record of it is not valid (`Recovery.Blocked`) or it is fenced by the work of another set (`Recovery.Fenced`), every `Process` action, `Reconcile`, `Replace`, `Remove`, `Update` and `Settle` of it are `ua.StatusBadInvalidState`; so are `CommitEdit` and `DiscardEdit` of an edit whose commit had an unknown outcome, until the Manager has followed the store. A read-only store (`StoreStatus().ReadOnly`) refuses every write with `ua.StatusBadInvalidState`. In a run, a journal write that fails is a `Failure` with FxErrorRuntimeError and the same StatusCodes; a call result that does not prove its outcome (decision C3-D13) fails its Connections with the ambiguous StatusCode, or `ua.StatusBadUnexpectedError` for a result that does not answer the call, and leaves the endpoints Unresolved |
| `uafx/fxcm.ErrSKSConnection` | `RemoteSKS` has no session with the SKS of a set (its Dialer's error wrapped). In a run, every Connection of the set fails with ExternalSksConnectionError (transient); another error of the SKS is ExternalSksProcessingError with the StatusCode of its result, a SecurityGroup that cannot be added (`fxcm.ErrConfig`: `ua.StatusBadConfigurationError` or `ua.StatusBadNotSupported`) ConnectionConfigurationSetInvalid (Part 81 §10.25) |
| `uafx/fxcm.ClientDialer` | `Dial` wraps the error of GetEndpoints, the connect, or no endpoint for the SecurityMode and SecurityPolicyUri (`ua.StatusBadSecurityPolicyRejected`); a ServerUri other than the ApplicationUri of the endpoint is `ua.StatusBadServerURIInvalid` |
| `uafx/fxserver.ErrConnectionManager` | `EnableConnectionManager` cannot serve the ConnectionManager: no CM or Data namespace, no Manager, no FxRoot.ConnectionManager or its Methods on the server, or members it cannot add (wrapped) |
| `uafx/fxserver.ErrConnections` | `EnableConnections` cannot serve the connection Methods: no AC model, no PubSub runtime, no AutomationComponent below FxRoot, or an AutomationComponent without the Methods or their argument declarations, `ConnectionOptions.SecurityKeys` without a Dial; with `ConnectionOptions.Store`, a store that cannot be opened, belongs to another owner (`fxstore.ErrForeignOwner`) or has a newer schema (`fxstore.ErrSchema`), wrapped |
| `uafx/fxserver` persistence (Method results) | With `ConnectionOptions.Store`, EstablishConnections and CloseConnections answer per element: IsPersistent TRUE without a store `Bad_NotSupported` (Part 81 Table 12); IsPersistent TRUE with a CleanupTimeout that is not negative `Bad_InvalidArgument` (C3-D4); a reader or writer that fails the persisted check, or a command on a RemovePending endpoint, `Bad_InvalidState`; a write of the store that definitely did not commit `Bad_ResourceUnavailable`, one with an unknown outcome `Bad_InternalError` (C3-D13), in ConnectionEndpointResult with CreateConnectionEndpointCmd, else EnableCommunicationResult with EnableCommunicationCmd, else CommunicationLinksResult for a SetCommunicationConfigurationCmd with links, else ConnectionEndpointResult (the `Bad_InvalidState` of a RemovePending endpoint follows the same rule); a persisted check that cannot read the configuration `Bad_InvalidState`. The Method status is `Bad_InvalidState` for an AutomationComponent fenced by an unresolved write or an unreadable quarantined record, and for both Methods after `Connections.Close` (`RetryRestore` and `Discard` then return an `ErrQuarantine` error). See [docs/uafx.md](docs/uafx.md#persistence) |
| `server.ErrPubSubChanged` | `PubSubConfigurationUpdate.Revert`: the PubSub configuration changed after the update, which is therefore not undone |
| `server` PubSub store | With `WithPubSubStore`: a change whose write fails is undone and fails with `ua.StatusBadInternalError` (the Methods of Part 14 §9.1.3, CloseAndUpdate, `ChangePubSubConfiguration`, `UpdatePubSubConfiguration`, `Revert`, `PersistPubSubConfiguration`), the error of the store in the chain; one that is not valid without its NotPersisted components fails with `ua.StatusBadConfigurationError`. A restore that fails (the error of the store, `pubsubstore.ErrNamespace`, a stored configuration that is not valid) fails `BuildPubSubModel`, `Start` and every change until it succeeds. `New` refuses `WithPubSubStore(nil)` and `WithPubSubStore` without `WithPubSub` |
| `server/pubsubstore.ErrNamespace` | `LoadPubSubConfiguration`, and so the restore of the server: a stored NodeId in a namespace the server does not have; the error names its URI |
| `server/pubsubstore.ErrClosed` | `StorePubSubConfiguration` of a closed `Store` (with `fxstore.ErrNotCommitted` in the chain), and its `Settle` |
| `server` RoleSet store | With `WithRoleSetStore`: a change of the RoleSet whose write fails is not made and fails with `ua.StatusBadInternalError` (the Methods of OPC 10000-18 §4.2.2 to §4.4.10, a Write of ApplicationsExclude or EndpointsExclude, the `RoleSet` methods), the error of the store in the chain. A restore that fails (the error of the store, `rolestore.ErrNamespace`, a stored role the RoleSet does not take) fails `Start` and every change until it succeeds. `New` refuses `WithRoleSetStore(nil)` and `WithRoleSetStore` without `WithRoleManagement` |
| `server/rolestore.ErrNamespace` | `LoadRoleSet`, and so the restore of the server: a stored role whose NodeId or BrowseName is in a namespace the server does not have; the error names its URI |
| `server/rolestore.ErrClosed` | `StoreRoleSet` of a closed `Store` (with `fxstore.ErrNotCommitted` in the chain), and its `Settle` |
| `uafx/fxserver.ErrModel` | `AddModel` cannot add the UAFX model: a UAFX namespace the server has already, an unknown `Model`, no ApplicationUri, a namespace 1 that is not the ApplicationUri, a DI namespace without the nodes the model refers to, or a NodeSet the server refuses (wrapped) |
| `uafx/fxserver.ErrQuarantine` | `RetryRestore` or `Discard` that cannot act: no store, no quarantined record of that id, a fenced store, a record that does not decode (only `Discard` takes it), or a restore or delete that fails again (wrapped with the cause) |
| `uafx/fxstore.ErrNotCommitted` | An `Apply` that made nothing of its batch durable: the definite "not committed" outcome (`fxstore.OutcomeOf`, `fxstore.AsNotCommitted`). Any other Apply error is an unknown outcome |
| `uafx/fxstore.ErrClosed` | A closed store (wraps `ErrNotCommitted`) |
| `uafx/fxstore.ErrLocked` | `OpenFile` of a directory another `FileStore`, in this process or another, holds |
| `uafx/fxstore.ErrLimit` | A key, value or state over its `Limits`; from `Apply` it wraps `ErrNotCommitted`; from `Domain.Require` it is not owed and does not fence the domain |
| `uafx/fxstore.ErrInvalidKey` | A `Domain` batch with an empty key or the reserved key `meta`; wraps `ErrNotCommitted`; never owed by `Require` |
| `uafx/fxstore.ErrCorrupt` | Stored data that does not decode: the data file of a `FileStore`, or the meta key of a `Domain` |
| `uafx/fxstore.ErrFenced` | A `Domain` write while an earlier write with an unknown outcome is not settled (wraps `ErrNotCommitted`) |
| `uafx/fxstore.ErrForeignOwner` | `OpenDomain` of a namespace another owner wrote |
| `uafx/fxstore.ErrSchema` | `OpenDomain` of a namespace written with a newer schema or meta format |
| `uafx/fxstore/storetest.ErrInjected` | The error of a fault `storetest.Faulty` injects: an unknown Apply outcome, or a Load failure |

Further API errors: package
`server` the condition errors (`ErrConditionRemoved`, `ErrConditionNotAlarm`,
`ErrConditionUnsupport`, `ErrBranchUnknown`, `ErrTooManyBranches`), package
`gds/gdsserver` `ErrClosed` and `ErrUnknownRequest`.

Errors that carry a wire status unwrap to it, so `errors.Is(err, ua.StatusBad…)`
matches them: `*opcua.ServiceError` (a refused request with the
DiagnosticInfo asked for by `opcua.ReturnDiagnostics`), `*gds.Error` (the
certificate management method that failed and its status); the A&C helpers
of the client (`Acknowledge`, `Suppress2`, ...) return the StatusCode of the
method call itself.

## Error types

Match these with `errors.As`.

| Type | Meaning |
|------|---------|
| `*opcua.InvalidResponseTypeError` | A response of another type than the request expects (`Got`, `Want`); `errors.Is(err, errors.ErrInvalidResponseType)` holds for it |
| `*monitor.ItemError` | The server rejected one monitored item of a batch (`NodeID`, `StatusCode`); the other items are still monitored. Unwraps to the StatusCode |
| `*pubsub.ConfigError` | An invalid PubSub configuration (`Path` of the setting, `Msg`); unwraps to `ua.StatusBadConfigurationError` |
| `*jsonmsg.UnsupportedMessageTypeError` | A well-formed JSON message of a type package `pubsub/jsonmsg` does not decode, or the called function does not handle (`MessageType`) |
| `*uamethod.CallError` | A Bad result of a Method called with a contract of package `uamethod` or with package `filetransfer` (`Method` "ObjectType.Name", `Status`, `InputArgumentResults`); unwraps to the StatusCode. In `gds` and `pubsub/remote` the TrustList and PubSubConfiguration file calls stay `*gds.Error` and `*remote.Error` |
| `*uamethod.ArgumentError` | Arguments that do not match the declaration of a Method (`Method`, `Output`, `Index` (-1 for the count), `Name`, `Detail`): `Unpack` of an Input on the server, of an Output on the client. `Status` is `ua.StatusBadArgumentsMissing`, `ua.StatusBadTooManyArguments` or `ua.StatusBadTypeMismatch`, which it unwraps to and `uamethod.StatusOf` returns |
| `*uasc.RequestFault` | How the secure channel reports a service fault that asks for recovery (an invalid session or subscription): the fault (`Err`, which it unwraps to) and the `AuthToken` of the request it answers |

Package documentation: [`errors/doc.go`](errors/doc.go).

## Wire status codes

`ua.StatusCode` is a `uint32` that implements `error`. Common values:

| Code | Meaning |
|------|---------|
| `ua.StatusOK` / `StatusGood` | Success |
| `ua.StatusBadNodeIDUnknown` | Node does not exist |
| `ua.StatusBadAttributeIDInvalid` | Attribute not supported |
| `ua.StatusBadUserAccessDenied` | Insufficient permissions |
| `ua.StatusBadTimeout` | Operation timed out (server-side status) |
| `ua.StatusBadSessionIDInvalid` | Session expired or invalid |
| `ua.StatusBadSecureChannelIDInvalid` | Channel needs renewal |
| `ua.StatusBadUnknownResponse` | Returned by the client: a response that is not an answer to its request, for example one whose number of results differs from the operations of a `ReadMulti`, `ReadValues`, `WriteValues` or `Node.Attributes` request |
| `ua.StatusBadSecurityChecksFailed` | Returned by `Connect`: among others, the endpoints of the CreateSession response differ from the selected endpoint or from the endpoint list it was selected from ([docs/security.md](docs/security.md#auto-detection)) |

Multi-item operations (for example `Read` with several nodes) can return a nil Go `error` with per-item statuses. Always inspect each result’s status.

`errors.Is(err, ua.StatusBad…)` works when the Go error *is* (or unwraps to) that status code. It does **not** inspect `DataValue.Status` fields for you.

## Choosing which to check

1. If the call returned a non-nil Go `error`, handle that first — the request often did not complete as a normal service exchange.
2. If the call returned results, check each item’s `ua.StatusCode` for OPC-UA application outcomes.
3. Use auto-reconnect and retry options for transient connection failures; do not assume a Bad node status means “reconnect”.
