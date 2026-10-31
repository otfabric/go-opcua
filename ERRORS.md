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
| `pubsub/transport/eth.ErrNotSupported` | `Open` on an OS other than Linux, macOS or FreeBSD; wraps `errors.ErrUnsupported` |
| `pubsub/uadp.ErrChunkRejected` | `Reassembler.Add` discards a chunk: outside its message, wrong size, duplicate, beyond the limits, or no room. Wrapped with the reason |
| `pubsub/uadp.ErrFiltered` | The Accept callback rejected the message after its header was decoded |
| `pubsub/uadp.ErrMalformed` | Message does not follow the UADP encoding, or `Encode` cannot encode the NetworkMessage |
| `pubsub/uadp.ErrUnsupported` | Valid UADP feature this package does not implement: discovery messages of PubSub Actions, reserved DataSetMessage types |
| `pubsub/uadp.ErrSecurityMode` | Message security weaker than required, or a secured message with no keys to verify it |
| `pubsub/uadp.ErrSecurityChecksFailed` | Invalid security header, bad signature or failed decryption; or `Encode` could not sign or encrypt |
| `pubsub/uadp.ErrNoMetaData` | RawData DataSetMessage whose DataSetMetaData the MetaData callback does not supply |

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

Multi-item operations (for example `Read` with several nodes) can return a nil Go `error` with per-item statuses. Always inspect each result’s status.

`errors.Is(err, ua.StatusBad…)` works when the Go error *is* (or unwraps to) that status code. It does **not** inspect `DataValue.Status` fields for you.

## Choosing which to check

1. If the call returned a non-nil Go `error`, handle that first — the request often did not complete as a normal service exchange.
2. If the call returned results, check each item’s `ua.StatusCode` for OPC-UA application outcomes.
3. Use auto-reconnect and retry options for transient connection failures; do not assume a Bad node status means “reconnect”.
