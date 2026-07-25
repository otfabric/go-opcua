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
| Not connected / session or channel closed | Go sentinel (`errors.ErrNotConnected`, `ErrSessionClosed`, …) |
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

Canonical definitions live in [`errors/sentinel.go`](errors/sentinel.go). Groups include:

- Connection / session: `ErrAlreadyConnected`, `ErrNotConnected`, `ErrSecureChannelClosed`, `ErrSessionClosed`, …
- Configuration / security setup: `ErrInvalidEndpoint`, `ErrNoCertificate`, …
- Subscriptions: `ErrSubscriptionNotFound`, `ErrSlowConsumer`, …
- Codec / protocol: `ErrUnsupportedType`, `ErrInvalidMessageType`, …

Match with `errors.Is`. When wrapping, use `%w`.

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
