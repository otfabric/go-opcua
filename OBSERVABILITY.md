# Observability: otfabric/go-opcua

Logging and metrics for the OPC-UA client and server.

## Logging (silent by default)

Logging uses `*slog.Logger`. **By default the library is silent**: client and
server configs use an internal discard handler whose `Enabled` method always
returns `false` (same pattern as go-mms). Nothing is written to
`slog.Default()` unless you opt in.

### Client

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))

c, err := opcua.NewClient(endpoint, opcua.WithLogger(logger))
```

`WithLogger(nil)` restores the silent default.

### Server

```go
s, err := server.New(
    server.EndPoint("localhost", 4840),
    server.SetLogger(logger),
)
```

`SetLogger(nil)` / `WithSlogLogger(nil)` restore the silent default.

## Metrics

Pluggable synchronous callbacks for service-level timing:

- Client: [`ClientMetrics`](metrics.go) via `opcua.WithMetrics`
- Server: [`ServerMetrics`](server/metrics.go) via server options

Callbacks run on the request path and must not block. See
[`examples/metrics`](examples/metrics) for a sample adapter.

| Hook | When |
|------|------|
| `OnRequest` | Before the request is sent / handled |
| `OnResponse` | Successful round-trip |
| `OnError` | Non-timeout failure |
| `OnTimeout` | Client timeout (client metrics only) |

Absence of a metrics implementation is intentional for simple apps; attach one
only when you have a concrete consumer (Prometheus, statsd, …).
