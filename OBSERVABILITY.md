# Observability: otfabric/go-opcua

Logging, metrics, server diagnostics and audit events for the OPC-UA client and server.

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

## Server diagnostics

The server keeps the OPC UA diagnostics of Part 5 §6.3.3 live under
`Server.ServerDiagnostics`: ServerDiagnosticsSummary (sessions,
subscriptions, rejected requests, timeouts), the sampling interval,
subscription, session and session security diagnostics arrays, and a
SessionDiagnosticsObject per session. Any OPC UA client can read them; in
process use `Server.ServerDiagnosticsSummary()`. `server.WithServerDiagnostics(false)`
starts with them off, and EnabledFlag (writable by SecurityAdmin and
ConfigureAdmin) switches them at run time.

The client reads them with typed helpers (`Client.ServerDiagnosticsSummary`,
`SessionDiagnostics`, `SubscriptionDiagnostics`, ...). `opcua.ReturnDiagnostics(mask)`
asks the server for DiagnosticInfos on every request; a request the server
rejects then fails with an `*opcua.ServiceError` that carries the resolved
diagnostic. See the [server guide](docs/server-guide.md#server-diagnostics)
and the [client guide](docs/client-guide.md#server-diagnostics).

PubSub has its own diagnostics objects (Part 14 §9.1.11): `PubSub.Diagnostics`
and, in a server, the PublishSubscribe information model. See
[PubSub](docs/pubsub.md).

## Audit events

`server.WithAuditing(true)` (or `Server.SetAuditing` at run time) makes the
server report audit events (Part 5 §6.4.3): an AuditConditionEventType subtype
for every call of a condition method (Part 9 §5.10), the audit events of the
GDS NodeSet when a `gds/gdsserver` Global Discovery Server is attached, and
the events the application reports with `Server.ReportAuditEvent`. They carry
the user and the arguments of the call, so only sessions an
`EventAccessController` allows receive them (the `RBACAccessController`: the
ReceiveEvents permission, which namespace 0 grants to SecurityAdmin). A
client reads them with an event subscription (`opcua.NewAuditConditionEventFilter`,
`ParseAuditConditionEvent`) and tags its own calls with `opcua.WithAuditEntryID`.
