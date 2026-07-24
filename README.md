# otfabric/go-opcua — OPC-UA library for Go

[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-opcua.svg)](https://pkg.go.dev/github.com/otfabric/go-opcua)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-opcua/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-opcua/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/otfabric/go-opcua/graph/badge.svg)](https://codecov.io/gh/otfabric/go-opcua)
[![Release](https://img.shields.io/github/v/release/otfabric/go-opcua?label=release)](https://github.com/otfabric/go-opcua/releases)

A pure Go implementation of the OPC-UA Binary Protocol, providing both **client** and **server** capabilities. No C dependencies, no CGo — just Go.

```sh
go get github.com/otfabric/go-opcua
```

Requires **Go 1.25** or later.

## Overview

otfabric/go-opcua gives you everything needed to interact with OPC-UA servers or build your own:

- **Client** — connect, browse, read/write (including IndexRange), subscribe, call methods, read/update history, Republish/TransferSubscriptions
- **Server** — host namespaces, expose variables, handle methods, emit events (`EmitBaseEvent`), pluggable `HistoryProvider` (default `*Historian` covers raw + optional update/delete/at-time/modified/processed)
- **Security** — six encryption policies, certificate and username/password authentication, server certificate validation with `TrustedCertificates()` and `InsecureSkipVerify()` options; **certificate chains** (leaf + intermediate) supported on connect; optional client-cert trust list at OpenSecureChannel
- **Subscriptions** — data-change and event monitoring with Part 4 queues, lifecycle, Republish/Transfer on server and client; `WithSubscriptionRecoveryHandler` for reconnect outcomes
- **Retry & Reconnect** — exponential backoff and automatic session / subscription recovery
- **Metrics** — pluggable instrumentation for request/response/error tracking
- **Logging** — structured logging via `*slog.Logger`; library is slog-native internally

For full API details see [API.md](API.md).

## Documentation

| Guide | Description |
|-------|-------------|
| [Client Guide](docs/client-guide.md) | Connecting, reading, writing, browsing, subscriptions, methods, history |
| [Server Guide](docs/server-guide.md) | Building servers, namespaces, custom nodes, methods, events, access control |
| [Security Guide](docs/security.md) | Certificates, encryption policies, authentication, security checklist |
| [Architecture](docs/architecture.md) | Package layering, message flow, concurrency patterns, internals |
| [API Reference](API.md) | Complete reference for all public types and functions |

## Quickstart

### Read a value

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/otfabric/go-opcua"
    "github.com/otfabric/go-opcua/ua"
)

func main() {
    ctx := context.Background()

    c, err := opcua.NewClient("opc.tcp://localhost:4840")
    if err != nil {
        log.Fatal(err)
    }
    if err := c.Connect(ctx); err != nil {
        log.Fatal(err)
    }
    defer c.Close(ctx)

    v, err := c.Node(ua.MustParseNodeID("i=2258")).Value(ctx) // or ua.StandardNodeID("CurrentTime") for symbolic name
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Server time:", v.Value())
}
```

### Subscribe to changes

```go
sub, notifs, err := c.NewSubscription().
    Interval(500 * time.Millisecond).
    Monitor(ua.MustParseNodeID("ns=2;s=Temperature")).
    Start(ctx)
if err != nil {
    log.Fatal(err)
}
defer sub.Cancel(ctx)

for msg := range notifs {
    if msg.Error != nil {
        log.Println("error:", msg.Error)
        continue
    }
    for _, item := range msg.Value.(*ua.DataChangeNotification).MonitoredItems {
        fmt.Printf("Value: %v\n", item.Value.Value.Value())
    }
}
```

### Browse the address space

```go
node := c.Node(ua.MustParseNodeID("ns=0;i=85")) // Objects folder
refs, err := node.References(ctx, 0, ua.BrowseDirectionForward, ua.NodeClassAll, true)
if err != nil {
    log.Fatal(err)
}
for _, ref := range refs {
    fmt.Printf("  %s: %s\n", ref.BrowseName.Name, ref.NodeID.NodeID)
}
```

### Run a server

```go
package main

import (
    "context"
    "log"

    "github.com/otfabric/go-opcua/server"
    "github.com/otfabric/go-opcua/ua"
)

func main() {
    srv, err := server.New(
        server.EndPoint("localhost", 4840),
        server.EnableSecurity("None", ua.MessageSecurityModeNone),
        server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    )
    if err != nil {
        log.Fatal(err)
    }

    ns := server.NewNodeNameSpace(srv, "example")
    idx := srv.AddNamespace(ns)
    _ = idx

    n := ns.AddNewVariableStringNode("temperature", float64(21.5))
    ns.Objects().AddRef(n, 47, true) // HasComponent

    if err := srv.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
    defer srv.Close()

    select {} // run until killed
}
```

## Client Features

| Area | Capabilities |
|------|-------------|
| **Connection** | Secure channel, session management, auto-reconnect, connection state callbacks, `SkipNamespaceUpdate`, configurable `DialTimeout` |
| **Reading** | Single/batch reads, all attributes, `Node.Value()`, `Node.Summary()`, `ReadMulti` (chunked batch N×attributes) |
| **Writing** | Single/batch writes, any attribute, `WriteValue`, `WriteAttribute` |
| **Browsing** | Forward/inverse/both, continuation points, `BrowseAll`, `Walk` / `WalkLimit` (depth-limited), `WalkLimitDedup`, `BrowseWithDepth` (client-side recursive, returns slice) |
| **Path resolution** | `NodeFromPath`, `NodeFromPathInNamespace`, `NodeFromQualifiedPath` (ns:name), `Node.TranslateBrowsePathInNamespaceToNodeID` (TranslateBrowsePathsToNodeIDs). Symbolic node names: `ua.StandardNodeID("CurrentTime")`, `id.NodeIDByName(name)` |
| **Subscriptions** | Data-change, events, modify/cancel, `SetTriggering`, `SetPublishingMode`, builder `Timestamps`; Part 4 queue / lifecycle semantics on go-opcua servers |
| **Monitoring** | `monitor` package: callback/channel subscriptions; batch add with per-item `ItemError`; zero-value `MonitoringMode` defaults to Reporting |
| **Methods** | `Call`, `CallMethod` (auto-wrap args), `MethodArguments` introspection |
| **History** | Read: raw/modified, events, processed, at-time. Update: data, events. Delete: raw/modified, at-time, events |
| **Node Management** | `AddNodes`, `DeleteNodes`, `AddReferences`, `DeleteReferences` |
| **Query** | `QueryFirst`, `QueryNext` |
| **Discovery** | `FindServers`, `GetEndpoints`, `ua.SelectEndpoint` |
| **Security** | None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss |
| **Authentication** | Anonymous, username/password, X.509 certificate, issued token |
| **Retry** | Pluggable `RetryPolicy`, exponential backoff with jitter |
| **Metrics** | Pluggable `ClientMetrics` interface for request/response/error/timeout tracking |

## Server Features

| Area | Capabilities |
|------|-------------|
| **Namespaces** | Custom `NameSpace` interface, `NodeNameSpace` in-memory implementation |
| **Services** | Read, Write, HistoryRead/HistoryUpdate (via `HistoryProvider`), Browse, BrowseNext, TranslateBrowsePaths, Call |
| **Node Management** | AddNodes, DeleteNodes, AddReferences, DeleteReferences |
| **Subscriptions** | Create, Modify, Delete, Publish, Republish, TransferSubscriptions, SetPublishingMode; revise clamps, `MoreNotifications`, Publish ACK |
| **MonitoredItems** | Create, Modify, Delete, SetMonitoringMode, SetTriggering; exact `QueueSize`/`DiscardOldest`/Overflow; per-item rejection for unknown nodes |
| **View** | RegisterNodes, UnregisterNodes |
| **Query** | QueryFirst, QueryNext with full ContentFilter evaluation (all 18 operators, 3-valued logic), type/subtype matching, and continuation points |
| **Session** | Create, Activate, Close (with DeleteSubscriptions), Cancel |
| **Methods** | Register handlers via `RegisterMethod`, argument introspection |
| **Events** | `EmitEvent` (raw fields) and `EmitBaseEvent` (`BaseEvent` + custom `Fields` + EventFilter SelectClauses / WhereClause) |
| **History** | Pluggable `HistoryProvider`; default in-memory `*Historian` with optional update/delete/at-time/modified/processed interfaces |
| **Access Control** | Pluggable `AccessController` interface for per-operation authorization |
| **NodeSet2 Import** | Load standard or custom NodeSet2 XML via `ImportNodeSetXML` |
| **Security** | Same encryption policies as client (server-side) |
| **Authentication** | Anonymous, username/password, X.509, issued token identity tokens |

## Service Support Matrix

| Service Set | Service | Client | Server |
|---|---|:---:|:---:|
| **Discovery** | FindServers | Yes | Yes |
| | FindServersOnNetwork | Yes | — |
| | GetEndpoints | Yes | Yes |
| **Secure Channel** | OpenSecureChannel | Yes | Yes |
| | CloseSecureChannel | Yes | Yes |
| **Session** | CreateSession | Yes | Yes |
| | ActivateSession | Yes | Yes |
| | CloseSession | Yes | Yes |
| | Cancel | — | Yes |
| **Attribute** | Read | Yes | Yes |
| | Write | Yes | Yes |
| | HistoryRead | Yes | Yes (via `HistoryProvider`; default `*Historian` supports raw/modified/at-time/processed) |
| | HistoryUpdate | Yes | Yes (when historian implements optional updater/deleter interfaces; default `*Historian` does) |
| **View** | Browse | Yes | Yes |
| | BrowseNext | Yes | Yes |
| | TranslateBrowsePathsToNodeIDs | Yes | Yes |
| | RegisterNodes | Yes | Yes |
| | UnregisterNodes | Yes | Yes |
| **Query** | QueryFirst | Yes | Yes |
| | QueryNext | Yes | Yes |
| **Method** | Call | Yes | Yes |
| **Node Management** | AddNodes | Yes | Yes |
| | DeleteNodes | Yes | Yes |
| | AddReferences | Yes | Yes |
| | DeleteReferences | Yes | Yes |
| **MonitoredItems** | CreateMonitoredItems | Yes | Yes |
| | DeleteMonitoredItems | Yes | Yes |
| | ModifyMonitoredItems | Yes | Yes |
| | SetMonitoringMode | Yes | Yes |
| | SetTriggering | Yes | Yes |
| **Subscription** | CreateSubscription | Yes | Yes |
| | ModifySubscription | Yes | Yes |
| | SetPublishingMode | Yes | Yes |
| | Publish | Yes | Yes |
| | Republish | Yes | Yes |
| | TransferSubscriptions | Yes | Yes |
| | DeleteSubscriptions | Yes | Yes |

**—** = API present but server returns `StatusBadServiceUnsupported`, or client has no dedicated helper (use `Client.Send`).

## Package Structure

| Package | Purpose |
|---------|---------|
| `opcua` | Client, Node, Subscription, configuration options, retry, metrics |
| `ua` | All OPC-UA types: Variant, DataValue, NodeID, StatusCode, enums, codec, `SelectEndpoint`, display name helpers |
| `server` | Server, NameSpace, AccessController, service implementations |
| `monitor` | High-level `NodeMonitor` with callback and channel-based subscriptions |
| `errors` | Sentinel errors for `errors.Is()` checking |
| `id` | Well-known NodeID constants (generated from OPC-UA schema) |
| `uacp` | OPC-UA Connection Protocol (TCP transport); `ParseEndpoint`, `DialWithTimeout` |
| `uasc` | OPC-UA Secure Conversation (secure channel) |
| `uapolicy` | Security policy implementations (encryption, signing) |
| `internal/stats` | Expvar-based statistics collection (internal) |


## Examples

The `examples/` directory contains runnable programs:

| Example | Description |
|---------|-------------|
| `read` | Read a node value (high-level `ReadValue`/`ReadValues` and low-level `Read`) |
| `readmulti` | Batch read a whole subtree with `ReadMulti` (auto-chunked) |
| `write` | Write a value to a node (high-level `WriteNodeValue` and low-level `Write`) |
| `browse` | Browse the server address space |
| `subscribe` | Subscribe to data changes/events with `SubscriptionBuilder` + `EventFilterBuilder` |
| `monitor` | High-level monitoring with `NodeMonitor` |
| `method` | Call a server method (high-level `CallMethod`/`MethodArguments` and low-level `Call`) |
| `history-read` | Read historical data with manual continuation points |
| `history-read-simple` | Read historical data with the `ReadHistoryAll` iterator |
| `crypto` | Connect with encryption and certificates |
| `datetime` | Read the server's current time |
| `discovery` | Discover servers on the network |
| `endpoints` | List available endpoints |
| `translate` | Resolve browse paths to NodeIDs (`NodeFromPath`/`NodeFromQualifiedPath`) |
| `trigger` | Set up monitored item triggering |
| `accesslevel` | Read node access levels |
| `regread` | Register nodes before reading for optimized repeated reads |
| `serverstatus` | Read `ServerStatus`, namespace table, and resolve a namespace URI |
| `metrics` | Instrument a client with `WithMetrics` and `WithRetryPolicy` |
| `node-summary` | Read all common node attributes in one call with `Node.Summary` |
| `udt` | Work with user-defined types |
| `reconnect` | Demonstrate auto-reconnection |
| `server/node_server` | Run a server using the node-based namespace |
| `server/map_server` | Run a server using a Go map-backed namespace |
| `server/NodeSet2_server` | Run a server that imports a NodeSet2 XML information model |
| `server/method_server` | Register a server-side method and call it from a client |

> Note: `examples/server/server.go` is a minimal low-level `uacp` transport
> stub (TCP listener only), not a full OPC-UA server. For a runnable server,
> use one of the `server/*_server` examples above.

Run any example:

```sh
go run examples/datetime/datetime.go -endpoint opc.tcp://localhost:4840
```

## Testing and production readiness

- **Unit tests**: `make test` (includes race detector).
- **Coverage**: `make coverage` writes `coverage.out`; `make cover` opens the report.
- **Integration tests** (tag-gated): `make integration` (Python client vs Go server), `make selfintegration` (Go client vs in-process server). These are not run by `go test ./...` by default.
- **Interop tests** (tag-gated): `make interop` — runs `go test -tags=interop ./interop/...`, spinning up [opcua-interop](https://github.com/otfabric/opcua-interop) adapter containers (open62541, Milo) to verify cross-stack wire compatibility. See [INTEROP.md](INTEROP.md) for fixture layout, environment variables, and how to iterate locally with `go work`.
- **Fuzz tests**: see `ua/fuzz_test.go` for Variant and NodeID decoding.
- **Linting**: `make lint` (staticcheck), `make lint-ci` (golangci-lint).

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and PR workflow.

## Protocol Support

| Layer | Protocol | Supported |
|-------|----------|:---------:|
| Encoding | OPC-UA Binary | Yes |
| Transport | UA-TCP | Yes |
| Encryption | None | Yes |
| | Basic128Rsa15 | Yes |
| | Basic256 | Yes |
| | Basic256Sha256 | Yes |
| | Aes128Sha256RsaOaep | Yes |
| | Aes256Sha256RsaPss | Yes |

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
