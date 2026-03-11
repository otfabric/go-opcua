# otfabric/opcua — OPC-UA library for Go

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/otfabric/opcua)](https://goreportcard.com/report/github.com/otfabric/opcua)
[![CI](https://github.com/otfabric/opcua/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/opcua/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/otfabric/opcua?style=flat&color=blue)](https://github.com/otfabric/opcua/releases)

A pure Go implementation of the OPC-UA Binary Protocol, providing both **client** and **server** capabilities. No C dependencies, no CGo — just Go.

```sh
go get github.com/otfabric/opcua
```

Requires **Go 1.23** or later.

## Overview

otfabric/opcua gives you everything needed to interact with OPC-UA servers or build your own:

- **Client** — connect, browse, read, write, subscribe, call methods, read history
- **Server** — host namespaces, expose variables, handle methods, emit events
- **Security** — six encryption policies, certificate and username/password authentication, server certificate validation with `TrustedCertificates()` and `InsecureSkipVerify()` options
- **Subscriptions** — data-change and event monitoring with automatic publishing
- **Retry & Reconnect** — exponential backoff and automatic session recovery
- **Metrics** — pluggable instrumentation for request/response/error tracking
- **Logging** — structured logging via `slog` or any custom `Logger` interface

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

    "github.com/otfabric/opcua"
    "github.com/otfabric/opcua/ua"
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

    v, err := c.Node(ua.MustParseNodeID("i=2258")).Value(ctx) // or opcua.StandardNodeID("CurrentTime") for symbolic name
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

    "github.com/otfabric/opcua/server"
    "github.com/otfabric/opcua/ua"
)

func main() {
    srv := server.New(
        server.EndPoint("localhost", 4840),
        server.EnableSecurity("None", ua.MessageSecurityModeNone),
        server.EnableAuthMode(ua.UserTokenTypeAnonymous),
    )

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
| **Connection** | Secure channel, session management, auto-reconnect, connection state callbacks, `SkipNamespaceUpdate` |
| **Reading** | Single/batch reads, all attributes, `Node.Value()`, `Node.Summary()`, `ReadMulti` (chunked batch N×attributes) |
| **Writing** | Single/batch writes, any attribute, `WriteValue`, `WriteAttribute` |
| **Browsing** | Forward/inverse/both, continuation points, `BrowseAll`, `Walk` / `WalkLimit` (depth-limited), `WalkLimitDedup`, `BrowseWithDepth` (client-side recursive, returns slice) |
| **Path resolution** | `NodeFromPath`, `NodeFromPathInNamespace`, `NodeFromQualifiedPath` (ns:name), `Node.TranslateBrowsePathInNamespaceToNodeID` (TranslateBrowsePathsToNodeIDs). Symbolic node names: `StandardNodeID("CurrentTime")`, `id.NodeIDByName(name)` |
| **Subscriptions** | Data-change, events, modify/cancel, `SetTriggering`, `SetPublishingMode`, builder API |
| **Methods** | `Call`, `CallMethod` (auto-wrap args), `MethodArguments` introspection |
| **History** | Read: raw/modified, events, processed, at-time. Update: data, events. Delete: raw/modified, at-time, events |
| **Node Management** | `AddNodes`, `DeleteNodes`, `AddReferences`, `DeleteReferences` |
| **Query** | `QueryFirst`, `QueryNext` |
| **Discovery** | `FindServers`, `GetEndpoints`, `SelectEndpoint` |
| **Security** | None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss |
| **Authentication** | Anonymous, username/password, X.509 certificate, issued token |
| **Retry** | Pluggable `RetryPolicy`, exponential backoff with jitter |
| **Metrics** | Pluggable `ClientMetrics` interface for request/response/error/timeout tracking |

## Server Features

| Area | Capabilities |
|------|-------------|
| **Namespaces** | Custom `NameSpace` interface, `NodeNameSpace` in-memory implementation |
| **Services** | Read, Write, Browse, BrowseNext, TranslateBrowsePaths, Call, HistoryRead, HistoryUpdate |
| **Node Management** | AddNodes, DeleteNodes, AddReferences, DeleteReferences |
| **Subscriptions** | Create, Modify, Delete, Publish, Republish, TransferSubscriptions, SetPublishingMode |
| **MonitoredItems** | Create, Modify, Delete, SetMonitoringMode, SetTriggering |
| **View** | RegisterNodes, UnregisterNodes, QueryFirst, QueryNext |
| **Session** | Create, Activate, Close (with DeleteSubscriptions), Cancel |
| **Methods** | Register handlers via `RegisterMethod`, argument introspection |
| **Events** | `EmitEvent` to push event notifications to subscribers |
| **Access Control** | Pluggable `AccessController` interface for per-operation authorization |
| **NodeSet2 Import** | Load standard or custom NodeSet2 XML files |
| **Security** | Same encryption policies as client (server-side) |
| **Authentication** | Anonymous, username/password, X.509, issued token identity tokens |

## Service Support Matrix

| Service Set | Service | Client | Server |
|---|---|:---:|:---:|
| **Discovery** | FindServers | Yes | Yes |
| | FindServersOnNetwork | Yes | Yes |
| | GetEndpoints | Yes | Yes |
| **Secure Channel** | OpenSecureChannel | Yes | Yes |
| | CloseSecureChannel | Yes | Yes |
| **Session** | CreateSession | Yes | Yes |
| | ActivateSession | Yes | Yes |
| | CloseSession | Yes | Yes |
| | Cancel | | Yes |
| **Attribute** | Read | Yes | Yes |
| | Write | Yes | Yes |
| | HistoryRead | Yes | Yes |
| | HistoryUpdate | Yes | Yes |
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
| | Republish | | Yes |
| | TransferSubscriptions | | Yes |
| | DeleteSubscriptions | Yes | Yes |

## Package Structure

| Package | Purpose |
|---------|---------|
| `opcua` | Client, Node, Subscription, configuration options, retry, metrics |
| `ua` | All OPC-UA types: Variant, DataValue, NodeID, StatusCode, enums, codec |
| `server` | Server, NameSpace, AccessController, service implementations |
| `monitor` | High-level `NodeMonitor` with callback and channel-based subscriptions |
| `errors` | Sentinel errors for `errors.Is()` checking |
| `id` | Well-known NodeID constants (generated from OPC-UA schema) |
| `uacp` | OPC-UA Connection Protocol (TCP transport) |
| `uasc` | OPC-UA Secure Conversation (secure channel) |
| `uapolicy` | Security policy implementations (encryption, signing) |
| `stats` | Expvar-based statistics collection |
| `logger` | Logger interface with slog and stdlib adapters |

## Examples

The `examples/` directory contains runnable programs:

| Example | Description |
|---------|-------------|
| `read` | Read a single node value |
| `write` | Write a value to a node |
| `browse` | Browse the server address space |
| `subscribe` | Subscribe to data changes |
| `monitor` | High-level monitoring with `NodeMonitor` |
| `method` | Call a server method |
| `history-read` | Read historical data |
| `crypto` | Connect with encryption and certificates |
| `datetime` | Read the server's current time |
| `discovery` | Discover servers on the network |
| `endpoints` | List available endpoints |
| `translate` | Translate browse paths to NodeIDs |
| `trigger` | Set up monitored item triggering |
| `accesslevel` | Read node access levels |
| `udt` | Work with user-defined types |
| `server` | Run a simple OPC-UA server |
| `reconnect` | Demonstrate auto-reconnection |

Run any example:

```sh
go run examples/datetime/datetime.go -endpoint opc.tcp://localhost:4840
```

## Testing and production readiness

- **Unit tests**: `make test` (includes race detector).
- **Coverage**: `make coverage` writes `coverage.out`; `make cover` opens the report.
- **Integration tests** (tag-gated): `make integration` (Python client vs Go server), `make selfintegration` (Go client vs in-process server). These are not run by `go test ./...` by default.
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

[MIT](LICENSE)
