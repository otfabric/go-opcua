# go-opcua — OPC UA Client and Server Library for Go (Golang)

[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/otfabric/go-opcua.svg)](https://pkg.go.dev/github.com/otfabric/go-opcua)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/otfabric/go-opcua/actions/workflows/ci.yml/badge.svg)](https://github.com/otfabric/go-opcua/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/otfabric/go-opcua/graph/badge.svg)](https://codecov.io/gh/otfabric/go-opcua)
[![Release](https://img.shields.io/github/v/release/otfabric/go-opcua?label=release)](https://github.com/otfabric/go-opcua/releases)

**go-opcua is a pure Go implementation of OPC Unified Architecture
(OPC UA), providing comprehensive client and server capabilities
for industrial automation, SCADA, industrial IoT (IIoT), and
Industry 4.0 applications.**

Connect to OPC UA servers, browse address spaces, read and write
values, subscribe to data changes and events, call methods, and
access historical data.

Build OPC UA servers with custom namespaces, variables, methods,
subscriptions, events, access control, and historical data support.

```sh
go get github.com/otfabric/go-opcua
```

Requires **Go 1.26** or later (`go.mod` and CI matrix; toolchain/`golang.org/x/tools` used for code generation).

## Table of contents

- [go-opcua — OPC UA Client and Server Library for Go (Golang)](#go-opcua--opc-ua-client-and-server-library-for-go-golang)
  - [Table of contents](#table-of-contents)
  - [Overview](#overview)
  - [Documentation](#documentation)
  - [Quickstart](#quickstart)
    - [Read a value](#read-a-value)
    - [Subscribe to changes](#subscribe-to-changes)
    - [Browse the address space](#browse-the-address-space)
    - [Run a server](#run-a-server)
  - [go-opcua vs open62541 and Eclipse Milo](#go-opcua-vs-open62541-and-eclipse-milo)
  - [Client Features](#client-features)
  - [Server Features](#server-features)
  - [Service Support Matrix](#service-support-matrix)
  - [Package Structure](#package-structure)
  - [Examples](#examples)
  - [Testing and production readiness](#testing-and-production-readiness)
  - [Protocol Support](#protocol-support)
  - [License](#license)

## Overview

**go-opcua** gives you everything needed to interact with OPC-UA servers or build your own.

- **Client and server** — Full OPC UA client and server implementations
  using OPC UA Binary over UA-TCP.
- **Pure Go** — No CGO or native C library dependencies. Cryptography is the
  Go standard library, plus ChaCha20-Poly1305 from `golang.org/x/crypto` for
  two of the ECC security policies.
- **Secure communication** — OPC UA message signing, encryption,
  X.509 certificates, and multiple authentication mechanisms.
- **Data access** — Read, write, browse, and manage OPC UA nodes.
- **Subscriptions** — Real-time data-change notifications,
  monitored items, events, and subscription management.
- **Historical data** — Historical reads, updates, and
  pluggable server-side history providers.
- **Method calls** — Invoke OPC UA methods or expose custom
  methods from your server.
- **Resilience** — Automatic reconnect, retry policies,
  and subscription recovery.
- **Observability** — Structured logging and pluggable metrics.
- **Interoperability tested** — Independently tested against
  open62541 (C) and Eclipse Milo (Java).

Built for developers integrating PLCs, industrial gateways,
SCADA systems, and industrial IoT applications.

**MIT licensed · Pure Go · Client + Server · No CGO**

For full API details see [API.md](API.md).

## Documentation

| Guide | Description |
|-------|-------------|
| [Client Guide](docs/client-guide.md) | Connecting, reading, writing, browsing, subscriptions, methods, history |
| [Server Guide](docs/server-guide.md) | Building servers, namespaces, custom nodes, methods, events, access control |
| [Security Guide](docs/security.md) | Certificates, encryption policies, authentication, security checklist |
| [Architecture](docs/architecture.md) | Package layering, message flow, concurrency patterns, internals |
| [PubSub](docs/pubsub.md) | Publishers and subscribers over UDP and MQTT, UADP and JSON, message security, Security Key Service, PublishSubscribe information model |
| [JSON and XML Data Encodings](docs/encodings.md) | `ua.EncodeJSON` / `ua.EncodeXML`: supported forms, namespace tables, custom structures, open62541 interoperability |
| [Errors](ERRORS.md) | Go sentinels vs wire `ua.StatusCode` |
| [Observability](OBSERVABILITY.md) | Silent slog default and metrics callbacks |
| [Interop](INTEROP.md) | Cross-stack testing vs open62541 / Milo; fixture layout, pins, local iteration |
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

    ns := server.NewNodeNameSpace(srv, "example") // registers the namespace

    n := ns.AddNewVariableStringNode("temperature", float64(21.5))
    ns.Objects().AddRef(n, 47, true) // HasComponent

    if err := srv.Start(context.Background()); err != nil {
        log.Fatal(err)
    }
    defer srv.Close()

    select {} // run until killed
}
```

## go-opcua vs open62541 and Eclipse Milo

go-opcua is tested against two other implementations in every applicable
client/server direction (see
[Testing and production readiness](#testing-and-production-readiness)):
[open62541](https://github.com/open62541/open62541) and
[Eclipse Milo](https://github.com/eclipse-milo/milo). Both are mature,
widely deployed stacks; this table shows where the three differ so you can
pick the right one for your project.

| Capability | otfabric/go-opcua | open62541 | Eclipse Milo |
|---|:---:|:---:|:---:|
| Language | Go | C (C99) | Java 17+ |
| License | MIT | MPL-2.0 | EPL-2.0 |
| Client | ✅ | ✅ | ✅ |
| Server | ✅ | ✅ | ✅ |
| Client/Server over UA-TCP, OPC UA Binary | ✅ | ✅ | ✅ |
| JSON / XML data encoding (Part 6 §5.4, §5.3) | ✅ all built-in types and structures; JSON Compact, Verbose and 1.04 reversible ⁵ | ✅ JSON 1.05 or 1.04; XML for built-in types and arrays ⁵ | ✅ JSON Compact and Verbose, XML |
| PubSub (Part 14) | ✅ UADP and JSON over UDP and MQTT, PubSub-Aes128/256-CTR, Security Key Service, PublishSubscribe information model ⁶ | ✅ UDP, Ethernet, MQTT | — |
| Reverse connect (client and server) | ✅ ¹ | ✅ | — |
| RSA security policies (Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss; Basic128Rsa15 and Basic256 for legacy peers) | ✅ | ✅ | ✅ |
| ECC security policies | ✅ ECC_nistP256, ECC_nistP384, ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly, ECC_curve25519 | ✅ with OpenSSL (also Brainpool and Curve448) | — |
| User identity: anonymous, username, X.509 | ✅ | ✅ | ✅ |
| User identity: issued token | ✅ carried to the application | ✅ | server side |
| SecureChannel renewal with token rotation | ✅ | ✅ | ✅ |
| Discovery: FindServers, GetEndpoints | ✅ | ✅ | ✅ |
| Discovery: local discovery server, mDNS (FindServersOnNetwork, RegisterServer, RegisterServer2) | ✅ LDS, registration, built-in mDNS (LDS-ME) | ✅ | client RegisterServer only |
| Attribute, View, Method service sets | ✅ | ✅ | ✅ |
| RegisterNodes / UnregisterNodes | ✅ | ✅ | ✅ |
| NodeManagement (AddNodes, DeleteNodes, references) | ✅ | ✅ | — delegated to the application ² |
| Query (QueryFirst, QueryNext) | ✅ client and server | — client request only | — |
| Subscriptions: data change, Republish, TransferSubscriptions | ✅ | ✅ | ✅ |
| DataChangeFilter (deadband, trigger) | ✅ ³ | ✅ | ✅ |
| Events: emission, SelectClauses, WhereClause | ✅ | ✅ | ✅ |
| Alarms & Conditions | — | experimental | types only |
| HistoryRead raw, built-in store | ✅ | ✅ | — delegated to the application ² |
| HistoryRead modified / at-time / processed, HistoryUpdate | ✅ built-in in-memory historian, pluggable provider | raw and update; rest via backend plugin | — delegated to the application ² |
| NodeSet2 XML import at run time | ✅ nodes, references, values ⁴ | ✅ optional loader, plus build-time compiler | — |
| Custom structured DataTypes | ✅ registered Go types | ✅ generated or runtime type descriptions | ✅ decoded dynamically from the server's type system |
| Automatic reconnect with subscription recovery | ✅ | reconnect; subscriptions re-created by the application | ✅ |
| Cancellation and deadlines per call | ✅ `context.Context` | — timeouts | ✅ futures and timeouts |
| Retry policy for requests | ✅ pluggable | — | — |
| Structured logging | ✅ `log/slog` | ✅ logger plugin | ✅ SLF4J |
| Metrics hooks (client and server) | ✅ | — | — |
| Concurrency model | goroutines | single-threaded event loop (multithreading optional) | Netty, asynchronous |
| Runs without an OS / on microcontrollers | — | ✅ | — |
| Native dependencies | none (pure Go, no cgo; one Go module besides the standard library for cryptography: `golang.org/x/crypto`) | none; mbedTLS or OpenSSL for encryption | JVM; Netty, Bouncy Castle |
| OPC Foundation certification | — | ✅ example server, Standard Server 2017 profile (v1.4) | — |
| Cross-tested against other stacks in CI | ✅ against both, [391 verified ledger rows](interop/COVERAGE.md) | CTT, fuzzing (OSS-Fuzz) | — not documented |

¹ Part 6 §7.1.3: the server opens the connection to a listening client and
announces itself with ReverseHello (`server.WithReverseConnect`,
`opcua.ReverseConnect`). Wire-compatible with open62541 in both directions.
Milo's transport has no ReverseHello message.

² Milo's server SDK routes these service sets to the application's
`AddressSpace`; there is no built-in implementation. In the reference server
used for go-opcua's interop tests, AddNodes returns `BadNotSupported`.

³ Client and server. The go-opcua server applies all three triggers, absolute
deadband on numeric scalars and arrays, and percent deadband on variables with
an `EURange` property; it also honours the sampling interval and the
`IndexRange` of a monitored item.

⁴ Nodes, references, role permissions and, for variables, the Value,
DataType, ValueRank, ArrayDimensions and access levels are imported.

⁵ An encoding of values (`ua.EncodeJSON`, `ua.EncodeXML`), not a transport:
the wire stays UA-TCP with the binary encoding. go-opcua's codecs are verified
against open62541 with a recorded corpus and, live, against open62541 and
Eclipse Milo in both directions (interop ledger, `encoding.*`); open62541
v1.5.9 does not encode structures, enumerations, DataValue, DiagnosticInfo or
matrices to XML. See
[JSON and XML Data Encodings](docs/encodings.md).

⁶ Publisher and subscriber, standalone (`pubsub.New`) or in the server
(`server.WithPubSub`, address space as data source and target variables);
UADP with Variant, DataValue and RawData fields, delta frames, keep-alive and
events; JSON `ua-data`, `ua-metadata`, `ua-status`; signed and encrypted UADP
with keys from a static key ring, a local or remote Security Key Service, or
SetSecurityKeys push; remote configuration with `pubsub/remote`. No Ethernet
or AMQP transport and no chunked messages. Interoperability-tested against
open62541 (interop ledger, profile `pubsub`). See [PubSub](docs/pubsub.md).

✅ = available · — = not available or not documented. For open62541 v1.5.9
and Eclipse Milo 1.1.8, the versions go-opcua is tested against, from their
public sources and documentation as of October 2026. If you spot an
inaccuracy, please [open an issue](https://github.com/otfabric/go-opcua/issues)
and we will correct it.

**Choose go-opcua if** you write Go and want client and server in one
library with no cgo and a permissive license, `context` control on every
call, reconnect with subscription recovery, retries and observability built
in, and a server that includes history and query out of the box.

**Choose open62541 if** you need a C library for embedded or bare-metal
targets, PubSub over Ethernet (TSN), the Brainpool / Curve448 ECC security policies,
or a stack with an OPC Foundation certified server profile.

**Choose Eclipse Milo if** you are on the JVM and want asynchronous client
and server SDKs with strong support for dynamically decoded custom data
types.

## Client Features

| Area | Capabilities |
|------|-------------|
| **Connection** | Secure channel, session management, auto-reconnect, connection state callbacks, `SkipNamespaceUpdate`, configurable `DialTimeout` |
| **Reverse connect** | `ReverseConnect` / `ReverseConnectListener`: wait for the server to connect (firewall/NAT traversal), one listener for many servers, ServerUri/EndpointUrl validation, auto-reconnect and discovery over reverse connections |
| **Reading** | Single/batch reads, all attributes, `Node.Value()`, `Node.Summary()`, `ReadMulti` (chunked batch N×attributes) |
| **Writing** | Single/batch writes, any attribute, `WriteValue`, `WriteAttribute` |
| **Browsing** | Forward/inverse/both, continuation points, `BrowseAll`, `Walk` / `WalkLimit` (depth-limited), `WalkLimitDedup`, `BrowseWithDepth` (client-side recursive, returns slice) |
| **Path resolution** | `NodeFromPath`, `NodeFromPathInNamespace`, `NodeFromQualifiedPath` (ns:name), `Node.TranslateBrowsePathInNamespaceToNodeID` (TranslateBrowsePathsToNodeIDs). Symbolic node names: `ua.StandardNodeID("CurrentTime")`, `id.NodeIDByName(name)` |
| **Subscriptions** | Data-change, events, modify/cancel, `SetTriggering`, `SetPublishingMode`, builder `Timestamps`, `SamplingInterval` and `DataChangeFilter` (trigger, deadband); Part 4 queue / lifecycle semantics on go-opcua servers |
| **Monitoring** | `monitor` package: callback/channel subscriptions; batch add with per-item `ItemError`; zero-value `MonitoringMode` defaults to Reporting |
| **Methods** | `Call`, `CallMethod` (auto-wrap args), `MethodArguments` introspection |
| **History** | Read: raw/modified, events, processed, at-time. Update: data, events. Delete: raw/modified, at-time, events |
| **Node Management** | `AddNodes`, `DeleteNodes`, `AddReferences`, `DeleteReferences` |
| **Query** | `QueryFirst`, `QueryNext` |
| **Discovery** | `FindServers`, `FindServersOnNetwork` (filters, paging), `GetEndpoints`, `ua.SelectEndpoint`, `opcua.SelectEndpoint` (aware of the client certificate's key type), `DiscoverServers` (well-known LDS port 4840), `RegisterServer` / `RegisterServer2`. Server: Local Discovery Server, registration with an LDS, mDNS (LDS-ME) without dependencies |
| **Security** | None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss, ECC_nistP256, ECC_nistP384, ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly, ECC_curve25519 (RSA, ECDSA and Ed25519 application certificates) |
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
| **MonitoredItems** | Create, Modify, Delete, SetMonitoringMode, SetTriggering; exact `QueueSize`/`DiscardOldest`/Overflow; `DataChangeFilter` (Status / StatusValue / StatusValueTimestamp, absolute and percent deadband), sampling interval, per-item `IndexRange`; per-item rejection for unknown nodes and unusable filters |
| **View** | RegisterNodes, UnregisterNodes |
| **Query** | QueryFirst, QueryNext with full ContentFilter evaluation (all 18 operators, 3-valued logic), type/subtype matching, and continuation points |
| **Session** | Create, Activate, Close (with DeleteSubscriptions), Cancel |
| **Methods** | Register handlers via `RegisterMethod`, argument introspection |
| **Events** | `EmitEvent` (raw fields) and `EmitBaseEvent` (`BaseEvent` + custom `Fields` + EventFilter SelectClauses / WhereClause) |
| **History** | Pluggable `HistoryProvider`; default in-memory `*Historian` with optional update/delete/at-time/modified/processed interfaces |
| **Access Control** | Pluggable `AccessController` interface for per-operation authorization |
| **NodeSet2 Import** | Load standard or custom NodeSet2 XML via `ImportNodeSetXML`, including variable values, data types and access levels |
| **Reverse connect** | `WithReverseConnect` / `AddReverseConnect`: connect to listening clients, keep one idle connection available, retry with back-off, add and remove targets at run time |
| **Security** | Same encryption policies as client (server-side) |
| **Authentication** | Anonymous, username/password, X.509, issued token identity tokens |

## Service Support Matrix

| Service Set | Service | Client | Server |
|---|---|:---:|:---:|
| **Discovery** | FindServers | Yes | Yes |
| | FindServersOnNetwork | Yes | Yes (`WithMulticastDiscovery`) |
| | GetEndpoints | Yes | Yes |
| | RegisterServer | Yes | Yes (`WithLocalDiscoveryServer`) |
| | RegisterServer2 | Yes | Yes (`WithLocalDiscoveryServer`) |
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
| `opcua` | Client, Node, Subscription (incl. Republish / TransferSubscriptions), config options, recovery handler, retry, metrics |
| `ua` | OPC-UA types and codec: Variant, DataValue, NodeID, StatusCode, NumericRange, EventFilter helpers, ExtensionObject registry, `SelectEndpoint` |
| `server` | Server, NameSpace, AccessController, events (`EmitBaseEvent`), pluggable `HistoryProvider` / `*Historian`, service handlers |
| `server/attrs` | Attribute helper constructors for building nodes |
| `server/refs` | Reference helper constructors for address-space links |
| `monitor` | High-level `NodeMonitor` with callback and channel-based subscriptions |
| `errors` | Sentinel errors for `errors.Is()` checking |
| `id` | Well-known NodeID constants (generated from OPC-UA schema) |
| `uacp` | OPC-UA Connection Protocol (TCP transport); `ParseEndpoint`, `DialWithTimeout` |
| `uasc` | OPC-UA Secure Conversation (secure channel) |
| `uapolicy` | Security policy implementations (encryption, signing) |
| `pubsub` | PubSub runtime (Part 14): publishers, subscribers, configuration builders; sub-packages `message`, `uadp`, `jsonmsg`, `transport` (`udp`, `mqtt`), `security`, `sks`, `remote` |
| `internal/stats` | Expvar-based statistics collection (internal) |

Test-only packages (`interop/`, `conformance/`, `tests/`) are not part of the public library surface.


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

go-opcua is continuously interoperability-tested in all applicable client/server directions against open62541 and Eclipse Milo. The directional evidence ledger is maintained in [interop/COVERAGE.md](interop/COVERAGE.md).

- **Verify gate**: `make verify` — `go vet`, unit tests, race tests, and interop (`make vet`, `make test-norace`, `make test`, `make interop`).
- **Unit tests**: `make test-norace` (`go test -count=1 ./...`), `make test` (same with `-race`).
- **Coverage**: `make coverage` writes `coverage.out` for core library packages (90% gate); CI passes the same `COVER_PKGS` list as `coverpkg` to the shared workflow so Codecov matches. `make cover` opens the report.
- **Integration tests** (tag-gated, not in `go test ./...`): `make integration` (Go client vs FreeOpcUa Python server; needs `make install-py-opcua`), `make selfintegration` (Go client vs in-process Go server).
- **Interop tests** (tag-gated): `make interop` — `go test -tags=interop ./interop/...` against [opcua-interop](https://github.com/otfabric/opcua-interop) adapter containers (open62541, Milo). See [INTEROP.md](INTEROP.md).
- **Chaos and parallelism tests** (Go client vs Go server in one process, no Docker; part of `go test ./...` with a short fault phase): `make chaos` runs them with a 30 s fault phase per scenario (`CHAOS_DURATION`, `CHAOS_SEED`, `CHAOS_LOG`). `chaos/` covers the unsecured state machines, `chaos/secure` the RSA, ECC and AEAD security policies (incl. bit flips, replayed, lost and reordered chunks), `chaos/datachange` DataChangeFilter and sampling, `chaos/reverse` reverse connect, `chaos/discovery` the LDS, registration and mDNS, `chaos/codec` the JSON / XML codecs and the shared NodeSet values. Every randomized scenario logs its seed and the command that replays it; see [`chaos/doc.go`](chaos/doc.go).
- **Fuzz tests**: `ua/fuzz_test.go`, `ua/codec_fuzz_test.go` (JSON and XML decoders), `uasc/fuzz_test.go`, `uacp/fuzz_test.go`.
- **Linting**: `make lint` (staticcheck), `make lint-ci` (golangci-lint); full local gate is `make check` (fmt + lint + verify + coverage).

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and PR workflow.

## Protocol Support

| Layer | Protocol | Supported |
|-------|----------|:---------:|
| Encoding (wire) | OPC-UA Binary | Yes |
| Encoding (values only, not a transport) | OPC-UA JSON — 1.05.04 Compact and Verbose, 1.04 reversible; non-reversible encode only | Yes |
| | OPC-UA XML — built-in types, structures, NodeSet2 values | Yes |
| Transport | UA-TCP (`opc.tcp://`) | Yes |
| | UA-TCP reverse connect (ReverseHello) | Yes (client and server) |
| | HTTPS / WebSockets | No |
| Message security | None / Sign / SignAndEncrypt | Yes |
| Security policy | None | Yes |
| | Basic128Rsa15 | Yes |
| | Basic256 | Yes |
| | Basic256Sha256 | Yes |
| | Aes128Sha256RsaOaep | Yes |
| | Aes256Sha256RsaPss | Yes |
| | ECC_nistP256 | Yes |
| | ECC_nistP384 | Yes |
| | ECC_nistP256_AesGcm (AES-128-GCM) | Yes |
| | ECC_nistP256_ChaChaPoly (ChaCha20-Poly1305) | Yes |
| | ECC_curve25519 (Ed25519, X25519, ChaCha20-Poly1305) | Yes |
| | ECC_brainpoolP256r1 / ECC_brainpoolP384r1 | No |
| | ECC_curve448 | No |
| | PubSub-Aes128-CTR / PubSub-Aes256-CTR | Yes (PubSub UADP message security) |

PubSub (Part 14) is implemented in the `pubsub` packages: UDP (`opc.udp://`, unicast and multicast) and MQTT 3.1.1 (`mqtt://`, `mqtts://`) transports with the UADP and JSON message mappings; the PubSub-Aes128-CTR / PubSub-Aes256-CTR policies secure UADP messages and are not secure-channel policies. Ethernet and AMQP transports are not implemented. See [PubSub](docs/pubsub.md).

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
