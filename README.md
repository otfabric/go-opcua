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
  - [go-opcua compared with other OPC UA stacks](#go-opcua-compared-with-other-opc-ua-stacks)
    - [Features](#features)
    - [Interop evidence](#interop-evidence)
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
- **Observability** — Structured logging, pluggable metrics, and live
  server diagnostics (ServerDiagnosticsSummary, session diagnostics,
  DiagnosticInfo on request).
- **Interoperability tested** — Tested in both directions against
  open62541 (C), Eclipse Milo (Java), async-opcua (Rust),
  UA-.NETStandard (C#), node-opcua (TypeScript) and asyncua (Python).

Built for developers integrating PLCs, industrial gateways,
SCADA systems, and industrial IoT applications.

**MIT licensed · Pure Go · Client + Server · No CGO**

For full API details see [API.md](API.md).

## Documentation

| Guide | Description |
|-------|-------------|
| [Client Guide](docs/client-guide.md) | Connecting, reading, writing, browsing, subscriptions, methods, history |
| [Server Guide](docs/server-guide.md) | Building servers, namespaces, custom nodes, methods, events, access control, diagnostics |
| [Security Guide](docs/security.md) | Certificates, encryption policies, authentication, security checklist |
| [Architecture](docs/architecture.md) | Package layering, message flow, concurrency patterns, internals |
| [PubSub](docs/pubsub.md) | Publishers and subscribers over UDP, Ethernet, MQTT 3.1.1 / 5.0 and AMQP 1.0, UADP and JSON, message security, Security Key Service, chunks, discovery, Actions, diagnostics, PublishSubscribe information model |
| [JSON and XML Data Encodings](docs/encodings.md) | `ua.EncodeJSON` / `ua.EncodeXML`: supported forms, namespace tables, custom structures, open62541 interoperability |
| [Errors](ERRORS.md) | Go sentinels vs wire `ua.StatusCode` |
| [Observability](OBSERVABILITY.md) | Silent slog default and metrics callbacks |
| [Interop](INTEROP.md) | Cross-stack testing against six other stacks; fixture layout, pins, local iteration |
| [Interop gaps and workarounds](docs/interop-gaps.md) | What go-opcua lacks, peer deviations you may meet, and how to work around them |
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

## go-opcua compared with other OPC UA stacks

go-opcua is tested against six other implementations in every applicable
client/server direction (see
[Testing and production readiness](#testing-and-production-readiness)):
[open62541](https://github.com/open62541/open62541) (C),
[Eclipse Milo](https://github.com/eclipse-milo/milo) (Java),
[async-opcua](https://github.com/freeopcua/async-opcua) (Rust), the OPC
Foundation [UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard)
reference stack (C#), [node-opcua](https://github.com/node-opcua/node-opcua)
(TypeScript) and [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio)
(Python, `asyncua`). Each runs as a container from
[opcua-interop](https://github.com/otfabric/opcua-interop). The tables show
where the stacks differ, so you can pick the right one for your project, and
what the interop suite has actually exercised.

### Features

| Capability | go-opcua | open62541 | Milo | async-opcua | UA-.NETStandard | node-opcua | asyncua |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Version tested | main | 1.5.9 | 1.1.8 | 0.19.0 | 2.0.1 | 2.187.12 | 2.1.0 |
| Language | Go | C (C99) | Java 17+ | Rust | C# (.NET) | TypeScript (Node.js) | Python 3 |
| License | MIT | MPL-2.0 | EPL-2.0 | MPL-2.0 | GPL-2.0 or OPC Foundation RCL | MIT | LGPL-3.0 |
| Client and server | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| UA-TCP, OPC UA Binary | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTPS / WebSockets transport (`opc.https`, `opc.wss`) | ✅ client and server | — (libwebsockets provider on master only) | incubating client transports, unpublished | — | ✅ | — | — |
| Reverse connect (ReverseHello) ¹ | ✅ | ✅ | — | ✅ | ✅ | ✅ | — |
| RSA security policies (Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss; Basic128Rsa15 and Basic256 for legacy peers) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ECC security policies ² | ✅ nistP256/384, brainpoolP256r1/P384r1, nistP256_AesGcm, nistP256_ChaChaPoly, curve25519, curve448 | ✅ (OpenSSL) | — | — | ✅ | — | — |
| User identity: anonymous, username, X.509 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User identity: issued token | ✅ carried to the application | ✅ | server side | · | ✅ | · | · |
| Discovery: FindServers, GetEndpoints, RegisterServer2 as registrant | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ ³ | ✅ |
| Local Discovery Server, mDNS (LDS-ME, FindServersOnNetwork) | ✅ built in | ✅ | — | — | separate LDS product | separate discovery server | registry only, no mDNS |
| Attribute, View, Method service sets, RegisterNodes | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ ⁴ |
| NodeManagement served (AddNodes, DeleteNodes, references) | ✅ | ✅ | delegated to the application ⁵ | ✅ | ✅ | — | Admin role only |
| Query (QueryFirst, QueryNext) | ✅ client and server | client request only | — | delegated to node managers | — | — | — |
| Subscriptions: data change, Republish, TransferSubscriptions | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ ⁴ |
| DataChangeFilter (deadband, trigger), sampling interval ⁶ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | client; server partial ⁴ |
| Events: emission, SelectClauses, WhereClause | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Alarms & Conditions (Part 9) | ✅ conditions, acknowledge, confirm, shelving, limit alarms, ConditionRefresh, v1.05 suppress / silence / out-of-service / latch methods, dialogs, branches, alarm groups, audit events | experimental | types only | · | ✅ | ✅ | · |
| HistoryRead raw with a built-in store | ✅ | ✅ | delegated ⁵ | delegated | delegated | ✅ | ✅ |
| HistoryRead modified / at-time / processed, HistoryUpdate | ✅ built-in historian, pluggable provider | raw and update; rest via backend plugin | delegated ⁵ | delegated | delegated | raw only | raw and events |
| Server diagnostics (ServerDiagnostics, DiagnosticInfo) | ✅ summary, session objects, ReturnDiagnostics | ✅ | — | — | ✅ | ✅ | — |
| PubSub (Part 14) ⁷ | ✅ UADP and JSON over UDP, Ethernet, MQTT 3.1.1 / 5.0 and AMQP 1.0, security, SKS | ✅ UDP, Ethernet, MQTT | — | — | ✅ UDP, MQTT | commercial add-on | experimental UADP over UDP |
| JSON / XML data encoding of values ⁸ | ✅ JSON 1.05 Compact and Verbose, 1.04; XML | ✅ JSON; XML for built-in types | ✅ JSON Compact and Verbose; XML | JSON 1.04 form; NodeSet2 XML | ✅ JSON Compact and Verbose; XML | JSON | — NodeSet2 XML only |
| NodeSet2 XML import at run time | ✅ | ✅ loader, plus build-time compiler | — | ✅ | ✅ | ✅ | ✅ |
| Custom structured DataTypes | registered Go types | generated or runtime descriptions | decoded dynamically | generated | decoded dynamically | decoded dynamically | decoded dynamically |
| GDS / certificate management (Part 12) | push: server and client (`gds`); pull: GDS and client (`gds/gdsserver`, `gds.PullClient`) | push (build option) | · | — | ✅ push and pull | push | — |
| Automatic reconnect with subscription recovery | ✅ | reconnect; application re-creates subscriptions | ✅ | ✅ | ✅ | ✅ | application reconnects |
| Cancellation and deadlines per call | ✅ `context.Context` | timeouts | futures, timeouts | async, timeouts | `CancellationToken` | promises, timeouts | asyncio, timeouts |
| Native dependencies | none (pure Go, no cgo) | mbedTLS or OpenSSL for encryption | JVM; Netty, Bouncy Castle | none (pure Rust, RustCrypto) | .NET runtime | Node.js (OpenSSL) | CPython, `cryptography` (OpenSSL) |
| Runs without an OS / on microcontrollers | — | ✅ | — | — | — | — | — |
| OPC Foundation certification | — | ✅ example server, Standard Server 2017 profile (v1.4) | — | — | reference implementation | — | — |

✅ = available · — = not available · · = not documented or not verified here.
"Delegated" means the server SDK routes the service to the application and has
no built-in implementation. The peer columns describe the stacks at the
versions above, from their public sources, documentation and adapter behaviour
as of October 2026; what the interop suite has proven is in the next table.
If you spot an inaccuracy, please
[open an issue](https://github.com/otfabric/go-opcua/issues) and we will
correct it.

¹ Part 6 §7.1.3: the server opens the connection to a listening client and
announces itself with ReverseHello (`server.WithReverseConnect`,
`opcua.ReverseConnect`). Verified against open62541, async-opcua and
node-opcua in both directions; the UA-.NETStandard adapter does not wire it.

² go-opcua follows open62541 1.5.9 where it and Part 6 1.05.07 differ (see
[Security](docs/security.md)); open62541 is the only ECC peer the suite can
test, because UA-.NETStandard 2.0.1 refuses ECC certificates from the RSA test
CA. The Brainpool curves come from a pure Go implementation that is not
constant time; see [Security](docs/security.md#brainpool-and-curve448).

³ node-opcua registers only with a discovery server that has a certificate,
and reports success when the registration failed.

⁴ asyncua 2.1.0 ignores TimestampsToReturn, IndexRange, the sampling interval,
MonitoringMode Sampling and ModifySubscription, applies the absolute deadband
against the previous sample and does not apply a percent deadband, and moves a
user's subscription to an anonymous session on TransferSubscriptions. See
[Interop gaps](docs/interop-gaps.md).

⁵ Milo's server SDK routes these service sets to the application's
`AddressSpace`; in the reference server used for the interop tests, AddNodes
returns `BadNotSupported`.

⁶ The go-opcua server applies all three triggers, absolute deadband on
numeric scalars and arrays, and percent deadband on variables with an
`EURange` property; it also honours the sampling interval and the
`IndexRange` of a monitored item.

⁷ Publisher and subscriber, standalone (`pubsub.New`) or in the server
(`server.WithPubSub`); UADP with Variant, DataValue and RawData fields, delta
frames, keep-alive and events; JSON `ua-data`, `ua-metadata`, `ua-status`;
PubSub-Aes128/256-CTR with keys from a static key ring, a Security Key Service
or SetSecurityKeys push; remote configuration with `pubsub/remote`; chunked
NetworkMessages, UADP discovery and the diagnostics objects. Transports: UDP
unicast and multicast, raw Ethernet (Linux, macOS, FreeBSD; no TSN
scheduling), MQTT 3.1.1 and 5.0, AMQP 1.0; PubSub Actions (request / response)
with Go handlers.
Interoperability-tested in both directions against open62541 (UDP,
multicast, Ethernet, MQTT 3.1.1 and 5.0, SKS) and UA-.NETStandard (UDP, MQTT
3.1.1 and 5.0, message security, chunked NetworkMessages, UADP discovery);
the AMQP transport is tested through RabbitMQ 4 and ActiveMQ Artemis. See
[PubSub](docs/pubsub.md).

⁸ An encoding of values (`ua.EncodeJSON`, `ua.EncodeXML`), not a transport.
Verified live in both directions against open62541, Milo and
UA-.NETStandard, and against a recorded open62541 corpus. See
[JSON and XML Data Encodings](docs/encodings.md).

### Interop evidence

Each ledger row is one capability in one direction (go-opcua client → peer
server, or peer client → go-opcua server), checked by a test. `unsupported`
rows record what the peer (or its adapter) lacks or where it deviates from the
specification; the test pins that behaviour or skips with the reason.

| Peer | Ledger | Verified | Unsupported | Deferred | Not applicable |
|---|---|---:|---:|---:|---:|
| open62541 and Eclipse Milo | [`interop/coverage.json`](interop/COVERAGE.md) | 445 | 210 | 64 | 44 |
| async-opcua | [`ledger-async-opcua.json`](interop/testdata/ledger-async-opcua.json) | 136 | 192 | 30 | 22 |
| UA-.NETStandard | [`ledger-dotnet.json`](interop/testdata/ledger-dotnet.json) | 192 | 130 | 34 | 22 |
| node-opcua | [`ledger-node-opcua.json`](interop/testdata/ledger-node-opcua.json) | 136 | 196 | 27 | 22 |
| asyncua | [`ledger-asyncua.json`](interop/testdata/ledger-asyncua.json) | 111 | 217 | 34 | 22 |

Interop with these stacks found and fixed go-opcua defects that a Go-to-Go
test cannot show, among them the RSA-OAEP-SHA256 block size (UA-.NETStandard),
the first sequence number of a channel (async-opcua), the renewal of a
superseded token (asyncua) and in-place key swaps on renewal (open62541,
Milo). The known gaps, the peer deviations you may meet and their workarounds
are listed in [Interop gaps and workarounds](docs/interop-gaps.md).

**Choose go-opcua if** you write Go and want client and server in one
library with no cgo and a permissive license, `context` control on every
call, reconnect with subscription recovery, retries and observability built
in, and a server that includes discovery, history and query out of the box.

**Choose open62541 if** you need a C library for embedded or bare-metal
targets, time-scheduled PubSub over Ethernet (TSN), constant time Brainpool ECC security
policies (OpenSSL), or a stack with an OPC Foundation certified server profile.

**Choose Eclipse Milo if** you are on the JVM and want asynchronous client
and server SDKs with strong support for dynamically decoded custom data
types.

**Choose UA-.NETStandard if** you build on .NET and need the OPC Foundation
reference implementation.

**Choose async-opcua, node-opcua or asyncua if** you work in Rust,
JavaScript / TypeScript or Python; check the footnotes and
[Interop gaps and workarounds](docs/interop-gaps.md) for the server behaviour
you rely on.

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
| **Alarms & Conditions** | `NewConditionEventFilter` / `ParseConditionEvent`, `Acknowledge`, `Confirm`, `AddComment`, `EnableCondition` / `DisableCondition`, `TimedShelve` / `OneShotShelve` / `Unshelve`, `ConditionRefresh` / `ConditionRefresh2`; v1.05 `Suppress` / `Unsuppress`, `RemoveFromService` / `PlaceInService`, `Silence`, `Reset`, `Respond`, `GetGroupMemberships` and every `*2` variant; `NewAuditConditionEventFilter` / `ParseAuditConditionEvent`, `WithAuditEntryID` (Part 9) |
| **Monitoring** | `monitor` package: callback/channel subscriptions; batch add with per-item `ItemError`; zero-value `MonitoringMode` defaults to Reporting |
| **Methods** | `Call`, `CallMethod` (auto-wrap args), `MethodArguments` introspection |
| **History** | Read: raw/modified, events, processed, at-time. Update: data, events. Delete: raw/modified, at-time, events |
| **Node Management** | `AddNodes`, `DeleteNodes`, `AddReferences`, `DeleteReferences` |
| **Query** | `QueryFirst`, `QueryNext` |
| **Discovery** | `FindServers`, `FindServersOnNetwork` (filters, paging), `GetEndpoints`, `ua.SelectEndpoint`, `opcua.SelectEndpoint` (aware of the client certificate's key type), `DiscoverServers` (well-known LDS port 4840), `RegisterServer` / `RegisterServer2`. Server: Local Discovery Server, registration with an LDS, mDNS (LDS-ME) without dependencies |
| **Security** | None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss, ECC_nistP256, ECC_nistP384, ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly, ECC_curve25519 (RSA, ECDSA and Ed25519 application certificates) |
| **Authentication** | Anonymous, username/password, X.509 certificate, issued token |
| **Certificate management** | `gds` package: push model of Part 12 §7 against a server's ServerConfiguration — TrustList read / write of every certificate group (`WithTrustList`), AddCertificate / RemoveCertificate, CreateSigningRequest, UpdateCertificate (PEM or PFX keys), GetRejectedList, ApplyChanges / CancelChanges, GetCertificates, CreateSelfSignedCertificate, ResetToServerDefaults, TransactionDiagnostics; pull model of Part 12 §6–§7.9 against a Global Discovery Server — `gds.PullClient` with the Directory and CertificateDirectory methods, `Enroll` (register, request, wait, read the trust list) and the result as client or server options |
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
| **Alarms & Conditions** | `AddCondition`: ConditionType, AcknowledgeableConditionType, AlarmConditionType and the limit / off-normal alarm subtypes with their standard components; Enable / Disable, AddComment, Acknowledge / Confirm with EventId checks, Retain, shelving, suppression, ConditionRefresh / ConditionRefresh2; v1.05 OutOfService / Silence / Latched states with Suppress / Unsuppress / RemoveFromService / PlaceInService / Silence / Reset and every `*2` variant, DialogConditionType (Respond / Respond2), condition branches, alarm groups and alarm suppression groups, AuditConditionEventType events (`WithAuditing`); methods run through the Call service and the `AccessController` (Part 9) |
| **History** | Pluggable `HistoryProvider`; default in-memory `*Historian` with optional update/delete/at-time/modified/processed interfaces |
| **Access Control** | Pluggable `AccessController` interface for per-operation authorization |
| **NodeSet2 Import** | Load standard or custom NodeSet2 XML via `ImportNodeSetXML`, including variable values, data types and access levels |
| **Reverse connect** | `WithReverseConnect` / `AddReverseConnect`: connect to listening clients, keep one idle connection available, retry with back-off, add and remove targets at run time |
| **Security** | Same encryption policies as client (server-side) |
| **Certificate management** | `WithPushManagement`: ServerConfiguration push model of Part 12 §7 — the DefaultApplicationGroup (trust list with CRLs, issuers and size limits that validates new channels and sessions), DefaultHttpsGroup (TLS certificate of opc.https / opc.wss, swapped live; TLS client trust list) and DefaultUserTokenGroup (X.509 user token trust list); UpdateCertificate with PEM or PFX keys, CreateSigningRequest (RSA, NIST / Brainpool ECC, Ed25519, Ed448), CreateSelfSignedCertificate, GetCertificates, GetRejectedList, ResetToServerDefaults, transactional ApplyChanges with TransactionDiagnostics, CertificateExpired / TrustListOutOfDate alarms; SecurityAdmin over SignAndEncrypt; optional `CertificateStore`. `gds/gdsserver`: a Global Discovery Server (pull model of Part 12 §6, §7.9) — application directory, CA issuing certificates and CRLs, TrustList, role-based access, pluggable `Store` |
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
| `gds` | Certificate management clients of Part 12: push (`Client`: trust lists of every group, signing requests, certificate updates (PEM, PFX), self-signed certificates, transaction diagnostics) and pull (`PullClient`: application directory, certificate requests, `Enroll`) |
| `gds/gdsserver` | Global Discovery Server (Part 12 pull model): application directory, CA issuing certificates and CRLs, TrustList, pluggable `Store`, DiscoveryAdmin / CertificateAuthorityAdmin / SecurityAdmin roles |
| `gds/gdsid` | NodeIds of the GDS information model (namespace `http://opcfoundation.org/UA/GDS/`) |
| `errors` | Sentinel errors for `errors.Is()` checking |
| `id` | Well-known NodeID constants (generated from OPC-UA schema) |
| `uacp` | OPC-UA Connection Protocol over TCP and TLS WebSockets; `ParseEndpoint`, `DialWithTimeout`, `ListenWebSocket` |
| `uasc` | OPC-UA Secure Conversation (secure channel); the HTTPS channel (`NewHTTPSChannel`) |
| `uapolicy` | Security policy implementations (encryption, signing) |
| `pubsub` | PubSub runtime (Part 14): publishers, subscribers, configuration builders; sub-packages `message`, `uadp`, `jsonmsg`, `transport` (`udp`, `eth`, `mqtt`, `amqp`), `security`, `sks`, `remote` |
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

go-opcua is continuously interoperability-tested in all applicable client/server directions against open62541, Eclipse Milo, async-opcua, UA-.NETStandard, node-opcua and asyncua, all six in every interop CI run. The directional evidence ledger is maintained in [interop/COVERAGE.md](interop/COVERAGE.md) and `interop/testdata/ledger-*.json`; see [Interop evidence](#interop-evidence).

- **Verify gate**: `make verify` — `go vet`, unit tests, race tests, and interop (`make vet`, `make test-norace`, `make test`, `make interop`).
- **Unit tests**: `make test-norace` (`go test -count=1 ./...`), `make test` (same with `-race`).
- **Coverage**: `make coverage` writes `coverage.out` for core library packages (90% gate); CI passes the same `COVER_PKGS` list as `coverpkg` to the shared workflow so Codecov matches. `make cover` opens the report.
- **Integration tests** (tag-gated, not in `go test ./...`): `make integration` (Go client vs FreeOpcUa Python server; needs `make install-py-opcua`), `make selfintegration` (Go client vs in-process Go server).
- **Interop tests** (tag-gated): `make interop` — `go test -tags=interop ./interop/...` against [opcua-interop](https://github.com/otfabric/opcua-interop) adapter containers (open62541 and Milo by default; async-opcua, UA-.NETStandard, node-opcua and asyncua with `ASYNC_OPCUA_IMAGE`, `DOTNET_IMAGE`, `NODE_OPCUA_IMAGE`, `ASYNCUA_IMAGE`). See [INTEROP.md](INTEROP.md).
- **Chaos and parallelism tests** (Go client vs Go server in one process, no Docker; part of `go test ./...` with a short fault phase): `make chaos` runs them with a 30 s fault phase per scenario (`CHAOS_DURATION`, `CHAOS_SEED`, `CHAOS_LOG`). `chaos/` covers the unsecured state machines, `chaos/secure` the RSA, ECC and AEAD security policies (incl. bit flips, replayed, lost and reordered chunks), `chaos/datachange` DataChangeFilter and sampling, `chaos/reverse` reverse connect, `chaos/discovery` the LDS, registration and mDNS, `chaos/codec` the JSON / XML codecs and the shared NodeSet values, `chaos/pubsub` PubSub over lossy UDP and in-memory networks, Ethernet, MQTT 3.1.1 / 5.0 and AMQP 1.0 broker faults, key rotation and the SKS, chunks, discovery, Actions and diagnostics, and many runtimes on shared brokers. Every randomized scenario logs its seed and the command that replays it; see [`chaos/doc.go`](chaos/doc.go).
- **Fuzz tests**: `ua/fuzz_test.go`, `ua/codec_fuzz_test.go` (JSON and XML decoders), `uasc/fuzz_test.go`, `uacp/fuzz_test.go`, the WebSocket framing and handshake (`internal/websocket`), HTTPS request bodies (`server`); PubSub: the UADP, JSON, chunk, discovery and Action decoders (`pubsub/uadp`, `pubsub/jsonmsg`), the runtime receive path and connection validation (`chaos/pubsub`), the MQTT and AMQP clients (`internal/mqtt`, `internal/amqp`) and the Ethernet frame, URL and BPF parsers (`pubsub/transport/eth`).
- **PubSub end to end**: `conformance/pubsub/pubsub_*_test.go` run server-to-server PubSub configured by OPC UA clients through the PublishSubscribe methods, over UDP (plain, secured, chunked), MQTT 5.0, AMQP 1.0 and an in-memory Ethernet link, with discovery and diagnostics read through a client.
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
| | WebSockets (`opc.wss://`, Part 6 §7.5, wss-uasc-uabinary, sub-protocol `opcua+uacp`) | Yes (client and server) |
| | HTTPS (`opc.https://`, `https://`, Part 6 §7.4, https-uabinary) | Yes (client and server) |
| | HTTPS / WebSockets with UA JSON (`https-uajson`, `wss-uajson`) | No |
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
| | ECC_brainpoolP256r1 / ECC_brainpoolP384r1 | Yes (not constant time, see [Security](docs/security.md#brainpool-and-curve448)) |
| | ECC_curve448 (Ed448, X448, ChaCha20-Poly1305) | Yes |
| | PubSub-Aes128-CTR / PubSub-Aes256-CTR | Yes (PubSub UADP message security) |

PubSub (Part 14) is implemented in the `pubsub` packages: UDP (`opc.udp://`, unicast and multicast), Ethernet (`opc.eth://`, UADP only), MQTT 3.1.1 and 5.0 (`mqtt://`, `mqtts://`) and AMQP 1.0 (`amqp://`, `amqps://`) transports with the UADP and JSON message mappings; the PubSub-Aes128-CTR / PubSub-Aes256-CTR policies secure UADP messages and are not secure-channel policies. See [PubSub](docs/pubsub.md).

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
