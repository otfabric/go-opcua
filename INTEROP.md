# go-opcua Interoperability

`go-opcua` owns which capabilities need verification. Tests in `interop/` consume the adapter images published by [opcua-interop](https://github.com/otfabric/opcua-interop) and assert `go-opcua` behaviour against live, independent OPC UA implementations.

New adapter commands or fixture capabilities are requested from `opcua-interop` only when a required external operation does not yet exist there.

## Architecture

The suite uses a dual layout that mirrors [`interop/COVERAGE.md`](interop/COVERAGE.md):

1. **Peer-direction baseline** — four large files mirrored across stacks; each maps to one ledger direction column (C→O, C→M, O→S, M→S).
2. **Capability companions** — smaller files grouped by COVERAGE.md section. `*_test.go` is Go↔Go semantics; `*_peer_test.go` is peer evidence that can earn ✅.

```
opcua-interop
  open62541 adapter image   (C, native OPC UA stack)
  milo adapter image        (Java/JVM OPC UA stack)
         |
    go-opcua/interop/
      # Infrastructure
      harness_test.go                      container lifecycle, dial helpers, fixture PKI
      helpers_test.go                      shared Go↔Go / peer helpers
      coverage_validate_test.go            ledger integrity (no docker)

      # Peer-direction baseline (COVERAGE directions)
      open62541_server_test.go             TestOpen62541Server_*           (C→O)
      open62541_client_test.go             TestGoServer_Open62541Client_*  (O→S)
      milo_server_test.go                  TestMiloServer_*                (C→M)
      milo_client_test.go                  TestGoServer_MiloClient_*       (M→S)

      # Capability companions (COVERAGE sections)
      events_test.go / events_peer_test.go / events_c2peer_test.go
      history_test.go / history_peer_test.go / history_c2peer_test.go
      history_continuation_peer_test.go
      subscription_lifecycle_test.go / subscription_lifecycle_peer_test.go
      subscription_recovery_test.go / subscription_recovery_peer_test.go
      subscription_reconnect_peer_test.go / tcp_disruptor_test.go
      subscription_timestamps_test.go / subscription_timestamps_peer_test.go
      discovery_peer_test.go / translate_peer_test.go
      security_peer_test.go / method_peer_test.go
      monitored_item_queue_test.go         subscriptions (queue windows)
      index_range_test.go                  attribute (IndexRange edges)
      browse_mask_test.go                  browse (ResultMask bits)

      # Ledger
      coverage.json / capabilities.json    source of truth
      COVERAGE.md                          generated matrix
      GAPS.md                              generated unverified summary
```

Peer tests:
1. Start the adapter container with `docker run` (server tests) or run the client container (client tests).
2. Wait for the server ready file (`/run/opcua-interop/ready`) via `docker exec`.
3. Exercise the `go-opcua` API under test, or parse the adapter client's JSON output.
4. Assert results.
5. Tear the container down.

Go↔Go companions skip docker and exercise deeper semantics that peers do not yet cover. They never earn a ledger ✅.

No pre-running containers. No manual steps. Tests are gated behind `-tags=interop`.

## Running

```bash
# Build adapter images locally (in opcua-interop)
cd ../opcua-interop && make image-open62541 image-milo

# Run against local dev images
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541:dev \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo:dev \
make interop

# Run against published v0.5.0 release images (default)
make interop

# CI — digest pinned (update interop.yml after each release)
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541@sha256:53c7a184ca9769bab87c6b5335c01322925411894368644913133c0812999283 \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo@sha256:c462f45a5e9b9ce8878788b97c77973832b23861e7ae5d0c6642279f798c15cf \
make interop
```

## Local development (go work)

While iterating between `go-opcua` and `opcua-interop` before a stable release, use the Go workspace to avoid publishing intermediate module versions:

```bash
# From the workspace root (otfabric/)
cat go.work          # go-opcua should be listed

# Build images locally
cd opcua-interop && make image-open62541 image-milo

# Run interop tests against the local images
cd ../go-opcua
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541:dev \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo:dev \
go test -tags=interop -v ./interop/...
```

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPEN62541_IMAGE` | open62541 adapter image | digest-pinned `v0.5.0` (see defaults in `harness_test.go`) |
| `MILO_IMAGE` | Milo (Java) adapter image | digest-pinned `v0.5.0` (see defaults in `harness_test.go`) |
| `OPCUA_INTEROP_FIXTURE_DIR` | Path to fixture directory containing `baseline.json` | `testdata/` |
| `OPCUA_INTEROP_PKI_DIR` | Root of test PKI tree | `../../opcua-interop/certs/test-pki` |
| `OPCUA_INTEROP_REQUIRE_CAPABILITIES` | Fail (instead of skip) when a peer image lacks a required client op | unset (skip) |

## Test naming

| Prefix | Go role | Adapter counterpart | Ledger direction |
|--------|---------|---------------------|------------------|
| `TestOpen62541Server_` | OPC UA client | open62541 server | C→O |
| `TestGoServer_Open62541Client_` | OPC UA server | open62541 client | O→S |
| `TestMiloServer_` | OPC UA client | Milo server | C→M |
| `TestGoServer_MiloClient_` | OPC UA server | Milo client | M→S |
| `TestGoServer_` (no peer infix) | OPC UA server + client | none (Go↔Go) | companion only |

Verified peer evidence names in `coverage.json` must exist as `func Test…` in `interop/*_test.go` (`TestCoverageManifestValid` enforces this).

---

## OPC UA compatibility matrix

The directional ledger ([`interop/COVERAGE.md`](interop/COVERAGE.md)) is authoritative for peer ✅.
The human-readable tables below summarize the peer-direction baseline surface.
Capability companions for `events`, `history`, and subscription recovery are tracked only in the ledger (and in the Go↔Go companion files).

Key: ✓ covered · — not yet tested · n/a not applicable · ⚠ known limitation

### go-opcua client ↔ open62541

| Capability | Go→open62541 | open62541→Go |
|-----------|:---:|:---:|
| Connect / disconnect | ✓ | ✓ |
| Namespace discovery | ✓ | ✓ |
| Browse Objects folder | ✓ | ✓ |
| Scalar read — Boolean | ✓ | ✓ |
| Scalar read — SByte | ✓ | ✓ |
| Scalar read — Byte | ✓ | ✓ |
| Scalar read — Int16 | ✓ | ✓ |
| Scalar read — UInt16 | ✓ | ✓ |
| Scalar read — Int32 | ✓ | ✓ |
| Scalar read — UInt32 | ✓ | ✓ |
| Scalar read — Int64 | ✓ | ✓ |
| Scalar read — UInt64 | ✓ | ✓ |
| Scalar read — Float | ✓ | ✓ |
| Scalar read — Double | ✓ | ✓ |
| Scalar read — String (Unicode) | ✓ | ✓ |
| Scalar read — DateTime | ✓ | ✓ |
| Scalar read — Guid | ✓ | ✓ |
| Scalar read — ByteString | ✓ | ✓ |
| Scalar read — XmlElement | ✓ | ✓ |
| Scalar read — NodeId | ✓ | ✓ |
| Scalar read — QualifiedName | ✓ | ✓ |
| Scalar read — LocalizedText | ✓ | ✓ |
| Scalar read — StatusCode | ✓ | ✓ |
| Array read — Int32 | ✓ | ✓ |
| Array read — Empty | ✓ | ✓ |
| Array read — String | ✓ | ✓ |
| Array read — ByteString | ✓ | ✓ |
| Array read — Matrix2D (Double) | ✓ | ✓ |
| Array read — Boolean | ✓ | ✓ |
| Array read — Double | ✓ | ✓ |
| Write and read-back — Int32 | ✓ | ✓ |
| Write and read-back — Boolean | ✓ | ✓ |
| Write and read-back — Float | ✓ | ✓ |
| Write and read-back — String | ✓ | ✓ |
| Dynamic counter read | ✓ | ✓ |
| Batch Read (4 scalars in one request) | ✓ | ✓ |
| Method call — Add (Int32) | ✓ | ✓ |
| Method call — Multiply (Double) | ✓ | ✓ |
| Method call — Echo (String round-trip) | ✓ | ✓ |
| Method call — NoArguments | ✓ | ✓ |
| Method call — MultipleOutputs | ✓ | ✓ |
| Method call — Fail (Bad result) | ✓ | ✓ |
| Subscription — Dynamic.Counter | ✓ | ✓ |
| Subscription — Dynamic.Toggle (bool alternation) | ✓ | ✓ |
| Subscription — Dynamic.Ramp (float64 sawtooth) | ✓ | ✓ |
| Subscription queue size > 1 (batch delivery) | ✓ | ✓ |
| Subscription discard-oldest=false (keep-oldest) | ✓ | ✓ |
| DataValue source + server timestamp | ✓ | ✓ |
| DataValue Uncertain status code | ✓ | ✓ |
| Access.ReadOnly write rejection | ✓ | ✓ |
| Access.WriteOnly read rejection | ✓ | ✓ |
| Browse interop namespace (top-level folders) | ✓ | ✓ |
| Browse Scalars folder (variable node list) | ✓ | ✓ |
| Browse interop Objects folder (node name check) | ✓ | ✓ |
| Browse with BrowseNext pagination | ✓ | ✓ |
| Basic256Sha256 / Sign | ✓ | ✓ |
| Basic256Sha256 / SignAndEncrypt | ✓ | ✓ |
| Aes128_Sha256_RsaOaep / SignAndEncrypt | ✓ | ✓ |
| Aes256_Sha256_RsaPss / SignAndEncrypt | ✓ | ✓ |
| Trusted cert accepted | ✓ | ✓ |
| Untrusted cert rejection | ✓ | ✓ |
| Username / valid credentials | ✓ | ✓ |
| Username / invalid credentials | ✓ | ✓ |
| Batch Write (per-item StatusCodes) | ✓ | ✓ |
| Write type mismatch → BadTypeMismatch | ✓ | ✓ |
| Method validation (count/type/identity) | ✓ | ✓ |
| IndexRange unsupported rejected | ✓ | ✓ |
| IndexRange subset Read/Write (1D + matrix) | ✓ | ✓ |
| Exact QueueSize / DiscardOldest windows | ✓ | ✓* |
| Subscription TimestampsToReturn | ✓ | ✓* |
| TimestampsToReturn honored (Read) | ✓ | ✓* |
| Write EncodingMask / BadWriteNotSupported | ✓ | ✓ |
| Browse ResultMask | ✓ | ✓ |
| BrowseNext early release | ✓ | ✓ |
| Untrusted cert rejected at SecureChannel | ✓ | ✓ |
| Browse filtering (NodeClassMask / IncludeSubtypes) | ✓ | ✓ |
| Invalid NodeId service results | ✓ | ✓ |

\* Go-client-driven against Go server always; adapter reverse only where CLI exposes the control (`--queue-size`, `--discard-oldest`, `--timestamps` on subscribe).

### go-opcua client ↔ Milo

| Capability | Go→Milo | Milo→Go |
|-----------|:---:|:---:|
| Connect / disconnect | ✓ | ✓ |
| Namespace discovery | ✓ | ✓ |
| Browse Objects folder | ✓ | ✓ |
| Scalar read — Boolean | ✓ | ✓ |
| Scalar read — SByte | ✓ | ✓ |
| Scalar read — Byte | ✓ | ✓ |
| Scalar read — Int16 | ✓ | ✓ |
| Scalar read — UInt16 | ✓ | ✓ |
| Scalar read — Int32 | ✓ | ✓ |
| Scalar read — UInt32 | ✓ | ✓ |
| Scalar read — Int64 | ✓ | ✓ |
| Scalar read — UInt64 | ✓ | ✓ |
| Scalar read — Float | ✓ | ✓ |
| Scalar read — Double | ✓ | ✓ |
| Scalar read — String (Unicode) | ✓ | ✓ |
| Scalar read — DateTime | ✓ | ✓ |
| Scalar read — Guid | ✓ | ✓ |
| Scalar read — ByteString | ✓ | ✓ |
| Scalar read — XmlElement | ✓ | ✓ |
| Scalar read — NodeId | ✓ | ✓ |
| Scalar read — QualifiedName | ✓ | ✓ |
| Scalar read — LocalizedText | ✓ | ✓ |
| Scalar read — StatusCode | ✓ | ✓ |
| Array read — Int32 | ✓ | ✓ |
| Array read — Empty | ✓ | ✓ |
| Array read — String | ✓ | ✓ |
| Array read — ByteString | ✓ | ✓ |
| Array read — Matrix2D (Double) | ✓ | ✓ |
| Array read — Boolean | ✓ | ✓ |
| Array read — Double | ✓ | ✓ |
| Write and read-back — Int32 | ✓ | ✓ |
| Write and read-back — Boolean | ✓ | ✓ |
| Write and read-back — Float | ✓ | ✓ |
| Write and read-back — String | ✓ | ✓ |
| Dynamic counter read | ✓ | ✓ |
| Batch Read (4 scalars in one request) | ✓ | ✓ |
| Method call — Add (Int32) | ✓ | ✓ |
| Method call — Multiply (Double) | ✓ | ✓ |
| Method call — Echo (String round-trip) | ✓ | ✓ |
| Method call — NoArguments | ✓ | ✓ |
| Method call — MultipleOutputs | ✓ | ✓ |
| Method call — Fail (Bad result) | ✓ | ✓ |
| Subscription — Dynamic.Counter | ✓ | ✓ |
| Subscription — Dynamic.Toggle (bool alternation) | ✓ | ✓ |
| Subscription — Dynamic.Ramp (float64 sawtooth) | ✓ | ✓ |
| Subscription queue size > 1 (batch delivery) | ✓ | ✓ |
| Subscription discard-oldest=false (keep-oldest) | ✓ | ✓ |
| DataValue source + server timestamp | ✓ | ✓ |
| DataValue Uncertain status code | ✓ | ✓ |
| Access.ReadOnly write rejection | ✓ | ✓ |
| Access.WriteOnly read rejection | ✓ | ✓ |
| Browse interop namespace (top-level folders) | ✓ | ✓ |
| Browse Scalars folder (variable node list) | ✓ | ✓ |
| Browse interop Objects folder (node name check) | ✓ | ✓ |
| Browse with BrowseNext pagination | ✓ | ✓ |
| Basic256Sha256 / Sign | ✓ | ✓ |
| Basic256Sha256 / SignAndEncrypt | ✓ | ✓ |
| Aes128_Sha256_RsaOaep / SignAndEncrypt | ✓ | ✓ |
| Aes256_Sha256_RsaPss / SignAndEncrypt | ✓ | ✓ |
| Trusted cert accepted | ✓ | ✓ |
| Untrusted cert rejection | ✓ | ✓ |
| Username / valid credentials | ✓ | ✓ |
| Username / invalid credentials | ✓ | ✓ |
| Batch Write (per-item StatusCodes) | ✓ | ✓ |
| Write type mismatch → BadTypeMismatch | ✓ | ✓ |
| Method validation (count/type/identity) | ✓ | ✓ |
| IndexRange unsupported rejected | ✓ | ✓ |
| IndexRange subset Read/Write (1D + matrix) | ✓ | ✓ |
| Exact QueueSize / DiscardOldest windows | ✓ | ✓* |
| Subscription TimestampsToReturn | ✓ | ✓* |
| TimestampsToReturn honored (Read) | ✓ | ✓* |
| Write EncodingMask / BadWriteNotSupported | ⚠ | ✓ |
| Browse ResultMask | ✓ | ✓ |
| BrowseNext early release | ✓ | ✓ |
| Untrusted cert rejected at SecureChannel | ✓ | ✓ |
| Browse filtering (NodeClassMask / IncludeSubtypes) | ✓ | ✓ |
| Invalid NodeId service results | ✓ | ✓ |

\* Go-client-driven against Go server always; adapter reverse only where CLI exposes the control (`--queue-size`, `--discard-oldest`, `--timestamps` on subscribe).
⚠ Milo soft-accepts EncodingMask-bearing Writes; ledger marks `write.encoding-mask` C→M as `unsupported` (claim requires `BadWriteNotSupported`).

---

## Fixtures

`interop/testdata/baseline.json` is a synchronized copy of the canonical fixture from `opcua-interop/fixtures/baseline/fixture.json`. Update it alongside the pinned adapter image version when the fixture contract changes.

## Current status

The directional compatibility ledger is the source of truth:

- [`interop/coverage.json`](interop/coverage.json) + [`interop/capabilities.json`](interop/capabilities.json) — edit these
- [`interop/COVERAGE.md`](interop/COVERAGE.md) — generated matrix (`go generate ./interop`)
- [`interop/GAPS.md`](interop/GAPS.md) — generated unverified summary (`go run ./internal/cmd/render-interop-coverage -summary -write-gaps=interop/GAPS.md`)

Go↔Go companions never earn a verified checkmark. A row may move to `verified` only after a named peer test runs against the pinned peer environment **without skip** and asserts that exact capability.

Every `unverified` row must carry a controlled `reason`:

`test-missing` · `adapter-command-missing` · `adapter-fixture-missing` · `fault-harness-missing` · `consumer-demand-missing` · `peer-capability-unknown`

Adapter images are pinned to [opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0) (digest-pinned below). Peer capability companions use `OPCUA_INTEROP_REQUIRE_CAPABILITIES=1` in CI so missing ops fail rather than skip.

| Image | Tag |
|-------|-----|
| `ghcr.io/otfabric/opcua-interop-open62541` | [`v0.5.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0) / `@sha256:53c7a184…2999283` |
| `ghcr.io/otfabric/opcua-interop-milo` | [`v0.5.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0) / `@sha256:c462f45a…798c15cf` |

> **Local dev images:** Override `OPEN62541_IMAGE` / `MILO_IMAGE` when testing unreleased adapter builds.

**Interop claim rule:** only modes with positive and negative peer tests in the ledger are claimed interoperable.

### Evidence objective

Optimise for accurate evidence, not a zero-unverified quota. Current ledger: **0 unverified** rows — remaining gaps are `deferred`, `unsupported`, or `not-applicable` (see [`GAPS.md`](interop/GAPS.md) and [`BUCKET_B.md`](interop/BUCKET_B.md)).

### Recently promoted peer rows (core evidence)

| Capability | Directions |
|---|---|
| `discovery.find-servers` | all applicable (C→ + O→S/M→S) |
| `translate.browse-path` | all four |
| `security.cert.trusted` | C→O, C→M |
| `method.validation` | C→O, C→M |
| `subscription.timestamps` | all four |
| `subscription.server.republish` | O→S, M→S |
| `subscription.server.transfer` | O→S, M→S |
| `subscription.client.republish` | C→O, C→M |
| `subscription.client.transfer` | C→O, C→M |
| `subscription.recovery.reconnect` | C→O, C→M (`recreated`) |
| `event.subscription` / decode / select | C→ + O→S/M→S (as applicable) |
| `event.filter.of-type` / `severity-threshold` | all four |
| `history.read.raw` | all four |
| `history.read.continuation` | O→S, M→S |

### Remaining gaps (summary)

- **Unsupported (behavioural):** `write.encoding-mask` C→M — Milo soft-accepts; claim requires `BadWriteNotSupported`.
- **Deferred** (outside current core parity): NodeSet2 import, advanced HA, cross-stack custom DataTypes, Query, NodeManagement, IssuedIdentityToken, A&C, LDS/GDS, dynamic EO decode, custom event emission, general WhereClause surface, C→ history continuation.

#### events — Go↔Go companions

All tests in `interop/events_test.go` exercise a Go server + Go client with no peer adapter:

| Test | What it covers |
|---|---|
| `TestGoServer_EventSubscription_BasicLifecycle` | CreateMonitoredItems + EmitBaseEvent + Publish delivery |
| `TestGoServer_EventFilter_InvalidReject` | Rejection of missing/empty filter; lenient acceptance of unsupported Where ops |
| `TestGoServer_EventMultipleEmissions` | Five events delivered in severity order |
| `TestGoServer_CustomEventSubtype` | User-defined `ObjectType` node accepted as `OfType` operand; non-matching type suppressed |
| `TestGoServer_WhereClause_SeverityFilter` | `GreaterThanOrEqual` WhereClause operator filters events by `Severity` |
| `TestGoServer_CustomEventFields` | User fields from `BaseEvent.Fields` selected by name and delivered |
| `TestGoServer_ModifyMonitoredItem_EventFilter` | ModifyMonitoredItems updates the live event filter; post-modify filter enforced |

Peer event subscription, BaseEvent emission, SelectClauses, OfType, and severity-threshold filters are verified on the published v0.5.0 pins. Broad WhereClause and custom event emission remain deferred.

#### custom-types — Go↔Go companions

Tests in `conformance/customtypes_test.go` exercise registered custom DataTypes locally. Cross-stack custom DataType fixture peer verification is `deferred`. Dynamic structure decoding is `deferred`.
