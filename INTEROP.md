# go-opcua Interoperability

`go-opcua` owns which capabilities need verification. Tests in `interop/` consume the adapter images published by [opcua-interop](https://github.com/otfabric/opcua-interop) and assert `go-opcua` behaviour against live, independent OPC UA implementations.

New adapter commands or fixture capabilities are requested from `opcua-interop` only when a required external operation does not yet exist there.

## Architecture

```
opcua-interop
  open62541 adapter image   (C, native OPC UA stack)
  milo adapter image        (Java/JVM OPC UA stack)
         |
    go-opcua/interop/
      harness_test.go                 lifecycle helpers, server/client helpers
      open62541_server_test.go        TestOpen62541Server_*           (go client ← open62541 server)
      open62541_client_test.go        TestGoServer_Open62541Client_*  (open62541 client → go server)
      milo_server_test.go             TestMiloServer_*                (go client ← Milo server)
      milo_client_test.go             TestGoServer_MiloClient_*       (Milo client → go server)
```

Each test:
1. Starts the adapter container with `docker run` (server tests) or runs the client container (client tests).
2. Waits for the server ready file (`/run/opcua-interop/ready`) via `docker exec`.
3. Exercises the `go-opcua` API under test, or parses the adapter client's JSON output.
4. Asserts results.
5. Tears the container down.

No pre-running containers. No manual steps. Tests are gated behind `-tags=interop`.

## Running

```bash
# Build adapter images locally (in opcua-interop)
cd ../opcua-interop && make image-open62541 image-milo

# Run against local dev images
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541:dev \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo:dev \
make interop

# Run against published v0.4.0 release images (default)
make interop

# CI — digest pinned (update interop.yml after each release)
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541@sha256:c3bf9c6b740948449e52080021a716def08db913eb3ba0b08e397f60cbd29061 \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo@sha256:eb204edd8a715e071118fae89650c114687bd97e31be24819da8ba5295cce844 \
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
| `OPEN62541_IMAGE` | open62541 adapter image | digest-pinned `v0.4.0` (see defaults in `harness_test.go`) |
| `MILO_IMAGE` | Milo (Java) adapter image | digest-pinned `v0.4.0` (see defaults in `harness_test.go`) |
| `OPCUA_INTEROP_FIXTURE_DIR` | Path to fixture directory containing `baseline.json` | `testdata/` |
| `OPCUA_INTEROP_PKI_DIR` | Root of test PKI tree | `../../opcua-interop/certs/test-pki` |

## Test naming

| Prefix | Go role | Adapter counterpart |
|--------|---------|---------------------|
| `TestOpen62541Server_` | OPC UA client | open62541 server |
| `TestGoServer_Open62541Client_` | OPC UA server | open62541 client |
| `TestMiloServer_` | OPC UA client | Milo server |
| `TestGoServer_MiloClient_` | OPC UA server | Milo client |

---

## OPC UA compatibility matrix

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
| Method validation (count/type/identity) | — | ✓ |
| IndexRange unsupported rejected | ✓ | ✓ |
| IndexRange subset Read/Write (1D + matrix) | ✓ | ✓ |
| Exact QueueSize / DiscardOldest windows | ✓ | ✓* |
| Subscription TimestampsToReturn | ✓ | ✓* |
| TimestampsToReturn honored (Read) | ✓ | ✓* |
| Write EncodingMask / BadWriteNotSupported | ✓ | ✓* |
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
| Method validation (count/type/identity) | — | ✓ |
| IndexRange unsupported rejected | ✓ | ✓ |
| IndexRange subset Read/Write (1D + matrix) | ✓ | ✓ |
| Exact QueueSize / DiscardOldest windows | ✓ | ✓* |
| Subscription TimestampsToReturn | ✓ | ✓* |
| TimestampsToReturn honored (Read) | ✓ | ✓* |
| Write EncodingMask / BadWriteNotSupported | ✓ | ✓* |
| Browse ResultMask | ✓ | ✓ |
| BrowseNext early release | ✓ | ✓ |
| Untrusted cert rejected at SecureChannel | ✓ | ✓ |
| Browse filtering (NodeClassMask / IncludeSubtypes) | ✓ | ✓ |
| Invalid NodeId service results | ✓ | ✓ |

\* Go-client-driven against Go server always; adapter reverse only where CLI exposes the control (`--queue-size`, `--discard-oldest`, `--timestamps` on subscribe).

---

## Fixtures

`interop/testdata/baseline.json` is a synchronized copy of the canonical fixture from `opcua-interop/fixtures/baseline/fixture.json`. Update it alongside the pinned adapter image version when the fixture contract changes.

## Current status

Phases 12–17 ship in go-opcua **v1.3.0**. Adapter images are pinned to
[opcua-interop v0.4.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.4.0) (digest-pinned below).

The interop suite has **318** tests (`go test -tags=interop ./interop/...`).

**Phases 12–14 are four-direction peer-complete** against open62541 and Milo (where the adapter CLI exposes the control).

**Phases 15–17 are implemented end-to-end and verified Go client ↔ Go server; independent peer interoperability remains deferred** (EventFilter / Republish / Transfer / HistoryRead adapter CLI not yet shipped).

| Image | Tag |
|-------|-----|
| `ghcr.io/otfabric/opcua-interop-open62541` | [`v0.4.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.4.0) / `@sha256:c3bf9c6b…d29061` |
| `ghcr.io/otfabric/opcua-interop-milo` | [`v0.4.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.4.0) / `@sha256:eb204edd…cce844` |

> **Local dev images:** Use `OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541:dev` and `MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo:dev` when testing local adapter changes. The defaults pin to a released version for reproducibility.

### Phases 12–14 — peer-verified (v0.4.0)

- IndexRange subsets, Read `TimestampsToReturn`, Write EncodingMask, Browse ResultMask / BrowseNext release, SecureChannel trust
- Exact `QueueSize` / `DiscardOldest` windows + subscription `TimestampsToReturn`
- `subscribe` — `subscriptionId` + revised CreateSubscription fields
- `subscription-lifecycle` — scenarios `revise`, `publishing-mode`, `monitoring-mode`, `delete`
- Go↔Go lifecycle tests in `interop/phase13_test.go` / `phase14_test.go` + adapter reverse in `phase14_adapter_test.go`

### Phases 15–17 — Go↔Go only (peer pending)

| Capability | Go→Go | Peer |
|-----------|:---:|:---:|
| Event subscription — EventFilter / OfType / EmitBaseEvent | ✓ | pending |
| Event subscription — invalid filter rejection | ✓ | pending |
| Republish — available / missing / invalid | ✓ | pending |
| TransferSubscriptions — ownership / invalid | ✓ | pending |
| ACK removes sequence from available | ✓ | pending |
| HistoryRead — raw / continuation / modified reject / non-historized | ✓ | pending |

### Adapter interop gaps (next peer-closure phase)

- `subscribe --event` — event subscription with EventFilter (open62541 + Milo)
- `history-read --raw` — HistoryRead with ReadRawModifiedDetails (open62541 + Milo)
- `republish` — Republish service call (open62541 + Milo)
- `transfer` — TransferSubscriptions service call (open62541 + Milo)
