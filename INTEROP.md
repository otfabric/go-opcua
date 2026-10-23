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
      helpers_test.go                      shared Go↔Go / peer helpers, capability gates
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
      extended_peer_test.go                channel renewal, C→ history continuation,
                                           RegisterNodes, NodeManagement, modify services
      monitored_item_queue_test.go         subscriptions (queue windows)
      index_range_test.go                  attribute (IndexRange edges)
      browse_mask_test.go                  browse (ResultMask bits)
      datachange_filter_peer_test.go       DataChangeFilter deadband (absolute / percent),
                                           trigger, sampling interval — all four directions
      codec_peer_test.go                   JSON / XML DataEncoding round trips (open62541, Milo)
      ecc_peer_test.go                     ECC_nistP256 / ECC_nistP384 (open62541), user token,
                                           renewal, unimplemented ECC policies refused;
                                           AEAD policies (AesGcm, ChaChaPoly, curve25519)
      reverse_connect_peer_test.go         reverse connect, both halves, None / RSA / ECC (open62541)
      discovery_lds_peer_test.go           LDS registration, RegisterServer(2),
                                           FindServersOnNetwork, mDNS
      discoverypeer/                       go-opcua server run in a container for the mDNS tests

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

# The security, ECC and secured reverse connect tests need the test PKI of
# opcua-interop v0.8.1 (RSA identities plus ecc-<curve>/ certificates):
(cd ../opcua-interop && certs/generate.sh)        # or: certs/generate.sh --add-ecc on an existing PKI
export OPCUA_INTEROP_PKI_DIR=$PWD/../opcua-interop/certs/test-pki

# Run against the default (digest-pinned) release images
make interop

# Release verification: nothing the images advertise may be skipped
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 make interop

# CI — digest pinned (update interop.yml after each release)
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541@sha256:2f008620c41ca6f752abe5d9a470cdba2742afed92d93b7ec6332750e20b9e84 \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo@sha256:0fbbf7624ce59d7e8e0ff866570e1cdb6fc8f3aadd6900d3d29e6d21b2a823ed \
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
| `OPEN62541_IMAGE` | open62541 adapter image | digest pin in `harness_test.go` (see [Current status](#current-status)) |
| `MILO_IMAGE` | Milo (Java) adapter image | digest pin in `harness_test.go` |
| `OPCUA_INTEROP_FIXTURE_DIR` | Path to fixture directory containing `baseline.json` | `testdata/` |
| `OPCUA_INTEROP_PKI_DIR` | Root of the test PKI tree generated by `opcua-interop/certs/generate.sh` (v0.8.0 or later; since v0.7.0 the ECC tests need `<identity>/ecc-<curve>/cert.crt\|cert.key`) | `../../opcua-interop/certs/test-pki` |
| `OPCUA_INTEROP_REQUIRE_CAPABILITIES` | `1`: fail instead of skip when an image lacks a client operation, a client/server feature or a security profile the suite has evidence for, or when the test PKI is missing | unset (skip) |
| `INTEROP_DEBUG_LOG` | Print the Go server's structured log to stderr in the SecureChannel renewal peer tests | unset |

### Requirements beyond Docker

- **Test PKI.** `opcua-interop/certs/generate.sh` (OpenSSL ≥ 1.1.1 with brainpool, Ed25519 and Ed448) writes the CA, the RSA identities and, per identity, one ECC certificate per curve. The suite never mounts that tree directly: it hands the containers a world-readable copy, because the generator writes private keys with mode `0600` and the adapter images do not run as root (on a Linux Docker host the key would be unreadable; Docker Desktop hides that). The CI workflow checks out `opcua-interop` at the pinned release and generates the PKI before `make interop`.
- **User-defined Docker networks.** mDNS needs both peers on one network segment and Docker Desktop does not route multicast between the host and containers. `TestMulticast_GoAndPeers` therefore creates a bridge network (`docker network create`), runs the open62541 LDS on it and cross-compiles `interop/discoverypeer` (a go-opcua LDS) into a second container on the same network; the Go client reaches both through published ports. The network is removed when the test ends. The Docker daemon must allow creating bridge networks and the Go toolchain must be able to cross-compile for the daemon's architecture (`GOOS=linux`, `CGO_ENABLED=0`).
- **Host reachability from containers.** Adapter clients and reverse-connecting servers reach the Go side through `host.docker.internal` (`--add-host=host.docker.internal:host-gateway`).
- **Default pins must match the suite.** A capability-gated test fails — it does not skip — when the image in use is the default pin and that pin is not the opcua-interop release named by `interopVersion` in `harness_test.go`. An image passed through `OPEN62541_IMAGE` / `MILO_IMAGE` that lacks a feature skips, unless `OPCUA_INTEROP_REQUIRE_CAPABILITIES=1`.

## Test naming

| Prefix | Go role | Adapter counterpart | Ledger direction |
|--------|---------|---------------------|------------------|
| `TestOpen62541Server_` | OPC UA client | open62541 server | C→O |
| `TestGoServer_Open62541Client_` | OPC UA server | open62541 client | O→S |
| `TestMiloServer_` | OPC UA client | Milo server | C→M |
| `TestGoServer_MiloClient_` | OPC UA server | Milo client | M→S |
| `TestGoServer_` (no peer infix) | OPC UA server + client | none (Go↔Go) | companion only |
| `TestGoServer_PeerClient_` | OPC UA server | both adapter clients (subtest per peer) | O→S, M→S |
| `TestCodec_<Peer>Encodes_GoDecodes` / `TestCodec_GoEncodes_<Peer>Decodes` | JSON / XML codec | adapter `codec` | O→S, M→S / C→O, C→M |
| `TestOpen62541LDS_` / `TestGoLDS_` | registrant / LDS | open62541 LDS / adapter server or client | C→O / O→S, M→S |
| `TestMulticast_` | LDS in a container | open62541 LDS, both adapter clients | all (see ledger `case`) |

For the capabilities that are not a client calling a server (codec, LDS registration, mDNS, reverse connect) the ledger keeps the four direction columns and the capability title says what "C→" and "→S" mean.

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
| SecureChannel renewal under subscription | ✓ | ✓ |
| HistoryRead continuation points | ✓ | ✓ |
| RegisterNodes / UnregisterNodes | ✓ | ✓ |
| AddNodes / DeleteNodes | ✓ | ✓ |
| ModifySubscription | ✓ | n/a |
| SetPublishingMode (queue kept while disabled) | ✓ | ✓ |
| ModifyMonitoredItems | ✓ | n/a |
| SetMonitoringMode (Disabled / Sampling / Reporting) | ✓ | ✓ |
| DataChangeFilter — absolute deadband | ✓ | ✓ |
| DataChangeFilter — percent deadband (AnalogItem EURange) | ✓ | ✓ |
| DataChangeFilter — trigger (Status / StatusValue / StatusValueTimestamp) | ✓ | ✓ |
| Sampling interval honoured | ✓ | ✓ |
| ECC_nistP256 / Sign, SignAndEncrypt | ✓ | ✓ |
| ECC_nistP384 / Sign, SignAndEncrypt | ✓ | ✓ |
| ECC_nistP256_AesGcm / SignAndEncrypt | ✓ | ✓ |
| ECC_nistP256_ChaChaPoly / SignAndEncrypt | ✓ | ✓ |
| ECC_curve25519 / SignAndEncrypt | ✓ | ✓ |
| ECC (all five policies) — subscription, SecurityToken renewal | ✓ | ✓ |
| ECC (all five policies) — UserName token (EccEncryptedSecret), valid / invalid | ✓ | ✓ |
| ECC AEAD policies — Write and read back | ✓ | ✓ |
| ECC policies not implemented by go-opcua (brainpool, curve448) refused cleanly | ✓ | ✓ |
| Reverse connect (ReverseHello) — read, subscription, discovery | ✓ | ✓ |
| Reverse connect secured — Basic256Sha256, ECC_nistP256, ECC_nistP384 | ✓ | ✓ |
| JSON DataEncoding — built-in scalars, arrays, matrix | ✓ | ✓ |
| JSON DataEncoding — DataValue | ✓ | ✓ |
| XML DataEncoding — built-in scalars, arrays, matrix | ✓‡ | ✓‡ |
| XML DataEncoding — DataValue | ⚠ | ⚠ |
| LDS registration (server registers / unregisters) | ✓ | ✓ |
| RegisterServer / RegisterServer2 driven by the peer client | n/a | ✓ |
| RegisterServer2 MdnsDiscoveryConfiguration → FindServersOnNetwork | ✓ | ✓ |
| FindServersOnNetwork | ✓ | ✓ |
| mDNS announce / browse | ✓ | ✓ |

\* Go-client-driven against Go server always; adapter reverse only where CLI exposes the control (`--queue-size`, `--discard-oldest`, `--timestamps` on subscribe).
‡ For the codec rows "Go→open62541" means go-opcua encodes and open62541 decodes, "open62541→Go" the reverse; for LDS registration and mDNS the left column is go-opcua acting towards the open62541 LDS (registering, browsing), the right column open62541 acting towards the go-opcua LDS; for reverse connect the left column is the Go client listening for the open62541 server, the right column the Go server dialling the open62541 client. open62541 1.5.9 cannot decode an XmlElement from XML and cannot encode a matrix to XML; both gaps are listed in `codec_peer_test.go` and asserted to still be there.
⚠ open62541 1.5.9 does not implement DataValue in the XML encoding (`BadNotImplemented`); `encoding.xml.datavalue` is `unsupported` in both open62541 directions.

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
| SecureChannel renewal under subscription | ✓ | ✓ |
| HistoryRead continuation points | ✓† | ✓ |
| RegisterNodes / UnregisterNodes | ✓ | ✓ |
| AddNodes / DeleteNodes | ⚠ | ✓ |
| ModifySubscription | ✓ | n/a |
| SetPublishingMode (queue kept while disabled) | ✓ | ✓ |
| ModifyMonitoredItems | ✓ | n/a |
| SetMonitoringMode (Disabled / Sampling / Reporting) | ✓ | ✓ |
| DataChangeFilter — absolute deadband | ✓ | ✓ |
| DataChangeFilter — percent deadband (AnalogItem EURange) | ✓ | ✓ |
| DataChangeFilter — trigger (Status / StatusValue / StatusValueTimestamp) | ✓ | ✓ |
| Sampling interval honoured | ✓ | ✓ |
| ECC security policies | ⚠ | ⚠ |
| Reverse connect | ⚠ | ⚠ |
| JSON DataEncoding — built-in scalars, arrays, matrix | ✓ | ✓ |
| JSON DataEncoding — DataValue | ⚠ | ✓ |
| XML DataEncoding — built-in scalars, arrays, matrix | ✓ | ✓ |
| XML DataEncoding — DataValue | ✓ | ✓ |
| LDS registration (server registers / unregisters) | ⚠ | ✓ |
| RegisterServer / RegisterServer2 driven by the peer client | n/a | ✓ |
| RegisterServer2 MdnsDiscoveryConfiguration → FindServersOnNetwork | ⚠ | ✓ |
| FindServersOnNetwork | ⚠ | ✓ |
| mDNS announce / browse | ⚠ | ⚠ |

\* Go-client-driven against Go server always; adapter reverse only where CLI exposes the control (`--queue-size`, `--discard-oldest`, `--timestamps` on subscribe).
⚠ Milo soft-accepts EncodingMask-bearing Writes; ledger marks `write.encoding-mask` C→M as `unsupported` (claim requires `BadWriteNotSupported`).
⚠ The Milo reference server does not implement NodeManagement (AddNodes → `BadNotSupported`); `nodemgmt.*` C→M is `unsupported`.
† Paging through continuation points is verified; Milo's SDK does not pass `ReleaseContinuationPoints` to the history backend, so release/reuse is asserted on C→O only.
⚠ Eclipse Milo 1.1.8 implements no ECC SecurityPolicy and no ReverseHello: all `security.ecc-*` and `transport.reverse-connect*` rows are `unsupported` for C→M and M→S.
⚠ Eclipse Milo 1.1.8 is no discovery server (RegisterServer, RegisterServer2 and FindServersOnNetwork answer `Bad_ServiceUnsupported`, pinned by `TestMiloServer_DiscoveryServerUnsupported`) and has no mDNS. The Milo server registers with a go-opcua LDS and the Milo client drives its discovery services, so M→S is verified.
⚠ Milo does not decode a JSON DataValue with the Variant members inlined (the Part 6 1.05 form go-opcua and open62541 emit); go-opcua decodes Milo's nested form.

---

## Fixtures

`interop/testdata/baseline.json` is a synchronized copy of the canonical fixture from `opcua-interop/fixtures/baseline/fixture.json` (v0.7.0 added the AnalogItems `Analog.Level` / `Analog.Setpoint` with EURange 0..100 and the ECC `securityProfiles`; v0.8.0 the `PubSub` folder of writable variables). Update it alongside the pinned adapter image version when the fixture contract changes. The Go reference server in `harness_test.go` (`startGoServer`) mirrors the fixture's nodes so that both directions assert the same values.

## Current status

The directional compatibility ledger is the source of truth:

- [`interop/coverage.json`](interop/coverage.json) + [`interop/capabilities.json`](interop/capabilities.json) — edit these
- [`interop/COVERAGE.md`](interop/COVERAGE.md) — generated matrix (`go generate ./interop`)
- [`interop/GAPS.md`](interop/GAPS.md) — generated unverified summary (`go run ./internal/cmd/render-interop-coverage -summary -write-gaps=interop/GAPS.md`)

Go↔Go companions never earn a verified checkmark. A row may move to `verified` only after a named peer test runs against the pinned peer environment **without skip** and asserts that exact capability.

Every `unverified` row must carry a controlled `reason`:

`test-missing` · `adapter-command-missing` · `adapter-fixture-missing` · `fault-harness-missing` · `consumer-demand-missing` · `peer-capability-unknown`

Adapter images are pinned to [opcua-interop v0.8.1](https://github.com/otfabric/opcua-interop/releases/tag/v0.8.1) (digest-pinned below), the release the suite and the ledger are written against (`interopVersion` in `harness_test.go`, `coverage.json`, `render-interop-coverage`). The ledger's peer versions are open62541 **1.5.9** and Eclipse Milo **1.1.8**. CI sets `OPCUA_INTEROP_REQUIRE_CAPABILITIES=1` so that missing operations, features, security profiles or a missing test PKI fail rather than skip.

| Image | Tag |
|-------|-----|
| `ghcr.io/otfabric/opcua-interop-open62541` | [`v0.8.1`](https://github.com/otfabric/opcua-interop/releases/tag/v0.8.1) / `@sha256:2f008620…e20b9e84` |
| `ghcr.io/otfabric/opcua-interop-milo` | [`v0.8.1`](https://github.com/otfabric/opcua-interop/releases/tag/v0.8.1) / `@sha256:0fbbf762…b2a823ed` |

> **Pins.** The default images in `harness_test.go` and `.github/workflows/interop.yml` are the multi-arch digests of the [v0.8.1 release run](https://github.com/otfabric/opcua-interop/actions/runs/40031915713). opcua-interop tags are immutable: on a new release update `interopVersion`, the digests, this table, `coverage.json` and `render-interop-coverage` in lockstep. A capability-gated test fails — it does not skip — when a default image is not the release named by `interopVersion`.

> **Local dev images:** Override `OPEN62541_IMAGE` / `MILO_IMAGE` when testing unreleased adapter builds.

> The adapter surface the suite relies on — since v0.8.0: open62541 `server --pubsub-config`, client operation `codec` with `pubsub-uadp-*` / `pubsub-json-*`, server feature `pubsub`, client feature `codec-pubsub`, the `PubSub` fixture folder and the Mosquitto broker pin; and since v0.7.0: client operations `codec`, `find-servers-on-network`, `register-server`; client features `deadband`, `reverse-listen`, `ecc-security`, `ecc-user-token`, `register-server2`, `codec-json`, `codec-xml`; server features `deadband`, `percent-deadband`, `reverse-connect`, `ecc-security`, `ecc-user-token`, `lds`, `mdns`, `register-with`; `subscription-lifecycle` with SamplingInterval 0. Older images fail those tests.

**Interop claim rule:** only modes with positive and negative peer tests in the ledger are claimed interoperable.

### Evidence objective

Optimise for accurate evidence, not a zero-unverified quota. Current ledger: **3 unverified** rows, all PubSub (`pubsub.uadp.udp-multicast` in both directions: multicast does not cross the Docker Desktop VM; `pubsub.uadp.security-header` O→S: the adapter's standalone codec has no keys) — the other gaps are `deferred`, `unsupported`, or `not-applicable` (see [`GAPS.md`](interop/GAPS.md) and [`BUCKET_B.md`](interop/BUCKET_B.md)).

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
| `history.read.continuation` | all four (O→S/M→S `--scenario continue`; C→M paging only) |
| `security.channel.renewal` | all four (Basic256Sha256 / SignAndEncrypt, ≥ 3 renewals under a live subscription) |
| `view.register-nodes` | all four |
| `nodemgmt.add-nodes` / `nodemgmt.delete-nodes` | C→O, O→S, M→S |
| `subscription.modify`, `monitoreditem.modify` | C→O, C→M |
| `subscription.publishing-mode`, `monitoreditem.monitoring-mode` | all four |
| `event.filter.where-clause` | C→O, C→M (five comparison operators, matching **and** non-matching operands) |
| `event.queue-overflow` | C→O, C→M (EventQueueOverflowEventType ahead of the queued events) |

### Promoted with opcua-interop v0.8.0 / v0.8.1 (go-opcua v1.7.0)

PubSub (Part 14) against open62541 1.5.9 — profile `pubsub` in the ledger, 50 verified rows; Eclipse Milo 1.1.8 has no PubSub (`unsupported`). Directions: C→O = go-opcua encodes / publishes / acts as client, O→S = open62541 does.

| Capability | Directions |
|---|---|
| `pubsub.uadp.codec`, `pubsub.json.codec` (byte-exact, all header options and field encodings) | C→O, O→S |
| `pubsub.uadp.udp` (Variant, DataValue, RawData), `pubsub.uadp.mqtt`, `pubsub.json.mqtt` | C→O, O→S |
| `pubsub.security.*` (Sign, SignAndEncrypt; PubSub-Aes128-CTR, PubSub-Aes256-CTR; wrong keys and unsecured messages rejected) | C→O, O→S |
| `pubsub.sks.*` (GetSecurityKeys, SKS pull, SetSecurityKeys push, Add/RemoveSecurityGroup) | C→O, O→S |
| `pubsub.runtime.*` (go publisher and subscriber, TargetVariables, receive timeout) | C→O, O→S |
| `pubsub.infomodel.*` (configuration methods, browse, Enable / Disable) | C→O (`pubsub/remote`), O→S (adapter `call` / `browse`) |

open62541 limits found by these tests (recorded in opcua-interop's contract): it publishes a ConfigurationVersion it generates itself, so go readers are configured without a MajorVersion; AddDataSetReader cannot target an existing variable; a ReaderGroup added to a running connection needs the connection disabled and enabled again; RemoveDataSetReader needs its group disabled; its reader discards KeepAlive messages.

### Promoted with opcua-interop v0.7.0 (go-opcua v1.6.0)

| Capability | Directions |
|---|---|
| `monitoreditem.deadband`, `monitoreditem.trigger`, `monitoreditem.sampling-interval` | all four |
| `monitoreditem.percent-deadband` | all four (AnalogItem `Analog.Level`, EURange 0..100; rejected without EURange and above 100 %) |
| `security.ecc-nistp256.*`, `security.ecc-nistp384.*` (sign, sign-encrypt, subscription, username.valid / invalid, renewal) | C→O, O→S |
| `security.ecc-nistp256-aesgcm.*`, `security.ecc-nistp256-chachapoly.*`, `security.ecc-curve25519.*` (sign-encrypt, write, subscription, username.valid / invalid, renewal ×5) | C→O, O→S (the adapter offers the AEAD policies in SignAndEncrypt only) |
| `security.ecc.unimplemented-policy` | C→O, O→S (brainpoolP256r1, brainpoolP384r1, curve448: not selectable, refused at once; with a P-256 certificate `opcua.SelectEndpoint` picks `ECC_nistP256_ChaChaPoly` — open62541 gives its ECC endpoints one SecurityLevel and the library ranking breaks the tie) |
| `transport.reverse-connect`, `.subscription` | C→O (Go client listens), O→S (Go server dials) |
| `transport.reverse-connect.secure` | C→O, O→S (Basic256Sha256, ECC_nistP256, ECC_nistP384) |
| `encoding.json.variant`, `encoding.xml.variant` | all four |
| `encoding.json.datavalue` | C→O, O→S, M→S |
| `encoding.xml.datavalue` | C→M, M→S |
| `discovery.lds-registration` | C→O (go-opcua server → open62541 LDS), O→S, M→S (peer server → go-opcua LDS) |
| `discovery.register-server` | O→S, M→S (peer client → go-opcua LDS) |
| `discovery.register-server2.mdns` | C→O, O→S, M→S |
| `discovery.find-servers-on-network` | C→O, O→S, M→S |
| `discovery.multicast` | C→O (go-opcua discovers open62541), O→S (open62541 discovers go-opcua) |
| `subscription.publishing-mode` | O→S, M→S assert the exact `[3,4,5]` window again (adapters request SamplingInterval 0) |

### Remaining gaps (summary)

- **Unsupported (behavioural):** `write.encoding-mask` C→M — Milo soft-accepts; claim requires `BadWriteNotSupported`. `nodemgmt.add-nodes` / `nodemgmt.delete-nodes` C→M — the Milo reference server has no NodeManagement service set.
- **Unsupported (peer stack lacks the feature):** all `security.ecc-*` and `transport.reverse-connect*` rows for Milo (no ECC policy, no ReverseHello); Milo as a discovery server (`discovery.lds-registration`, `discovery.register-server2.mdns`, `discovery.find-servers-on-network` C→M) and `discovery.multicast` C→M / M→S (no mDNS); `encoding.xml.datavalue` C→O / O→S (open62541 has no XML DataValue); `encoding.json.datavalue` C→M (Milo decodes only its nested DataValue form).
- **Not implemented in go-opcua:** the ECC policies `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1`, `ECC_curve448` (open62541 offers them; the ledger only claims that they are refused cleanly).
- **Known representation limits** (asserted, not claimed away): go-opcua has no null String (`""` is the null String in binary and `""` in JSON / XML); open62541 cannot decode XmlElement from XML nor encode a matrix to XML; Milo's XML decoder keeps a DateTime to the millisecond.
- **Deferred** (outside current core parity): NodeSet2 import, advanced HA, cross-stack custom DataTypes, Query, IssuedIdentityToken, A&C, GDS, dynamic EO decode, custom event emission, general WhereClause surface, HistoryRead modified/at-time/processed/events, HistoryUpdate, certificate chains / CRL, secured LDS registration against a peer LDS, the JSON / XML encodings as a transport (only the DataEncoding of values is verified).

### Server defects found by peer evidence

Peer tests are the only place these showed up — the Go client tolerated all of them:

| Defect | Peer symptom | Fix |
|---|---|---|
| Server renewed SecurityTokens in place (same TokenId, new keys, keys swapped on the live instance) | open62541 / Milo: `could not verify signature` on the first message after renewal — any peer session died at 75% of the channel lifetime | Renewal issues a new TokenId on a fresh instance; old token stays valid until it expires (`uasc/secure_channel_renew.go`) |
| Server rejected an OpenSecureChannel renewal carrying a session AuthenticationToken | open62541: `BadSecureChannelTokenUnknown`, then `SecurityToken timed out` | Token is ignored for this service |
| Server never revised the requested token lifetime and never expired tokens | — (hygiene) | Lifetime capped at the configured maximum, `0` → server default; expired tokens are retired, un-renewed channels closed |
| AddNodes ignored `NodeAttributes` | open62541 / Milo: added Variable read back `null` | VariableAttributes applied (unset mask read as "all", as open62541 clients send it) |

Codec and client defects found the same way with v0.7.0:

| Defect | Peer symptom | Fix |
|---|---|---|
| The XML encoder wrote the content of an XmlElement as raw markup into a document whose default namespace is the OPC UA types namespace | Milo decoded `<compat>test</compat>` as `<compat xmlns="http://opcfoundation.org/UA/2008/02/Types.xsd">test</compat>` | Unprefixed top-level elements of the fragment get `xmlns=""`; the decoder removes it again (`ua/xml_encode.go`, `TestXMLElementNamespace`) |
| A client told to use an endpoint with a policy that is not implemented failed with whatever broke first | open62541 brainpool / Ed448 endpoints: `x509: unsupported elliptic curve`, `unsupported public key type <nil>` | `uasc.NewSecureChannel` returns `ErrUnsupportedSecurityPolicy` for a client channel before anything else (`uapolicy.IsSupported`) |

Not changed, but worth knowing: the Go server answers a Hello whose EndpointUrl names another **port** than the one it listens on with `Bad_TcpEndpointUrlInvalid`, so a go-opcua server in a container must be published on the same port number it listens on (`-p 4841:4841`, not `-p 5000:4840`) — see `startGoPeerContainer`.

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

Peer event subscription, BaseEvent emission, SelectClauses, OfType, and severity-threshold filters are verified since the v0.6.0 adapters. WhereClause comparison operators are verified C→O / C→M; the adapter clients expose only `--of-type` / `--min-severity`, so the general WhereClause surface stays deferred for O→S / M→S, as does custom event emission.

#### custom-types — Go↔Go companions

Tests in `conformance/customtypes_test.go` exercise registered custom DataTypes locally. Cross-stack custom DataType fixture peer verification is `deferred`. Dynamic structure decoding is `deferred`.
