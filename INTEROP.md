# go-opcua Interoperability

`go-opcua` owns which capabilities need verification. Tests in `interop/` consume the adapter images published by [opcua-interop](https://github.com/otfabric/opcua-interop) and assert `go-opcua` behaviour against live, independent OPC UA implementations.

New adapter commands or fixture capabilities are requested from `opcua-interop` only when a required external operation does not yet exist there.

## Architecture

The suite uses a dual layout that mirrors [`interop/COVERAGE.md`](interop/COVERAGE.md):

1. **Peer-direction baseline** — four large files mirrored across stacks; each maps to one ledger direction column (C→O, C→M, O→S, M→S).
2. **Capability companions** — smaller files grouped by COVERAGE.md section. `*_test.go` is Go↔Go semantics; `*_peer_test.go` is peer evidence that can earn ✅.

```
opcua-interop v0.17.0
  open62541 adapter image     (C, open62541 1.5.9)
  milo adapter image          (Java, Eclipse Milo 1.1.8)
  async-opcua adapter image   (Rust, async-opcua 0.19.0)
  dotnet adapter image        (C#, OPC Foundation UA-.NETStandard 2.0.1)
  node-opcua adapter image    (TypeScript, node-opcua 2.187.12)
  asyncua adapter image       (Python, FreeOpcUa opcua-asyncio 2.1.0)
  dotnet-gds adapter image    (C#, UA-.NETStandard GDS 2.0.1; opt-in)
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

      # Peers with their own ledger (testdata/ledger-<peer>.json); the same
      # file set for asyncopcua_*, nodeopcua_* and asyncua_*
      dotnet_harness_test.go               DOTNET_IMAGE, image gate, directions
      dotnet_server_test.go                TestDotnetServer_*              (go-client-to-dotnet-server)
      dotnet_client_test.go                TestGoServer_DotnetClient_*     (dotnet-client-to-go-server)
      dotnet_peer_test.go                  capability tests on the shared peer assertions
      dotnet_alarms_test.go                A&C on the shared assertions of alarms_peer_test.go
      dotnet_ledger_validate_test.go       ledger-dotnet.json integrity (no docker)
      dotnet_pubsub_peer_test.go           PubSub against Opc.Ua.PubSub
      dotnet_gds_pull_test.go              GDS pull model against the dotnet-gds adapter (opt-in)
      optional_peers_test.go               opt-in adapter images (DOTNET_GDS_IMAGE)

      # Capability companions (COVERAGE sections)
      events_test.go / events_peer_test.go / events_c2peer_test.go
      history_test.go / history_peer_test.go / history_c2peer_test.go
      history_continuation_peer_test.go
      history_events_test.go               event history: the go fixture s=History.Events and the
                                           shared assertions; history_events_peer_test.go (open62541,
                                           Milo) and <peer>_history_events_test.go for the others
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
      codec_peer_test.go                   JSON / XML DataEncoding round trips (open62541, Milo),
                                           JSON Verbose (Milo)
      c2p_services_peer_test.go            go-opcua client against every peer server: multi-chunk
                                           secured messages, SetTriggering, TransferSubscriptions
                                           identity rules, Add/DeleteReferences, server diagnostics
                                           (shared assertions; the other peers in their own files)
      diagnostics_peer_test.go             every peer client reads EnabledFlag and the session counts
                                           of the go-opcua server's ServerDiagnosticsSummary; the
                                           go-opcua client's diagnostics assertions in process
      ecc_peer_test.go                     ECC_nistP256 / ECC_nistP384 (open62541), user token,
                                           renewal, unimplemented ECC policies refused;
                                           AEAD policies (AesGcm, ChaChaPoly, curve25519)
      reverse_connect_peer_test.go         reverse connect, both halves, None / RSA / ECC (open62541)
      discovery_lds_peer_test.go           LDS registration, RegisterServer(2),
                                           FindServersOnNetwork, mDNS
      discoverypeer/                       go-opcua server run in a container for the mDNS tests
      transport_peer_test.go               opc.https and opc.wss
      alarms_peer_test.go                  A&C (Part 9): conditions, Acknowledge / Confirm,
                                           ConditionRefresh, both directions
      alarms105_peer_test.go               Part 9 1.05 methods, dialogs, branches, alarm groups,
                                           audit events (peer client → go-opcua server)
      alarms105_timing_peer_test.go        OnDelay / OffDelay, ReAlarm, AudibleSound,
                                           FirstInGroup, AlarmMetrics
      certmgmt_peer_test.go                push certificate management (Part 12 §7)
      certmgmt_call_peer_test.go           push management methods through each peer's `client call`
      certmgmt_groups_peer_test.go         push management: the 1.05 groups and methods
      pubsub_*_test.go                     PubSub (Part 14) against open62541 and through brokers

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
make -C ../opcua-interop image-open62541 image-milo

# Run against local dev images
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541:dev \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo:dev \
make interop

# The security, ECC and secured reverse connect tests need the test PKI of
# opcua-interop v0.17.0 (RSA identities of all six adapters plus ecc-<curve>/ certificates):
(cd ../opcua-interop && certs/generate.sh)        # or: certs/generate.sh --add-ecc on an existing PKI
export OPCUA_INTEROP_PKI_DIR=$PWD/../opcua-interop/certs/test-pki

# Run against the default (digest-pinned) release images
make interop

# Release verification: nothing the images advertise may be skipped
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 make interop

# One of N slices of the suite, as the CI workflow runs it (ten parallel jobs)
make interop-shard SHARD=2 SHARDS=10

# CI — digest pinned (update interop.yml after each release)
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541@sha256:90487dbca66d623c0d5234dbab8d6b9b4c4c12317d27ef424c93156a17dfa16f \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo@sha256:cb2b182ef3bfe5a4fb6fd67b4c949945be27d1a2380ef0bed3fbafa1eed2924e \
ASYNC_OPCUA_IMAGE=ghcr.io/otfabric/opcua-interop-async-opcua@sha256:dcb809cc8eaa20de7f1a34893a24300e228c8067a79d60e330997b3a0d413caa \
DOTNET_IMAGE=ghcr.io/otfabric/opcua-interop-dotnet@sha256:aae1a636b3321c96678f4da972ba0e003ba3666f9d01293c42e0f912883c4728 \
NODE_OPCUA_IMAGE=ghcr.io/otfabric/opcua-interop-node-opcua@sha256:0bd16799d9a187af640c178c9fcc4f50103097bcfea18184050803d7750ff054 \
ASYNCUA_IMAGE=ghcr.io/otfabric/opcua-interop-asyncua@sha256:aad312f3fb23addd9fcc33f742d0816a69bc91c99f1b09331a0c197109578fb6 \
make interop
```

## Local development (go work)

While iterating between `go-opcua` and `opcua-interop` before a stable release, use the Go workspace to avoid publishing intermediate module versions:

```bash
# From the workspace root (otfabric/)
cat go.work          # go-opcua should be listed

# Build images locally
make -C opcua-interop image-open62541 image-milo

# Run interop tests against the local images
cd go-opcua
OPEN62541_IMAGE=ghcr.io/otfabric/opcua-interop-open62541:dev \
MILO_IMAGE=ghcr.io/otfabric/opcua-interop-milo:dev \
go test -tags=interop -v ./interop/...
```

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPEN62541_IMAGE` | open62541 adapter image | digest pin in `harness_test.go` (see [Current status](#current-status)) |
| `MILO_IMAGE` | Milo (Java) adapter image | digest pin in `harness_test.go` |
| `ASYNC_OPCUA_IMAGE` | async-opcua (Rust) adapter image (see [go-opcua ↔ async-opcua](#go-opcua--async-opcua)) | the v0.17.0 digest `ghcr.io/otfabric/opcua-interop-async-opcua@sha256:dcb809cc…0d413caa` |
| `DOTNET_IMAGE` | UA-.NETStandard (C#) adapter image (see [go-opcua ↔ UA-.NETStandard](#go-opcua--ua-netstandard)) | the v0.17.0 digest `ghcr.io/otfabric/opcua-interop-dotnet@sha256:aae1a636…883c4728` |
| `DOTNET_GDS_IMAGE` | UA-.NETStandard 2.0.1 GDS adapter image (dotnet-gds, opt-in; see [GDS pull model](#gds-pull-model-part-12-6-79)) | the v0.17.0 digest `ghcr.io/otfabric/opcua-interop-dotnet-gds@sha256:9782e45e…`, used only if present locally |
| `NODE_OPCUA_IMAGE` | node-opcua (TypeScript / Node.js) adapter image (see [go-opcua ↔ node-opcua](#go-opcua--node-opcua)) | the v0.17.0 digest `ghcr.io/otfabric/opcua-interop-node-opcua@sha256:0bd16799…750ff054` |
| `ASYNCUA_IMAGE` | opcua-asyncio (Python, `asyncua`) adapter image (see [go-opcua ↔ opcua-asyncio](#go-opcua--opcua-asyncio)) | the v0.17.0 digest `ghcr.io/otfabric/opcua-interop-asyncua@sha256:aad312f3…09578fb6` |
| `OPCUA_INTEROP_FIXTURE_DIR` | Path to fixture directory containing `baseline.json` | `testdata/` |
| `OPCUA_INTEROP_PKI_DIR` | Root of the test PKI tree generated by `opcua-interop/certs/generate.sh` of the pinned release (the identities of all six adapters; the ECC tests need `<identity>/ecc-<curve>/cert.crt\|cert.key`) | `../../opcua-interop/certs/test-pki` |
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
| `TestAsyncOpcuaServer_` | OPC UA client | async-opcua server | `go-client-to-async-opcua-server` (`ledger-async-opcua.json`) |
| `TestGoServer_AsyncOpcuaClient_` | OPC UA server | async-opcua client | `async-opcua-client-to-go-server` (`ledger-async-opcua.json`) |
| `TestNodeOpcuaServer_` | OPC UA client | node-opcua server | `go-client-to-node-opcua-server` (`ledger-node-opcua.json`) |
| `TestGoServer_NodeOpcuaClient_` | OPC UA server | node-opcua client | `node-opcua-client-to-go-server` (`ledger-node-opcua.json`) |
| `TestAsyncuaServer_` | OPC UA client | opcua-asyncio server | `go-client-to-asyncua-server` (`ledger-asyncua.json`) |
| `TestGoServer_AsyncuaClient_` | OPC UA server | opcua-asyncio client | `asyncua-client-to-go-server` (`ledger-asyncua.json`) |
| `TestGoServer_` (no peer infix) | OPC UA server + client | none (Go↔Go) | companion only |
| `TestGoServer_PeerClient_` | OPC UA server | both adapter clients (subtest per peer) | O→S, M→S |
| `TestCodec_<Peer>Encodes_GoDecodes` / `TestCodec_GoEncodes_<Peer>Decodes` | JSON / XML codec | adapter `codec` | O→S, M→S / C→O, C→M |
| `TestCodec_<Peer>EncodesVerbose_GoDecodes` / `TestCodec_GoEncodesVerbose_<Peer>Decodes` | JSON Verbose codec | adapter `codec --json-mode verbose` | M→S / C→M (and the dotnet directions) |
| `TestOpen62541LDS_` / `TestGoLDS_` | registrant / LDS | open62541 LDS / adapter server or client | C→O / O→S, M→S |
| `TestMulticast_` | LDS in a container | open62541 LDS, both adapter clients | all (see ledger `case`) |
| `TestDotnetServer_` | OPC UA client | UA-.NETStandard server | `go-client-to-dotnet-server` (`ledger-dotnet.json`) |
| `TestGoServer_DotnetClient_` | OPC UA server | UA-.NETStandard client | `dotnet-client-to-go-server` (`ledger-dotnet.json`) |
| `TestDotnetGDSPull_` | GDS client / GDS | UA-.NETStandard GDS / GDS client (dotnet-gds) | both dotnet directions (`ledger-dotnet.json`) |
| `TestCertMgmtPush_`, `TestCertMgmtPushGroups_` | push management client / server | peer servers with push management / node-opcua client | per peer ledger |

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
| Historical events: read, continuation, filter, update, delete | n/a (no event store) | ✓ |
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
| Multi-chunk messages, Basic256Sha256 / Aes256_Sha256_RsaPss SignAndEncrypt | ✓ | n/a |
| SetTriggering / RemoveLinks (linked item in Sampling) | ✓ | n/a |
| TransferSubscriptions: anonymous → anonymous (same certificate); user → other identity refused | ✓ | n/a |
| AddReferences / DeleteReferences | ✓ | n/a |
| ServerDiagnosticsSummary, SessionDiagnosticsArray | ✓ | ✓ |
| ReturnDiagnostics (operation DiagnosticInfos) | ⚠ | n/a |
| ECC_nistP256 / Sign, SignAndEncrypt | ✓ | ✓ |
| ECC_nistP384 / Sign, SignAndEncrypt | ✓ | ✓ |
| ECC_nistP256_AesGcm / SignAndEncrypt | ✓ | ✓ |
| ECC_nistP256_ChaChaPoly / SignAndEncrypt | ✓ | ✓ |
| ECC_curve25519 / SignAndEncrypt | ✓ | ✓ |
| ECC_brainpoolP256r1 / SignAndEncrypt | ✓ | ✓ |
| ECC_brainpoolP384r1 / SignAndEncrypt | ✓ | ✓ |
| ECC_curve448 / SignAndEncrypt | ✓ | ✓ |
| ECC (all eight policies) — subscription, SecurityToken renewal | ✓ | ✓ |
| ECC (all eight policies) — UserName token (EccEncryptedSecret), valid / invalid | ✓ | ✓ |
| ECC policies offered in SignAndEncrypt only (AEAD, Brainpool, curve448) — Write and read back | ✓ | ✓ |
| Reverse connect (ReverseHello) — read, subscription, discovery | ✓ | ✓ |
| Reverse connect secured — Basic256Sha256, ECC_nistP256, ECC_nistP384 | ✓ | ✓ |
| JSON DataEncoding — built-in scalars, arrays, matrix | ✓ | ✓ |
| JSON DataEncoding — DataValue | ✓ | ✓ |
| XML DataEncoding — built-in scalars, arrays, matrix | ✓‡ | ✓‡ |
| XML DataEncoding — DataValue | ⚠ | ⚠ |
| JSON DataEncoding, Verbose form | ⚠ | ⚠ |
| LDS registration (server registers / unregisters) | ✓ | ✓ |
| RegisterServer / RegisterServer2 driven by the peer client | n/a | ✓ |
| RegisterServer2 MdnsDiscoveryConfiguration → FindServersOnNetwork | ✓ | ✓ |
| FindServersOnNetwork | ✓ | ✓ |
| mDNS announce / browse | ✓ | ✓ |

\* Go-client-driven against Go server always; adapter reverse only where CLI exposes the control (`--queue-size`, `--discard-oldest`, `--timestamps` on subscribe).
‡ For the codec rows "Go→open62541" means go-opcua encodes and open62541 decodes, "open62541→Go" the reverse; for LDS registration and mDNS the left column is go-opcua acting towards the open62541 LDS (registering, browsing), the right column open62541 acting towards the go-opcua LDS; for reverse connect the left column is the Go client listening for the open62541 server, the right column the Go server dialling the open62541 client. open62541 1.5.9 cannot decode an XmlElement from XML and cannot encode a matrix to XML; both gaps are listed in `codec_peer_test.go` and asserted to still be there.
⚠ open62541 1.5.9 does not implement DataValue in the XML encoding (`BadNotImplemented`); `encoding.xml.datavalue` is `unsupported` in both open62541 directions.
⚠ open62541 1.5.9 has the compact JSON form only: `encoding.json-verbose.*` is `unsupported` in both open62541 directions. It returns no DiagnosticInfos for a Read with ReturnDiagnostics (`diagnostics.return-diagnostics` C→O `unsupported`).

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
| Historical events: read, continuation, filter, update, delete | n/a (no event history server) | ✓ |
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
| Multi-chunk messages, Basic256Sha256 / Aes256_Sha256_RsaPss SignAndEncrypt | ✓ | n/a |
| SetTriggering / RemoveLinks (linked item in Sampling) | ✓ | n/a |
| TransferSubscriptions: anonymous → anonymous (same certificate); user → other identity refused | ✓ | n/a |
| AddReferences / DeleteReferences | ⚠ | n/a |
| ServerDiagnosticsSummary, SessionDiagnosticsArray | ⚠ | ✓ |
| ReturnDiagnostics (operation DiagnosticInfos) | ⚠ | n/a |
| ECC security policies | ⚠ | ⚠ |
| Reverse connect | ⚠ | ⚠ |
| JSON DataEncoding — built-in scalars, arrays, matrix | ✓ | ✓ |
| JSON DataEncoding — DataValue | ⚠ | ✓ |
| XML DataEncoding — built-in scalars, arrays, matrix | ✓ | ✓ |
| XML DataEncoding — DataValue | ✓ | ✓ |
| JSON DataEncoding, Verbose form — built-in scalars, arrays, matrix | ✓ | ✓ |
| JSON DataEncoding, Verbose form — DataValue | ⚠ | ✓ |
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
⚠ Milo does not decode a JSON DataValue with the Variant members inlined (the Part 6 1.05 form go-opcua and open62541 emit); go-opcua decodes Milo's nested form. The same holds for the Verbose form.
⚠ The Milo reference server answers AddReferences / DeleteReferences with `BadNotSupported` (pinned by `TestMiloServer_ReferencesUnsupported`), runs with server diagnostics off (`EnabledFlag` false) and returns no DiagnosticInfos: `nodemgmt.*-references`, `diagnostics.*` C→M are `unsupported`.

### go-opcua ↔ async-opcua

[async-opcua](https://github.com/FreeOpcUa/async-opcua) 0.19.0 (Rust) is a third peer, added with the opcua-interop **v0.9.0** adapter `ghcr.io/otfabric/opcua-interop-async-opcua`. Its tests (`interop/asyncopcua_*_test.go`, the async-opcua peers of `TestMulticast_GoAndPeers`) run with every interop run against the digest-pinned v0.17.0 image (`ASYNC_OPCUA_IMAGE` overrides it); a capability-gated test fails rather than skips when the image reports another opcua-interop release than `interopVersion`.

```sh
# in opcua-interop: build the adapter, generate (or extend) the test PKI
make -C ../opcua-interop image-async-opcua
certs/generate.sh                     # or: certs/generate.sh --add-async-opcua
# in go-opcua
ASYNC_OPCUA_IMAGE=ghcr.io/otfabric/opcua-interop-async-opcua:dev \
OPCUA_INTEROP_PKI_DIR=../opcua-interop/certs/test-pki \
go test -tags=interop -run 'AsyncOpcua' -v ./interop/
```

Its evidence is kept in its own ledger, [`interop/testdata/ledger-async-opcua.json`](interop/testdata/ledger-async-opcua.json) (one row per capability for `go-client-to-async-opcua-server` and `async-opcua-client-to-go-server`; LDS evidence names `async-opcua-server-to-go-lds` / `async-opcua-client-to-go-lds` in its `case`), checked without Docker by `TestAsyncOpcuaLedgerValid`. `coverage.json` and `COVERAGE.md` stay open62541 / Milo only.

What async-opcua 0.19 does not provide is `unsupported` in the ledger, declared by the adapter (`print-capabilities`) and skipped by the tests, never emulated: ECC security policies, Local Discovery Server and mDNS (the server answers the discovery services with `Bad_ServiceUnsupported`, pinned by `TestAsyncOpcuaServer_DiscoveryServerUnsupported`), PubSub (`TestPubSub_AsyncOpcuaHasNoPubSub`), and the `codec` operation (its JSON Variant is the 1.04 Type/Body form, its XML Variant the NodeSet2 form without the Part 6 `<Value>` element). Its server answers AddReferences / DeleteReferences with `Bad_ServiceUnsupported` (`TestAsyncOpcuaServer_ReferencesUnsupported`; AddNodes / DeleteNodes are verified), has no server diagnostics (`EnabledFlag` is null) and returns empty DiagnosticInfos for ReturnDiagnostics.

⚠ Stack deviations the suite found (details in `opcua-interop/async-opcua/README.md`):

- A String written to an Int32 variable is accepted instead of `Bad_TypeMismatch` (`TestAsyncOpcuaServer_WriteTypeMismatch` skips; `write.type-mismatch` C→ is `unsupported`).
- Browse of an unknown NodeId returns `Good` without references (`TestAsyncOpcuaServer_InvalidNodeId/Browse` skips; the Read part is verified).
- No `EventQueueOverflowEventType` event when an event queue overflows (`event.queue-overflow` C→ is `unsupported`).
- Under trigger `StatusValueTimestamp` a SourceTimestamp change is reported inside a deadband, and a percent-deadband change of exactly the deadband is reported (floating point); both are logged, not asserted, by `TestAsyncOpcuaServer_DataChangeFilter`.
- A Write with a SourceTimestamp is accepted (as Milo does), logged by `TestAsyncOpcuaServer_WriteEncodingMask`.
- Certificates are trusted by exact match only (no CA chains): the v0.17.0 test PKI lists the go-opcua consumer certificate in the async-opcua server's trust list.
- `MaxByteStringLength` is 65535, so `TestAsyncOpcuaServer_ChunkedSecureMessages` writes and reads three ByteStrings of that size in one request (the messages are still split into four chunks).

### go-opcua ↔ node-opcua

[node-opcua](https://github.com/node-opcua/node-opcua) 2.187.12 (TypeScript / Node.js) is another peer, added with the opcua-interop **v0.9.0** adapter `ghcr.io/otfabric/opcua-interop-node-opcua`. Its tests (`interop/nodeopcua_*_test.go`, the node-opcua peers of `TestMulticast_GoAndPeers`) run with every interop run against the digest-pinned v0.17.0 image (`NODE_OPCUA_IMAGE` overrides it).

```sh
# in opcua-interop: build the adapter, generate (or extend) the test PKI
make -C ../opcua-interop image-node-opcua
certs/generate.sh                     # or: certs/generate.sh --add-node-opcua
# in go-opcua
NODE_OPCUA_IMAGE=ghcr.io/otfabric/opcua-interop-node-opcua:dev \
OPCUA_INTEROP_PKI_DIR=../opcua-interop/certs/test-pki \
go test -tags=interop -run 'NodeOpcua' -v ./interop/
```

Its evidence is kept in [`interop/testdata/ledger-node-opcua.json`](interop/testdata/ledger-node-opcua.json) (directions `go-client-to-node-opcua-server` and `node-opcua-client-to-go-server`; LDS evidence names `node-opcua-server-to-go-lds` / `node-opcua-client-to-go-lds` in its `case`), checked without Docker by `TestNodeOpcuaLedgerValid`. node-opcua validates certificates against the test CA and its CRL, so no per-certificate trust entries are needed.

What node-opcua does not provide is `unsupported` in the ledger, declared by the adapter and skipped or pinned by the tests: ECC security policies (`TestNodeOpcuaServer_EccUnsupported`), AddNodes / DeleteNodes on the server (`Bad_ServiceUnsupported`, `TestNodeOpcuaServer_NodeManagementUnsupported`; the node-opcua client's node-management is verified against go-opcua), QueryFirst / QueryNext and HistoryUpdate on the server (`Bad_ServiceUnsupported`), a discovery server in the adapter (`OPCUAServer` answers the LDS services with `Bad_ServiceUnsupported`, `TestNodeOpcuaServer_DiscoveryServerUnsupported`; node-opcua's LDS is a separate application), PubSub (`TestPubSub_NodeOpcuaHasNoPubSub`), the `codec` operation (`TestNodeOpcuaAdapter_CodecUnsupported`), AddReferences / DeleteReferences on the server (`Bad_ServiceUnsupported`, `TestNodeOpcuaServer_ReferencesUnsupported`) and DiagnosticInfos for ReturnDiagnostics (none are returned). ServerDiagnosticsSummary and SessionDiagnosticsArray are verified.

⚠ Stack deviations the suite found (details in `opcua-interop/node-opcua/README.md`):

- A Read with an IndexRange on a scalar returns `Good` with the scalar instead of `Bad_IndexRangeNoData` (`TestNodeOpcuaServer_IndexRange` skips; array subsets are verified by `TestNodeOpcuaServer_IndexRangeSubset`).
- The queue size of an event monitored item is revised to at least 100, so the event queue overflow cannot be provoked at the fixture's event rate (`TestNodeOpcuaServer_EventQueueOverflow` skips; `event.queue-overflow` C→ is `unverified`, `adapter-fixture-missing`).
- A Write with a SourceTimestamp is accepted (as Milo and async-opcua do), logged by `TestNodeOpcuaServer_WriteEncodingMask`.
- The node-opcua server registers only with an LDS endpoint that has a server certificate, so `TestGoLDS_NodeOpcuaServerRegisters` runs the go-opcua LDS with Basic256Sha256 SignAndEncrypt instead of the None-only LDS of the shared registration test.

### go-opcua ↔ opcua-asyncio

[opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) (PyPI `asyncua` 2.1.0, Python 3.14) is another peer, added with the opcua-interop **v0.9.0** adapter `ghcr.io/otfabric/opcua-interop-asyncua`. Its tests (`interop/asyncua_*_test.go`, the asyncua peers of `TestMulticast_GoAndPeers`) run with every interop run against the digest-pinned v0.17.0 image (`ASYNCUA_IMAGE` overrides it).

```sh
# in opcua-interop: build the adapter, generate (or extend) the test PKI
make -C ../opcua-interop image-asyncua
certs/generate.sh                     # or: certs/generate.sh --add-asyncua
# in go-opcua
ASYNCUA_IMAGE=ghcr.io/otfabric/opcua-interop-asyncua:dev \
OPCUA_INTEROP_PKI_DIR=../opcua-interop/certs/test-pki \
go test -tags=interop -run 'Asyncua' -v ./interop/
```

Its evidence is kept in [`interop/testdata/ledger-asyncua.json`](interop/testdata/ledger-asyncua.json) (directions `go-client-to-asyncua-server` and `asyncua-client-to-go-server`; LDS evidence names `asyncua-server-to-go-lds` / `asyncua-client-to-go-lds` in its `case`), checked without Docker by `TestAsyncuaLedgerValid`. The adapter validates a peer certificate as a chain to the test CA in `trusted/certs` (with `issuers/certs` as intermediates) and the CRLs of `trusted/crl` / `issuers/crl`, like open62541 and Milo; it loads the PKI itself because asyncua's TrustStore reads only `*.der` / `*.pem` files and has no issuer list. The `asyncua-server` / `asyncua-client` identities are new in v0.9.0 (`certs/generate.sh --add-asyncua` adds them to an existing PKI).

What opcua-asyncio does not provide is `unsupported` in the ledger and skipped or pinned by the tests: ECC security policies (asyncua implements RSA policies only), reverse connect, mDNS, FindServersOnNetwork on the server (`TestAsyncuaServer_DiscoveryServer`), AddNodes / DeleteNodes and AddReferences / DeleteReferences, which asyncua serves only to its Admin role (`Bad_UserAccessDenied`, `TestAsyncuaServer_NodeManagementUnsupported`, `TestAsyncuaServer_ReferencesUnsupported`), server diagnostics and DiagnosticInfos for ReturnDiagnostics, PubSub and the `codec` operation (asyncua has no Part 6 JSON encoding; its XML is nodeset import / export). The adapter declares no `deadband` / `percent-deadband` server features. A multi-chunk request cannot be provoked: the server revises `MaxRequestMessageSize` to 65536.

⚠ Stack deviations the suite found (each a skip with the reason, `asyncuaDeviation`, and an `unsupported` ledger row; details in `opcua-interop/asyncua/README.md`):

- TimestampsToReturn is ignored for Read and monitored items (both timestamps are always returned).
- IndexRange is ignored on Read (a scalar answers `Good`, a subset returns the whole array).
- A Write with a SourceTimestamp is accepted (`Good`), as Milo, async-opcua and node-opcua do.
- Write to an unknown node answers `Bad_UserAccessDenied`, Browse of an unknown node `Bad_NodeIdInvalid` (want `Bad_NodeIdUnknown`).
- Browse ignores RequestedMaxReferencesPerNode, so there is no ContinuationPoint for BrowseNext or its release.
- HistoryRead with NumValuesPerNode truncates without a ContinuationPoint.
- ModifySubscription ignores the requested parameters; ModifyMonitoredItems does not apply a new ClientHandle.
- MonitoringMode Sampling still reports, so SetTriggering cannot be asserted either.
- The absolute deadband is compared with the previous sample instead of the last reported value; a percent deadband is accepted but not applied; the SamplingInterval is revised to the publishing interval and every write is reported (`peerDataChangeDeviation`, consulted by `assertPeerDataChangeFilter`).
- No EventQueueOverflowEventType event when an event queue overflows.
- Republish of an unknown sequence number answers `Good` with an empty NotificationMessage instead of `Bad_MessageNotAvailable`.
- TransferSubscriptions checks no identity: a user's subscription moves to an anonymous session.
- RegisterServer with IsOnline=false is stored like a registration, so an unregistered server stays in FindServers.

Two go-opcua bugs found by this peer are fixed in v1.8.1 (a superseded security token was renewed again; a Republish without the requested message rewound the subscription's sequence numbers). go-opcua encodes an empty Go string as a null String, which the asyncua client reads as `None` (`TestGoServer_AsyncuaClient_*` expect that).

---

### go-opcua ↔ UA-.NETStandard

The OPC Foundation [UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard) stack 2.0.1 (C#, .NET 10) is a fourth peer, added with the opcua-interop **v0.9.0** adapter `ghcr.io/otfabric/opcua-interop-dotnet`. Its tests (`interop/dotnet_*_test.go`, the dotnet peer of `TestMulticast_GoAndPeers`) run with every interop run against the digest-pinned v0.17.0 image (`DOTNET_IMAGE` overrides it).

```sh
# in opcua-interop: build the adapter, generate (or extend) the test PKI
make -C ../opcua-interop image-dotnet
certs/generate.sh                     # or: certs/generate.sh --add-dotnet
# in go-opcua
DOTNET_IMAGE=ghcr.io/otfabric/opcua-interop-dotnet:dev \
OPCUA_INTEROP_PKI_DIR=../opcua-interop/certs/test-pki \
go test -tags=interop -run 'Dotnet' -v ./interop/
```

Its evidence is kept in its own ledger, [`interop/testdata/ledger-dotnet.json`](interop/testdata/ledger-dotnet.json) (one row per capability for `go-client-to-dotnet-server` and `dotnet-client-to-go-server`; LDS evidence names `dotnet-server-to-go-lds` / `dotnet-client-to-go-lds` in its `case`), checked without Docker by `TestDotnetLedgerValid`: known capabilities, a row for every capability in both directions, evidence tests that exist and declare the row's subtest, and a row or case for every `coverage/…` subtest of the dotnet files.

What the dotnet adapter does not offer is `unsupported` in the ledger and declared by `print-capabilities`: reverse connect (the stack has it, the adapter does not wire it), ECC (2.0.1 refuses the test PKI's ECC certificates, which the RSA test CA issues) and the Local Discovery Server and mDNS (pinned by `TestDotnetServer_DiscoveryServerUnsupported`). Its server runs with diagnostics off (`EnabledFlag` false, `diagnostics.server-summary` `unsupported`); ReturnDiagnostics is verified (it is the only peer that returns operation DiagnosticInfos), as are AddReferences / DeleteReferences and the JSON Verbose codec in both directions. Its codec reads namespace-qualified XML only, so open62541's XML documents fail to decode there (an opcua-interop smoke check, not a go-opcua test).

**PubSub (`interop/dotnet_pubsub_peer_test.go`).** Since opcua-interop v0.10.0 the dotnet adapter has the PubSub contract (§14, its .NET limits in §14.13) on the Opc.Ua.PubSub runtime of 2.0.1. Verified in both directions: the UADP and JSON codecs (byte-exact UADP but for the empty String, which .NET writes with length 0 and go-opcua with length -1), UDP unicast with the Variant, DataValue and RawData field encodings, Sign and SignAndEncrypt with static keys (PubSub-Aes128-CTR, PubSub-Aes256-CTR), MQTT 3.1.1 and 5.0 with UADP and JSON (the .NET publisher needs MQTT 5.0: Opc.Ua.PubSub.Mqtt sets the MQTT 5 ContentType on every publication), the go-opcua runtime and TargetVariables, chunk NetworkMessages (`pubsub.uadp.chunk`) and UADP discovery in the .NET layout (`pubsub.uadp.discovery`). KeepAlive DataSetMessages (`pubsub.keepalive`) and `pubsub.receive-timeout` are verified dotnet publisher → go-opcua reader: with `"deltaFrames": true` and a large KeyFrameCount the dotnet writer builds no DataSetMessage over unchanged values and sends KeepAlive messages every KeepAliveTime, which keep the go-opcua reader (MessageReceiveTimeout 1 s) Operational (`TestPubSubRuntime_KeepAlive_DotnetPublishes`); pausing the publisher's container sends the reader to Error and unpausing it brings it back to Operational (`TestPubSubRuntime_ReceiveTimeout_DotnetPublisher`). The opposite direction needs the dotnet reader's state, which the adapter does not expose. SKS, the PublishSubscribe information model, Ethernet and AMQP are `unsupported`; multicast (`--network host`, Linux only) is verified go-opcua publisher → dotnet subscriber (`TestPubSubMulticast_GoPublishes_DotnetSubscribes`); the other direction waits for the opcua-interop v0.16.0 adapter, because UA-.NETStandard 2.0.1 sends multicast with IP_MULTICAST_LOOP off (`UdpTransportOptions.MulticastLoopback`), so a subscriber on the same host receives nothing (`TestPubSubMulticast_DotnetPublishes_GoSubscribes` skips until then). .NET leaves the `UaType` of a DataValue field out when its DataSetMetaData implies it; `jsonmsg.Decode` types such a Value from the metadata (found by these tests).

```sh
DOTNET_IMAGE=ghcr.io/otfabric/opcua-interop-dotnet:dev OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 \
go test -tags=interop -run 'Dotnet|TestPubSubChunk_|TestPubSubDiscovery_' -v ./interop/
```

UA-.NETStandard found three go-opcua defects, fixed in v1.8.1: the RSA-OAEP-SHA256 plaintext block size (Aes256_Sha256_RsaPss), CreateSession without `ServerEndpoints` for a client that connects with another host name, and client certificate chains in `WithClientCertificateTrustList`. Other behaviour the tests account for: a username token needs an encrypting channel (the dotnet client refuses one over SecurityPolicy None, so the username tests use Basic256Sha256 SignAndEncrypt); TransferSubscriptions needs the same identity in both sessions: two anonymous sessions on a None channel carry nothing to compare and are refused with `Bad_UserAccessDenied` (pinned), two anonymous sessions of the same application certificate over Basic256Sha256 SignAndEncrypt transfer (`TestDotnetServer_TransferSubscriptionsIdentity`), as with every other peer; the end time of a raw history read is exclusive; a continuation-point release answers with a null HistoryData.

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

`test-missing` · `adapter-command-missing` · `adapter-unreleased` (the adapter command exists on an opcua-interop branch and the test passes against a local build; verified once the release publishes the image) · `adapter-fixture-missing` · `fault-harness-missing` · `consumer-demand-missing` · `peer-capability-unknown`

Adapter images are pinned to [opcua-interop v0.17.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) (digest-pinned below), the release the suite and the ledgers are written against (`interopVersion` in `harness_test.go`, `coverage.json`, `testdata/ledger-*.json`, `render-interop-coverage`). The peer versions are open62541 **1.5.9**, Eclipse Milo **1.1.8**, async-opcua **0.19.0**, UA-.NETStandard **2.0.1**, node-opcua **2.187.12** and opcua-asyncio **2.1.0**. CI sets `OPCUA_INTEROP_REQUIRE_CAPABILITIES=1` so that missing operations, features, security profiles or a missing test PKI fail rather than skip.

| Image | Tag |
|-------|-----|
| `ghcr.io/otfabric/opcua-interop-open62541` | [`v0.17.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) / `@sha256:90487dbc…17dfa16f` |
| `ghcr.io/otfabric/opcua-interop-milo` | [`v0.17.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) / `@sha256:cb2b182e…eed2924e` |
| `ghcr.io/otfabric/opcua-interop-async-opcua` | [`v0.17.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) / `@sha256:dcb809cc…0d413caa` |
| `ghcr.io/otfabric/opcua-interop-dotnet` | [`v0.17.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) / `@sha256:aae1a636…883c4728` |
| `ghcr.io/otfabric/opcua-interop-node-opcua` | [`v0.17.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) / `@sha256:0bd16799…750ff054` |
| `ghcr.io/otfabric/opcua-interop-asyncua` | [`v0.17.0`](https://github.com/otfabric/opcua-interop/releases/tag/v0.17.0) / `@sha256:aad312f3…09578fb6` |

> **Pins.** The default images in `harness_test.go` and `.github/workflows/interop.yml` are the multi-arch digests of the [v0.17.0 release run](https://github.com/otfabric/opcua-interop/actions/runs/40237547159) (the four newer peers' defaults are in their `*_harness_test.go` files). opcua-interop tags are immutable: on a new release update `interopVersion`, the digests, this table, `coverage.json` and `render-interop-coverage` in lockstep. A capability-gated test fails — it does not skip — when a default image is not the release named by `interopVersion`.

> **Local dev images:** Override `OPEN62541_IMAGE`, `MILO_IMAGE`, `ASYNC_OPCUA_IMAGE`, `DOTNET_IMAGE`, `NODE_OPCUA_IMAGE` or `ASYNCUA_IMAGE` when testing unreleased adapter builds.

> The adapter surface the suite relies on — since v0.8.0: open62541 `server --pubsub-config`, client operation `codec` with `pubsub-uadp-*` / `pubsub-json-*`, server feature `pubsub`, client feature `codec-pubsub`, the `PubSub` fixture folder and the Mosquitto broker pin; and since v0.7.0: client operations `codec`, `find-servers-on-network`, `register-server`; client features `deadband`, `reverse-listen`, `ecc-security`, `ecc-user-token`, `register-server2`, `codec-json`, `codec-xml`; server features `deadband`, `percent-deadband`, `reverse-connect`, `ecc-security`, `ecc-user-token`, `lds`, `mdns`, `register-with`; `subscription-lifecycle` with SamplingInterval 0. Older images fail those tests.

**Interop claim rule:** only modes with positive and negative peer tests in the ledger are claimed interoperable.

### Evidence objective

Optimise for accurate evidence, not a zero-unverified quota. Current ledger (`coverage.json`, 896 rows): **521 verified, 0 unverified**, 281 unsupported, 52 deferred, 42 not applicable. Since opcua-interop v0.15.0 the open62541 and Milo adapters have `client push` and `client gds-pull`, so their push management and GDS pull client rows are verified; what the two peers lack (a GDS, push management on the Milo server, the Part 9 1.05 conditions on the open62541 server) is recorded as `unsupported` with the reason; see [`GAPS.md`](interop/GAPS.md) and [`BUCKET_B.md`](interop/BUCKET_B.md). The other peers' ledgers are summarised in the [README](README.md#interop-evidence): 8 rows remain unverified there (a node-opcua GDS pull client, PubSub reader state of the UA-.NETStandard adapter, the UA JSON transport profiles in the UA-.NETStandard adapter client).

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

PubSub (Part 14) against open62541 1.5.9 — profile `pubsub` in the ledger, 52 verified rows; Eclipse Milo 1.1.8 has no PubSub (`unsupported`). Directions: C→O = go-opcua encodes / publishes / acts as client, O→S = open62541 does.

| Capability | Directions |
|---|---|
| `pubsub.uadp.codec`, `pubsub.json.codec` (byte-exact, all header options and field encodings) | C→O, O→S |
| `pubsub.uadp.udp` (Variant, DataValue, RawData), `pubsub.uadp.mqtt`, `pubsub.json.mqtt` | C→O, O→S |
| `pubsub.uadp.udp-multicast` | C→O, O→S (adapter with `--network host`; Linux only, skipped on macOS) |
| `pubsub.uadp.eth` (since go-opcua v1.9.0; Variant, SignAndEncrypt) | C→O, O→S (adapter on a Docker bridge network with a named bridge interface; Linux and root only, run by the Interop job `ethernet`, skipped elsewhere) |
| `pubsub.mqtt5` (since go-opcua v1.9.0; UADP and JSON, go-opcua on MQTT 5.0 with QoS 2, content type and UAMessageType checked by an MQTT 5.0 listener; open62541 on 3.1.1) | C→O, O→S |
| `pubsub.security.*` (Sign, SignAndEncrypt; PubSub-Aes128-CTR, PubSub-Aes256-CTR; wrong keys and unsecured messages rejected) | C→O, O→S |
| `pubsub.sks.*` (GetSecurityKeys, SKS pull, SetSecurityKeys push, Add/RemoveSecurityGroup) | C→O, O→S |
| `pubsub.runtime.*` (go publisher and subscriber, TargetVariables, receive timeout) | C→O, O→S |
| `pubsub.infomodel.*` (configuration methods, browse, Enable / Disable) | C→O (`pubsub/remote`), O→S (adapter `call` / `browse`) |

AMQP 1.0 (`pubsub.amqp`, since go-opcua v1.9.0): open62541 1.5.9 has no AMQP transport, so the ledger rows are `unsupported`; `TestPubSubAMQP_RabbitMQ` and `TestPubSubAMQP_Artemis` run a go-opcua publisher and subscriber through RabbitMQ 4.1.4 (v2 addresses `/queues/<name>`, queues declared through the management API) and ActiveMQ Artemis 2.42.0 (auto-created anycast addresses through the `queue` capability), both with SASL PLAIN: UADP unsecured and SignAndEncrypt, JSON, and a reader that learns the DataSetMetaData from its metadata queue. The broker images are pinned by digest in `interop/pubsub_broker_peer_test.go`.

open62541 limits found by these tests (recorded in opcua-interop's contract): it publishes a ConfigurationVersion it generates itself, so go readers are configured without a MajorVersion; AddDataSetReader cannot target an existing variable; a ReaderGroup added to a running connection needs the connection disabled and enabled again; RemoveDataSetReader needs its group disabled; its reader discards KeepAlive messages.

### Promoted with opcua-interop v0.7.0 (go-opcua v1.6.0)

| Capability | Directions |
|---|---|
| `monitoreditem.deadband`, `monitoreditem.trigger`, `monitoreditem.sampling-interval` | all four |
| `monitoreditem.percent-deadband` | all four (AnalogItem `Analog.Level`, EURange 0..100; rejected without EURange and above 100 %) |
| `security.ecc-nistp256.*`, `security.ecc-nistp384.*` (sign, sign-encrypt, subscription, username.valid / invalid, renewal) | C→O, O→S |
| `security.ecc-nistp256-aesgcm.*`, `security.ecc-nistp256-chachapoly.*`, `security.ecc-curve25519.*` (sign-encrypt, write, subscription, username.valid / invalid, renewal ×5) | C→O, O→S (the adapter offers the AEAD policies in SignAndEncrypt only) |
| `security.ecc.unimplemented-policy` | C→O, O→S (brainpoolP256r1, brainpoolP384r1, curve448: not selectable, refused at once). Retired when go-opcua implemented these policies, see below |
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

### ECC_brainpoolP256r1, ECC_brainpoolP384r1 and ECC_curve448

| Capability | Directions |
|---|---|
| `security.ecc-brainpoolp256r1.*`, `security.ecc-brainpoolp384r1.*`, `security.ecc-curve448.*` (sign-encrypt, write, subscription, username.valid / invalid, renewal; ×5 for curve448) | C→O, O→S against open62541 1.5.9 (OpenSSL); the opcua-interop v0.17.0 adapter offers these policies in SignAndEncrypt only. Milo, asyncua, async-opcua, node-opcua and UA-.NETStandard (adapter) `unsupported` |

The capability `security.ecc.unimplemented-policy` (the three policies refused cleanly) is retired with these rows.

### Historical events (Part 11 §6.5.2, §6.9.4, §6.9.7)

Profile `history`: `history.read.events` (ReadEventDetails forward and reverse, an empty range), `history.read.events.continuation` (NumValuesPerNode paging, release and reuse of a continuation point), `history.read.events.filter` (WhereClause OfType, Severity and both), `history.update.events` (UpdateEventDetails insert / replace / update) and `history.delete.events` (DeleteEventDetails). Since opcua-interop v0.17.0 every adapter has the client operations `history-read-events` and `history-update-events`, and the UA-.NETStandard (`history-events`, `history-events-update`) and asyncua (`history-events`) servers have the fixture `s=History.Events`: five seeded events `hist-evt-0` … `hist-evt-4` from 2026-07-24T10:00:00Z in steps of 5 s, Severity 100 … 500, `hist-evt-3` a SystemEventType (CLIENT_CONTRACT §17). The go-opcua interop server serves the same fixture (`startGoServerWithEventHistory`, `interop/history_events_test.go`): a writable HistoricalEventNode of the built-in `*Historian` (`EnableEventHistory`, `EnableEvents`, the seed recorded with `RecordEvent`) and the method `s=History.ResetEvents`.

| Direction | read | continuation | filter | update | delete |
|---|---|---|---|---|---|
| open62541, Milo, UA-.NETStandard, node-opcua, asyncua, async-opcua client → go-opcua server | ✅ | ✅ | ✅ | ✅ | ✅ |
| go-opcua client → UA-.NETStandard 2.0.1 server | ✅ | ✅ | ✅ | ✅ | ✅ |
| go-opcua client → asyncua 2.1.0 server | ✅ ¹ | ✅ ¹ | ✅ ¹ | N/A ² | N/A ² |
| go-opcua client → open62541, Milo, async-opcua, node-opcua servers | N/A ³ | N/A ³ | N/A ³ | N/A ³ | N/A ³ |

The peer clients (`TestGoServer_<Peer>Client_HistoryReadEvents`, `…Continuation`, `…Filter`, `…HistoryUpdateEvents`, `…HistoryDeleteEvents`) read forward and in reverse (the reverse range ends at 09:59:00: go-opcua excludes EndTime in both directions), page with `--scenario continue` (pages 2, 2, 1; the release and the reuse of the continuation point the third request consumed are `Bad_ContinuationPointInvalid`), filter (`OfType i=2130`; `Severity >= 300`; both, OfType matching subtypes), and insert, replace, update and delete with the operation results of §17.1; the go-opcua server answers an unknown EventId to delete with `Bad_NoData` (Part 11 §6.9.7.2), UA-.NETStandard with `Bad_NoEntryExists`. Milo's status names have an underscore, so the tests compare codes. The go-opcua client (`TestDotnetServer_History*Events*`, `TestAsyncuaServer_History*Events*`) uses `ReadEventHistory`, `ReadEventHistoryAll`, `HistoryReleaseContinuationPoints`, `HistoryUpdateEvents` and `HistoryDeleteEvents`, and calls `s=History.ResetEvents` around the updates.

¹ asyncua 2.1.0 deviations (§17.4), asserted as such: both range ends inclusive, an empty range answers `Good` instead of `Good_NoData`, continuation points are stateless (a released point still continues the read), OfType compares the event type exactly (`OfType BaseEventType` does not match `hist-evt-3`). ² asyncua refuses HistoryUpdate with `Bad_UserAccessDenied` (no handler); `TestAsyncuaServer_HistoryUpdateEvents` pins the refusal. ³ open62541 1.5.9, Milo 1.1.8 and async-opcua 0.19.0 have no event history server (§17.5); node-opcua 2.187.12 historizes variables only and answers ReadEventDetails with the service fault `Bad_HistoryOperationInvalid`, HistoryUpdate with `Bad_ServiceUnsupported` (§17.3).

### Alarms & Conditions (Part 9)

Profile `alarms-conditions`. `alarms.condition-refresh` and `alarms.acknowledgeable` (ConditionRefresh, Acknowledge / Confirm / AddComment against the alarm fixture) are verified in both directions with open62541, UA-.NETStandard and node-opcua, and peer client → go-opcua server with Milo, async-opcua and asyncua (the Milo and asyncua servers have no conditions: `unsupported`; async-opcua's is `peer-capability-unknown`). The Part 9 1.05 rows — `alarms.alarm-state-methods`, `.dialog`, `.branches`, `.alarm-groups`, `.audit-events` (`alarms105_peer_test.go`) and `.alarm-timing`, `.audible-sound`, `.first-in-group`, `.alarm-metrics` (`alarms105_timing_peer_test.go`) — are verified peer client → go-opcua server with all six peers, through their generic `client call`, `client event-subscribe` and `client read` operations. No peer server fixture has these features, so the go-opcua client direction is `unverified` (`adapter-fixture-missing` for open62541, UA-.NETStandard and node-opcua) and covered in process by `conformance/alarms`. The exception is `alarms.audit-events` go-opcua client → node-opcua server, verified by `TestNodeOpcuaServer_AlarmAudit`: node-opcua 2.187.12 raises the AuditConditionAcknowledge / Confirm / Comment events of the fixture alarm without an auditing switch and delivers them only to SecurityAdmin sessions, so the test adds a SecurityAdmin user to the fixture and subscribes over SignAndEncrypt with `opcua.NewAuditConditionEventFilter`. node-opcua leaves MethodId / InputArguments null, sends the Status of Acknowledge and Confirm as a StatusCode instead of a Boolean, reports the EventId after the call as the ConditionEventId of Acknowledge, raises the AddComment audit event on the Server object (SourceName `Method/AddComment`) and raises one for Confirm as well (`Method/Confirm`). Against UA-.NETStandard the row stays `unverified` (`adapter-command-missing`): 2.0.1 raises the events but delivers audit events only when the server has auditing enabled, which the dotnet adapter does not set.

### Push certificate management (Part 12 §7)

Profile `certificate-management`: `certmgmt.push.trust-list`, `.certificate-update`, `.rejected-list`, `.access`. `TestCertMgmtPush_GoClient_PeerServers` drives package `gds` against open62541 1.5.9 (UA_ENABLE_GDS_PUSHMANAGEMENT), UA-.NETStandard 2.0.1 and node-opcua 2.187.12; `TestCertMgmtPush_NodeOpcuaClient_GoServer` drives node-opcua's ClientPushCertificateManagement (adapter `client push`) against `server.WithPushManagement`. They need opcua-interop v0.13.0 or later (serverFeatures `push-management`, client operation `push`, contract §15): on older images they skip, or fail with `OPCUA_INTEROP_REQUIRE_CAPABILITIES=1`. The Milo 1.1.8, async-opcua 0.19.0 and asyncua 2.1.0 servers have no push management (`unsupported`).

The Part 12 1.05 additions have rows of their own: `certmgmt.push.get-certificates`, `.create-self-signed`, `.delete-certificate`, `.reset-to-defaults`, `.https-group`, `.usertoken-group`, `.pfx`, `.transaction-diagnostics` and `.alarms` (CertificateExpired / TrustListOutOfDate). `TestCertMgmtPushGroups_GoClient_PeerServers` verifies all of them against UA-.NETStandard 2.0.1 but CreateSelfSignedCertificate (`adapter-fixture-missing`) and ResetToServerDefaults (`unsupported`), and the DefaultUserTokenGroup against open62541 and node-opcua; the others are `unsupported` where the peer server lacks the method or object, and ResetToServerDefaults on node-opcua is `peer-capability-unknown`.

Peer client → go-opcua server, the methods that are a single call are verified with every peer's generic `client call` (and `client translate` / `client read` for the alarms; `certmgmt_call_peer_test.go`, one test per peer, `TestCertMgmtPush_<Peer>ClientCall_GoServer`), as the SecurityAdmin user over Basic256Sha256 SignAndEncrypt:

| Capability | What the peer client checks | Peers |
|---|---|---|
| `.rejected-list` | GetRejectedList returns the self-signed certificate of a client the server refused just before | open62541, Milo, asyncua, async-opcua, UA-.NETStandard (node-opcua: `client push`) |
| `.access` | GetRejectedList answers Bad_UserAccessDenied to an anonymous session and Bad_SecurityModeInsufficient on a Sign-only channel | open62541, Milo, asyncua, async-opcua, UA-.NETStandard (node-opcua: `client push`) |
| `.get-certificates` | GetCertificates (NodeId input) of the DefaultApplicationGroup returns RsaSha256ApplicationCertificateType and the server's certificate | all six |
| `.reset-to-defaults` | ResetToServerDefaults drops a certificate the go-opcua `gds` client added; the trust list is the configured one again | all six |
| `.alarms` | CertificateExpired of the DefaultApplicationGroup is active (an ExpirationLimit longer than the certificate's life) and reports the certificate; TrustListOutOfDate is inactive (UpdateFrequency one hour) | all six |

The Milo adapter prints the elements of a ByteString array as the Java object `{"bytes": <Base64>, …}` instead of a Base64 string (contract §7); the test accepts both. The UA-.NETStandard adapter cannot load the key of the test PKI's `untrusted` identity (a CA certificate), so the rejected client uses a self-signed application certificate made by the test. The methods with structured inputs or several steps — the trust list file methods, CreateSigningRequest / UpdateCertificate, CreateSelfSignedCertificate, DeleteCertificate, the HTTPS and user token groups, PFX and the transaction diagnostics — still wait for a push client (→S `adapter-command-missing`: UA-.NETStandard's push client has no 2.0.1 package, open62541 has no push client API, the Milo, asyncua and async-opcua adapters have no `client push`, and node-opcua's does not cover them); the go-opcua server side is covered by `conformance/certmgmt` and `chaos/certmgmt`.

### GDS pull model (Part 12 §6, §7.9)

Profiles `discovery` and `certificate-management`: `gds.pull.directory`, `gds.pull.certificate-request`, `gds.pull.trust-list`, `gds.pull.revocation`. open62541 1.5.9, Milo 1.1.8, node-opcua 2.187, asyncua 2.1.0 and async-opcua 0.19.0 have no Global Discovery Server (`peer-capability-unknown` for their servers). Since opcua-interop v0.15.0 the open62541, Milo, asyncua, async-opcua and dotnet adapters have a `client gds-pull` built on plain method calls (CLIENT_CONTRACT §16.2): `TestGDSPull_<Peer>Client_GoServer` runs it against `gds/gdsserver`, so their client rows are `verified`; node-opcua has none (`adapter-command-missing`). UA-.NETStandard's Global Discovery Server and GDS client (Opc.Ua.Gds.Server / .Gds.Client 2.0.1) run in the separate opcua-interop adapter **dotnet-gds** (CLIENT_CONTRACT §16), an opt-in peer (`DOTNET_GDS_IMAGE`, default the v0.17.0 image by digest, `ghcr.io/otfabric/opcua-interop-dotnet-gds@sha256:9782e45e…`; without the variable the tests run only when that image is present locally, and skip otherwise. The Interop workflow pulls it, so CI runs them). `TestDotnetGDSPull_GoClient_DotnetServer` drives `gds.PullClient` against its GlobalDiscoverySampleServer (register / find / update / query / unregister, a P-256 CSR, a new key pair delivered as PFX, the trust list, revocation and the CRL) and `TestDotnetGDSPull_DotnetClient_GoServer` its GlobalDiscoveryServerClient (`client gds-pull`) against `gds/gdsserver`. All eight dotnet ledger rows are `verified` against the published image:

```bash
docker pull ghcr.io/otfabric/opcua-interop-dotnet-gds@sha256:9782e45ee4f3c55b1dadea5975bcd95831e6c3b8ac96c7a11f028febb64489bd
OPCUA_INTEROP_REQUIRE_CAPABILITIES=1 go test -tags=interop -run 'TestDotnetGDSPull' ./interop/
```

The go side is also covered by `conformance/certmgmt/gds_pull_test.go` and `gds_pull_groups_test.go` (the address space with the three certificate groups, a request lifecycle, the HTTPS group, Brainpool, PFX, a FileStore and the audit events over the wire), `gds/pull_test.go` (an enrolled server and client connect) and `chaos/gdspull`.

### Remaining gaps (summary)

- **Unsupported (behavioural):** `write.encoding-mask` C→M — Milo soft-accepts; claim requires `BadWriteNotSupported`. `nodemgmt.add-nodes` / `nodemgmt.delete-nodes` C→M — the Milo reference server has no NodeManagement service set.
- **Unsupported (peer stack lacks the feature):** all `security.ecc-*` and `transport.reverse-connect*` rows for Milo (no ECC policy, no ReverseHello); Milo as a discovery server (`discovery.lds-registration`, `discovery.register-server2.mdns`, `discovery.find-servers-on-network` C→M) and `discovery.multicast` C→M / M→S (no mDNS); `encoding.xml.datavalue` C→O / O→S (open62541 has no XML DataValue); `encoding.json.datavalue` C→M (Milo decodes only its nested DataValue form).
- **Known representation limits** (asserted, not claimed away): go-opcua has no null String (`""` is the null String in binary and `""` in JSON / XML); open62541 cannot decode XmlElement from XML nor encode a matrix to XML; Milo's XML decoder keeps a DateTime to the millisecond.
- **Deferred** (outside current core parity): NodeSet2 import, advanced HA, cross-stack custom DataTypes, Query against Milo, IssuedIdentityToken, dynamic EO decode, custom event emission, general WhereClause surface and event queue overflow for O→S / M→S, HistoryRead modified/at-time/processed, HistoryUpdate and HistoryDelete of data, certificate chains / CRL, secured LDS registration against a peer LDS, the JSON / XML encodings as a transport (only the DataEncoding of values is verified).

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
