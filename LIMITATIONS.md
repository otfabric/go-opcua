# Limitations

What go-opcua does not do, and what has not been verified. The workarounds, the
behaviour you may notice, and the deviations of peers are in
[docs/interop-gaps.md](docs/interop-gaps.md); the evidence per capability is in
[INTEROP.md](INTEROP.md) and the ledger [interop/COVERAGE.md](interop/COVERAGE.md).

## Scope not implemented

- The OpenAPI mapping of the UA JSON services. UA JSON over HTTPS and
  WebSockets (`https-uajson`, `wss-uajson`) and the binary `opc.https` and
  `opc.wss` transports are implemented.
- A file-based certificate store for the push model: `server.CertificateStore`
  has no implementation in the library, so without one, pushed trust lists,
  certificates and keys live in memory only.
- Dynamic decoding of custom structures from the server's DataTypeDefinition:
  unknown structures stay ExtensionObject bodies.
- OPC UA FX (UAFX, OPC 10000-81): the information model, and
  connections with PubSub (EstablishConnections and CloseConnections, served
  by `uafx/fxserver` and called by `uafx`), with ControlGroups; a
  ControlGroup a client controls has no Controls Reference (Part 81
  §6.5.2 wants it from the Object of the client connection, which the
  server does not have).
  The ConnectionManager (`uafx/fxcm`, served by
  `fxserver.EnableConnectionManager`) keeps its sets and the records of its
  endpoints in memory, and with a Store also durably; it has no ConnectionManagerLog, lists no
  GlobalDiscoveryServers, reflects no Qos or ReceiveQos of an edited flow
  onto the PubSub configuration; it configures no SecurityKeyServer,
  asks no GDS, resolves no AliasNames, generates no PubSub configuration
  from the flows, and cannot adapt subscribers to the PublisherId of a
  matched PubSubConnection on AutomationComponents with
  CommandBundleRequired that subscribe to each other in a cycle (the
  Connection fails instead). Persistent ConnectionEndpoints of an
  AutomationComponent (with `ConnectionOptions.Store`) keep the endpoints,
  their control and the PubSub components they reference, not
  ConfigurationData or the VariableStorage Methods (§6.4.6), and not the
  rest of the server's PubSub configuration (OPC 10000-14 §9.1.2). With a
  Store the ConnectionManager keeps its sets, endpoint records with their
  evidence and run journal, but after a restart verifies no record (all
  are Unverified and never closed or adopted) and executes no owed work:
  it reports it and refuses what would act on the endpoints of a set
  that owes work until it is settled (C3.3)
  ([docs/uafx.md](docs/uafx.md#persistence-of-the-connectionmanager)).
  Enable and Disable of a persisted
  component with the Methods of its Status Object are not persisted: after
  a restart its enablement follows its endpoints. Without a Store, an
  ElementModify by another client (CloseAndUpdate) of a reader or writer
  an endpoint references is not followed: the endpoint keeps a Reference
  to the replaced component until it is closed (EstablishConnections calls
  are followed with or without a Store). The restart gate of a
  secured SecurityGroup is not protection against a key source rolled back
  to keys used before the restart that the process never saw current. `fxstore.FileStore` survives a power
  loss on Unix systems, only a crash of the process on Windows (no
  directory fsync), and does not support network file systems. The other
  Methods of Part 81 are not implemented, and Parts 82 to 84 are not implemented. None of the pinned references of opcua-interop
  implements UAFX, so it is tested against go-opcua only (see [docs/uafx.md](docs/uafx.md#limits)).
- Time-scheduled Ethernet (TSN), AMQP over WebSockets, and PubSub Actions bound
  to server Methods (go-opcua runs Go handlers).
- Triggering links are not restored when the client re-creates a subscription
  after a reconnect.
- mDNS has no probing or conflict resolution.

## Verification

- Tested against open62541, Eclipse Milo, async-opcua, UA-.NETStandard,
  node-opcua and asyncua through
  [opcua-interop](https://github.com/otfabric/opcua-interop), pinned by digest.
  Each ledger row is one capability in one direction; `unsupported` and
  `deferred` rows are not verified, and the totals per peer are in the
  [README](README.md#interop-evidence).
- Real mDNS multicast is verified on Linux only.
- ECC has one testable peer: where open62541 1.5.10 and Part 6 1.05.07 differ,
  go-opcua follows open62541.
- Certification: none. OPC Foundation certification has not been attempted.

## Known deviations

- UAFX persisted check (OPC 10000-81 §6.2.4.3.9.2): for a non-persistent
  ConnectionEndpoint the DataSetReader or DataSetWriter must not be
  persisted, which under OPC 10000-14 §6.2.2 Table 4 means 0:NotPersisted
  TRUE. `uafx/fxserver` checks this only with
  `ConnectionOptions.StrictNotPersisted`; by default such endpoints are
  accepted, since few configurations state the property. The check for
  persistent endpoints always runs. 0:NotPersisted on PublishSubscribe is
  not checked, and Enable or Disable of a component with the PubSub
  Methods is not persisted (enablement follows the endpoints after a
  restart). A restored secured group gates its whole SecurityGroup until a
  key newer than the restart becomes current
  ([docs/uafx.md](docs/uafx.md#persistence)).
- ECC follows open62541, not Part 6 1.05.07, for curve25519 key material
  and ChannelThumbprint
  ([docs/interop-gaps.md](docs/interop-gaps.md)).
- PubSub chunked NetworkMessages and UADP discovery use the layout of the OPC
  Foundation .NET stack 2.x where the specification is ambiguous; open62541
  1.5.10 sends and accepts neither.
- Raw history deletes (DeleteRawModified) of the built-in historian remove the
  sample at the end time, while a raw read excludes it.
- PubSub over AMQP sends ExactlyOnce as AtLeastOnce.
