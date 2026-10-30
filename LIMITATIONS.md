# Limitations

What go-opcua does not do, and what has not been verified. The workarounds, the
behaviour you may notice, and the deviations of peers are in
[docs/interop-gaps.md](docs/interop-gaps.md); the evidence per capability is in
[INTEROP.md](INTEROP.md) and the ledger [interop/COVERAGE.md](interop/COVERAGE.md).

## Scope not implemented

- JSON over HTTPS and WebSockets (`https-uajson`, `wss-uajson`, the OpenAPI
  mapping). The binary `opc.https` and `opc.wss` transports are implemented.
- A file-based certificate store for the push model: `server.CertificateStore`
  has no implementation in the library, so without one, pushed trust lists,
  certificates and keys live in memory only.
- Dynamic decoding of custom structures from the server's DataTypeDefinition:
  unknown structures stay ExtensionObject bodies.
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
- ECC has one testable peer: where open62541 1.5.9 and Part 6 1.05.07 differ,
  go-opcua follows open62541.
- Certification: none. OPC Foundation certification has not been attempted.

## Known deviations

- ECC follows open62541, not Part 6 1.05.07, for curve25519 key material,
  Sign-mode key derivation and ChannelThumbprint
  ([docs/interop-gaps.md](docs/interop-gaps.md)).
- PubSub chunked NetworkMessages and UADP discovery use the layout of the OPC
  Foundation .NET stack 2.x where the specification is ambiguous; open62541
  1.5.9 sends and accepts neither.
- Raw history deletes (DeleteRawModified) of the built-in historian remove the
  sample at the end time, while a raw read excludes it.
- PubSub over AMQP sends ExactlyOnce as AtLeastOnce.
