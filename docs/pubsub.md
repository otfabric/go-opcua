# PubSub (Part 14)

OPC UA PubSub sends data from publishers to any number of subscribers without
sessions: a publisher samples a *DataSet* at a fixed interval and sends it as a
*NetworkMessage* over UDP or through an MQTT broker, and subscribers pick the
DataSets they are interested in from what arrives. go-opcua implements both
sides, standalone (no OPC UA server needed) and inside the server, where
published fields come from the address space and received fields are written
to variables.

| Area | Supported |
|------|-----------|
| Message mappings | UADP (binary) and JSON (`ua-data`, `ua-metadata`, `ua-status`) |
| Transports | UDP unicast and multicast (`opc.udp://`), MQTT 3.1.1 (`mqtt://`, `mqtts://`) with UADP or JSON |
| UADP field encodings | Variant, DataValue, RawData |
| DataSetMessages | key frames, delta frames, keep-alive, events (PublishedEvents) |
| Message security | Sign and SignAndEncrypt with PubSub-Aes128-CTR and PubSub-Aes256-CTR (UADP) |
| Keys | static keys, Security Key Service (SKS) server, SKS pull client, SetSecurityKeys push |
| Configuration | the standard `ua.PubSubConfigurationDataType`, builders for common setups, runtime add / remove / enable / disable |
| Information model | `Server/PublishSubscribe` with connections, groups, writers, readers, published data sets, status and the configuration methods |
| Remote configuration | package `pubsub/remote` calls the PubSub methods of any Part 14 server |
| UADP chunks and discovery | chunked NetworkMessages with bounded reassembly, discovery probes and announcements (see below) |
| Not implemented | Ethernet (`opc.eth://`), AMQP, Diagnostics objects, PubSub actions |

Interoperability is tested against open62541 v1.5.9 (see the interop ledger,
profile `pubsub`), the only peer with PubSub in the interop suite: Eclipse Milo
1.1.8 and async-opcua 0.19 have no PubSub implementation, PubSub is a commercial
add-on for node-opcua, and UA-.NETStandard 2.0.1 ships a PubSub runtime that its
opcua-interop adapter does not drive (not tested).

## Packages

| Package | Contents |
|---------|----------|
| `pubsub` | runtime: publishers, subscribers, state machine, builders |
| `pubsub/message` | encoding-independent NetworkMessage / DataSetMessage model |
| `pubsub/uadp` | UADP message mapping incl. message security |
| `pubsub/jsonmsg` | JSON message mapping |
| `pubsub/transport`, `/udp`, `/mqtt` | transport registry and the UDP and MQTT transports |
| `pubsub/security` | security policies, key rings, the key service (SKS logic) |
| `pubsub/sks` | SKS client: GetSecurityKeys, SetSecurityKeys, a key source that pulls and refreshes |
| `pubsub/remote` | client helpers for the PublishSubscribe methods of a server |

The configuration model is the generated one in package `ua`
(`PubSubConfigurationDataType`, `WriterGroupDataType`,
`UADPWriterGroupMessageDataType`, `DataSetMetaDataType`, the content masks,
...). There is no second type system: a configuration built with go-opcua can
be sent to another server with `AddConnection`, and one read from another
stack can be loaded with `pubsub.New`.

## Publish without a server

```go
values := pubsub.NewMemoryDataSource()
counter := ua.NewStringNodeID(1, "counter")

pds := pubsub.PublishedDataItems("Measurements",
    pubsub.Var("Counter", counter, ua.TypeIDUint32))
group := pubsub.WriterGroup("Group", 100, 100*time.Millisecond,
    pubsub.DataSetWriter("Writer", 1, "Measurements"))
cfg := pubsub.NewConfiguration([]*ua.PublishedDataSetDataType{pds},
    pubsub.AttachWriterGroups(
        pubsub.UDPConnection("UDP", "opc.udp://224.0.0.22:4840", uint16(2234)), group))

ps, err := pubsub.New(cfg, pubsub.WithDataSource(values))
if err != nil { ... }
if err := ps.Start(ctx); err != nil { ... }
defer ps.Close()

_ = values.Set(counter, uint32(42)) // published with the next interval
```

`DataSource` is an interface; implement it to publish values from anywhere.
`KeyFrameCount` on the writer sends delta frames between key frames,
`KeepAliveTime` on the group sends keep-alive messages when nothing changes.

## Subscribe without a server

UADP carries no field names and, with RawData, no types, so a reader needs the
DataSetMetaData of the writer:

```go
md := pubsub.MetaData("Measurements",
    pubsub.Field{Name: "Counter", Type: ua.TypeIDUint32})
reader := pubsub.DataSetReader("Reader", uint16(2234), 100, 1, md)
reader.MessageReceiveTimeout = 1000 // ms: the reader goes to Error without messages

cfg := pubsub.NewConfiguration(nil,
    pubsub.AttachReaderGroups(
        pubsub.UDPConnection("UDP", "opc.udp://224.0.0.22:4840", nil),
        pubsub.ReaderGroup("Group", reader)))

ps, err := pubsub.New(cfg, pubsub.WithDataSetHandler(func(ds *pubsub.ReceivedDataSet) {
    log.Printf("#%d Counter=%v", ds.SequenceNumber, ds.Field("Counter").Value)
}))
```

The reader filters on PublisherId, WriterGroupId and DataSetWriterId, discards
duplicate and stale messages by sequence number, merges delta frames onto the
last key frame (`ReceivedDataSet.Fields` always holds every field, `Changed`
lists the ones the message carried) and drops messages with a different
MajorVersion. With the JSON mapping the field names travel in the message and
the metadata can also arrive as a `ua-metadata` message on the broker.

## MQTT and JSON

```go
conn := pubsub.MQTTConnection("Broker", "mqtt://broker:1883", "urn:my:publisher", pubsub.MappingJSON)
group := pubsub.JSONWriterGroup("Group", 1, time.Second, "plant/line1",
    pubsub.DataSetWriter("Writer", 1, "Measurements"))
```

`MQTTConnection(..., pubsub.MappingUADP)` sends UADP over the broker instead.
Topics are the `QueueName` of the writer (or group) and of the reader;
`SetWriterQueue` / `SetReaderQueue` also set the metadata queue, on which the
publisher sends retained `ua-metadata` messages. `WithTransportConfig` sets
broker credentials and TLS (`mqtts://`).

## In the server

`server.WithPubSub(cfg, opts...)` runs a PubSub runtime inside the server:

- `PublishedDataItems` read the variables of the address space (AttributeId,
  IndexRange, SubstituteValue for Bad values),
- `PublishedEvents` publish the events the server emits,
- readers with `TargetVariables` write the received fields to variables
  (WriteIndexRange, OverrideValueHandling), and `SubscribedDataSetMirror`
  creates variables for them,
- the configuration appears below `Objects/Server/PublishSubscribe`, and
  clients can change it with AddConnection, AddWriterGroup,
  AddPublishedDataItems, AddDataSetWriter, AddReaderGroup, AddDataSetReader,
  the Remove methods and Enable / Disable on every Status object.
  `server.WithPubSubAuthorizer` decides who may call them (default: everyone,
  as open62541).

`(*Server).PubSub()` returns the runtime; `PubSubNodeID` and
`PubSubComponentID` map between components and their nodes. See
`examples/pubsub/server`.

## Configure a remote server

```go
r := remote.New(client)
connID, err := r.AddConnection(ctx, pubsub.UDPConnection("UDP", "opc.udp://224.0.0.22:4840", uint16(7)))
pds, err := r.AddPublishedDataItems(ctx, "DataSet", aliases, flags, variables) // DataSet node, version, per-field results
wgID, err := r.AddWriterGroup(ctx, connID, pubsub.WriterGroup("Group", 1, time.Second))
_, err = r.AddDataSetWriter(ctx, wgID, pubsub.DataSetWriter("Writer", 1, "DataSet"))
err = r.Enable(ctx, connID)
```

The helpers find the methods by browse name and work with go-opcua and
open62541 servers.

## Security

A secured group has a `SecurityMode` (Sign or SignAndEncrypt) and a
`SecurityGroupId` (`pubsub.Secure(group, mode, id)`); the runtime takes the keys
of that SecurityGroup from a `security.KeySource`:

| Source | Use |
|--------|-----|
| `security.NewKeyRing(id, policy)` + `SetKeys` | static keys, or keys pushed with SetSecurityKeys |
| `security.KeyService.KeySource(id)` | the SKS runs in the same process |
| `sks.NewKeySource(ctx, sks.Config{...})` | pull keys from a remote SKS and refresh them before they rotate |

Pass it with `pubsub.WithKeySource(id, ks)` or `pubsub.WithKeySourceLookup`.
A secured writer group sends nothing until it has keys; a reader requires at
least the security mode of its group and rejects messages with unknown tokens,
bad signatures or weaker security.

A go-opcua server becomes a Security Key Service with
`srv.EnableSecurityKeyService(ks)` (GetSecurityKeys, Add/Remove/GetSecurityGroup;
keys are only handed out over SignAndEncrypt channels and, by default, not to
anonymous users) and accepts pushed keys with `srv.EnableSecurityKeyPush`.

## Chunked NetworkMessages

A UADP DataSetMessage that does not fit the `MaxNetworkMessageSize` of its
writer group (or, if 0, the transport's largest message: 65507 bytes for UDP
over IPv4) is sent as chunks (Part 14 §7.2.4.4.4). Each chunk is a
NetworkMessage of its own with the headers of the message, its own
GroupHeader sequence and NetworkMessage numbers, and, in a secured group, its
own security header, nonce and signature. Several DataSetMessages are first
split across NetworkMessages; only a single one that is still too large is
chunked. The JSON mapping has no chunks: an oversized JSON message is an
encoding error, as is a `MaxNetworkMessageSize` too small for any chunk data.

Subscribers reassemble the chunks per publisher, writer group, DataSetWriter,
security mode and MessageSequenceNumber. Chunks are attacker-controlled
input, so the reassembly is strict and bounded; set the limits with
`pubsub.WithChunkReassembly(uadp.ReassemblerOptions{...})`, per connection:

| Limit | Default |
|-------|---------|
| `MaxMessageSize`: largest reassembled message (TotalSize) | 2 MiB |
| `MaxChunks`: chunks of one message | 8192 |
| `MaxPendingMessages` / `MaxPendingBytes`: incomplete messages | 512 / 32 MiB |
| `MaxPublisherMessages` / `MaxPublisherBytes`: incomplete messages of one PublisherId | 64 / 8 MiB |
| `Timeout`: wait for the missing chunks of a message | 5 s |

Every chunk is charged with its size plus 64 bytes. A chunk that lies outside
its message, overlaps or repeats one already received, disagrees with the
TotalSize or the chunk size of its message, or does not fit the limits is
rejected; when a limit is reached the oldest incomplete message of the same
publisher, then the oldest overall, is dropped. The connection counters
`ChunksReceived`, `ChunkedMessagesReceived` and `ChunksDiscarded` (rejected
chunks and the chunks of dropped or expired messages) show what happened;
writer groups count `ChunksSent`.

## UADP discovery

Datagram connections (UDP) exchange discovery probes and announcements
(Part 14 §7.2.4.6), in the spec layout or the one of the OPC Foundation .NET
stack (`message.DiscoveryLayoutDotNet`).

- **Publisher.** It listens for probes on its connection address when that is
  a multicast group (a unicast address belongs to the subscriber), and on the
  `DiscoveryAddress` of the connection's `DatagramConnectionTransportDataType`
  or `DatagramConnectionTransport2DataType`. It answers PublisherEndpoints
  (with `DiscoveryOptions.Endpoints`, Bad_NotSupported without),
  DataSetMetaData, DataSetWriter configuration, WriterGroup configuration,
  PubSubConnection and FindApplications probes (with
  `DiscoveryOptions.Application`, the state of the runtime without). The
  DataSetMetaData and writer configuration announcements go to the connection
  address, where the subscribers listen, secured like the writer group they
  describe; the others go to the DiscoveryAddress. Announcements larger than
  the `DiscoveryMaxMessageSize` are chunked. With a `DiscoveryAnnounceRate`
  (`DatagramWriterGroupTransport2DataType`, or the connection's
  `DatagramConnectionTransport2DataType`) the DataSetMetaData of the writers is
  also announced at that interval (seconds), as before for MQTT on the
  MetaDataQueueName.
- **Rate limits.** A probe cannot make a publisher flood the network: the same
  announcement (kind and writer or group) is sent at most once every
  `MinInterval` (default 500 ms, §7.2.4.6.12.2), and all announcements in
  answer to probes together at most `Rate` per second in bursts of `Burst`
  (default 20 and 20) per connection. Probes over the limit are counted as
  `DiscoveryRequestsIgnored`.
- **Subscriber.** A UADP reader with a PublisherId and DataSetWriterId but no
  DataSetMetaData, or whose DataSetMetaData has another MajorVersion than the
  messages it receives, probes for it after a random delay of 100 to 500 ms,
  on the DiscoveryAddress or a multicast connection address. It does not probe
  while another subscriber's probe for the same writer is recent, and repeats
  the probe at an interval doubling from 500 ms to `MaxProbeInterval`
  (default 8 s) until the announcement arrives.

Set the options with `pubsub.WithDiscovery(pubsub.DiscoveryOptions{...})`;
`Disabled` turns discovery off. Limits: probes are sent and expected
unsecured (a secured probe is verified with the keys of the first secured
writer group); the .NET layout cannot carry WriterGroup and PubSubConnection
probe filters, nor its probe type 6; DataSetWriter "Actions" announcements
(types 6 and 7) are not supported; a unicast DiscoveryAddress is only good
for probes (the answers that go to it reach only the publisher's host).

## Interoperating with open62541

- UADP PublisherIds are matched with the same integer width: configure the
  same type (e.g. UInt16) on both sides.
- open62541 1.5.9's JSON subscriber accepts only key frames and sequence
  numbers up to 65535 (go-opcua wraps JSON sequence numbers at 16 bits).
- open62541's MQTT client uses QoS 0, no TLS, and messages must stay small
  (about 1000 bytes).
- open62541 publishes delta frames even with KeyFrameCount 1 and discards
  them as a subscriber; it has no events, chunking or discovery messages.
- Its GetSecurityKeys returns a wrong (negative) TimeToNextKey; go-opcua's
  key rings treat a non-positive TimeToNextKey as KeyLifetime.
