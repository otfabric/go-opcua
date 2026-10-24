# PubSub (Part 14)

OPC UA PubSub sends data from publishers to any number of subscribers without
sessions: a publisher samples a *DataSet* at a fixed interval and sends it as a
*NetworkMessage* over UDP, raw Ethernet or through an MQTT broker, and
subscribers pick the DataSets they are interested in from what arrives. go-opcua implements both
sides, standalone (no OPC UA server needed) and inside the server, where
published fields come from the address space and received fields are written
to variables.

| Area | Supported |
|------|-----------|
| Message mappings | UADP (binary) and JSON (`ua-data`, `ua-metadata`, `ua-status`) |
| Transports | UDP unicast and multicast (`opc.udp://`), Ethernet with UADP (`opc.eth://`, Linux, macOS, FreeBSD), MQTT 3.1.1 and 5.0 (`mqtt://`, `mqtts://`) with UADP or JSON, QoS 0, 1 and 2 |
| UADP field encodings | Variant, DataValue, RawData |
| DataSetMessages | key frames, delta frames, keep-alive, events (PublishedEvents) |
| Message security | Sign and SignAndEncrypt with PubSub-Aes128-CTR and PubSub-Aes256-CTR (UADP) |
| Keys | static keys, Security Key Service (SKS) server, SKS pull client, SetSecurityKeys push |
| Configuration | the standard `ua.PubSubConfigurationDataType`, builders for common setups, runtime add / remove / enable / disable |
| Information model | `Server/PublishSubscribe` with connections, groups, writers, readers, published data sets, status and the configuration methods |
| Diagnostics | Part 14 §9.1.11 diagnostics objects on PublishSubscribe and every connection, group, writer and reader (`pubsub.Diagnostics`, Reset, DiagnosticsLevel) |
| Remote configuration | package `pubsub/remote` calls the PubSub methods of any Part 14 server |
| UADP chunks and discovery | chunked NetworkMessages with bounded reassembly, discovery probes and announcements (see below) |
| Not implemented | AMQP, PubSub actions |

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
| `pubsub/transport`, `/udp`, `/eth`, `/mqtt` | transport registry and the UDP, Ethernet and MQTT transports |
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
broker credentials and TLS (`mqtts://`). The `RequestedDeliveryGuarantee` of
the writer or reader picks the QoS (Part 14 §7.3.4.5): BestEffort and
AtMostOnce are QoS 0, AtLeastOnce QoS 1 and ExactlyOnce QoS 2.

The connection speaks MQTT 3.1.1 unless asked otherwise (Part 14 §7.3.4.4,
`0:MqttVersion` of Table 201):

```go
pubsub.SetMQTTVersion(conn, pubsub.MQTTVersion5)             // or MQTTVersionBestAvailable
pubsub.SetConnectionProperty(conn, "connection-Session Expiry Interval", uint32(300))
pubsub.SetConnectionProperty(conn, "site", "berlin")          // sent as a CONNECT user property
```

`BestAvailable` tries 5.0 and falls back to 3.1.1 when the broker refuses it.
With 5.0, the Table 202 properties (`connection-ClientID`, `connection-Receive
Maximum`, `connection-Maximum Packet Size`, `connection-Session Expiry Interval`,
`connection-Request Response Information`, `connection-Request Problem
Information`) go into the CONNECT, any other connection property becomes a
user property, and `Validate` checks their values; with 3.1.1 they are ignored.
Topic aliases are never used. Each message carries its content type
(`application/opcua+uadp` or `application/json`, §7.3.4.9) and the
`UAMessageType` user property (`ua-data`, `ua-metadata`, §7.3.4.8); the
subscriber uses the content type to pick the decoder. Broker refusals (reason
codes) are reported as errors with the broker's reason string.

## Ethernet

The Ethernet transport (Part 14 §7.3.3, profile
`http://opcfoundation.org/UA-Profile/Transport/pubsub-eth-uadp`) sends UADP
NetworkMessages directly as the payload of Ethernet II frames with EtherType
`0xB62C`, without IP and UDP headers. JSON is not defined over Ethernet.

```go
conn := pubsub.EthernetConnection("Ethernet", "opc.eth://01-00-5e-00-00-01:100.5", "eth0", uint16(2234))
```

The address is `opc.eth://<host>[:<VID>[.<PCP>]]`:

| Part | Meaning |
|------|---------|
| host | the destination MAC address, six hexadecimal groups separated by hyphens (`01-23-45-67-89-ab`): unicast, multicast or broadcast (`ff-ff-ff-ff-ff-ff`); empty for a connection that only receives. Host names and IP addresses (which the specification allows if they resolve to a MAC address) are not supported. |
| VID | VLAN identifier, 0 to 4094: frames carry an IEEE 802.1Q tag. VID 0 is a priority tag (no VLAN, only the PCP). |
| PCP | priority code point of the tag, 0 to 7 (default 0) |

- **Interface.** `NetworkInterface` of the address is required: the frames
  are sent on that interface with its MAC address as source (the kernel
  fills it in on macOS and FreeBSD).
- **Receiving.** A subscriber gets the `0xB62C` frames on the interface sent
  to its MAC address, to broadcast or, for a multicast URL, to that group,
  which it joins (`PACKET_ADD_MEMBERSHIP` on Linux, `SIOCADDMULTI` on the
  BSDs). Frames this host sends are received too, unless
  `transport.Config.MulticastLoopback` is false. The VLAN tag is not a
  receive filter (Linux removes it before raw sockets see the frame): to
  receive one VLAN only, use the VLAN interface (`eth0.100`) and a URL
  without VID.
- **Size.** A NetworkMessage is at most 1500 bytes (§7.3.3: a frame is at
  most 1522 bytes with addresses, VLAN tag, EtherType and FCS), or the MTU of
  the interface if smaller; on the BSDs a VLAN tag takes 4 bytes of it.
  Larger messages fail with `transport.ErrMessageTooLarge`. The hardware pads
  frames below the Ethernet minimum: a receiver sees zero bytes after a
  NetworkMessage of fewer than 46 bytes.
- **Privileges.** Linux uses `AF_PACKET` raw sockets and needs
  `CAP_NET_RAW` (or root): `sudo setcap cap_net_raw+ep ./app`, or
  `--cap-add NET_RAW` in a container (Docker grants it by default). macOS and
  FreeBSD use BPF devices (`/dev/bpf*`): root, or read-write access to the
  devices (the `access_bpf` group of Wireshark's ChmodBPF on macOS). Joining
  a multicast group needs root on macOS, and macOS hides the MAC address of
  an interface from processes without privileges: the transport then cannot
  filter on its own unicast address and accepts every unicast frame the
  interface delivers. Without access `Open` (or the first `Subscribe`) fails
  with an error that wraps `os.ErrPermission`.
- **Operating systems.** Linux, macOS and FreeBSD. On Windows and the other
  systems `Open` fails with `eth.ErrNotSupported`, and the server lists the
  profile in `SupportedTransportProfiles` only where it works.
- **TSN.** go-opcua does no time-scheduled sending: frames leave when the
  writer group publishes, without `SO_TXTIME`, launch times or traffic
  classes. PCP marks the frames for the switches; the queueing of the host
  is up to its configuration (for example a Linux `mqprio` or `taprio`
  qdisc).

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

## Diagnostics

`(*PubSub).Diagnostics(id)` returns the diagnostics object of a component (Part
14 §9.1.11): the counters with their value, `Active`, `Classification`,
`DiagnosticsLevel` and `TimeFirstChange`, `TotalInformation`, `TotalError`,
`SubError` and the LiveValues. `ResetDiagnostics(id)` is the Reset method,
`SetDiagnosticsLevel(id, level)` and `pubsub.WithDiagnosticsLevel` set the
level (default Basic). In a server they appear as the `Diagnostics` object of
`PublishSubscribe` (i=17409, PubSubDiagnosticsRootType) and of every
connection, group, writer and reader, added and removed with them. The
DiagnosticsLevel is read-only in the address space.

| Object | Counters (besides the state counters) | LiveValues |
|--------|----------------------------------------|------------|
| PublishSubscribe | | Configured / Operational DataSetWriters and DataSetReaders |
| Connection | | ResolvedAddress |
| WriterGroup | SentNetworkMessages, FailedTransmissions, EncryptionErrors (Advanced) | Configured / Operational DataSetWriters, SecurityTokenID, TimeToNextTokenID (Info) |
| ReaderGroup | ReceivedNetworkMessages, ReceivedInvalidNetworkMessages (Advanced), DecryptionErrors (Advanced) | Configured / Operational DataSetReaders |
| DataSetWriter | FailedDataSetMessages | MessageSequenceNumber, StatusCode, MajorVersion, MinorVersion (Info) |
| DataSetReader | FailedDataSetMessages, DecryptionErrors (Advanced) | MessageSequenceNumber, StatusCode, MajorVersion, MinorVersion, SecurityTokenID, TimeToNextTokenID (Info) |

Every object counts its state transitions by cause: StateError,
StateOperationalByMethod / ByParent / FromError, StatePausedByParent and
StateDisabledByMethod (Start and the end of the runtime count as caused by
the parent of PublishSubscribe). Counters and LiveValues above the
DiagnosticsLevel of their object do not count and read Bad_OutOfService; a
counter starts again at 0 when it becomes active. A NetworkMessage that cannot
be decoded counts for the reader groups whose readers its header matched (all
of the connection when the header itself is broken): as DecryptionErrors when
the message security failed (also for the secured readers), else as
ReceivedInvalidNetworkMessages. The `Counters` of `Status` stay cumulative and
are not reset.

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
- Over Ethernet, open62541 sends no VLAN tag for VID 0 (go-opcua sends a
  priority tag) and only accepts MAC addresses (no host names), like
  go-opcua.
