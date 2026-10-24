# PubSub (Part 14)

OPC UA PubSub sends data from publishers to any number of subscribers without
sessions: a publisher samples a *DataSet* at a fixed interval and sends it as a
*NetworkMessage* over UDP or through an MQTT or AMQP broker, and subscribers pick the
DataSets they are interested in from what arrives. go-opcua implements both
sides, standalone (no OPC UA server needed) and inside the server, where
published fields come from the address space and received fields are written
to variables.

| Area | Supported |
|------|-----------|
| Message mappings | UADP (binary) and JSON (`ua-data`, `ua-metadata`, `ua-status`) |
| Transports | UDP unicast and multicast (`opc.udp://`), MQTT 3.1.1 (`mqtt://`, `mqtts://`) and AMQP 1.0 (`amqp://`, `amqps://`) with UADP or JSON |
| UADP field encodings | Variant, DataValue, RawData |
| DataSetMessages | key frames, delta frames, keep-alive, events (PublishedEvents) |
| Message security | Sign and SignAndEncrypt with PubSub-Aes128-CTR and PubSub-Aes256-CTR (UADP) |
| Keys | static keys, Security Key Service (SKS) server, SKS pull client, SetSecurityKeys push |
| Configuration | the standard `ua.PubSubConfigurationDataType`, builders for common setups, runtime add / remove / enable / disable |
| Information model | `Server/PublishSubscribe` with connections, groups, writers, readers, published data sets, status and the configuration methods |
| Remote configuration | package `pubsub/remote` calls the PubSub methods of any Part 14 server |
| Not implemented | Ethernet (`opc.eth://`), AMQP over WebSockets (`wss://`), chunked NetworkMessages, UADP discovery requests, Diagnostics objects, PubSub actions |

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
| `pubsub/transport`, `/udp`, `/mqtt`, `/amqp` | transport registry and the UDP, MQTT and AMQP transports |
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

## AMQP

```go
conn := pubsub.AMQPConnection("Broker", "amqps://broker:5671", "urn:my:publisher", pubsub.MappingUADP)
writer := pubsub.SetWriterQueue(pubsub.DataSetWriter("Writer", 1, "Measurements"),
    "/exchanges/amq.topic/plant.line1", "/queues/plant.line1.meta")
group := pubsub.WriterGroup("Group", 1, time.Second, writer)
```

The AMQP transport (Part 14 §7.3.4, Annex B.3, profiles `pubsub-amqp-uadp` and
`pubsub-amqp-json`) runs on an AMQP 1.0 client of its own (`internal/amqp`, no
dependencies): SASL ANONYMOUS, PLAIN and EXTERNAL (TLS client certificates),
TLS, idle time-outs with heartbeats, multi-frame messages, credit-based flow
control and reconnection with backoff, after which the links are attached
again and unsettled messages are sent again.

Queue names are AMQP addresses: the publisher sends to the target address
`QueueName` (`MetaDataQueueName` for metadata), the subscriber receives from
the source address of its reader. Wildcards do not exist in AMQP; how an
address is resolved depends on the broker:

| Broker | Send to | Receive from |
|--------|---------|--------------|
| RabbitMQ 4 (native AMQP 1.0) | `/queues/<queue>`, or `/exchanges/<exchange>/<routing-key>` (e.g. `/exchanges/amq.topic/plant.line1`) | `/queues/<queue>`; the queue must exist and, for an exchange, be bound to it |
| ActiveMQ Artemis | a plain address (`plant/line1`), created on first use | the same address |

For Artemis the routing type of an auto-created address follows the broker
configuration, or the capabilities set with the connection properties
`target-capabilities` and `source-capabilities` (`queue` for anycast, `topic`
for multicast).

Each message has one data section with the NetworkMessage and the properties
of Table B.1: a random UUID as `message-id`, the `subject` `ua-data` or
`ua-metadata` and the `content-type` `application/opcua+uadp` or
`application/json`. The WriterGroupProperties and DataSetWriterProperties
named in Table B.2 (`message-to`, `message-reply-to`, `message-correlation-id`,
`message-group-id`, `message-user-id`, `message-content-encoding`,
`message-absolute-expiry-time`, `message-creation-time`, ...) set the
corresponding message properties; other properties are sent as
application-properties. Received messages may carry their bytes in data
sections or, leniently, in an amqp-value or amqp-sequence.

Delivery guarantees (B.3.5): BestEffort and AtMostOnce send pre-settled
messages (fire and forget; Send fails while the connection is down);
AtLeastOnce sends unsettled messages, and the publisher waits for the broker
to accept each one (after a reconnect a message can arrive twice);
ExactlyOnce is downgraded to AtLeastOnce. Metadata is sent at least once.
AMQP has no retained messages: send the metadata to a queue (as above) so
that a subscriber that starts later finds it, or set `MetaDataUpdateTime`.

Connection settings come from `WithTransportConfig` (credentials, TLS, the
container-id as `ClientID`) and from the connection properties (B.3.4):
`connection-hostname` (RabbitMQ virtual hosts: `vhost:<name>`),
`connection-max-frame-size`, `connection-idle-time-out` (milliseconds) and
`link-max-message-size` set those AMQP fields, other `connection-*`,
`session-*` and `link-*` names become properties of the open, begin and attach
frames, and `container-id`, `username`, `password`, `sasl-mechanism`,
`credit` and `idle-timeout` (seconds) are honoured as well.

The AMQP transport has been tested with the in-process test broker
(`internal/testutil/amqpbroker`) only so far; tests against RabbitMQ and
ActiveMQ Artemis are pending.

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
