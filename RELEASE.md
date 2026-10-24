# go-opcua Releases

## v1.9.0

**Date:** 2026-10-24
**Previous release:** v1.8.1

### Summary

PubSub (Part 14) completes its transport and message model: the Ethernet and AMQP 1.0 transports, MQTT 5.0, chunked NetworkMessages, UADP discovery and diagnostics objects in the information model.

### Added

- **pubsub, server: PubSub diagnostics objects (Part 14 §9.1.11).** `PublishSubscribe.Diagnostics` (PubSubDiagnosticsRootType, i=17409) and a Diagnostics object on every connection, writer group, reader group, DataSetWriter and DataSetReader (PubSubDiagnosticsConnectionType / WriterGroupType / ReaderGroupType / DataSetWriterType / DataSetReaderType), added and removed with the component: DiagnosticsLevel, TotalInformation, TotalError, SubError, the Reset method (through the PubSub authorizer), the state counters by cause (StateError, StateOperationalByMethod / ByParent / FromError, StatePausedByParent, StateDisabledByMethod), SentNetworkMessages, FailedTransmissions, EncryptionErrors, ReceivedNetworkMessages, ReceivedInvalidNetworkMessages, DecryptionErrors and FailedDataSetMessages, each with Active, Classification, DiagnosticsLevel and TimeFirstChange, and the LiveValues (Configured / Operational DataSetWriters and DataSetReaders, ResolvedAddress, MessageSequenceNumber, StatusCode, MajorVersion, MinorVersion, SecurityTokenID, TimeToNextTokenID). Counters and LiveValues above the DiagnosticsLevel of their object do not count and read `Bad_OutOfService`; the optional TimeFirstChange properties of the root object, which the standard nodeset leaves out, are added with their standard NodeIds.
- **pubsub: Ethernet transport (`opc.eth://`, profile pubsub-eth-uadp).** UADP NetworkMessages directly in Ethernet II frames with EtherType 0xB62C (Part 14 §7.3.3), optionally with an IEEE 802.1Q tag: `opc.eth://<MAC>[:<VID>[.<PCP>]]`. The interface (NetworkInterface) is required; the new builder `pubsub.EthernetConnection(name, url, iface, publisherID)` sets it. A multicast MAC joins the group. A NetworkMessage is at most 1500 bytes or the smaller MTU of the interface, larger ones fail with `transport.ErrMessageTooLarge`. Linux uses `AF_PACKET` raw sockets (CAP_NET_RAW or root), macOS and FreeBSD BPF devices (root or access to `/dev/bpf*`; joining a multicast group needs root on macOS); other systems get `eth.ErrNotSupported`. JSON is not defined over Ethernet and `Validate` rejects it; the server lists the profile in `SupportedTransportProfiles` where it works. go-opcua does no time-scheduled (TSN) sending.
- **pubsub: MQTT 5.0 (Part 14 §7.3.4).** `SetMQTTVersion(conn, MQTTVersion311 | MQTTVersion5 | MQTTVersionBestAvailable)` sets `0:MqttVersion` (Table 201); 3.1.1 stays the default and is unchanged on the wire, BestAvailable falls back to 3.1.1 when the broker refuses 5.0. `SetConnectionProperty` maps the Table 202 `connection-*` properties onto the CONNECT (session expiry, Receive Maximum, Maximum Packet Size, …) and sends the others as user properties; `Validate` checks them. Over MQTT 5.0 messages carry the content type of their mapping (`application/opcua+uadp`, `application/json`; §7.3.4.9) and the `UAMessageType` user property (§7.3.4.8); subscribers pick the decoder by content type and recognise metadata by UAMessageType. `transport.Message` exposes `ContentType` and `UserProperties`.
- **internal/mqtt: MQTT 5.0 client.** Properties on every packet, reason codes as errors with the broker's reason string, session expiry, Receive Maximum and Maximum Packet Size both ways, Maximum QoS, Retain and Wildcard availability, Server Keep Alive, server DISCONNECT, subscription options, and QoS 2 publishing with retransmission on both versions. Topic aliases, enhanced authentication and AUTH packets are not implemented (Topic Alias Maximum is 0).
- **pubsub/uadp, pubsub: chunked NetworkMessages (Part 14 §7.2.4.4.4).** A publisher sends a DataSetMessage larger than the MaxNetworkMessageSize of its group as chunks, each with its own GroupHeader SequenceNumber and NetworkMessageNumber and, in a secured group, its own nonce and signature. Subscribers check the security of every chunk and reassemble them per connection in bounded memory (per message, per publisher and overall, with a timeout), rejecting chunks outside their message, of another total size, duplicates and overlaps; `WithChunkReassembly` sets the limits. Codec: `uadp.EncodeChunks`, `uadp.Reassembler`, `uadp.PeekType`, `DecodeReassembled`. The layout is the one of the OPC Foundation .NET stack 2.x; open62541 1.5.9 neither sends nor accepts chunks. New counters ChunksSent, ChunksReceived, ChunkedMessagesReceived, ChunksDiscarded.
- **pubsub/uadp, pubsub: UADP discovery (Part 14 §7.2.4.6).** All probes (publisher information with every InformationType, FindApplications) and announcements (PublisherEndpoints, DataSetMetaData, DataSetWriter configuration, PubSubConnection, ApplicationInformation), in the specification layout or the .NET 2.x layout, which Decode recognises. With `WithDiscovery(DiscoveryOptions{…})` datagram publishers listen for probes on a multicast connection address and on the DiscoveryAddress, answer them rate-limited (one announcement per 500 ms, a token bucket per connection) and announce their DataSetMetaData at the DiscoveryAnnounceRate; readers without DataSetMetaData, or with a MajorVersion mismatch, probe for it after a random delay with backoff. Announcements with a bad StatusCode are ignored. New counters DiscoveryRequestsSent / Received / Ignored, DiscoveryResponsesSent / Received.
- **pubsub: AMQP 1.0 transport (Part 14 §7.3.4, Annex B.3).** Profiles `pubsub-amqp-uadp` and `pubsub-amqp-json` (`transport.ProfileAMQPUADP`, `transport.ProfileAMQPJSON`), URL schemes `amqp://` and `amqps://`, builder `pubsub.AMQPConnection`. A message carries the NetworkMessage in one data section with a UUID `message-id`, the subject `ua-data` or `ua-metadata` and the content type of the mapping (Table B.1); the Table B.2 writer group and writer properties (`message-to`, `message-correlation-id`, …) set the message properties, other properties are application properties. BestEffort and AtMostOnce are sent pre-settled, AtLeastOnce unsettled and waiting for the broker's acceptance; ExactlyOnce is downgraded to AtLeastOnce. Received messages report their content-type, and their subject as the UAMessageType, so the subscriber picks the decoder like with MQTT 5.0. Queue names are AMQP addresses (RabbitMQ 4: `/queues/<q>`, `/exchanges/<x>/<key>`; ActiveMQ Artemis: plain addresses); AMQP has no retained messages, so metadata belongs on a queue. The server lists both profiles in SupportedTransportProfiles. Not implemented: AMQP over WebSockets, promoted fields (Table B.3).
- **internal/amqp: a dependency-free AMQP 1.0 client.** SASL ANONYMOUS, PLAIN and EXTERNAL, TLS, max-frame-size negotiation, idle time-outs with heartbeats, session and link flow control, multi-frame messages, settled and unsettled deliveries, and reconnect with backoff that attaches the links again and resends unsettled messages. Everything decoded from the network is bounded (frame size, nesting depth, counts and lengths before allocation).
- `transport.PublishOptions` has `ContentType`, `MessageType`, `MessageExpiry`, `UserProperties` (MQTT 5.0) and `Properties` (AMQP); the publisher fills them, each transport uses what it can carry.
- **pubsub: `Diagnostics`, `ResetDiagnostics`, `SetDiagnosticsLevel`, `WithDiagnosticsLevel`.** The runtime keeps the Part 14 counters per component next to the cumulative `Counters` of `Status`, which a Reset does not touch; `DiagnosticsCountersOf` lists the counters of a component kind with their classification and level.

### Tests

- Transport review: new fuzz targets for the AMQP connection and session state machine (`FuzzClientFrames`), MQTT 3.1.1 / 5.0 client packet handling (`FuzzClientPackets`) and the BPF record parser of the Ethernet transport (`FuzzBPFRecords`); regression tests for Close from a handler, packet-identifier exhaustion, a stalled MQTT broker, an AMQP broker that floods without reading, oversized QoS 1/2 messages and acknowledgements of unsent publications; `TestMQTT5EndToEnd` waits for the metadata announcement instead of reading it once.
- Interop through real brokers: MQTT 5.0 against open62541 1.5.9 through Mosquitto 2.0.22 in both directions (UADP and JSON; go-opcua publishes with QoS 2 and an MQTT 5.0 listener checks the content type and UAMessageType; open62541 on 3.1.1), ledger capability `pubsub.mqtt5`; AMQP 1.0 go-opcua to go-opcua through RabbitMQ 4.1.4 and ActiveMQ Artemis 2.42.0 (UADP unsecured and SignAndEncrypt, JSON, metadata learned from a queue), ledger capability `pubsub.amqp` (open62541 has no AMQP).
- AMQP: `internal/testutil/amqpbroker`, an in-process AMQP 1.0 broker with queues, topic fan-out, credit, settlement and fault injection (dropped connections, detached links, refused opens and addresses, withheld dispositions, restart); malformed-input and fuzz tests of the frame and value decoders; end-to-end runtime tests with UADP and JSON, metadata from a queue, Sign and SignAndEncrypt and a broker restart.
- Chunks and discovery: codec round trips, fuzzing of the chunk and discovery decoders, reassembly limits and every rejection, runtime tests for secured chunked messages and for probe, announcement and rate limiting. `TestPubSub_MessageSecurity` tells a message lost at a key change (an encode error of the publisher or a decode error of the subscriber) from a UDP datagram the host dropped under load; `transport.TestRegistry` can run more than once in a process.
- MQTT 5.0: the test broker speaks 5.0 and QoS 2, honours the client's limits and subscription options and can refuse or disconnect with a reason; client, transport and runtime tests cover both versions, BestAvailable fallback, content types and properties. `TestSecuredGroup` no longer reads a subscriber's counter before that subscriber has received a message.
- Ethernet transport: unit tests for the address grammar, frame building and parsing (fuzzed), receive filtering and the OS layers against replaceable system calls; real-socket tests on the loopback interface and a veth pair, including a publisher / subscriber runtime test with UADP and SignAndEncrypt, which skip without raw access. The new CI job `pubsub-eth` runs them as root and fails instead of skipping (`GO_OPCUA_ETH_REQUIRE`).
- Interop: UADP over Ethernet against open62541 1.5.9 in both directions, unsecured and SignAndEncrypt (PubSub-Aes256-CTR), new ledger capability `pubsub.uadp.eth` (C→O, O→S). The adapter runs on a Docker bridge network with a named bridge interface, on which go-opcua sends and receives raw frames; the new Interop job `ethernet` runs the tests as root on Linux, and they skip elsewhere.

### Dependency

- `golang.org/x/sys` is a direct dependency (raw sockets and BPF of the Ethernet transport).

### Fixed

- **pubsub/transport, internal/amqp, internal/mqtt: Close from a message handler no longer deadlocks.** Closing an AMQP, MQTT, Ethernet or UDP connection from inside its own handler waited for the handler, that is for itself; Close from another goroutine still waits for a running handler, and no handler starts after Close.
- **internal/mqtt: no hang when the packet identifiers run out.** A broker that never acknowledges QoS 1/2 publications made the client loop forever under its lock once all 65535 identifiers were in use, freezing Publish, Subscribe and Close. At most 64511 publications are now in flight; beyond that Publish returns `ErrNoPacketID`.
- **internal/mqtt: Close returns within about a second when the broker has stopped reading**, instead of waiting for a blocked write up to the keep-alive or the broker's Server Keep Alive (up to 18 hours).
- **internal/mqtt: QoS 1/2 messages dropped for exceeding the maximum packet size are acknowledged (MQTT 3.1.1)**, so the broker no longer stops delivering once its in-flight window is full or redelivers them on every reconnect.
- **internal/amqp: a broker that keeps sending without reading the client's answers is disconnected** instead of making the client queue flow and disposition frames without limit.
- **internal/mqtt: an acknowledgement for a publication that was never sent no longer completes it as delivered**, and the decoder refuses a CONNECT without a protocol name (found by fuzzing).
- **pubsub: a reader without DataSetMetaData no longer fails JSON messages that arrive before the metadata.** A reader configured without metadata holds an empty one, and the JSON decoder checked the field names of the message against it (`field "…" is not in the DataSetMetaData`), counting a decode error for every message until the announcement arrived. Such a reader now has no metadata to decode against, and the message decodes by its field names. Over MQTT the retained announcement usually came first; over AMQP, where nothing is retained, data and metadata travel on separate links.
- **pubsub: ExactlyOnce is QoS 2 over MQTT.** A `RequestedDeliveryGuarantee` of ExactlyOnce published with QoS 1; it is QoS 2 now (§7.3.4.5), with both MQTT versions.
- **server: Browse reports the type definition of a target, not its DataType.** The `TypeDefinition` of a ReferenceDescription to a Variable was the Variable's DataType (e.g. `i=6` for an Int32 variable); it is the target of the Variable's HasTypeDefinition reference, and the null NodeId for node classes other than Object and Variable (Part 4 §7.30). `MapNamespace` returned the variable itself as its type definition and its Objects folder reference had a NodeId of its own namespace as reference type; they are BaseDataVariableType, FolderType and Organizes now.

---

## v1.8.1

**Date:** 2026-10-24
**Previous release:** v1.8.0

### Summary

Interop pin update (the suite runs against opcua-interop **v0.9.0**), four new interop peers in CI next to open62541 and Milo (async-opcua, UA-.NETStandard, node-opcua, opcua-asyncio), a fix that keeps a session alive while its request waits, a fix for the first sequence number of server channels, three interoperability fixes found by UA-.NETStandard, two found by opcua-asyncio (security token renewal, Republish recovery), and the client now sends the caller's ReturnDiagnostics and AuditEntryId.

### Fixed

- **server: the first sequence number of a channel is below 1024.** The channel broker seeded new channels with 1..1023 and the first chunk carries seed+1, so about one channel in 1023 started at 1024. With the RSA security policies the first sequence number must be below 1024 (Part 6 §6.7.2.4); clients that check it (async-opcua) closed the channel with `Bad_SequenceNumberInvalid`. Found by the async-opcua interop peer.
- **uapolicy: RSA-OAEP-SHA256 plaintext block size.** Aes256_Sha256_RsaPss computed the plaintext block size of asymmetric encryption with the padding of SHA-512 (`2·64+2` instead of `2·32+2` bytes), so asymmetric messages were split into blocks 64 bytes smaller than the peer expected; UA-.NETStandard failed to verify their signatures. The client and server of this library agreed with each other, which hid it. Found by the UA-.NETStandard interop peer.
- **server: CreateSession endpoints for another host name.** CreateSession returned no `ServerEndpoints` when the client connected with a host name that no endpoint URL matches (a container name, an IP address); it now returns all endpoints of the server. UA-.NETStandard clients abort the session without a matching endpoint.
- **server: client certificate chains.** `WithClientCertificateTrustList` read only the first certificate of a client certificate chain; the leaf is verified and the rest of the chain is used as intermediates (Part 6 lets a client send its certificate chain).
- **client: the RequestHeader of the caller is kept.** The secure channel built a new RequestHeader for every request and kept only its AdditionalHeader, and `Read` and `Browse` cloned the request without its header, so a `ReturnDiagnostics` mask or an `AuditEntryId` the caller set never reached the server: no server returned DiagnosticInfos to a go-opcua client. Both are sent now (the authentication token, timestamp, request handle and timeout hint stay the channel's). Found by the server diagnostics interop tests.
- **uasc: a replaced security token is not renewed again.** When `Renew` replaced a token before its scheduled renewal fired, the timer still renewed the superseded token: the OpenSecureChannel request took that token's next sequence number, one already used on the channel (Part 6 §6.7.2.4). open62541 and Milo tolerate this; opcua-asyncio closes the channel and the request times out. The renewal of a token that is no longer active is skipped, since its successor schedules one of its own. Found by the opcua-asyncio interop peer.
- **client: a Republish answered without the requested message ends the republish loop.** The recovery loop took any NotificationMessage of a Good Republish response as the retransmission. opcua-asyncio answers a sequence number it does not hold with Good and an empty message (sequence number 0), so the client rewound the subscription's sequence numbers and asked again until recovery failed. A response that does not carry the requested sequence number is treated like `Bad_MessageNotAvailable`. Found by the opcua-asyncio interop peer.
- **server: a request keeps its session alive when it arrives.** Requests of all channels are handled one at a time, and the session timeout was restarted only when the handler got to a request, so a session whose requests waited behind slow ones (a busy server, a long method call) could be closed with `Bad_SessionIdInvalid` although its client was active. Part 4 §5.6.2 counts from the last request the server received: each channel now restarts the timeout when a request arrives. Session activity is also measured on the monotonic clock, so a step of the wall clock neither expires a session nor keeps one alive. Found by an intermittent `TestSession_TimeoutEnforced` failure under the race detector; `TestSessionTouchedWhenRequestArrives` fails without the fix. A request for a session whose timeout has already elapsed no longer revives it before the periodic reaper removes it: the session lookup and the arrival of the request leave an expired session expired, and the request gets `Bad_SessionIdInvalid` (`TestExpiredSessionNotRevived`).

### Tests

- Interop images pinned to the opcua-interop v0.9.0 multi-arch digests of all six adapters (open62541 `9c5757d5…4a811f88`, Milo `68f450b0…e34579e1`, async-opcua `6a936193…de2d405d7`, dotnet `57b41e14…2099bc6d`, node-opcua `98be675f…cecede37`, asyncua `725d9d1f…85ac471c`; release run https://github.com/otfabric/opcua-interop/actions/runs/40071233368). Since v0.8.2 the open62541 adapter re-enables PubSub components that went to Error when an MQTT send failed before the broker accepted the connection, and no longer aborts with a double free when the broker refuses connections (the intermittent `mqtt-json` failure).
- All six peers run in every interop CI run, in ten shards; `interop/coverage.json`, the peer ledgers and the coverage render name v0.9.0.
- **Interop: no test passes without checking its claim.** async-opcua and node-opcua accept a Write that carries a SourceTimestamp (Good), as Milo does: their `write.encoding-mask` rows are `unsupported` now, not `verified`. The UA-.NETStandard Write test asserts its BadWriteNotSupported instead of only logging the result, the untrusted-certificate tests fail when the Go client refuses the certificate itself (the server's trust check would go untested), and the open62541 TransferSubscriptions test requires Good instead of accepting a service error.
- **Interop:** a new peer, the FreeOpcUa async-opcua 0.19.0 Rust stack (opcua-interop v0.9.0 `async-opcua` adapter, `ASYNC_OPCUA_IMAGE`), in both directions with its own ledger `interop/testdata/ledger-async-opcua.json`, checked by `TestAsyncOpcuaLedgerValid` (see INTEROP.md). What async-opcua lacks (ECC, LDS and mDNS, PubSub, the 1.05 JSON / Part 6 XML encodings) is `unsupported` in the ledger and skipped by the tests; the stack deviations it showed (a type-mismatched Write is accepted, Browse of an unknown node is `Good`, no event queue overflow event) are skips with the reason.
- **Interop:** a new peer, the OPC Foundation UA-.NETStandard 2.0.1 C# stack (opcua-interop v0.9.0 `dotnet` adapter, `DOTNET_IMAGE`), in both directions, with the go-opcua LDS (registration, `TestMulticast_GoAndPeers`) and the JSON / XML codec, with its own ledger `interop/testdata/ledger-dotnet.json`, checked by `TestDotnetLedgerValid` (see INTEROP.md). What the dotnet adapter does not offer (reverse connect, ECC, LDS and mDNS server, PubSub) is `unsupported` in the ledger. The shared history helpers treat the end time of a raw read as exclusive.
- **Interop:** a new peer, node-opcua 2.187.12 (TypeScript / Node.js; opcua-interop v0.9.0 `node-opcua` adapter, `NODE_OPCUA_IMAGE`), in both directions with its own ledger `interop/testdata/ledger-node-opcua.json`, checked by `TestNodeOpcuaLedgerValid` (see INTEROP.md). What node-opcua lacks (ECC, AddNodes / DeleteNodes, Query and HistoryUpdate on the server, an LDS in the adapter, PubSub, the codec operation) is `unsupported` in the ledger and skipped or pinned by the tests; the stack deviations it showed (an IndexRange on a scalar is answered `Good`, the event queue is revised to at least 100 so its overflow cannot be provoked) are skips with the reason. The node-opcua LDS registration test uses a secured go-opcua LDS, the only kind node-opcua registers with.
- **Interop:** a new peer, FreeOpcUa opcua-asyncio (PyPI `asyncua` 2.1.0, Python; opcua-interop v0.9.0 `asyncua` adapter, `ASYNCUA_IMAGE`), in both directions with its own ledger `interop/testdata/ledger-asyncua.json`, checked by `TestAsyncuaLedgerValid` (see INTEROP.md), including the C→P services (chunking, SetTriggering, TransferSubscriptions identity, references, diagnostics). What asyncua lacks (ECC, reverse connect, mDNS and FindServersOnNetwork, node management for the adapter's User role, server diagnostics, PubSub, the codec operation) is `unsupported` in the ledger and skipped or pinned by the tests. The stack deviations it showed are skips with the reason (`asyncuaDeviation`) and `unsupported` rows: TimestampsToReturn and IndexRange are ignored, Write to an unknown node is `Bad_UserAccessDenied`, Browse has no continuation points, ModifySubscription / ModifyMonitoredItems / MonitoringMode Sampling are not applied, the deadband compares with the previous sample, no event queue overflow event, Republish of an unknown message is `Good`, TransferSubscriptions checks no identity, and an unregistration leaves the server listed. `assertPeerDataChangeFilter` skips only the deadband or sampling-interval case of a peer listed in `peerDataChangeDeviation`, so its trigger case is still asserted.
- **Interop: client services against every peer server** (`interop/c2p_services_peer_test.go`, 10 new capabilities). They cover: multi-chunk messages of about 200 KB over Basic256Sha256 and Aes256_Sha256_RsaPss SignAndEncrypt, sized from the negotiated limits, with the chunk counts asserted; SetTriggering and RemoveLinks with the linked item in Sampling; the TransferSubscriptions identity rules; AddReferences / DeleteReferences; ServerDiagnosticsSummary and SessionDiagnosticsArray; and a Read with ReturnDiagnostics, whose DiagnosticInfos are decoded. A JSON Verbose codec round trip runs with Milo and UA-.NETStandard in both directions. What a peer lacks is `unsupported` in the ledgers, never faked: Add/DeleteReferences on Milo, async-opcua and node-opcua; server diagnostics on Milo, async-opcua and UA-.NETStandard; operation DiagnosticInfos everywhere except UA-.NETStandard; and the Verbose form on open62541.
- `chaos/pubsub` `TestParallelStartClose`: the order check no longer spans a reader restart that fell between the runtime processing a data set and calling the handler (the handler runs after the runtime releases its lock); a restart is bounded by the Timestamp of the earlier data set instead of the handler call.
- The asyncua `monitoreditem.percent-deadband` server case skips as a stack deviation (asyncua 2.1.0 accepts a percent deadband without applying it) instead of failing on the missing adapter feature when the capabilities are required.
- The channel writer tests start with every in-flight slot free: the writer returns the slot of the setup round trip after the write, which can be after the client got the response (`TestChannelWriterCov_SendAfterClose` found a slot still taken).
- `TestPubSub_KeepAliveAndReceiveTimeout` counts the receive timeout of the stopped publisher from the moment it stops; a keep-alive delayed past the 300 ms timeout on a loaded machine (an extra Error → Operational cycle in the reader's states) no longer fails it. The comparison of the keep-alives sent and received waits for the publisher's counter, which is updated after the send returns.
- `TestCloseSemantics` (UDP transport) checks that no receive loop is left after Close instead of comparing goroutine counts, which other goroutines of the test binary change.
- `TestOpen62541LDS_GoServerRegisters` waits for the registration event as well as the FindServers listing; the LDS can list the server before the RegisterServer2 response reaches the registrant.

### Docs

- **README:** the comparison covers all six interop peers (open62541, Eclipse Milo, async-opcua, UA-.NETStandard, node-opcua, asyncua) in one feature table, followed by the interop evidence per peer ledger.
- **New [docs/interop-gaps.md](docs/interop-gaps.md):** what go-opcua does not implement and what to use instead, go-opcua behaviour you may notice, the deviations of each peer stack the interop suite found, and the go-opcua defects interop found, with the version that fixed them.
- `docs/encodings.md` lists the live codec peers per encoding, `docs/pubsub.md` what the other stacks have, and `docs/server-guide.md` what the server does not implement.

---

## v1.8.0

**Date:** 2026-10-24
**Previous release:** v1.7.1

### Summary

Security and robustness release: the server no longer accepts username or issued identity tokens that nobody validated, the secure channel keeps its sequence numbers contiguous when a send fails, and several panics on malformed server responses are now errors. Test coverage of the client, node, secure channel, server and transport code is raised to 93–100% per file.

### Behaviour changes

- **server: username tokens need a validator.** A server with `EnableAuthMode(ua.UserTokenTypeUserName)` and no `WithUsernameValidator` accepted every user name and password. It now rejects them with `Bad_UserAccessDenied`, as it does X.509 user tokens without an `X509UserValidator`. Part 4 leaves the decision to accept a user identity to the server, so this stays within the specification. **Servers that offer username login must register a validator.** The example servers and the integration test server now do; `examples/server_test` takes `-user` and `-password` and offers username login only when both are set.
- **server: warning for auth modes without a validator.** `server.New` logs a warning for every enabled UserName, Certificate or IssuedToken mode that has no validator, since every token of that type will be rejected.
- **server: issued tokens need a validator.** A server with `EnableAuthMode(ua.UserTokenTypeIssuedToken)` accepted every IssuedIdentityToken without checking it. The new `WithIssuedTokenValidator` registers a validator that receives the token as the issuer created it (decrypted where the security policy encrypts it); without one, issued tokens are rejected with `Bad_IdentityTokenRejected`, as X.509 user tokens are without an `X509UserValidator`. **Servers that use issued tokens must register a validator.**
- **uapolicy: AES rejects bad key and IV sizes.** `AES.Encrypt` zero-padded a short key while `Decrypt` did not, and an IV that is not one block long panicked in `cipher.NewCBC*`. Both now return `ErrInvalidSecurityConfig`.

### Fixed

- **uasc:** a request that failed to encode or sign, or was cancelled before a chunk was written, left its response handler behind and used up the sequence numbers of the chunks it never wrote; the peer of a secured channel refuses every chunk after such a gap. The handler is removed and the numbers of unwritten chunks are given back. A chunk whose write failed keeps its number, since part of it may have reached the peer, and an AEAD policy cannot open a chunk that reuses a number. `SendMsgWithContext` did not take the send lock, so concurrent sends could interleave sequence numbers; it does now.
- **client: no reconnect on a fault of a session the client has left.** A request still under way in the session the client had before (typically a Publish when the application activated another session, which closes the previous one) is answered with `Bad_SessionIdInvalid`. The connection monitor took that for the session in use and reconnected. The secure channel now reports such a fault as a `uasc.RequestFault` carrying the request's authentication token, and the monitor ignores faults of a session it no longer uses.
- **client: no second recreation of a subscription on a stale `Bad_NoSubscription`.** A Publish request that reached the server in the moment a subscription was being recreated (deleted, then created again) found the session without subscriptions; the monitor then marked the new subscription broken and recreated it once more, changing its id under the caller. Only the publish loop handles `Bad_NoSubscription` now, and only if no subscription was registered since the request was sent. `Bad_NoSubscription` is no longer a reconnect trigger of the secure channel (only Publish requests get it).
- **server: a channel that cannot send is closed.** The response writer took `ErrSecureChannelClosed` (no active security token) for a response that could not be encoded: it tried a ServiceFault, which failed the same way, and kept the channel instead of closing it. It is treated as a broken connection now. Seen as an intermittent CI hang of `TestChannelWriterCov_FaultOnDeadConnection`; `TestChannelWriterCov_NoActiveToken` reproduces it deterministically.
- **client:** `Node.BrowseName`, `DisplayName`, `AccessLevel` and `UserAccessLevel` panicked on an attribute value of an unexpected type, and `Browse`/`BrowseNext` on a response without exactly one result; they return an error.

### Tests

- Fault and end-to-end tests over real channels and servers: secure channel (every policy, truncated and malformed chunks, sequence gaps, bad signatures, unknown tokens, abort chunks, chunk limits, renewals), client and node APIs, server channel writer, event monitor, historian and PubSub, uacp connections and reverse connect, mDNS sockets (through replaceable OS calls, so no host multicast is needed) and the AES/HMAC/RSA-PSS primitives.
- Regression tests for both client races (`TestStaleSessionFaultIgnored` reproduces the reconnect seen in CI without the fix), and the monitor trigger tests now send `Bad_NoSubscription` on a Publish request, where servers send it.
- `chaos/pubsub` `TestParallelStartClose` no longer reports a data set the kernel delivered late to a reader that had just been restarted: a restarted reader starts over, so the order is only checked between two restarts.
- Own-package coverage per file: `client.go` 61% → 93%, `node.go` 58% → 99.6%, `uasc/secure_channel.go` 51% → 97%, `uasc/secure_channel_renew.go` 69% → 100%, `server/channel_writer.go` 47% → 94%, `server/event_monitor.go` 73% → 100%, `server/historian.go` 79% → 100%, `server/pubsub.go` 84% → 99%, `uacp/conn.go` 84% → 94%, `uacp/reverse.go` 94% → 96%, `internal/mdns/conn_udp.go` 40% → 100%, `uapolicy/crypto_aes.go`, `crypto_hmac.go`, `crypto_rsapss.go` → 100%.

---

## v1.7.1

**Date:** 2026-10-24
**Previous release:** v1.7.0

### Fixed

- **pubsub/sks:** `KeySource` refetched the keys one key change too late: after the change that left it with no future key instead of the one that leaves it with one, as documented. A fetch that took longer than one key lifetime (an SKS under load, a new SignAndEncrypt session per fetch) let the ring run out of keys, and a subscriber rejected the messages of a publisher that had fetched first. A fetch now has two key lifetimes to complete when the SKS hands out two or more future keys.
- **pubsub/sks:** a received message whose token is just ahead of the keys a `KeySource` holds (the peer fetched first) now triggers a fetch, at most once per `MinRetry`.

### Tests

- Fake-clock test of the refresh schedule for 0–5 future keys, a test against an SKS that takes a whole key lifetime to answer, and a test of the token-triggered fetch; each fails on the old schedule.

---

## v1.7.0

**Date:** 2026-10-24
**Previous release:** v1.6.0

### Summary

Feature release adding OPC UA PubSub (Part 14): publishers and subscribers over UDP and MQTT with the UADP and JSON message mappings, UADP message security with the PubSub-Aes128-CTR / PubSub-Aes256-CTR policies, the Security Key Service, the PublishSubscribe information model with its configuration methods in the server, and client helpers to configure any Part 14 server. PubSub is interoperability-tested against open62541 v1.5.9 through [opcua-interop v0.8.1](https://github.com/otfabric/opcua-interop/releases/tag/v0.8.1); Eclipse Milo 1.1.8 has no PubSub implementation. The library stays pure Go without new module dependencies (the MQTT 3.1.1 client is built in).

### Added — PubSub

- **Runtime** (package `pubsub`): `pubsub.New(*ua.PubSubConfigurationDataType, ...)` runs PubSubConnections, WriterGroups, DataSetWriters, ReaderGroups, DataSetReaders and PublishedDataSets from the standard configuration model; components can be added, removed, enabled and disabled at run time and follow the Part 14 state machine (Disabled, Paused, PreOperational, Operational, Error). Publishers: publishing interval and offset, key frames and delta frames (KeyFrameCount), keep-alive, DataSetOrdering, splitting of oversize groups, MQTT topics and retained metadata, PublishedDataItems through a `DataSource`, PublishedEvents through an `EventSource`. Subscribers: filtering by PublisherId / WriterGroupId / DataSetWriterId, sequence number checks, delta frame merging, MessageReceiveTimeout, MajorVersion checks, a `DataSetHandler`, TargetVariables (with OverrideValueHandling) and SubscribedDataSetMirror through a `TargetWriter`. Builders (`UDPConnection`, `MQTTConnection`, `WriterGroup`, `JSONWriterGroup`, `PublishedDataItems`, `DataSetReader`, `Secure`, ...) and `Validate`.
- **Message mappings:** `pubsub/uadp` (all NetworkMessage and DataSetMessage header options, Variant / DataValue / RawData field encodings, key and delta frames, keep-alive, events, DataSetMetaData announcements, message security) and `pubsub/jsonmsg` (`ua-data` with every content mask, `ua-metadata`, `ua-status`). Model in `pubsub/message`; both decoders are fuzzed.
- **Transports:** `pubsub/transport/udp` (`opc.udp://`, unicast and multicast, IPv4 and IPv6) and `pubsub/transport/mqtt` (`mqtt://`, `mqtts://`, MQTT 3.1.1 with QoS 0/1, retain, reconnect and resubscribe) on a dependency-free MQTT client.
- **Security:** `pubsub/security` with the PubSub-Aes128-CTR and PubSub-Aes256-CTR policies (byte-compatible with open62541), `KeyRing` with key rotation, and `KeyService` (SecurityGroups, GetSecurityKeys semantics, authorization: keys only over SignAndEncrypt channels and not to anonymous users by default); `pubsub/sks` with GetSecurityKeys / SetSecurityKeys calls and a key source that pulls keys from a remote SKS and refreshes them before they rotate.
- **Server:** `server.WithPubSub` runs PubSub inside the server with its address space as data source, event source and target; the PublishSubscribe information model (connections, groups, writers, readers, published data sets, status) with AddConnection, RemoveConnection, AddPublishedDataItems, AddPublishedDataItemsTemplate, RemovePublishedDataSet, AddWriterGroup, AddReaderGroup, RemoveGroup, AddDataSetWriter, RemoveDataSetWriter, AddDataSetReader, RemoveDataSetReader, Enable and Disable; `server.WithPubSubAuthorizer`; `Server.EnableSecurityKeyService` (GetSecurityKeys, Add/Remove/GetSecurityGroup) and `Server.EnableSecurityKeyPush` (SetSecurityKeys).
- **Client:** `pubsub/remote` wraps the PubSub configuration methods of any Part 14 server (tested against go-opcua and open62541).
- **Method handlers** receive the calling session and channel (`server.MethodCallerFromContext`), so they can authorize by identity and security mode.
- Examples in `examples/pubsub` (publisher, subscriber, server) and the guide [docs/pubsub.md](docs/pubsub.md).

### Behaviour changes

- **`monitor`:** `ModifyMonitorItems` returns `ErrMonitoredItemNotFound` for a node that is not monitored (it was ignored); a failed `RemoveMonitorItems` keeps the items known (they are still monitored on the server).
- **Reverse connect:** `Dialer.AcceptReverse` reports a server refused at any time since the wait began, also before a failed handshake; new `ReverseListener.Rejected`, `ReverseListener.AcceptSince` and `Dialer.AcceptReverseSince`.
- **Generated files** carry the standard marker `// Code generated ... DO NOT EDIT.` (was `DO NOT EDIT!`), so Go tooling recognises them.

### Fixed

- **Events:** a Publish request could be answered while events emitted before it were still waiting in the subscription's queue, splitting a burst over two notification messages.
- **Reverse connect:** a server refused between opening the client's listener and starting to wait was not reported; the wait ended with only "context canceled".
- **MQTT client:** a QoS 1 / QoS 2 message was handed to the application before its acknowledgement was written, so closing right after receiving it could make the broker deliver it again.
- **`monitor`:** `AddMonitorItems` left the client handles of a failed call behind; `RemoveMonitorItems` forgot its items before the call (see Behaviour changes).
- **XML:** an `XmlElement` whose top-level element had `xmlns=""` directly followed by an attribute was decoded to an element that no XML parser reads (found by fuzzing).
- **PubSub runtime** (found by the chaos and conformance suites): a secured reader accepted unsecured JSON messages and messages verified with another SecurityGroup's keys; UADP fields were placed by one reader's metadata for all readers; the strictest reader's security mode applied to all readers of a writer; a delta-frame field index could size the received DataSet (amplification); a restarted publisher was discarded until its sequence numbers caught up; equal connection names took over each other's MQTT session; a change carried by an unsent delta frame was lost until the next key frame; `Start` right after a cancelled context left the runtime stopped; a refused MQTT re-subscription was not retried.
- **PubSub runtime:** a panic in an application callback (`DataSetHandler`, `DataSource`, `TargetWriter`, event handler) or while decoding crashed the program, with `server.WithPubSub` the whole server; it is now recovered, logged and counted (`Counters.Panics`).
- **PubSub information model:** with concurrent configuration changes a component could end up without a node (its parent's event was handled after its own).
- **ExtensionObject registration:** several generated structures whose Go name differs from the OPC UA name (`UADP*/JSON*MessageDataType`, `NetworkAddressURLDataType`, `ReadValueID`, ...) were never registered; they encoded with TypeId i=0 and decoded to nil.
- **Method argument checks** accept subtypes of the declared built-in type (IntegerId, Duration, ...) and empty arrays; such calls failed with `BadTypeMismatch`.
- **Server:** `Node.DisplayName` raced with Browse when nodes were added while the server runs.

### Tests

- Every library package has at least 90% statement coverage on its own, generated code excluded (`make coverage-gate`, CI job `coverage-gate`; 94% in all).
- A goroutine leak check runs after the tests of every library package; `FuzzServerRawConnection` fuzzes a running server over TCP; chaos suite `chaos/pubsub` (network faults, security attacks, key-rotation storms, SKS outages, broker restarts, configuration churn, 70 parallel writer groups, transport fuzzing).
- The interop suite runs as six parallel CI jobs (`make interop-shard`).

### Interoperability

- Peers: open62541 v1.5.9 and Eclipse Milo 1.1.8 via opcua-interop **v0.8.1** (open62541 with PubSub, MQTT, PubSub encryption and SKS; a `--pubsub-config` server flag; NetworkMessage codec operations; an Eclipse Mosquitto broker).
- PubSub against open62541, in both directions: UADP and JSON codecs byte-exact, live data over UDP and MQTT, Sign / SignAndEncrypt with both policies, SKS pull and push, the runtime as publisher and subscriber, and the information-model methods — 52 verified ledger rows, [`interop/COVERAGE.md`](interop/COVERAGE.md) (393 verified rows in all). Milo 1.1.8 has no PubSub.
- UDP multicast is verified on Linux, with the adapter in the host's network namespace (it does not cross Docker Desktop's VM). Not interop-verified: keep-alive from open62541 (it sends none).

### Known limitations

- No Ethernet (`opc.eth://`) or AMQP transport, no chunked NetworkMessages, no UADP discovery requests; DataSetMetaData announcements over UDP are not sent (metadata is published on broker transports).
- Not implemented in the information model: Diagnostics objects, AddVariables / RemoveVariables, AddPublishedEvents, AddDataSetFolder, ReserveIds, the PubSub configuration file methods, CreateTargetVariables / CreateDataSetMirror; the optional SKS methods InvalidateKeys and ForceKeyRotation.

---

## v1.6.0

**Date:** 2026-10-11
**Previous release:** v1.5.0

### Summary

Feature release closing the largest gaps to open62541: ECC security policies, reverse connect, a Local Discovery Server with mDNS, the OPC UA JSON and XML data encodings, and server-side DataChangeFilter / sampling. Every feature is interoperability-tested against open62541 v1.5.9, and against Eclipse Milo 1.1.8 where Milo implements it, through [opcua-interop v0.7.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.7.0).

Several changes alter what existing clients and servers observe — read **Behaviour changes** before upgrading.

### Behaviour changes

- **Minimum Go version is now 1.26** (was 1.25), required by `golang.org/x/crypto` v0.58.0.
- **Unchanged values no longer notify.** A write of an identical value, or a `ChangeNotification` without a change, produces no data-change notification unless the monitored item's trigger asks for it (a timestamp-only change needs `StatusValueTimestamp`).
- **The sampling interval is enforced.** A monitored item with a sampling interval above 0 is sampled at most once per interval and keeps the latest value; previously every write was queued. Request `0` to receive every change. `RevisedSamplingInterval` is now the revised request (0 stays 0, negative means the publishing interval, otherwise 1 ms – 1 h); it used to echo the publishing interval.
- **Unusable monitored items are rejected** per item: a malformed `IndexRange` (`BadIndexRangeInvalid`), a filter on a non-Value attribute or non-numeric deadband (`BadFilterNotAllowed`), a percent deadband without `EURange` (`BadMonitoredItemFilterUnsupported`), an invalid deadband (`BadDeadbandFilterInvalid`). They were silently accepted.
- **NodeSet2 import applies variable values and attributes.** `ImportNodeSetXML` and the built-in namespace 0 now set Value, DataType, ValueRank, ArrayDimensions and (when present) AccessLevel / UserAccessLevel of variables; standard variables that used to be empty now serve their values.
- **X.509 user tokens must be signed.** On a secured channel the server requires the `UserTokenSignature` (proof of possession); a missing signature used to skip the check.
- **Non-enabled security policies are rejected at OpenSecureChannel** (`BadSecurityPolicyRejected`) instead of at CreateSession.
- **A server no longer acts on a ReverseHello it receives.** It used to close the connection and dial the announced ServerUri as a TCP address; it now answers `BadTcpMessageTypeInvalid`.
- **FindServers** applies the `serverUris` filter to the server itself and honours `endpointUrl` when choosing its discovery URLs.
- **Event monitored items** no longer receive a data notification when `ChangeNotification` is called on their node; creating a monitored item no longer re-notifies the other items on that node.
- **Secured channels reject out-of-sequence chunks** (`BadSequenceNumberInvalid`, Part 6 §6.7.2.4). A peer that does not keep sequence numbers contiguous on a secured channel loses its channel; channels without security are not checked.
- After a failed CreateSubscription the client deletes subscriptions of its own session that it does not know; `Server.Close` waits (bounded by the request timeout) for a discovery registration already on the wire; DeleteMonitoredItems is synchronous; Variant arrays are limited to 32 dimensions.

### Added — security

- **ECC security policies `ECC_nistP256` and `ECC_nistP384`** on client and server: ECDSA-signed OpenSecureChannel, ephemeral ECDH + HKDF key derivation with fresh keys on every renewal, `EccEncryptedSecret` for passwords and issued tokens, ECDSA X.509 user tokens.
- **AEAD ECC security policies `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` and `ECC_curve25519`** (OPC UA 1.05.07, the set open62541 enables by default) on client and server: AES-128-GCM / ChaCha20-Poly1305 message protection, Ed25519 application and user certificates, X25519 key agreement, ChannelThumbprint binding, key chaining on renewal and channel-bound session signatures.
- New dependency: `golang.org/x/crypto` v0.58.0 (ChaCha20-Poly1305 only). The library remains pure Go; no cgo.
- Client options `PrivateKeySigner(crypto.Signer)` and `AuthPrivateKeySigner(crypto.Signer)`; `PrivateKeyFile` also loads ECDSA keys (PKCS#8, SEC1; PEM or DER).
- Server option `ApplicationIdentity(cert, key)`, repeatable: one application certificate per key type for servers that offer RSA and ECC endpoints.
- `opcua.SelectEndpoint(endpoints, policy, mode, certDER)` picks the best endpoint usable with the client certificate's key type; ECC endpoints rank above RSA ones, AEAD policies first, and endpoints with equal advertised SecurityLevel are ordered by the library's ranking.
- A server with ECC-only certificates can register with a discovery server; the registration client uses the certificate that fits the endpoint.
- The client and server refuse a security policy that is not implemented by name instead of failing later in the handshake.

### Added — transport

- **Reverse connect** (Part 6 §7.1.3) on client and server. Client: `opcua.ReverseConnect(listenAddr, …)`, `opcua.ReverseConnectListener(l, …)` (one listener serves many servers), `opcua.ReverseServerURI`; the announced ServerUri and EndpointUrl are validated and, with security, the ServerUri must match the server certificate. Works with `AutoReconnect` and the discovery helpers. Server: `server.WithReverseConnect(clientURL, …)`, `Server.AddReverseConnect`, `Server.ReverseConnects` and a `ReverseConnect` handle; one idle connection is kept available, with retry back-off.
- `uacp`: `ReverseDialer`, `Conn.AcceptHello`, `ListenReverse` / `NewReverseListener` / `ReverseListener`, `Dialer.AcceptReverse`; sentinel `errors.ErrReverseHelloRejected`.

### Added — discovery

- **Local Discovery Server:** `server.WithLocalDiscoveryServer` accepts RegisterServer / RegisterServer2 (validation, expiry after 60 min by default, semaphore files, registration only over a secured channel and only for the registrant certificate's URI unless opted out) and returns registered servers from FindServers.
- **Registration with a discovery server:** `server.WithDiscoveryRegistration(ldsURL, …)` registers in the background (RegisterServer2 with fallback to RegisterServer), renews, retries with back-off and unregisters on `Close`, without blocking `Start`.
- **Multicast discovery (LDS-ME):** `server.WithMulticastDiscovery` announces the server (and, on an LDS, its registered servers) with a built-in, dependency-free mDNS / DNS-SD implementation and serves FindServersOnNetwork with record ids, paging and capability filter.
- Client: `RegisterServer`, `RegisterServer2`, `FindServersWithFilter`, `FindServersOnNetworkWithFilter`, `opcua.DiscoverServers`, `opcua.DiscoveryURL` (well-known LDS port 4840).
- `server.ApplicationURI(uri)` for servers without a certificate; `Server.RegisteredServers()`, `Server.ServersOnNetwork()`; `uasc.SecureChannel.RemoteCertificate()`.

### Added — data encoding

- **OPC UA JSON (Part 6 §5.4) and XML (Part 6 §5.3) DataEncodings** in `ua`: `EncodeJSON` / `DecodeJSON` / `EncodeXML` / `DecodeXML` for all built-in types, generated structures, enumerations and registered custom structures. JSON forms: 1.05 Compact (default) and Verbose, 1.04 reversible; 1.04 non-reversible encode only. This is a data encoding — the transport stays UA-TCP / UA Binary.
- Options `WithJSONForm`, `WithNamespaceArray`, `WithServerArray`, `WithIndent`, `WithMaxDepth`, `WithMaxArrayLength`, `WithXMLRootName`, `WithoutXMLNamespace`; `RegisterDataTypeInfo` for the DataType / encoding NodeIds of custom structures; `StatusCodeDesc.Symbol`.
- Existing `MarshalJSON` display formats of `Variant`, `DataValue`, `NodeID` and friends are unchanged.

### Added — subscriptions

- **Server honours `DataChangeFilter`** on CreateMonitoredItems and ModifyMonitoredItems: triggers Status, StatusValue (default) and StatusValueTimestamp; absolute deadband on numeric scalars and arrays; percent deadband on variables with an `EURange` property.
- **Server honours the monitored item's `IndexRange`**: only the range is reported and changes outside it do not trigger.
- Client: `opcua.NewDataChangeFilter` and `SubscriptionBuilder.DataChangeFilter`.

### Fixed

Found by the new chaos and parallelism suites for the v1.6.0 features (`chaos/secure`, `chaos/datachange`, `chaos/reverse`, `chaos/discovery`, `chaos/codec`):

- **Security:** sequence numbers of secured channels were never verified — on the RSA policies and `ECC_nistP256` / `ECC_nistP384` a replayed request was executed again and a multi-chunk message with a lost or reordered chunk was accepted. Multi-chunk messages on SignAndEncrypt channels with a block cipher exceeded the peer's 65535-byte buffer by one byte and dropped the connection. Races on channel renewal (server rewrote its policy and peer certificate) and on unsolicited OpenSecureChannel messages (client). `ActivateSession` wrote the protected password into the identity token shared by all sessions.
- **Monitored item ids are stable across reconnects.** The id `Monitor` returns keeps denoting the same item after the subscription is recreated on the server; `Unmonitor`, `ModifyMonitoredItems`, `SetMonitoringMode` and `SetTriggering` translate it to the server's current id. Before, an id obtained before a reconnect could address a different item afterwards. The id returned by `Monitor` can therefore differ from the id on the wire.
- **A SecureChannel renewal cannot change the security mode.** The server refuses an OpenSecureChannel renewal that names another mode than the channel was opened with (`BadSecurityModeRejected`); it used to adopt it, so a renewal could downgrade SignAndEncrypt to Sign.
- **Subscriptions follow a session change.** When the application re-activates or replaces the session after the client's own recovery, subscriptions are recreated in the new session instead of being deleted on the server while the client still lists them; a subscription that stays silent for three keep-alive intervals while other Publish responses arrive is recreated. Before, a client could report `Connected` with a subscription that never delivered again.
- **`TransferSubscriptions` requires the owner.** The server only transfers a subscription to a session of the same user (`BadUserAccessDenied` otherwise); it used to hand any subscription to any session that asked by id.
- Publish requests queued in a session are answered when the session is closed (`BadSessionClosed`) or its subscriptions are transferred away, instead of staying unanswered until the client's request timeout.
- A notification message republished during recovery is no longer delivered a second time.
- `uacp`: an Acknowledge with buffer sizes above those of the Hello made the client slice past its buffer and panic.
- **Session AuthenticationTokens are unguessable.** The server issues an opaque NodeId with 256 bits from the cryptographic random generator; it used to be a 31-bit number from `math/rand`.
- **Client:** a response with too few results panicked `ReadValue`, `WriteValue`, `WriteAttribute`, `Browse`, `Monitor` and `Cancel` (now `BadUnknownResponse`); a subscription whose recreation failed on a healthy connection was never retried; a lost CreateSubscription response left an orphan subscription on the server; the mode set with `SetMonitoringMode` was lost on recreation; `ModifyMonitoredItems` could dereference nil when racing `Unmonitor`; a server's Error message at OpenSecureChannel could surface as `io.EOF` instead of its status code.
- **Server:** a request handled during `Close`, or a refused CreateSession, left a session behind; two samples could be taken within one sampling interval and the sampler timer stayed armed after its last item; data race in `Node.Value()`; an IndexRange write into an Uncertain array was rejected; built-in NodeSet values were shared (and raced) between all servers in a process.
- **Discovery:** `Close` abandoned an in-flight registration that the discovery server then processed after the unregistration; a registration with a lost response was not unregistered; `RegisterRequestTimeout` did not bound an attempt; overlapping registrations withdrew each other's mDNS announcement; `ServersOnNetwork()` was not empty after `Close`.
- **Data encoding:** concurrent first use, `RegisterDataTypeInfo` while coding, half-registered custom types, order-dependent lookup by name, mismatched XML metadata for ExtensionObjects; Variant dimension overflow and unbounded array allocation from a length prefix.

Other fixes:

- `ua`: nil `*Variant`, `*DataValue`, `*DiagnosticInfo` and `*GUID` pointers and body-less ExtensionObjects no longer panic or corrupt the binary stream; DateTime values outside 1678–2262 no longer overflow; `NewVariant` accepts arrays of ByteStrings of different lengths.
- Client: the endpoint re-fetch after `BadCertificateInvalid` uses the client's own connection method (dial or reverse listener).

### Interoperability

- Peers: open62541 v1.5.9 and Eclipse Milo 1.1.8 via opcua-interop **v0.7.0** (OpenSSL-based open62541 build with ECC endpoints, reverse connect, LDS / mDNS, DataChangeFilter flags and a `codec` command on both adapters).
- See [`interop/COVERAGE.md`](interop/COVERAGE.md) for the per-direction evidence of every feature above; Milo 1.1.8 has no ECC, no reverse connect and no discovery server, so those rows are open62541-only.

### Known limitations

- ECC: `Sign` mode follows open62541's key derivation, which differs from the Part 6 1.05.07 Sign-only rule implemented by the OPC Foundation .NET stack; use `SignAndEncrypt` when in doubt. Where open62541 and the specification text differ for the AEAD policies, go-opcua follows open62541 (see `docs/security.md`). Not implemented: `ECC_curve448`, Brainpool.
- mDNS: no probing / conflict resolution; real multicast is verified on Linux only.
- open62541 v1.5.9 cannot XML-encode structures, enumerations, DataValue or matrices and cannot JSON-decode a structure encoded in place in an ExtensionObject; go-opcua reads and writes the Part 6 forms.
- When registering with a discovery server its certificate is not validated unless `RegisterCertificateValidator` is set.
- An item re-enabled from `Disabled` does not report immediately; `ModifySubscription` does not re-revise items that use the default sampling interval.
- A forged mDNS announcement can stay cached for up to 24 h.
- Triggering links set with `SetTriggering` are not restored when a subscription is recreated after a reconnect.

---

## v1.5.0

**Date:** 2026-10-11
**Previous release:** v1.4.0

### Summary

Hardening release. Peer interoperability moves to open62541 v1.5.9 / Eclipse Milo 1.1.8 (opcua-interop v0.6.0) with 32 more verified ledger rows; a chaos / parallelism suite and a much larger Go↔Go conformance suite found and fixed defects in SecureChannel renewal, session handling, the publish loop and reconnect; the OPC UA schema is refreshed to UA-1.05.07; merged coverage is 91% with a 90% gate.

Several fixes change behaviour that existing deployments may have relied on — read **Behaviour changes** before upgrading.

### Behaviour changes

- **Sessions are enforced.** Services other than discovery and session management require an activated session; requests without one (or with a closed session's token) get `BadSessionIdInvalid` / `BadSessionNotActivated` instead of being served.
- **Sessions time out.** The server drops a session that is idle longer than its revised timeout, with its subscriptions.
- **Enabled security is enforced.** `CreateSession` over a policy/mode the server did not enable is rejected (`BadSecurityPolicyRejected` / `BadSecurityModeRejected`).
- **SecurityToken lifetime is revised and enforced.** The server grants at most its configured lifetime (and that value when the client asks for `0`), retires superseded tokens after lifetime + 25%, and closes a channel whose token was never renewed. Clients retire superseded tokens on the same schedule, measured on the local clock.
- **Stalled clients are disconnected.** A client that does not read a response within `WithResponseWriteTimeout` (default 15s) loses its channel.
- **Subscription ids** are monotonic from a random base and never reused; they no longer start at 1.
- **`Client.Close` waits** for the client's monitor goroutine (bounded by the context); the dial timeout now also covers the HEL/ACK handshake.
- **Attribute types:** `EventNotifier` is served as Byte (was Int16); the `DataType` of helper-created variables is a NodeId derived from the value (was `ExpandedNodeId i=267`); `NewFolderNode` no longer adds a reference back to the namespace Objects folder (the hierarchy was cyclic).
- An untrusted client certificate is answered with a transport `ERR` (`BadCertificateUntrusted`) instead of an undecodable ServiceFault.

### Added

- **Server options** `WithResponseWriteTimeout(d)` (default 15s) and `WithMaxPendingResponses(n)` (default 256).
- **`uasc.SecureChannel.Disconnected()`** and **`uasc.SecureChannel.ReleaseTokens()`**.
- **Server sends `StatusChangeNotification(BadTimeout)`** when a subscription expires; AutoReconnect clients recreate expired or deleted subscriptions (and on `BadNoSubscription`) through the existing recovery handler.
- **Panic containment in the server:** a panic in a handler or application callback fails that request with `BadInternalError`; a panic while decoding drops only that channel. Both are logged at Error with the stack.
- **AddNodes applies `VariableAttributes`** (value, data type, access levels, display name, description); an unset `SpecifiedAttributes` mask is read as "all", as open62541 clients send it.
- **Status codes** `StatusUncertainOverRange`, `StatusUncertainUnderRange`; new structures (`NumberRange`, alias-name types) and 123 NodeIds from the UA-1.05.07 schema.
- **`chaos/` package** and `make chaos`: seeded chaos monkey over a fault-injecting proxy (`internal/testutil.ChaosProxy`), parallelism tests and hostile raw-frame tests. Knobs: `CHAOS_SEED`, `CHAOS_DURATION`, `CHAOS_LOG`.
- **Conformance suite** grown from ~85 to ~200 Go↔Go tests (security matrix, identities, session and channel lifecycle, raw Publish protocol, monitored items, events, history, view, attributes, node management, query); the API matrix now also covers `Node`, `Subscription`, the builder, `Session`, `monitor` and every client/server option.
- **`.github/workflows/schema-check.yml`**: weekly check that opens a tracking issue when the upstream OPC Foundation schema changes.

### Fixed — server

- **SecureChannel renewal** reused the TokenId and swapped keys on the live instance: every peer session (open62541, Milo) failed with `could not verify signature` at its first renewal. Renewal now issues a new TokenId on a fresh instance and keeps the old token valid until it expires.
- A renewal request carrying a session `AuthenticationToken` (as open62541 sends) was rejected with `BadSecureChannelTokenUnknown`.
- Username passwords on secured endpoints were never decrypted; X509 user-token signatures were checked against the wrong nonce.
- One client that stopped reading stalled every client (responses are now written by a per-channel writer).
- A truncated 8–11 byte frame panicked `readChunk`; a silent TCP connection blocked the accept loop; a peer reset during the handshake stopped the server accepting connections.
- Lock-order deadlock between the subscription and monitored-item services; recursive read lock in Browse; data races on subscription parameters, `Node.refs` and stored `DataValue`s.
- Publish responses were sent on the channel a subscription was created on rather than the requesting one; a transferred subscription kept serving the old session; Publish without a subscription hung; a full publish queue dropped requests silently; idle subscriptions effectively never expired.
- RBAC could not be enabled through the public API; reading `RolePermissions` failed the whole Read; user-defined event types were rejected in `OfType`; MapNamespace variables could not be monitored.
- NodeSet2 import stored references declared on both ends twice and kept the `"1:"` prefix in browse names; reverse raw history reads returned the oldest values; `SoftwareVersion` was ignored in ServerStatus.
- Building the address space was quadratic in the number of references; `server.New` is several times faster.

### Fixed — client

- Reconnect closed the session it had just restored, leaving the client `Connected` with dead subscriptions; the restore path never resumed publishing; a second drop during recovery left the client stuck on a dead channel; a failed recreate dropped the subscription for good.
- A consumer that stopped reading after `Cancel` blocked the publish loop for all subscriptions; `Subscribe` / `Cancel` could block for a keep-alive period.
- The HEL/ACK handshake ignored the context and had no timeout; `Close` could race the monitor and leak a server session; a failed `Connect` left the state at `Connecting`.
- The client adopted the policy URI and certificate from every OpenSecureChannel response; token renewal rounded the lifetime to whole seconds (a tight renew loop below 1.34s).
- `Monitor` remembered items the server had rejected, which aborted subscription recreation after a reconnect.
- Encoding a nil `*LocalizedText` panicked.

### Interoperability

- Peers: **open62541 v1.5.9**, **Eclipse Milo 1.1.8** via [opcua-interop v0.6.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.6.0) (digest-pinned in `interop/harness_test.go` and `.github/workflows/interop.yml`).
- Ledger: **231 verified** rows (was 199). Newly verified: SecureChannel renewal under a live subscription (all four directions), HistoryRead continuation C→O / C→M, RegisterNodes (all four), AddNodes / DeleteNodes (C→O, O→S, M→S), ModifySubscription and ModifyMonitoredItems (C→O, C→M), SetPublishingMode and SetMonitoringMode (all four), EventFilter WhereClause comparison operators and event queue overflow (C→O, C→M).
- Recorded peer limits: the Milo reference server has no NodeManagement service set; Milo's SDK does not pass `ReleaseContinuationPoints` to its history backend.

### Changed

- **Schema** refreshed to UA-1.05.07 (2026-07-30 hotfix); `schema/update-schema.sh` now fetches the upstream `latest` branch and writes `Opc.Ua.NodeSet2.xml` to `internal/schema/`, where it is embedded.
- **Coverage gate** raised from 80% to 90% (`make coverage`, `codecov.yml`); merged coverage is 91%.

### Known limitations

- Request handling is still serial: a slow or blocking handler (for example a user method callback) delays all clients. Only the write side is decoupled.
- Reference types and browse names created through the node helpers are always in namespace 0.
- Any `BadSessionIdInvalid` / `BadSubscriptionIdInvalid` / `BadNoSubscription` service fault makes the client start recovery, including faults provoked by an application request.
- DataChangeFilter (deadband, trigger) and the sampling interval are ignored by the server; every write notifies.
- Raw history delete removes the sample at the end time (Part 11 specifies an exclusive end).
- `ServerStatus` child nodes `BuildInfo`, `ShutdownReason` and `SecondsTillShutdown` have the wrong value types; `MapNamespace` reads are not synchronised with writes.

---

## v1.4.0

**Date:** 2026-07-30
**Previous release:** v1.3.1

### Summary

Minor release: make logging silent by default (no longer delegates to `slog.Default()`), document the dual error model and lifecycle/observability contracts, and ship subscription/session correctness fixes that were staged ahead of the release.

### Added

- **ERRORS.md** — Go sentinel errors vs wire `ua.StatusCode`.
- **OBSERVABILITY.md** — silent slog default and metrics callback semantics.
- Client guide / API sections for lifecycle and concurrency.
- **Makefile `vuln`** — `govulncheck ./...`, included in `make check`.
- Unit tests for `discardHandler` (`Handle` / `WithAttrs` / `WithGroup`) on client and server, plus `WithSlogLogger(nil)`.
- **`uasc.NewCryptoChannel`** — construct a crypto-only `SecureChannel` for session/user-token helper tests (not for Open/SendRequest).
- **`export_test.go`** — testing helpers for subscription recreate paths (`TestingRecreateSubscription`, `TestingRecreateDelete`, `TestingRecreateCreate`).
- Deeper coverage for subscription notify/publish/recreate, server session service, history continuation, attribute service, and secure-channel crypto helpers.

### Changed

- **Default logger** — client (`newConfig`) and server (`New` / `newServerNoNS`) use a discard `slog.Handler` (`Enabled` always false). `WithLogger(nil)`, `SetLogger(nil)`, and `WithSlogLogger(nil)` restore that silent default.
- **API.md** / **README** — document silent logging; link ERRORS and OBSERVABILITY guides.
- **README** — note Go 1.25 floor tracks `go.mod` / CI and codegen tooling.
- **golang.org/x/sys** — bump indirect `v0.42.0` → `v0.44.0` (fixes [GO-2026-5024](https://pkg.go.dev/vuln/GO-2026-5024); Windows-only, not called by this module).

### Fixed

- **Server session timeout clamps** — `sessionTimeoutMin` / `Max` / `Default` are now proper `time.Duration` values (`100ms` / `30m` / `60s`). Previously they were bare integers compared against `time.Duration`, so the floor was effectively ~100ns rather than 100ms.
- **Subscription recreate** — after a successful standalone `recreateSubscription`, call `resumeSubscriptions` so the publish loop is not left permanently paused when the last subscription was forgotten during recreate.

### Compatibility

Behavioural change: applications that relied on the previous default of writing through `slog.Default()` must pass an explicit logger via `WithLogger` / `SetLogger`. Protocol behaviour is otherwise unchanged aside from the session-timeout clamp and subscription-recreate resume fixes above.

---

## v1.3.1

**Date:** 2026-07-25
**Previous release:** v1.3.0

### Summary

Patch release raising the **core-library coverage gate to 80%** and aligning Codecov with the local `make coverage` metric. No public API or protocol behaviour changes.

Highlights:
- **`make coverage` threshold 75% → 80%** — measured with `-coverpkg` over `COVER_PKGS` (unit + conformance)
- **Codecov aligned** — CI passes the same `COVER_PKGS` list as `coverpkg` to [`go-ci.yml@v2`](https://github.com/otfabric/.github/blob/v2/.github/workflows/go-ci.yml) ([otfabric/.github v2.0.2](https://github.com/otfabric/.github/releases/tag/v2.0.2))
- **Unit-test depth** for event WhereClause evaluation, `EmitBaseEvent`, HistoryRead/Update dispatch, historian delete/modified/aggregates, client certificate trust-list option, and package-level discovery helpers
- **`codecov.yml`** — project target 80%; ignore `examples/`, `cmd/`, `tests/`, `interop/`, `internal/testutil/`

### Testing and CI

- `server/event_monitor_test.go` — `evalEventFilter` operators (`OfType`, comparisons, `And`/`Or`/`Not`), cyclic/null passthrough, `EmitBaseEvent` delivery/filtering/disabled mode
- `server/attribute_service_test.go` — HistoryRead (raw / modified / at-time / processed / release CP) and HistoryUpdate (update / delete raw / delete at-time) with `SetHistorian`
- `server/historian_ext_test.go` — `DeleteRawModified`, `ReadModified`, Min/Max/Count aggregates
- `server/server_config_options_test.go` — `WithClientCertificateTrustList`
- `discovery_helpers_test.go` — package-level `FindServers` / `GetEndpoints` / `FindServersOnNetwork`
- `server/alarms_scaffold_test.go` — `AlarmsConditionsSupported` probe
- `.github/workflows/ci.yml` — `coverpkg` matches Makefile `COVER_PKGS`
- `codecov.yml` — status target and ignore paths

### Compatibility

No intentional breaking changes. Library behaviour is unchanged; only tests, coverage gates, and CI/Codecov configuration.

---

## v1.3.0

**Date:** 2026-07-25
**Previous release:** v1.2.0

### Summary

Minor release focused on **Part 4 correctness** for Read/Write/Browse, **subscription and monitored-item semantics**, **event subscriptions**, **subscription recovery**, and **historical access** — with matching public APIs and a large expansion of open62541 / Milo interop coverage ([opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0)). Also absorbs race-detector test timeout fixes that were prepared as an unreleased v1.2.1 patch.

Highlights:
- **IndexRange** on array and matrix Values, with Part 4 status codes and helpers in `ua`
- **Monitored-item queues** that honor `QueueSize`, `DiscardOldest`, and the Overflow InfoBit
- **Subscription lifecycle** — revise clamps, monitoring/publishing modes, `MoreNotifications`, Publish ACK, delete and lifetime expiry
- **Events** — `EventFilter` (SelectClauses / OfType / comparison WhereClauses), `EmitBaseEvent` with custom `Fields`
- **Republish / TransferSubscriptions** on server and client (`Client.Republish`, `Client.TransferSubscriptions`) plus `WithSubscriptionRecoveryHandler`
- **HistoryRead / HistoryUpdate** via pluggable `HistoryProvider`; default `*Historian` also covers update/delete/at-time/modified/processed aggregates
- **Interop evidence ledger** — **199** verified / **316** total rows; **376** interop test functions against digest-pinned adapter images
- **Public API freeze** for the v1.3.0 surface (see [`docs/api-freeze-review.md`](docs/api-freeze-review.md)); Query / NodeManagement / A&C stay out of scope
- **Server test suite under `-race`** no longer times out in CI (nodeset import cache + Query subtype recursion guard)

No intentional breaking changes for correct callers. Servers that previously ignored queue or monitoring-mode parameters now follow Part 4 — notification batches may differ.

### Read, Write, and Browse

- **IndexRange / NumericRange** — 1D (`"i"`, `"i:j"`) and multi-dimensional (`"a:b,c:d"`) Value Read/Write; ByteString IndexRange slices bytes. Scalar + IndexRange → `BadIndexRangeInvalid`; empty/out-of-range → `BadIndexRangeNoData`; write size mismatch → `BadIndexRangeDataMismatch`.
- **TimestampsToReturn** — Read and DataChange notifications honor Source / Server / Both / Neither; invalid enum → `BadTimestampsToReturnInvalid`.
- **Write EncodingMask** — value-only Writes succeed; status and/or timestamp bits → `BadWriteNotSupported`.
- **Browse ResultMask** — omitted fields are cleared on `ReferenceDescription`s (`NodeID` always kept).
- **BrowseNext** — early `ReleaseContinuationPoints` invalidates the token (`BadContinuationPointInvalid`).
- **Client certificate trust** — `WithClientCertificateTrustList` is enforced at `OpenSecureChannel` (CreateSession retained as defense-in-depth).

### Subscriptions and monitored items

- **QueueSize** revised to `max(1, requested)` (cap 100), returned as `RevisedQueueSize`.
- **DiscardOldest** — `true` keeps the newest `QueueSize` samples; `false` keeps the oldest `QueueSize-1` plus the newest (e.g. writes `1..5` / QS=3 → `[1,2,5]`).
- **Overflow** — InfoBit `0x480` when `QueueSize > 1` and the queue overflows; queues are per-item.
- **SetMonitoringMode** — Disabled (no enqueue) / Sampling (enqueue only) / Reporting (Publish).
- **SetPublishingMode** — disable holds queues; re-enable delivers the queued window.
- **Create/ModifySubscription revise** — publishing interval clamped; `RevisedLifetimeCount >= 3 × RevisedMaxKeepAliveCount`.
- **MoreNotifications** — honors `MaxNotificationsPerPublish` with partial drain.
- **Publish ACK** — Results + AvailableSequenceNumbers; keepalives do not fabricate DataChange.
- **Delete / lifetime expiry** — second delete → `BadSubscriptionIdInvalid` / `BadMonitoredItemIdInvalid`; idle lifetime removes the subscription.
- **monitor package** — zero-value `Request.MonitoringMode` means Reporting (use `SetMonitoringMode` for Disabled/Sampling).

### Events

- Event monitored items accept `EventFilter` SelectClauses and WhereClause operators (`OfType`, comparisons, `And`/`Or`/`Not`); invalid filters are rejected.
- `EmitBaseEvent` delivers a `BaseEventType`-shaped event (optional custom `Fields`) and applies each item’s filter.
- `EmitEvent` remains for raw `EventFieldList` delivery.
- `ModifyMonitoredItems` can update a live EventFilter.
- Event queues are bounded (max 50). Alarms/Conditions, historical events, and shelving are not included.

### Subscription recovery

- **Server Republish / TransferSubscriptions** — returns available sequences; missing → `BadMessageNotAvailable`; transfer reassigns session/channel under lock.
- **Client helpers** — `Client.Republish` (protocol response only; does not mutate notify channels) and `Client.TransferSubscriptions`.
- **`WithSubscriptionRecoveryHandler`** — observes Transfer → Republish → Recreate outcomes during `AutoReconnect`.
- ACK removes sequences from the retransmission set.
- `SendInitialValues` is accepted but currently a no-op. Durable subscriptions are not included.

### Historical Access

- Pluggable `HistoryProvider`; default in-memory `*Historian` (per-node ring buffer, default 1000 samples, process-lifetime only).
- Raw `ReadRawModifiedDetails` with session-bound continuation points (30s TTL, max 100 active).
- Optional interfaces on the same provider (implemented by `*Historian`): UpdateData, DeleteRawModified (`isDeleteModified=false`), DeleteAtTime, ReadAtTime, ReadModified, ReadProcessed (Average/Minimum/Maximum/Count).
- `returnBounds` is accepted but bounding/interpolation is not implemented for raw reads. Historical events are not included. HistoryRead stays unsupported until `SetHistorian` is configured.

### New and changed public APIs

#### `ua` — NumericRange and timestamp helpers

```go
type NumericRange struct {
    Start int // inclusive
    End   int // inclusive
}

func ParseNumericRange(s string) (NumericRange, error)
func ParseNumericRanges(s string) ([]NumericRange, error)
func SliceVariantRead(v *Variant, rangeStr string) (*Variant, StatusCode)
func MergeVariantWrite(current *Variant, rangeStr string, newVal *Variant) (*Variant, StatusCode)
func ApplyTimestampsToReturn(dv *DataValue, ts TimestampsToReturn) StatusCode
```

Used by the server for Value IndexRange and timestamp filtering; safe to call directly.

#### `opcua` — client recovery helpers

```go
func (c *Client) Republish(ctx context.Context, subscriptionID, sequenceNumber uint32) (*ua.RepublishResponse, error)
func (c *Client) TransferSubscriptions(ctx context.Context, subscriptionIDs []uint32, sendInitialValues bool) (*ua.TransferSubscriptionsResponse, error)
func WithSubscriptionRecoveryHandler(f func(SubscriptionRecoveryEvent)) Option
```

#### `server` — BaseEvent emission

```go
type BaseEvent struct {
    EventID    []byte
    EventType  *ua.NodeID
    SourceNode *ua.NodeID
    SourceName string
    Time       interface{} // time.Time
    Message    *ua.LocalizedText
    Severity   uint16
    Fields     map[string]*ua.Variant // custom SelectClause fields
}

func (s *Server) EmitBaseEvent(nodeID *ua.NodeID, event *BaseEvent) error
```

#### `server` — HistoryProvider / Historian

```go
type HistoryProvider interface {
    ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
    ReleaseContinuation(continuationPoint []byte)
}

// Optional capabilities (type-assert; *Historian implements all):
// HistoryDataUpdater, RawHistoryDeleter, AtTimeHistoryDeleter,
// AtTimeHistoryReader, ModifiedHistoryReader, ProcessedHistoryReader

func NewHistorian() *Historian
func (h *Historian) EnableNode(nodeID *ua.NodeID, maxSamples int)
func (h *Historian) RecordValue(nodeID *ua.NodeID, dv *ua.DataValue)
func (h *Historian) IsEnabled(nodeID *ua.NodeID) bool
func (s *Server) SetHistorian(h HistoryProvider)
```

### Interoperability

Verified four-direction against open62541 and Milo for IndexRange, timestamps, Browse ResultMask / BrowseNext release, queue windows, subscription timestamps, and subscription lifecycle (revise / publishing-mode / monitoring-mode / delete). Write EncodingMask is verified in three directions; Go→Milo is `unsupported` (Milo soft-accepts). Peer capability rows on [opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0) include:

- `discovery.find-servers` / `translate.browse-path` — all applicable directions
- `event.subscription` / decode / select / `of-type` / `severity-threshold` — all four (as applicable)
- `history.read.raw` — all four; `history.read.continuation` — open62541→Go and Milo→Go
- `subscription.server.republish` / `transfer` — open62541→Go and Milo→Go
- `subscription.client.republish` / `transfer` — Go→open62541 and Go→Milo
- `subscription.recovery.reconnect` — Go→open62541 and Go→Milo (`recreated`)

| Image | Pin |
|-------|-----|
| open62541 | `ghcr.io/otfabric/opcua-interop-open62541@sha256:53c7a184ca9769bab87c6b5335c01322925411894368644913133c0812999283` |
| Milo | `ghcr.io/otfabric/opcua-interop-milo@sha256:c462f45a5e9b9ce8878788b97c77973832b23861e7ae5d0c6642279f798c15cf` |

Digests are fix-forwarded on the same `v0.5.0` tag when opcua-interop requirements change (no RC / `v0.5.1` pins). See [INTEROP.md](INTEROP.md) and [`interop/COVERAGE.md`](interop/COVERAGE.md) for the full matrix. Docs updated in `API.md`, `README.md`, and `docs/*`.

### Bug fixes and test infrastructure

Absorbed from the skipped v1.2.1 patch:

- **`server` tests: nodeset import cached across tests** — `newTestServer()` was calling `New()` (full built-in XML nodeset import, ~0.4 s each under `-race`) for every server-package test case, exceeding the 120 s CI per-package timeout. A `sync.Once` cache (`warmNS0Cache`) imports once per test binary; later servers copy the cached nodes in microseconds. Server package time under `-race`: **>120 s → ~11 s**.
- **`getSubRefs` infinite recursion guard** — `HasSubtype` expansion for `QueryFirst`/`QueryNext` could loop on the cyclic built-in type hierarchy. A `visited` map (`getSubRefsVisited`) prevents re-traversal; individual query tests now run in <50 ms instead of 41+ s.
- **`newServerNoNS()`** (package-private) — lightweight `Server` constructor that skips nodeset import; used by the test helper.

Additional hardening in this release:

- **`DefaultDialer` / UACP ACK cloning** — `ReceiveBufferSize` / `SendBufferSize` / related options no longer mutate the shared `uacp.DefaultClientACK` (previously poisoned later HEL/ACK handshakes with `message too large: 57 > 5 bytes`). `NewConn` / `Listen` / `Accept` also clone ACK templates per connection.
- **`Variant.Decode` array-length guard** — negative lengths other than `-1` (null array) return `BadEncodingLimitsExceeded` instead of panicking in `reflect.MakeSlice` (fuzz regression corpus retained).
- **Ephemeral listen port (`:0`)** — `uacp.ParseEndpoint` accepts port `0`; `Server.Start` rewrites listen/endpoint URLs to the OS-assigned port and exposes `Server.Port()`. Interop Go servers bind `:0` instead of `freePort()` pick-then-release, eliminating `address already in use` flakes under load.
- **Fuzz targets expanded** — `ua` (Variant, NodeID, ExtensionObject, ParseNodeID, NumericRange, EventFilter, ContentFilter, DecodeService, common binary shapes), `uasc` headers, `uacp` Hello/Header.
- **Lifecycle / recovery stress** — concurrent Close+subscribe, cancel-during-publish, event+data-change together, blocking recovery-handler contract, history continuation-point session close under `-race`, sequence-number rollover.
- **Interop ledger tooling** — `go generate ./interop` renders [`interop/COVERAGE.md`](interop/COVERAGE.md) / [`interop/GAPS.md`](interop/GAPS.md) from `capabilities.json` + `coverage.json`.
- **Make targets** — `make verify` runs `go vet`, unit, race, and interop; `make check` includes fmt/lint/verify/coverage.

### Known limitations

- Broad EventFilter WhereClause surface and custom event emission are **deferred**; C→ history continuation is **deferred**
- `write.encoding-mask` Go→Milo is **unsupported** (strict `BadWriteNotSupported` claim)
- No Alarms/Conditions, historical events, durable subscriptions, or full bounding/interpolation for raw HistoryRead `returnBounds`

---

## v1.2.0

**Date:** 2026-07-22
**Previous release:** v1.1.1

### Summary

Minor release focused on **X.509 security hardening**, **server API correctness**, and a large step forward in **test coverage** (50% → 81%).

Highlights:
- **ApplicationURI SAN verification** — the client now binds the server certificate to the `ApplicationURI` advertised in its `ApplicationDescription`, closing an OPC UA PKI identity gap.
- **Strict key-usage enforcement** — server certificates that declare a `KeyUsage` extension must include `DigitalSignature` (and `KeyEncipherment` for SignAndEncrypt); verification is now a hard failure instead of a warning.
- **Server-side X.509 user token validation** — the server validates the `UserTokenSignature` (signature over `serverCertificate || serverNonce`) and calls an application-provided `X509UserValidator` for trust decisions.
- **Critical server nil-pointer fixes** — 14 distinct nil-pointer panic paths in `server/` were found and fixed; the entire subscription/monitored-item service set now handles unauthenticated or malformed requests without crashing.
- **`AddObject` / `AddVariable` API fixed** — both methods were silently broken (nil back-reference on every registered node); they now work correctly and are covered by tests.
- **New documentation** — `API.md` (full public API reference with table of contents) and `INTEROP.md` (compatibility matrix against open62541 and Eclipse Milo).
- **Coverage** reaches 81%, well above the 75% threshold enforced by `make coverage`.

No breaking changes for correct existing callers. Minor version bump.

### Security hardening

#### Client — ApplicationURI SAN verification (OPC UA Part 6 §6.2.2)

`SecurityFromEndpoint` now stores the server's `ApplicationURI` from the endpoint `ApplicationDescription`. `validateServerCertificate` compares the certificate's URI SANs against this stored value. Trusting the CA alone is insufficient: the URI SAN is the OPC UA identity binding that ties a certificate to a specific application instance.

```go
// Automatic when using SecurityFromEndpoint — no API change required.
// InsecureSkipVerify() bypasses this check as before.
```

#### Client — Strict key-usage validation (OPC UA Part 6 §6.2.4)

Certificates that declare a `KeyUsage` extension are now required to include `DigitalSignature` (and additionally `KeyUsageKeyEncipherment` for `SignAndEncrypt` mode). Previously a missing bit produced a warning; it is now a rejected connection. Certificates that do not declare any `KeyUsage` extension are still accepted for interoperability with legacy deployments.

#### Server — X.509 user token validation

The server now fully validates `X509IdentityToken` presented in `ActivateSession`:
1. The token certificate must be parseable.
2. The `UserTokenSignature` (signature over `serverCertificate ‖ serverNonce`) is verified with the token certificate's public key — this prevents certificate-replay attacks.
3. An application-supplied `X509UserValidator` hook is called for trust-store and policy decisions.

```go
v := server.X509UserValidator(func(certDER []byte) error {
    // parse certDER, check trust store, enforce your policy
    return nil // or ua.StatusBadIdentityTokenRejected
})
srv, _ := server.New(
    server.WithX509UserValidator(v),
    // ...
)
```

### New server API

#### `ListenOn(addr string) Option`

Binds the server to a specific host/port without going through `EndPoint`:

```go
srv, _ := server.New(server.ListenOn("0.0.0.0:4840"))
```

#### `UsernameValidator` and `WithUsernameValidator`

Previously an internal type; now a first-class exported type and option:

```go
v := server.UsernameValidator(func(user, pass string) error {
    if user != "admin" || pass != secret {
        return ua.StatusBadUserAccessDenied
    }
    return nil
})
srv, _ := server.New(server.WithUsernameValidator(v))
```

#### `X509UserValidator` and `WithX509UserValidator`

New type and option for server-side X.509 user token trust decisions (see Security hardening above).

#### `AllowUsernameOnNone() Option`

Permits username/password authentication on `SecurityModeNone` endpoints (opt-in; disabled by default for safety).

### Bug fixes

#### Server — `AddObject` / `AddVariable` always panicked

Every node registered via `NodeNameSpace.AddNode` had its `ns` back-reference left `nil`. Any subsequent call to `Node.AddObject` or `Node.AddVariable` on that node immediately panicked. Both methods now work correctly:
- `AddNode` sets `n.ns = as`.
- `AddVariable` registers the new child node in the namespace (previously it returned the cloned child without inserting it).

#### Server — `AddNamespace` did not inject server reference

`NewNameSpace(name)` creates a `NodeNameSpace` with `srv = nil`. `AddNamespace` now sets `nns.srv = s` on any `*NodeNameSpace` instance that arrives without a server reference, so `Browse`, `ChangeNotification`, and `SetAttribute` work correctly on namespaces registered after construction.

#### Server — `Browse` nil type definition

`NodeNameSpace.Browse` called `td.DataType()` on the result of `as.srv.Node(...)` without a nil check. Any reference pointing to a node that does not exist in the server's address space panicked. The nil case is now handled gracefully.

#### Server — `node.DataType()` nil `ReferenceTypeID`

The method logged a warning about a nil `ReferenceTypeID` but then immediately called `.IntID()` on it in the next statement. The warning is now followed by a `continue`.

#### Server — `nodeset2_import.go` — nil node before `AddRef` (7 sites)

All six node-type sections of `refsImportNodeSet` called `node.AddRef(...)` after a `Warn`-but-no-`continue` nil check, or with no nil check at all. All seven call sites now skip the reference loop when the node cannot be resolved.

#### Server — subscription / monitored-item service nil panics (7 critical paths)

All service handlers that compare session tokens against a nil `Session()` result now guard with `sess == nil`:

| Method | Symptom |
|---|---|
| `SetMonitoringMode` | `!ok` check came *after* the nil dereference |
| `DeleteMonitoredItems` | Missing `continue` after `!ok`; nil `item` used on fallthrough |
| `CreateMonitoredItems` | `sess` nil, used immediately |
| `ModifyMonitoredItems` | `sess` nil, used immediately |
| `SetTriggering` | `sess` nil, used immediately |
| `DeleteSubscriptions` | `session` nil, used immediately |
| `CloseSession` | `SubscriptionService` nil before `Start()` |

#### Server — `Subscription.run()` goroutine nil session / channel panic

`CreateSubscription` sets `sub.Session = srv.Session(...)` which returns `nil` for an invalid token. The background `run()` goroutine then panicked on `s.Session.PublishRequests`. Both `Session` and `Channel` are now checked at the start of `run()` with an immediate clean shutdown. `keepalive()` also guards against a nil `Channel`.

#### Server — `ChangeNotification` before `Start()`

`MonitoredItemService` is `nil` until `initHandlers()` is called inside `Start()`. Any call to `ChangeNotification` (or `SetAttribute`, which calls it) during pre-`Start()` namespace population panicked. The method now returns early when `MonitoredItemService == nil`.

#### `uasc.SecureChannel` — new `SecurityPolicyURI()` accessor

The field was private and inaccessible to callers that need to inspect the negotiated policy URI without access to the internal `Config`. A public accessor is now exported.

### Documentation

- **`API.md`** — comprehensive public API reference for the `opcua`, `server`, `ua`, `uasc`, `uacp`, `uapolicy`, `monitor`, and `errors` packages, with a full table of contents.
- **`INTEROP.md`** — compatibility matrix showing verified behavior against open62541 and Eclipse Milo across all security policies, authentication methods, and service operations.

### Testing

Test coverage increased from ~50% to **81%** (threshold enforced at 75% via `make coverage`).

New test files and significant additions include:
- `ua/enums_all_values_test.go`, `ua/enums_string_methods_test.go` — 100% branch coverage for all generated enum `FromString` / `String` methods.
- `ua/extobjs_header_test.go` — `Header` / `SetHeader` for all generated request/response types.
- `server/server_config_options_test.go` — all server `Option` constructors.
- `server/channel_broker_test.go`, `server/query_service_test.go` — previously 0% covered.
- `server/subscription_service_test.go`, `server/monitored_item_service_test.go` — regression tests for all nil-panic fixes.
- `server/namespace_node_test.go` — `AddObject`, `AddVariable`, `AddNamespace` back-reference, `Browse` nil td, `DataType()` nil ref.
- `uasc/secure_channel_test.go` — accessors, `conditionLocker`, `mergeChunks`, `notifyMonitor`, `isReconnectTrigger`, `getActiveChannelInstance`.
- `uacp/conn_test.go` — `minNonZero`, `defaultNetDialer`, live connection accessors.
- `config_test.go` — `setCertificate` URI extraction, `loadPrivateKey` PEM/DER/PKCS#8 branches.
- `conformance/` — cross-package coverage of `uasc` and `opcua` root via in-process client/server tests.

### Compatibility

All additions are backward-compatible. The stricter certificate validation (ApplicationURI SAN, key usage) is a security fix; callers with correctly configured certificates are unaffected. `InsecureSkipVerify()` bypasses both new checks. Minor version bump.

---

## v1.1.1

**Date:** 2026-07-09
**Previous release:** v1.1.0

### Summary

Patch release focused on **interop hardening** with strict OPC UA clients and servers (certificate chains, encrypted-channel handshakes, large responses), plus **monitoring ergonomics** and **transport-layer improvements** in `uacp`.

Highlights:
- **Certificate chains** (leaf + intermediate) are parsed correctly on connect; thumbprints use the leaf certificate only.
- **Server secure-channel handshake** now includes `ReceiverCertificateThumbprint` on OpenSecureChannel responses.
- **Large server responses** (e.g. Browse of a big folder) are split across multiple chunks instead of dropping the connection.
- **`monitor.ItemError`** — batch monitored-item creation succeeds for valid nodes and reports per-item failures individually.
- **`uacp.ParseEndpoint`** and default dial timeouts for direct `uacp` package users; DNS resolution delegated to `net.Dialer`.

No breaking API changes. Patch version bump.

### Bug fixes

#### Certificate chains on connect

Servers that present their application instance certificate as a **leaf plus intermediate chain** (e.g. Siemens WinCC Unified Runtime) previously failed validation because `x509.ParseCertificate` rejects trailing DER. The client now uses `x509.ParseCertificates`, validates the leaf against the trust pool with intermediates, and `uapolicy.PublicKey` / `Thumbprint` extract the **leaf** certificate only. Session signature paths use the same chain-aware helpers.

#### Server OpenSecureChannel response missing client thumbprint

The server recorded the client's certificate on incoming OPN requests but never set `cfg.Thumbprint`, so OpenSecureChannel responses carried an empty `ReceiverCertificateThumbprint`. Strict clients (UaExpert, Prosys) reject encrypted channels against the server. The thumbprint is now derived from the client's `SenderCertificate` when the OPN request is processed.

#### Server large responses dropped the connection

`sendResponseWithContext` encoded the entire response as a single chunk. Responses larger than the negotiated buffer (common when browsing folders with many nodes) overflowed the client's receive buffer and closed the connection. Server responses now use `EncodeChunks(maxBodySize)` with per-chunk sign/encrypt/write, mirroring the client request path. `SetMaximumBodySize` is called on the server after symmetric keys are established. The UACP server handshake also negotiates send/receive buffer sizes to the **minimum** of what each side advertises.

#### Monitor batch failed on first bad node

`monitor.Subscription.AddMonitorItems` returned immediately on the first per-item `StatusCode` failure, abandoning valid items in the same batch. It now collects `ItemError` values for rejected items (recoverable via `errors.As`), cleans up speculatively registered handles, and still returns successfully created items. The server's `CreateMonitoredItems` handler rejects unknown nodes individually with `BadNodeIDUnknown` instead of failing the whole request.

### New features / improvements

#### `monitor.ItemError`

```go
type ItemError struct {
    NodeID     *ua.NodeID
    StatusCode ua.StatusCode
}
```

`AddMonitorItems` returns `(items, errors.Join(itemErrors...))` when some items fail. `errors.Is(err, ua.StatusBadNodeIDUnknown)` works via `Unwrap`.

#### `uacp` endpoint parsing and dial timeouts

- `ParseEndpoint(endpoint)` — parse and validate `opc.tcp://` URLs **without DNS**; requires a host and validates explicit ports. Hostname resolution is deferred to `net.Dialer` / `net.Listen` (standard library happy eyeballs).
- `uacp.DefaultDialTimeout` (10s); `Dial` / `DialTCP` use it by default.
- `DialWithTimeout` / `DialTCPWithTimeout` for explicit timeouts (zero = no dial timeout beyond `ctx`).
- `opcua.DefaultDialTimeout` is now an alias of `uacp.DefaultDialTimeout`.

### Testing

- `uapolicy/cert_utils_test.go` — chain thumbprint and public-key extraction.
- `config_test.go` — leaf+intermediate chain validation.
- `conformance/monitor_chunk_test.go` — partial-batch monitor (`ItemError`), multi-chunk browse with small negotiated buffer.
- `uacp/dial_timeout_test.go` — default dial timeout and zero-timeout behavior.
- `monitor/subscription_test.go` — `ItemError` unit test.

### Compatibility

No breaking API changes. All additions are new types/functions or relaxed behavior (partial monitor success, chain parsing). Patch version bump.

---

## v1.1.0

**Date:** 2026-07-09
**Previous release:** v1.0.2

### Summary

Feature and hardening release, and the first release prepared for open-source distribution under the MIT license.

Highlights:
- New **server-side Query service** (QueryFirst/QueryNext) with a full Part 4 `ContentFilter` evaluator.
- A new **client↔server conformance test suite** (conformance, adversarial, concurrency, and property-based tiers) covering the client/server API surface over a real `opc.tcp` loopback.
- **Correctness fixes** in the binary codec, the client's fault handling, and the server's fault routing.
- **Open-source preparation**: SPDX license headers across the codebase and licensing/documentation updates.

No breaking API changes. Minor version bump.

### New features

#### Server-side Query service (QueryFirst / QueryNext)

The server now implements the Query Service Set. Previously `QueryFirst`/`QueryNext` returned `Bad_ServiceUnsupported`.

- `QueryFirst` matches candidate nodes by `TypeDefinition` (with `IncludeSubTypes` via the type tree), applies the `ContentFilter` WhereClause, and builds `QueryDataSet`s by resolving each `QueryDataDescription` (`RelativePath` + attribute read). It honors `MaxDataSetsToReturn` and reports per-NodeType `ParsingResults` and a `FilterResult`.
- `QueryNext` supports pagination via a continuation-point store, releasing continuation points, and returns `Bad_ContinuationPointInvalid` for unknown tokens.
- A specified but unknown `View` returns `Bad_ViewIdUnknown`; a null view scans the whole address space. Empty `NodeTypes` returns `Bad_NothingToDo`.

The Service Support Matrix in the README now lists QueryFirst/QueryNext as supported on both client and server.

#### Full ContentFilter evaluator

New self-contained `ContentFilter` evaluator (`server/content_filter.go`) implementing full Part 4 semantics:

- All 18 `FilterOperator`s: `Equals`, `IsNull`, `GreaterThan`, `LessThan`, `GreaterThanOrEqual`, `LessThanOrEqual`, `Like`, `Not`, `Between`, `InList`, `And`, `Or`, `Cast`, `InView`, `OfType`, `RelatedTo`, `BitwiseAnd`, `BitwiseOr`.
- Three-valued logic (TRUE/FALSE/NULL) for the logical operators.
- Operand resolution for `LiteralOperand`, `ElementOperand` (with forward-only, cycle-checked element references), `AttributeOperand`, and `SimpleAttributeOperand`.
- Implicit numeric/string comparison, the OPC UA `Like` grammar (`%`, `_`, `[]`, `[^]`, `\` escaping) translated to a Go regexp, and a `Cast` conversion for the common built-in scalar types.
- A structural validation pass producing a `ContentFilterResult` with per-element/per-operand status codes.

#### Node enumeration API

New optional `Nodes()` accessors return a snapshot of a namespace's nodes:

```go
func (as *NodeNameSpace) Nodes() []*Node
func (ns *MapNamespace) Nodes() []*Node
```

The Query service uses these to scan candidate nodes; custom namespaces that implement the same signature participate automatically.

#### New and modernized examples

New runnable examples: `readmulti` (auto-chunked batch read), `history-read-simple` (`ReadHistoryAll` iterator), `serverstatus`, `metrics` (`WithMetrics`/`WithRetryPolicy`), `node-summary` (`Node.Summary`), `regread` (register-nodes), and dedicated server examples `server/node_server`, `server/map_server`, `server/NodeSet2_server`, and `server/method_server`. Existing `read`/`write`/`subscribe`/`method`/`translate`/`history-read` examples were reworked to demonstrate both the high-level convenience wrappers and the low-level service calls.

### Bug fixes

#### Binary encoder nil-pointer asymmetry

`ua/encode.go` wrote zero bytes for a nil pointer field, but the decoder always allocates and reads pointer fields. Any message that left a pointer field nil produced a stream that could not be decoded symmetrically. The encoder now writes the zero value for a nil pointer, matching decode (a nil `*NodeID` encodes as the null NodeID `0x00 0x00`). Existing messages that fully populate their pointers are unaffected. Added round-trip idempotence tests covering empty `QueryFirstRequest`/`QueryNextRequest`, `ContentFilter` with each operand type, and nil `*NodeID`.

#### Operation-level ServiceFaults no longer disconnect the client

The client's read dispatcher forwarded every failed message to the connection monitor, which treats any notification as a connection failure. A normal operation-level ServiceFault (a decoded response carrying a non-OK `ServiceResult`, e.g. a bad NodeID or an invalid filter) therefore tore down the whole connection. The dispatcher now forwards only connection/transport-level failures and the faults that actually require the channel, session, or subscriptions to be recreated (`Bad_SecureChannelIdInvalid`, `Bad_SessionIdInvalid`, `Bad_SubscriptionIdInvalid`, `Bad_NoSubscription`, `Bad_CertificateInvalid`). Ordinary faults are returned to the caller with the connection left usable. Auto-reconnect behavior is unchanged.

#### Server no longer tears down the secure channel on a per-request error

When a single request failed to decode/process, the server's channel broker closed the entire secure channel without replying, so the client blocked until its full `RequestTimeout` (and `Client.Close` then blocked too). The broker now returns a `ServiceFault` correlated to the offending `RequestID` and keeps serving the channel; only connection-level failures close it.

#### Node.Description panic

`Node.Description` could panic because the server's node constructors stored the wrong value type (a numeric NodeClass instead of a `LocalizedText`) under the Description attribute. The server constructors now store a `LocalizedText`, and the client-side `Node.Description` performs a checked type assertion and returns an error instead of panicking on unexpected types.

### Testing

#### New conformance test suite (`conformance/` package)

A new in-process client↔server test suite exercises the full client/server API surface over a real `opc.tcp` loopback:

- **Conformance** per service set (attribute, view, method, node management, subscription, events, history, query, misc).
- **Adversarial** tests for malformed/hostile inputs and edge cases.
- **Concurrency** tests (safe under `-race`).
- **Property-based** round-trip/invariance tests using `pgregory.net/rapid` (added as a dependency).
- An **API coverage matrix** (`matrix_test.go`) that reflects over the client/server APIs to guard against untested surface.
- Shared harness and a rich node `Fixture` in `internal/testutil` (scalars of every common type, arrays, access-controlled nodes, a callable method, an event source, and a typed/subtyped `VariableType` hierarchy for Query).

Unit tests were also added for the ContentFilter evaluator (`server/content_filter_test.go`: operator matrix, three-valued logic, `Like` grammar, `Cast`, validation).

### Open-source preparation / licensing

- **SPDX headers**: every first-party Go file now begins with `// SPDX-License-Identifier: MIT`. Code-generator templates (`cmd/*`) and the generation orchestrator (`internal/cmd/gen`) emit the SPDX header, and `stringer` output is post-processed so generated files stay consistent with `go generate ./...`.
- **LICENSE**: added the OT Fabric copyright line; the project remains MIT-licensed.
- **Documentation**: `README.md` badges refreshed (pkg.go.dev reference, Codecov, release), the examples table expanded, and the Query rows updated; `API.md` documents the client Query API and the new `Nodes()` accessors.

### Compatibility

No breaking API changes. All additions are new methods/behavior; the encoder change only affects previously-undecodable output; SPDX headers and licensing updates are non-functional. Minor version bump.

---

## v1.0.2

**Date:** 2026-03-24
**Previous release:** v1.0.1

### Summary

Production-grade hardening release. Makes the library fully slog-native, removes the custom logger abstraction, hardens NodeSet2 XML import against malformed input, adds generator tests and CI drift detection, and finishes the panic audit.

### Breaking changes

#### Logger package removed

The `logger/` package and `logger_alias.go` re-exports have been deleted. The library is now slog-native internally — all logging uses `*slog.Logger` directly.

```go
// Before
import "github.com/otfabric/go-opcua/logger"
opcua.WithLogger(logger.NewSlogLogger(handler))

// After
import "log/slog"
opcua.WithLogger(slog.New(handler))
```

#### `WithLogger` accepts `*slog.Logger`

The client option `WithLogger` now takes `*slog.Logger` directly instead of the former `logger.Logger` interface. The separate `WithSlogLogger` option has been removed (merged into `WithLogger`).

```go
// Before
opcua.WithSlogLogger(myLogger)

// After
opcua.WithLogger(myLogger)
```

#### `SetLogger` accepts `*slog.Logger` (server)

The server option `SetLogger` now takes `*slog.Logger` directly instead of `logger.Logger`.

#### `uacp.Dialer.Logger` and `uasc.Config.Logger` type changed

The exported `Logger` fields on `uacp.Dialer` and `uasc.Config` have changed from `logger.Logger` to `*slog.Logger`.

#### `uacp.Conn.SetLogger` accepts `*slog.Logger`

The `SetLogger` method now takes `*slog.Logger`.

#### `TypeRegistry.New(nil)` returns nil instead of panicking

`TypeRegistry.New` with a nil NodeID now returns nil instead of panicking. This protects runtime paths processing incoming messages with potentially malformed type IDs.

#### Stricter NodeSet2 XML import validation

`ImportNodeSetXML` now returns contextual errors instead of panicking when NodeSet2 XML contains invalid node IDs, reference targets, or reference types. All 29 uses of `ua.MustParseNodeID` on XML-derived data have been replaced with `ua.ParseNodeID` and error propagation.

Error messages include the import phase, node type, and offending value:
```
nodeset import: variable: parse node id "not-valid": ...
nodeset import: reference type "ns=1;i=1": parse reference target "bad-ref": ...
nodeset import: data type "ns=1;i=2": unknown reference type "NonExistent"
```

### New features

#### Slog-native logging

All internal logging now uses `*slog.Logger` with structured key-value fields. No `Debugf`/`Infof`/`Warnf`/`Errorf` format-string logging remains in production code.

The default logger is `slog.Default()`, which means the library respects any global slog configuration set by the application.

#### Generator test coverage

`internal/cmd/gen` now has focused tests covering:
- Enum type discovery (sorted, deduplicated)
- Generated file list validation (no duplicates)
- File cleanup behavior
- Missing file tolerance

#### CI generation drift detection

A new `gen-drift` CI job runs `go generate ./...` and fails if the working tree becomes dirty, ensuring generated files stay in sync with source changes.

A new `check-gen` Makefile target provides the same check locally: `make check-gen`.

#### NodeSet2 import regression tests

New test suite `TestImportNodeSetXML_BadInput` covers 12 malformed XML scenarios including invalid node IDs for each node type, invalid alias references, invalid reference targets, unknown reference types, and malformed XML.

### Improvements

#### All logging converted to structured slog

243+ log call sites across all packages (`client`, `server`, `uacp`, `uasc`) converted from printf-style format strings to structured slog calls with meaningful key-value fields.

#### Deterministic generator targets

`discoverEnumTypes` now deduplicates discovered types using `slices.Compact` after sorting, and returns errors instead of calling `log.Fatalf`.

#### Generator error propagation

All generator functions (`clean`, `generate`, `stringer`, `run`) now return errors instead of calling `log.Fatalf`, making failures actionable and testable.

#### Nil-safe map lookups in NodeSet import

Reference type lookups in NodeSet import now use the comma-ok pattern and return descriptive errors for unknown reference types instead of nil-pointer panics.

### Migration guide

1. **Logger package** — remove all imports of `"github.com/otfabric/go-opcua/logger"`. Use `*slog.Logger` directly.
2. **`WithLogger`** — change argument from `logger.Logger` to `*slog.Logger`. Remove calls to `WithSlogLogger` (use `WithLogger` instead).
3. **`SetLogger` (server)** — change argument from `logger.Logger` to `*slog.Logger`.
4. **`uacp`/`uasc` Logger fields** — update any direct assignments of `Dialer.Logger` or `Config.Logger` to use `*slog.Logger`.
5. **NodeSet import errors** — callers of `ImportNodeSetXML` should handle more granular errors from stricter validation.
6. **CI** — the new `gen-drift` job will fail PRs that modify generator inputs without regenerating. Run `make gen` before committing generated file changes.

---

## v1.0.1

**Date:** 2026-03-24
**Previous release:** v1.0.0

### Summary

Production hardening and maintainability release. Replaces shell-driven code generation with a Go-based driver, tightens package boundaries, unifies configuration patterns, eliminates avoidable panics, internalizes non-public packages, documents service support, and reduces root package sprawl.

### Breaking changes

#### `server.New` returns `(*Server, error)`

`server.New` now returns an error instead of panicking on bootstrap failures. All server option functions also return `error`, matching the client's `Option func(*Config) error` pattern.

```go
// Before
srv := server.New(opts...)

// After
srv, err := server.New(opts...)
```

#### Server options return errors instead of logging warnings

`EnableSecurity` and `EnableAuthMode` now return `fmt.Errorf` for invalid or duplicate configurations instead of silently logging warnings.

#### `schema` package moved to `internal/schema`

The `schema` package (NodeSet2 XML types and embedded spec data) is now internal. Use `server.ImportNodeSetXML(data []byte)` instead of unmarshaling into `schema.UANodeSet` directly.

```go
// Before
import "github.com/otfabric/go-opcua/schema"
var nodes schema.UANodeSet
xml.Unmarshal(data, &nodes)
srv.ImportNodeSet(&nodes)

// After
srv.ImportNodeSetXML(data)
```

#### `stats` package moved to `internal/stats`

The experimental `stats` package is now internal. It was not intended for downstream use.

#### `testutil` package moved to `internal/testutil`

The test helper package is now internal. It was not intended for downstream use.

#### Root package helpers removed

The following functions have been removed from the root `opcua` package and moved to their canonical locations:

| Function | New location |
|----------|-------------|
| `AggregateType` | `id.AggregateType` (returns `(uint32, bool)` instead of `*ua.NodeID`) |
| `ReferenceTypeDisplayName` | `ua.ReferenceTypeDisplayName` |
| `TypeDefinitionDisplayName` | `ua.TypeDefinitionDisplayName` |
| `DataTypeDisplayName` | `ua.DataTypeDisplayName` |
| `StandardNodeID` | `ua.StandardNodeID` |
| `SelectEndpoint` | `ua.SelectEndpoint` |

### New features

#### Go-based code generation driver

`generate.sh` has been replaced by `internal/cmd/gen/main.go`. The new driver:
- Cleans an explicit list of generated files (no shell globs).
- Runs each generator in dependency order.
- Discovers enum types via Go's `go/ast` parser and runs `stringer`.
- Uses `go tool stringer` (version pinned in `go.mod` via the `tool` directive).
- Does not install tools or run `go mod tidy`.

Generation is invoked via `go generate ./...` or `make gen`.

#### Pinned stringer version

`stringer` is now declared as a tool dependency in `go.mod` (`golang.org/x/tools v0.43.0`) and invoked via `go tool stringer` instead of `go install ...@latest`.

#### `server.ImportNodeSetXML`

New public API for importing custom NodeSet2 XML data without depending on schema types:

```go
data, _ := os.ReadFile("my-model.xml")
if err := srv.ImportNodeSetXML(data); err != nil {
    log.Fatal(err)
}
```

#### `WithSlogLogger` option

Both client and server now accept `WithSlogLogger(*slog.Logger)` as a convenience option for configuring structured logging without manually wrapping a handler.

#### Service support matrices

Comprehensive service support matrices added to:
- `docs/server-guide.md` — server-side service status
- `docs/client-guide.md` — client-side method coverage
- `README.md` — combined matrix with accurate unsupported-service markers

### Improvements

#### Package tiering

All packages are now explicitly classified into three tiers in `docs/architecture.md`:
- **Tier 1 (stable public):** `opcua`, `server`, `ua`, `id`, `monitor`, `errors`
- **Tier 2 (advanced public):** `uacp`, `uasc`, `uapolicy`, `logger`, `schema/` (data files), `server/attrs`, `server/refs`
- **Tier 3 (internal):** `internal/schema`, `internal/stats`, `internal/testutil`, `internal/goname`, `internal/cmd/gen`

#### Panic discipline

- Three panics in `server.New` replaced with error returns (XML unmarshal, namespace assertion, node set import).
- Panic in `monitor/subscription.go` goroutine replaced with `sendError`.
- All remaining panics audited and documented as justified (`Must*` helpers, init-time registration, or internal invariants).

#### Unified config semantics

Client and server option patterns now follow the same model: `type Option func(*config) error` with error aggregation. Invalid configurations fail explicitly instead of being silently ignored.

#### Code generation documentation

Generation flow documented in `CONTRIBUTING.md` with a table mapping each generator to its inputs and outputs.

### Migration guide

1. **`server.New`** — add error handling: `srv, err := server.New(opts...)`.
2. **`schema` import** — replace `schema.UANodeSet` + `xml.Unmarshal` + `ImportNodeSet` with `srv.ImportNodeSetXML(data)`.
3. **`stats` import** — remove direct imports of `stats`; the package is now internal.
4. **`testutil` import** — remove direct imports of `testutil`; the package is now internal.
5. **Relocated helpers** — update imports to use `id.AggregateType`, `ua.SelectEndpoint`, `ua.ReferenceTypeDisplayName`, etc. The root package wrappers have been removed.

---

## v1.0.0

**Date:** 2026-03-24
**Previous release:** v0.1.15

### Summary

Makes all generated Go identifiers fully idiomatic by removing spec-derived underscore names from exported constants, fields, and symbols. This is a **breaking change** — all exported identifiers containing underscores have been renamed to CamelCase, and `id.Name()` now returns OPC UA spec names instead of Go identifier spellings.

### Breaking changes

#### Identifier renames

All exported generated identifiers now use idiomatic Go CamelCase without underscores. Approximately 14,600 `id` package constants, plus status code constants and schema struct fields, have been renamed.

Common rename patterns:

| Old name | New name |
|----------|----------|
| `id.ServerType_ServerArray` | `id.ServerTypeServerArray` |
| `id.Server_ServerStatus_CurrentTime` | `id.ServerServerStatusCurrentTime` |
| `id.AggregateFunction_Average` | `id.AggregateFunctionAverage` |
| `id.WellKnownRole_Anonymous` | `id.WellKnownRoleAnonymous` |
| `id.FindServersRequest_Encoding_DefaultBinary` | `id.FindServersRequestEncodingDefaultBinary` |
| `StatusGoodEdited_DependentValueChanged` | `StatusGoodEditedDependentValueChanged` |

#### Go initialism normalization

Standard Go initialisms are now consistently applied across all generators:

| Token | Normalized |
|-------|-----------|
| `Id` | `ID` |
| `Uri` | `URI` |
| `Url` | `URL` |
| `Xml` | `XML` |
| `Json` | `JSON` |
| `Guid` | `GUID` |
| `Tcp` | `TCP` |
| `Tls` | `TLS` |
| `Http` | `HTTP` |
| `Https` | `HTTPS` |
| `Dns` | `DNS` |
| `Uadp` | `UADP` |

#### `id.Name()` returns spec names

`id.Name()` now returns the original OPC UA specification name (with underscores) instead of the Go identifier spelling:

```go
id.Name(2005) == "ServerType_ServerArray"  // was: "ServerTypeServerArray"
```

#### Schema struct field renames

`schema/uaNodeSet.go` struct fields and types updated to use Go initialisms:
- `NodeIdAttr` → `NodeIDAttr`
- `TransactionIdAttr` → `TransactionIDAttr`
- `UriTable` → `URITable`
- `NodeId` → `NodeID`
- `NodeIdAlias` → `NodeIDAlias`

XML tags are unchanged — wire format compatibility is preserved.

### New features

#### Shared naming formatter (`internal/goname`)

All code generators now use a single shared naming formatter (`internal/goname.Format`) that:
- Removes underscores and applies CamelCase conversion.
- Normalizes all standard Go initialisms.
- Validates generated identifiers.

#### Collision detection

The `cmd/id` generator now detects naming collisions (where distinct spec names would normalize to the same Go identifier) and fails with a clear error. No collisions exist in the current OPC UA specification.

### Lint and quality

- **ST1003 exclusion removed** — The `.golangci.yml` exclusion for `ST1003` on generated files and `schema/` has been removed. All generated code now passes staticcheck without exceptions.
- **ST1016** — Fixed inconsistent receiver name `n` → `s` on `StatusCode.Error()`.
- **ST1021** — Fixed `AttributeID` type comment format.

### Migration guide

This release contains no compatibility aliases. Update all references mechanically:

1. Replace `id.Foo_Bar_Baz` with `id.FooBarBaz` (remove all underscores).
2. Replace `StatusFoo_Bar` with `StatusFooBar`.
3. Update any code using `id.Name()` that expected Go-style names — it now returns spec-style names with underscores.
4. Update `schema.NodeIdAttr` → `schema.NodeIDAttr` and similar field references.

---

## v0.1.15

**Date:** 2026-03-24
**Previous release:** v0.1.14

## Summary

Renames the Go module from `github.com/otfabric/opcua` to `github.com/otfabric/go-opcua`, migrates CI and release workflows to shared reusable workflows, upgrades Go and all dependencies, expands the linter configuration, and fixes all lint issues across the codebase.

## Module rename

- **Go module** — `github.com/otfabric/opcua` → `github.com/otfabric/go-opcua`. All import paths across the entire codebase (source, tests, examples, commands, documentation) are updated accordingly.
- **Retract directives removed** — The `retract` block referencing old `otfabric/opcua` tags (v0.7.2, v0.2.4, v0.2.5) has been dropped since it no longer applies to the new module path.

## Go and dependency upgrades

- **Go version** — `go 1.23` → `go 1.25.0`.
- **testify** — v1.10.0 → v1.11.1.
- **golang.org/x/exp** — updated to 2026-03-12 snapshot.
- **golang.org/x/term** — v0.27.0 → v0.41.0.
- **golang.org/x/sys** — v0.28.0 → v0.42.0.

## GitHub workflows

- **CI** (`ci.yml`) — Replaced the inline multi-job workflow (test matrix, coverage, lint, integration) with a single call to the shared reusable workflow `otfabric/.github/.github/workflows/go-ci.yml@v2`. Test matrix now targets Go 1.25 and 1.26. Triggers on pushes and PRs to all branches.
- **Release** (`release.yml`) — Replaced the inline release workflow (version detection, tag creation, release notes extraction, GitHub release creation) with a call to the shared reusable workflow `otfabric/.github/.github/workflows/go-package-release.yml@v2`. Supports a `release-name-prefix` parameter (`go-opcua`).
- **goreleaser** — Removed `.goreleaser.yml` and the `make release` target. Release is now handled entirely by the shared workflow.

## Linting and code quality

- **golangci-lint** (`.golangci.yml`) — Expanded from 2 linters (`govet`, `unparam`) to 8 linters with all checks enabled: `errcheck`, `govet`, `ineffassign`, `staticcheck` (full SA/S/ST/QF), `misspell`, `godot`, `nilerr`, `exhaustive`. Added `gofmt` and `goimports` formatters. No exclusions except ST1003 on generated code (OPC UA spec names use underscores). All issues fixed at the source across code, tests, examples, and cmd/.
- **errcheck** — All unchecked error returns resolved across the entire codebase: `defer` calls wrapped in `defer func() { _ = ... }()`, cleanup `Close()`/`SetDeadline()`/`WriteByte()` calls prefixed with `_ =`, and `xml.Unmarshal`/`ImportNodeSet` in server init now panic on error.
- **godot** — Trailing periods added to all comments (production code, tests, examples, generated template).
- **misspell** — `occured` → `occurred`, `taht` → `that`.
- **ineffassign** — Removed 3 dead assignments to `action` in `client.go` reconnect logic.
- **exhaustive** — Added missing switch cases for `reconnectAction`, `ConnState`, and `crypto.Hash`.
- **goimports** — Fixed import grouping in `cmd/id/main.go` and `uacp/endpoint_test.go`.
- **staticcheck QF** — Applied 44 quickfix suggestions: removed redundant embedded field selectors (`.Header.`, `.PublicKey.`, `.MessageHeader.`, `.SequenceHeader.`, `.TCPConn.`), replaced `strings.Replace(..., -1)` with `strings.ReplaceAll`, converted untagged switches to tagged switches, and lifted loop conditions.
- **staticcheck ST1003** — Renamed 25 underscore-named variables and methods to camelCase across `client_sub.go`, `subscription.go`, `server/`, and examples (e.g. `recreate_delete` → `recreateDelete`, `matching_endpoints` → `matchingEndpoints`).
- **staticcheck ST1016** — Standardized inconsistent receiver names across 10 files (`server/namespace_map.go`, `server/namespace_node.go`, `server/nodeset2_import.go`, `ua/expanded_node_id.go`, `ua/status_gen.go`, `uapolicy/`, `uasc/`).
- **staticcheck ST1020/ST1021** — Fixed 48 exported method comments to start with the method name and 5 exported type comments to start with the type name, following Go doc conventions.
- **staticcheck ST1000** — Added package doc comments to all 11 packages that lacked them (`id`, `logger`, `monitor`, `schema`, `server`, `server/attrs`, `server/refs`, `testutil`, `tests/go`, `tests/python`, `cmd/service/goname`).
- **.gitignore** — Reorganized with categories (Python, binaries, IDE, coverage, certificates). Added `/bin/`, `cover.*`, `coverage.*`, `*.out`. Removed `vendor/`, `build/`, `dist/`, `__debug*`.
- **Makefile** — Removed the `release` target (goreleaser). Added `coverage` to the `check` target.

## Documentation

All references to `otfabric/opcua` updated to `otfabric/go-opcua` across:

- **README.md** — Title, badges, `go get` command, import paths, overview text.
- **API.md** — Module path and `pkg.go.dev` links.
- **CONTRIBUTING.md** — Title and `git clone` URL.
- **docs/architecture.md**, **docs/client-guide.md**, **docs/security.md**, **docs/server-guide.md** — Module path references and import paths in code examples.

## Files changed

196 files changed, +1130 / -1235 lines.

---

## v0.1.14

**Date:** 2026-03-12
**Previous release:** v0.1.13

## Summary

New unified github release flow.

---

## v0.1.13

**Date:** 2026-03-11
**Previous release:** v0.1.12

## Summary

Implements `fmt.Stringer` for `*ua.LocalizedText` and `*ua.QualifiedName` so that `fmt.Sprintf("%v", v)` and logging print readable text instead of struct literals (e.g. `&{3 en-US Siemens AG}`).

## LocalizedText and QualifiedName display

- **`(*ua.LocalizedText).String() string`** — Returns the text; if locale is set, returns `"locale: text"` (e.g. `"en-US: Siemens AG"`). Nil receiver returns `""`.
- **`(*ua.QualifiedName).String() string`** — Returns the name only when namespace is 0, otherwise `"ns:name"` (e.g. `"2:Temperature"`). Nil receiver returns `""`.

CLI and tools that print variant values, display names, or browse names no longer need custom formatting for these types; `%v` and default logging use the new methods.

---

## v0.1.12

**Date:** 2026-03-11
**Previous release:** v0.1.11

## Summary

Adds batch read (`ReadMulti`) and client-side recursive browse (`BrowseWithDepth`) APIs, with tests and documentation updates.

## ReadMulti (batch read)

- **`Client.ReadMulti(ctx, items []ReadItem, opts ...ReadMultiOption) ([]ReadResult, error)`** — Batch read of N node/attribute pairs in one or more OPC UA Read calls. Chunks by `DefaultReadMultiChunkSize` (32) or by `ReadMultiWithChunkSize(n)`. Results match input order; each result has `DataValue` and `StatusCode`. Use for large subtrees or bulk export to reduce round-trips.
- **`ReadItem`** — NodeID, AttributeID, optional IndexRange.
- **`ReadResult`** — DataValue and StatusCode per item.
- Empty or nil `items` returns `(nil, nil)` without sending a request.

## BrowseWithDepth (client-side recursive browse)

- **`Node.BrowseWithDepth(ctx, opts BrowseWithDepthOptions) ([]BrowseWithDepthResult, error)`** — Client-side recursive browse up to `opts.MaxDepth`. Returns a flat slice of references with depth (no iterator). Options: MaxDepth, RefType, Direction, NodeClassMask, IncludeSubtypes. Standard OPC UA Browse is single-level; recursion is implemented via multiple Browse calls (same as Walk/WalkLimit).
- **`BrowseWithDepthOptions`** — MaxDepth (-1 = unlimited), RefType (0 = HierarchicalReferences), Direction, NodeClassMask, IncludeSubtypes.
- **`BrowseWithDepthResult`** — Ref (*ua.ReferenceDescription) and Depth.

## Tests and documentation

- **Tests:** `TestReadMulti`, `TestReadMultiChunking`, `TestReadMultiEmptyItems`, `TestReadMultiMixedAttributes`, `TestNodeBrowseWithDepth`, `TestNodeBrowseWithDepthMaxDepthZero`, `TestNodeBrowseWithDepthInverse`.
- **API.md:** ReadMulti and BrowseWithDepth types and behavior; empty-items note.
- **README.md:** Reading and Browsing rows mention ReadMulti and BrowseWithDepth.
- **docs/client-guide.md:** "Batch read (ReadMulti)" and "Recursive browse (BrowseWithDepth)" sections with examples.

---

## v0.1.11

**Date:** 2026-03-11
**Previous release:** v0.1.10

## Summary

Exposes the remaining standard-node name lookups in the `id` package and adds
a type-definition display helper so browse UIs can show "PropertyType",
"FolderType", and other well-known names instead of raw NodeIDs.

## Type definition display

- **`id.VariableTypeName(id uint32) string`** — Standard name for well-known VariableTypes in namespace 0 (e.g. 68 → "PropertyType", 63 → "BaseDataVariableType"), or "" if unknown.
- **`id.ObjectTypeName(id uint32) string`** — Same for ObjectTypes (e.g. 58 → "BaseObjectType", 61 → "FolderType").
- **`TypeDefinitionDisplayName(typeDefID *ua.NodeID) string`** — Root package: tries VariableTypeName then ObjectTypeName; otherwise returns the NodeID string. Use when displaying type definition columns (e.g. browse) so "PropertyType" is shown instead of "i=68".

## id package: Object, Variable, Method names

All seven name maps used by `id.Name(id)` are now exposed as dedicated helpers:

- **`id.ObjectName(id uint32) string`** — Well-known Object nodes (e.g. 84 → "RootFolder", 85 → "ObjectsFolder", 2253 → "Server").
- **`id.VariableName(id uint32) string`** — Well-known Variable nodes (e.g. 2256 → "Server_ServerStatus", 2258 → "Server_ServerStatus_CurrentTime").
- **`id.MethodName(id uint32) string`** — Well-known Method nodes (e.g. 11492 → "Server_GetMonitoredItems").

Together with existing `DataTypeName`, `ReferenceTypeName`, `VariableTypeName`, and `ObjectTypeName`, callers can resolve standard names by node class when displaying NodeIDs (e.g. in browse or diagnostics).

---

## v0.1.10

**Date:** 2026-03-11
**Previous release:** v0.1.9

## Summary

Adds type and status display helpers, namespace-qualified path resolution,
symbolic node name lookup, TCP-only dial for diagnostics, and documentation
improvements for path semantics and CSV/JSON consistency.

## DataType display names

- **`id.DataTypeName(id uint32) string`** — Returns the standard OPC UA name for well-known DataTypes in namespace 0 (e.g. 10 → "Float", 12 → "String", 294 → "UtcTime"), or "" if unknown.
- **`DataTypeDisplayName(dataTypeID *ua.NodeID) string`** — Convenience in the root package: standard name for known ns=0 DataTypes, otherwise the NodeID string. Use to normalize type rendering (e.g. "Float" instead of "i=10").

## Status code helpers

- **`StatusCode.Symbol() string`** — Short symbolic name only (e.g. "Good", "BadServiceUnsupported"), stripping the "Status" prefix. Use for compact status rendering instead of `Error()`.
- **`StatusCode.Uint32() uint32`** — Raw 32-bit value for consistent CSV/JSON serialization.

## Variant array

- **`Variant.IsArray() bool`** — Returns true if the variant value is an array (one- or multi-dimensional). `ArrayDimensions()` was already present (returns `[]int32`).

## Connection diagnostics

- **`uacp.DialTCP(ctx, endpoint) (net.Conn, error)`** — TCP-only connect to the endpoint host:port; no OPC UA HEL/ACK or secure channel. Caller must close the returned connection. Use for TCP reachability checks (e.g. ping) without creating a session.

## Path resolution

- **Path semantics docs** — Godoc and API.md/client-guide now state start node, namespace handling, and error behavior for `NodeFromPath`, `NodeFromPathInNamespace`, `Node.TranslateBrowsePathInNamespaceToNodeID`, and `Node.TranslateBrowsePathsToNodeIDs`.
- **`Client.NodeFromQualifiedPath(ctx, path) (*Node, error)`** — Parses namespace-qualified path syntax `ns:segment.ns:segment` (e.g. `0:Server.0:ServerStatus`, `2:DeviceSet.4:PLC_Name`) and calls TranslateBrowsePathsToNodeIDs with per-segment namespace indices. Start node is Objects folder.

## Symbolic node names

- **`id.NodeIDByName(name string) (uint32, bool)`** — Reverse lookup from well-known standard node names (namespace 0) to numeric ID. Names include full spec names ("Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime") and short aliases: "CurrentTime" → 2258, "ServerStatus" → 2256, "Objects" → 85.
- **`StandardNodeID(name string) (*ua.NodeID, bool)`** — Root package helper: returns `ua.NewNumericNodeID(0, id)` when `id.NodeIDByName(name)` succeeds. Use for CLI or config that accepts symbolic names (e.g. `get value -n CurrentTime` instead of `-n i=2258`).

## CSV/JSON and canonical form

- **`ua.NodeID.String()`** — Godoc and API.md now state that output is canonical (namespace 0 omitted; round-trip with `ParseNodeID`).
- **`StatusCode.Uint32()`** — See above; supports consistent numeric serialization.

## Endpoint troubleshooting

- **Verification** — `EndpointDescription` fields `TransportProfileURI`, `ServerCertificate`, and `Server.ApplicationURI` are already exposed and used; no code change; documented for endpoint output tooling.

## Documentation

- README.md path resolution row updated with `NodeFromQualifiedPath` and symbolic names (`StandardNodeID`, `id.NodeIDByName`). Quickstart comment added for `StandardNodeID("CurrentTime")`.
- docs/client-guide.md: connection diagnostics (ping) section, path semantics table with `NodeFromQualifiedPath`, and symbolic node names (`StandardNodeID`) subsection.
- API.md: all new functions and tables (path semantics, DataType/StatusCode/Variant, uacp.DialTCP, id.NodeIDByName, StandardNodeID, NodeID canonical, StatusCode.Uint32).

---

## v0.1.9

**Date:** 2026-03-11
**Previous release:** v0.1.8

## Summary

Adds an API to resolve well-known reference type NodeIDs to their standard
names (e.g. "HasComponent", "Organizes") so tools like `opcuactl browse refs` can
show names instead of raw NodeIDs (i=47, i=46) in the reference type column.

## Reference type display names

- **`id.ReferenceTypeName(id uint32) string`** — Returns the standard OPC UA
  name for a well-known reference type in namespace 0 (e.g. 47 → "HasComponent",
  35 → "Organizes"), or "" if unknown.
- **`ReferenceTypeDisplayName(refTypeID *ua.NodeID) string`** — Convenience
  helper in the root package: returns the standard name when the NodeID is in
  namespace 0 and known, otherwise returns the NodeID string. Use when
  displaying the reference type column in browse refs or similar UIs.

Clients can call `ReferenceTypeDisplayName(ref.ReferenceTypeID)` when rendering
`ReferenceDescription` rows to show "HasComponent" instead of "i=47".

---

## v0.1.8

**Date:** 2026-03-11
**Previous release:** v0.1.7

## Summary

Adds subscription sampling interval control and a deduplicating walk API:
callers can set the server-side sampling rate for monitored items independently
of the publishing interval, and can walk the address space with each node
yielded at most once.

## Client: Subscription sampling interval

- **`SubscriptionBuilder.SamplingInterval(d time.Duration)`** — Sets the
  requested sampling interval for monitored items added by `Monitor` or
  `MonitorEvents`. The server samples at this rate (converted to milliseconds
  on the wire); the subscription's publishing interval still controls how often
  notifications are sent to the client. If not set or zero, the server uses
  the fastest practical rate (unchanged from before).

## Browsing: WalkLimitDedup

- **`Node.WalkLimitDedup(ctx, maxDepth)`** — Same as `WalkLimit` but yields
  each node at most once, keyed by NodeID. When a node is reachable via
  multiple hierarchical paths, only the first occurrence (by traversal order) is
  yielded. Callers no longer need to maintain their own visited set to avoid
  duplicate nodes.

---

## v0.1.7

**Date:** 2026-03-11
**Previous release:** v0.1.6

## Summary

Fixes a **regression introduced in v0.1.5** that broke connection establishment
(e.g. `opcuactl browse` or any client connecting with `--security-mode None`).
The generic encoder no longer skips nil optional fields; nil is now encoded as
the correct OPC UA null representation so message layout stays valid.

## Bug fix: Encoder regression (nil optional fields)

In v0.1.5 we changed `ua/encode.go` to skip nil pointer fields entirely
(return `nil, nil`) to avoid calling `BinaryEncoder.Encode()` on a nil receiver.
That broke the OPC UA binary wire format: the server expects **all fields at
fixed offsets**. Omitting bytes for nil optional fields corrupted the message
layout and caused "failed to open a new secure channel" / EOF during connect.

- **`ua/encode.go`** — Reverted the early-exit that returned no bytes for any
  nil pointer. Nil optional fields are no longer skipped.
- **`ua/qualified_name.go`** — When the receiver is nil, `Encode()` now
  returns the OPC UA null QualifiedName encoding (namespace 0 + string length
  -1), i.e. 6 bytes, so struct field offsets are preserved.
- **`ua/node_id.go`** — When the receiver is nil, `Encode()` now returns the
  OPC UA null NodeID (two-byte form, id=0), i.e. 2 bytes, so optional NodeID
  fields keep a fixed layout.

Connection establishment and all messages with optional `*QualifiedName` or
`*NodeID` fields now encode correctly.

## Other changes

- **testutil**: Test client uses longer `DialTimeout` and `RequestTimeout`
  (30s) so tests have time to connect under load (e.g. race detector).
- **examples/browse**: Test uses `testutil.NewTestServer` / `NewTestClient`
  (dynamic port, shared timeouts); removed unused `join` helper (lint).

---

## v0.1.6

**Date:** 2026-03-11
**Previous release:** v0.1.5

## Summary

Improves error messages when the server closes the connection (EOF) during
subscription or monitored-item creation. Callers (e.g. `monitor event` /
`monitor alarm` against servers that do not support event subscriptions) now
see a clear hint instead of a raw "EOF".

## Client: EOF handling in subscription path

When the server closes the connection instead of returning a service fault
(e.g. WAGO PLC not supporting OPC UA event or alarm subscriptions), the SDK
previously surfaced **io.EOF** with no context.

- **`Subscription.Monitor()`** — If the request returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  monitored items (server may not support event or alarm subscriptions)".
  Callers can still use `errors.Is(err, io.EOF)`.
- **`Client.Subscribe()`** — If `CreateSubscription` returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  subscription (server may not support subscriptions)".

Documentation and doc comments for `Monitor` and `SubscriptionBuilder.Start`
note that connection-close errors may wrap `io.EOF` with this hint.

---

## v0.1.5

**Date:** 2026-03-11
**Previous release:** v0.1.4

## Summary

Adds the depth-limited `WalkLimit` API for browsing the address space and fixes a
nil pointer dereference when encoding `HistoryReadRequest` with optional
`DataEncoding` (e.g. `history value` / `history event` commands).

## Client: WalkLimit (depth-limited walk)

- **`Node.WalkLimit(ctx, maxDepth)`** — Same as `Walk` but stops recursing when
  depth reaches `maxDepth`. The node at `maxDepth` is still yielded. Use for
  "find node", "find type", or "browse tree" style tools to avoid unbounded
  traversal (e.g. a `-depth` flag on the CLI). If `maxDepth < 0`, depth is
  unlimited (equivalent to `Walk`).
- **`Node.Walk(ctx)`** — Unchanged; now implemented via `WalkLimit(ctx, -1)`.

## Bug fix: HistoryReadRequest encoding with nil DataEncoding

Encoding a `HistoryReadRequest` whose `HistoryReadValueID` entries had
`DataEncoding == nil` caused a panic in `QualifiedName.Encode()` (nil pointer
dereference). This affected `HistoryReadRawModified`, `HistoryReadEvent`, and
other history read calls when the optional `DataEncoding` field was omitted.

- **`ua/encode.go`** — Nil pointer fields that implement `BinaryEncoder` are
  now encoded as no bytes instead of calling `Encode()` on a nil receiver.
- **`ua/qualified_name.go`** — `QualifiedName.Encode()` guards against a nil
  receiver and returns `(nil, nil)`.

---

## v0.1.4

**Date:** 2026-03-11
**Previous release:** v0.1.3

## Summary

Adds server certificate validation infrastructure and two new client options:
`InsecureSkipVerify()` and `TrustedCertificates()`. When `SecurityMode` is
`Sign` or `SignAndEncrypt`, the client now validates the server certificate by
default. Use `TrustedCertificates()` to trust self-signed servers or private
CAs, or `InsecureSkipVerify()` to disable validation for development.

## Client: Server Certificate Validation

The SDK previously performed no X.509 trust-chain validation of the server's
certificate — it parsed the certificate only to extract the RSA public key for
signing and encryption. This release adds opt-in validation and a deprecation
path toward secure-by-default behavior.

### New Options

| Option | Description |
|--------|-------------|
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA or self-signed certificates to the trust pool. Merged with the system CA pool. Enables full validation (chain, expiry, key usage). |
| `InsecureSkipVerify()` | Disable all server certificate validation. Certificate is still parsed for its public key. **INSECURE — development only.** |

### Validation Checks (when `TrustedCertificates` is configured)

| Check | Description |
|-------|-------------|
| **Trust chain** | Verifies the certificate chains to a trusted root CA (system pool + user-supplied certs) |
| **Expiration** | Rejects expired or not-yet-valid certificates |
| **Key usage** | Warns if `DigitalSignature` / `KeyEncipherment` bits are missing |

### Validation Points

Server certificate validation runs at two points in the connection flow:

- **`Dial()`** — validates `RemoteCertificate` (set via `SecurityFromEndpoint`
  or `RemoteCertificate` option) after `OpenSecureChannel`
- **`CreateSession()`** — validates `ServerCertificate` from the
  `CreateSessionResponse` after verifying the session signature

### Behavioral Summary

| Scenario | Certificate check | How to configure |
|----------|------------------|------------------|
| `SecurityMode == None` | No certificate exchanged, nothing to validate | Default |
| `Sign` or `SignAndEncrypt` (default) | Full validation: chain, expiry, key usage | Default |
| `Sign` or `SignAndEncrypt` + self-signed server | Fails unless cert added to trust pool | `TrustedCertificates(serverCACert)` |
| `Sign` or `SignAndEncrypt` + skip verify | No validation, just parse for public key | `InsecureSkipVerify()` |

### Config Changes

Added `serverCertValidator` to the internal `Config` struct:

```go
type serverCertValidator struct {
    insecureSkipVerify bool
    trustedCerts       *x509.CertPool
    trustedCertsList   []*x509.Certificate
}
```

## Documentation

- **API.md** — added `InsecureSkipVerify()` and `TrustedCertificates()` to the
  options table
- **docs/security.md** — new "Server Certificate Validation" section with
  usage examples, trust configuration, and dev-mode skip
- **docs/client-guide.md** — added new options to the client options table
- **README.md** — updated security feature description

## Files Changed

6 files changed. Hand-written Go: 3 files (config.go, client.go, config_test.go).

---

## v0.1.3

**Date:** 2026-03-11
**Previous release:** v0.1.2

## Summary

Patch release with a small improvement for anonymous authentication when using
the client (e.g. `--auth anonymous` in example CLIs).

## Client: anonymous auth without pre-set PolicyID

When `AuthAnonymous()` is applied before the server's endpoints are known (for
example when using `--auth anonymous` on the command line), the
`AnonymousIdentityToken` is created without a policy ID. The client now
resolves the correct anonymous user token policy from the server's advertised
endpoints after `CreateSession` and sets it on the token, so anonymous
authentication works correctly without requiring endpoint or security options
to be applied first.

---

## v0.1.2

**Date:** 2026-03-11
**Previous release:** v0.1.1

## Summary

This release brings the OPC UA schema files up to the latest OPC Foundation
specification and adds a security layer to the server: access restrictions,
role-based access control (RBAC), and session identity-to-role mapping. Three
new code generators were added and the existing service generator was hardened
to skip JSON-only types.

## Schema Update

Updated all schema files from the OPC Foundation UA-Nodeset repository:

- **NodeIds.csv** — refreshed; thousands of new/renamed node identifiers
- **StatusCode.csv** — new status codes added
- **Opc.Ua.Types.bsd** — new structured types and enumerations
- **Opc.Ua.NodeSet2.xml** — expanded node set with role permissions
- **Opc.Ua.PredefinedNodes.xml** — added (new file, used by .NET tooling)
- **AttributeIds.csv** — added (new file, 27 attribute IDs)
- **ServerCapabilities.csv** — added (new file, 39 capability identifiers)
- **Opc.Ua.NodeIds.permissions.csv** — added (new file, 557 default permission entries)

## New Code Generators

| Generator | Input | Output | Description |
|-----------|-------|--------|-------------|
| `cmd/attrid` | `AttributeIds.csv` | `ua/enums_attribute_id_gen.go` | AttributeID enum constants (replaces hand-maintained block) |
| `cmd/capability` | `ServerCapabilities.csv` | `ua/server_capabilities_gen.go` | 39 `ServerCapability*` constants, `KnownCapabilities` map, `ValidateCapability()` |
| `cmd/permissions` | `Opc.Ua.NodeIds.permissions.csv` | `server/default_permissions_gen.go` | 557 default node permission entries for RBAC |

## Code Generation Fixes

- **Service generator** (`cmd/service`): added `-nodeids` flag and
  `filterByBinaryEncoding()` to skip types that only have a JSON encoding in
  the spec — prevents generating codec registrations for types that cannot be
  serialized over OPC UA Binary.
- **`generate.sh`**: updated to run the three new generators; added descriptive
  header comment; fixed shellcheck warnings (SC2035, SC2086).

## Server Security & RBAC

### Access Restrictions (OPC UA Part 3 §5.2.11)

- `checkAccessRestrictions()` enforces `SigningRequired` and
  `EncryptionRequired` bits against the secure channel's security mode.
- `checkAccessRestrictionsForBrowse()` only enforces restrictions when the
  `ApplyRestrictionsToBrowse` bit is set.
- Wired into Read, Write, Browse, and Call service handlers.
- Added `SecurityMode()` getter on `SecureChannel`.

### Role-Based Access Control

- **`RBACAccessController`** — checks node `rolePermissions` against the
  session's assigned roles for Read, Write, Browse, and Call operations.
  Nodes without role permissions are unrestricted.
- **`RoleMapper`** function type and `DefaultRoleMapper` — maps identity tokens
  to well-known role NodeIDs (anonymous → `Anonymous`, others →
  `AuthenticatedUser`). Configurable via `WithRoleMapper()` server option.
- **Session identity tracking** — `ActivateSession` now extracts the
  `UserIdentityToken` and resolves roles through the configured `RoleMapper`.

### Well-Known Roles

- New `ua/well_known_role.go`: 12 well-known roles from the spec (Anonymous,
  AuthenticatedUser, Observer, Operator, Engineer, Supervisor, ConfigureAdmin,
  SecurityAdmin, SecurityKeyServer, SecurityKeyServerAdmin,
  SecurityKeyServerAccess, SecurityKeyServerPush).
- Each role has `String()`, `NodeID()` methods and lookup via `RoleByName` map.

### Node RolePermissions

- Server `Node` stores `[]*ua.RolePermissionType` resolved from the generated
  default permissions at import time via `resolveRolePermissions()`.
- `AttributeIDRolePermissions` and `AttributeIDUserRolePermissions` are served
  from the node as `[]*ua.ExtensionObject`.

## Server Capabilities Expansion

- `OperationalLimits` expanded from 1 field to 12 (all defaulting to 32):
  `MaxNodesPerRead`, `MaxNodesPerWrite`, `MaxNodesPerBrowse`,
  `MaxNodesPerMethodCall`, `MaxNodesPerRegisterNodes`,
  `MaxNodesPerTranslateBrowsePathsToNodeIDs`, `MaxNodesPerNodeManagement`,
  `MaxMonitoredItemsPerCall`, `MaxNodesPerHistoryReadData`,
  `MaxNodesPerHistoryReadEvents`, `MaxNodesPerHistoryUpdateData`,
  `MaxNodesPerHistoryUpdateEvents`.
- Server capability nodes generated dynamically from the struct.

## Code Quality

- Enabled `unparam` linter in `.golangci.yml` — `make check` now catches
  unused parameters.
- Fixed 4 genuine unused-parameter issues in `secure_channel.go` and
  `race_test.go`:
  - `newSecureChannel`: removed 3 dead parameters (`secureChannelID`,
    `sequenceNumber`, `securityTokenID`) — values were only used by
    `NewServerSecureChannel` which sets them on `openingInstance` directly.
  - `sendResponseWithContext`: wired up `ctx` for cancellation checks and
    write deadlines.
  - `mergeChunks`: removed always-nil error return.
  - `race_test.go`: removed unused goroutine parameter.

## Generated Code Changes

All generated files were regenerated from the updated schema:

- `id/` — NodeID constants (DataType, Method, Object, ObjectType, ReferenceType,
  Variable, VariableType)
- `ua/enums_gen.go` — updated/new enum types
- `ua/enums_strings_gen.go` — stringer output for all enums
- `ua/extobjs_gen.go` — extension object codecs
- `ua/register_extobjs_gen.go` — filtered to binary-encoded types only
- `ua/status_gen.go` — new status codes
- `connstate_strings_gen.go` — regenerated

## Files Changed

52 files changed, ~232k insertions, ~53k deletions (bulk is schema XML and
generated code). Hand-written Go: 19 files, +866 / -73 lines.
