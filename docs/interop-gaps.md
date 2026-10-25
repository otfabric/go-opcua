# Interop gaps and workarounds

What go-opcua does not implement, where it behaves differently from what an
older version or another stack might lead you to expect, and the deviations
of other OPC UA stacks you may meet when you connect go-opcua to them. Every
peer entry comes from the interop suite ([INTEROP.md](../INTEROP.md)): the
test that found it skips with the reason or pins the behaviour, and the
ledger row says `unsupported` with the same reason.

Versions: go-opcua v1.22.0; open62541 1.5.9, Eclipse Milo 1.1.8, async-opcua
0.19.0, UA-.NETStandard 2.0.1, node-opcua 2.187.12 and opcua-asyncio
(`asyncua`) 2.1.0, as packaged by opcua-interop v0.14.0.

## What go-opcua does not implement

| Gap | Who has it | Workaround |
|---|---|---|
| **JSON over HTTPS and WebSockets** (`https-uajson`, `wss-uajson`, the OpenAPI mapping). The binary `opc.https` and `opc.wss` transports are implemented. | UA-.NETStandard | Use the binary transports. |
| **A file-based certificate store for the push model.** `server.CertificateStore` has no implementation in the library: without one, pushed trust lists, certificates and keys live in memory only. The pull model of Part 12 (package `gds/gdsserver`, `gds.PullClient`) and the push model (`server.WithPushManagement`, package `gds`) are implemented, the push model with the three default certificate groups and certificate groups of the application, GetCertificates, CreateSelfSignedCertificate, DeleteCertificate, ResetToServerDefaults, TransactionDiagnostics, PFX keys and the certificate alarms of 1.05; the pull model with the three default certificate groups, CSRs of every key type, PEM and PFX keys, the RolePermissions and audit events of the GDS NodeSet, and a `MemoryStore` or a file-based `gdsserver.NewFileStore`. | UA-.NETStandard | Implement `server.CertificateStore` over the application's storage. |
| **Historical events on the server.** The history provider interfaces cover data only; the client has `HistoryReadEvent`. | UA-.NETStandard (framework), asyncua | Store events in the application, or keep event history in another historian. |
| **Dynamic decoding of custom structures** from the server's DataTypeDefinition | Milo, UA-.NETStandard, node-opcua, asyncua | Generate or register Go types (`ua.RegisterExtensionObject`); unknown structures stay ExtensionObject bodies. |
| **Time-scheduled Ethernet (TSN)**, AMQP over WebSockets, PubSub Actions bound to server Methods (go-opcua runs Go handlers) | open62541 (Ethernet / TSN) | Plain Ethernet, UDP, MQTT or AMQP for data; register an `ActionHandler` that calls the Method. |

## go-opcua behaviour you may notice

| Behaviour | Why | What to do |
|---|---|---|
| Username logins are refused with `BadUserAccessDenied` unless the server has `WithUsernameValidator`; issued tokens unless it has `WithIssuedTokenValidator` (since v1.8.0). | Part 4 leaves acceptance to the server; accepting unchecked credentials is unsafe. | Register a validator. `server.New` logs a warning per unvalidated token type. |
| A peer that leaves gaps in sequence numbers on a secured channel loses the channel (`BadSequenceNumberInvalid`). | Part 6 §6.7.2.4. | Nothing for compliant peers. |
| A server in a container refuses the Hello with `BadTcpEndpointUrlInvalid` when it is published on another host port (`-p 5000:4840`). | The server checks the port of the EndpointUrl in the Hello against its listen port. | Publish the same port number. |
| Writing the same value again produces no data-change notification; a timestamp-only change needs trigger `StatusValueTimestamp`. | DataChangeFilter semantics (Part 4 §7.22.2). | Use `StatusValueTimestamp`. |
| A discovery server registration does not validate the LDS certificate unless asked to. | Opt-in. | Pass `server.RegisterCertificateValidator`. |
| Raw history deletes (DeleteRawModified) remove the sample at the end time, while a raw read excludes it. | Known limitation of the built-in historian. | Pass an end time just past the last sample to delete. |
| Triggering links (SetTriggering) are not restored when the client re-creates a subscription after a reconnect. | Recovery re-creates subscriptions and monitored items only. | Call `Subscription.SetTriggering` again after recovery. |
| mDNS has no probing or conflict resolution, and real multicast is verified on Linux only. | Scope of the built-in responder. | Prefer the LDS registry over mDNS on untrusted networks. |
| PubSub: chunked NetworkMessages and UADP discovery use the layout of the OPC Foundation .NET stack 2.x where the specification is ambiguous. They interoperate with UA-.NETStandard 2.0.1; open62541 1.5.9 sends and accepts neither. | open62541 drops chunks and ignores discovery probes. | Keep MaxNetworkMessageSize large enough to avoid chunks towards open62541; configure DataSetMetaData on readers instead of relying on discovery. |
| PubSub over MQTT: go-opcua speaks MQTT 3.1.1 unless `SetMQTTVersion` asks for 5.0; only 5.0 carries the content type and UAMessageType of a message, a 3.1.1 subscriber tells the mapping from the payload. | Part 14 §7.3.4.4 leaves the default to the implementation; open62541 1.5.9 speaks 3.1.1. | Use `MQTTVersionBestAvailable` with brokers that speak 5.0. |
| PubSub over AMQP: ExactlyOnce is sent as AtLeastOnce, and DataSetMetaData is not retained (AMQP has no retained messages). | AMQP 1.0 settlement has no exactly-once in practice; Part 14 B.3. | Put the metadata on a queue address so late subscribers still get it. |
| ECC: where open62541 1.5.9 and Part 6 1.05.07 differ (curve25519 key material, Sign-mode key derivation, ChannelThumbprint), go-opcua follows open62541. | open62541 is the only ECC peer that can be tested. | Prefer SignAndEncrypt with ECC_nistP256 / P384 or the AEAD policies with other stacks. See [Security](security.md). |

## Peer deviations

What each stack does differently from Part 4 / Part 6, as observed by the
interop suite. None of these needs a change in go-opcua; the workaround is
on the side of the application that talks to the peer.

### open62541 1.5.9

- **XML codec:** cannot encode structures, enumerations, DataValue, DiagnosticInfo, matrices or a null Variant, and cannot decode DataValue, DiagnosticInfo or XmlElement. **JSON:** cannot decode a structure encoded in place in an ExtensionObject (its own 1.05 output) and rejects unknown members. go-opcua writes the Part 6 forms and reads open62541's ([encodings](encodings.md)).
- **Clients** must send the certificate's SAN URI as ApplicationUri, otherwise `BadCertificateUriInvalid`.
- **ECC endpoints** all have the same SecurityLevel: pin the policy rather than relying on `opcua.SelectEndpoint`.
- **PubSub:** publishes its own ConfigurationVersion, discards KeepAlive and delta frames, wraps JSON sequence numbers at 65535, MQTT is QoS 0 without TLS, GetSecurityKeys may return a negative TimeToNextKey, and a reader in Error after its MessageReceiveTimeout stays there. go-opcua handles the sequence numbers and the TimeToNextKey ([PubSub](pubsub.md)).
- **MQTT publisher** started before its broker accepts connections stays in Error, and a refusing broker can crash it (double free); fixed in the opcua-interop adapter (v0.8.2), not upstream. Start the broker first.
- **Alarms & Conditions** (experimental in 1.5.9, a build option): ignores an Acknowledge / Confirm / AddComment comment without a locale (the go-opcua client sends the session locale), sends RefreshStart / RefreshEnd only to event items on the Server object, rewrites Message on every method call, and reports the Confirm event with a null Time. A repeated Acknowledge answers `Bad_EventIdUnknown`. ConditionRefresh needed a fix in the opcua-interop adapter to accept the SubscriptionId.
- **Client** stalls its subscription when a node-opcua server answers a request under the token that was current when the request was sent (see node-opcua below).
- **Push management:** of the Part 12 1.05 additions only the DefaultUserTokenGroup trust list; no GetCertificates, CreateSelfSignedCertificate, TransactionDiagnostics, HTTPS group trust list, PFX keys (SupportedPrivateKeyFormats PEM, DER) or certificate alarms, and ResetToServerDefaults answers `Bad_InternalError`.

### Eclipse Milo 1.1.8

- A Write of a DataValue with a SourceTimestamp or StatusCode is accepted (`Good`) instead of `BadWriteNotSupported`. Read back to confirm.
- JSON DataValue: Milo decodes only its own form with the Variant nested in `"Value"`. Send Variants rather than DataValues to Milo; go-opcua reads Milo's form.
- XML DateTime keeps milliseconds only.
- `ReleaseContinuationPoints` of a HistoryRead does not reach the history backend.
- The server refuses more than 4 connection attempts per second from one address (`Stack.ConnectionLimits`); many clients behind one NAT address can hit it.
- No NodeManagement in the reference server, no ECC, no reverse connect, no LDS or mDNS, no PubSub.

### async-opcua 0.19.0

- A String written to an Int32 is accepted (want `BadTypeMismatch`); Browse of an unknown NodeId returns `Good` with no references (want `BadNodeIdUnknown`). Validate types on the client; read the NodeClass to check that a node exists.
- No EventQueueOverflowEventType; the oldest events are dropped silently. Size event queues generously.
- A Write with a SourceTimestamp is accepted (`Good`).
- Under `StatusValueTimestamp`, a timestamp change inside a deadband is reported; a percent deadband without EURange answers `BadDeadbandFilterInvalid` where go-opcua returns `BadMonitoredItemFilterUnsupported`. Treat both as "filter refused".
- Over SecurityPolicy None, ActivateSession carries a null ServerNonce (open62541 rejects that, go-opcua accepts it).
- Certificates are trusted by exact match only, no CA chains: put the go-opcua leaf certificate into its trust store.
- MaxByteStringLength is 65535.
- JSON is the 1.04 `{"Type":..,"Body":..}` form (go-opcua reads it with `ua.WithJSONForm`); no ECC, LDS, mDNS or PubSub.

### UA-.NETStandard 2.0.1

- The client refuses to send a UserName token over SecurityPolicy None: offer username on a secured endpoint or with a token policy that has its own SecurityPolicyUri.
- The end time of a raw HistoryRead is exclusive, and releasing a continuation point answers with a null HistoryData.
- The XmlDecoder reads namespace-qualified elements only: do not use `ua.WithoutXMLNamespace` with .NET peers.
- ECC application certificates issued by an RSA CA are refused; ECC between go-opcua and .NET is untested.
- The OPC Foundation LDS is a separate product; there is no multicast discovery.
- Push management: CreateSelfSignedCertificate refuses a certificate slot that holds a certificate (`Bad_InvalidState`) until DeleteCertificate empties it, and DeleteCertificate refuses the only application certificate at once (`Bad_InvalidState`), so with one application certificate there is no slot to create one for; no ResetToServerDefaults. GetCertificates, the TransactionDiagnostics, the HTTPS and UserToken trust lists, PFX keys and the alarms work.
- Alarms & Conditions: a repeated Acknowledge with the same EventId answers `Bad_ConditionBranchAlreadyAcked`; every method call reports an event with a new Time.
- PubSub (Opc.Ua.PubSub 2.0.1): an MQTT publisher needs MQTT 5.0 (it sets the MQTT 5 content type on every publication); subscribing works on 3.1.1 too. Its UDP transport sends with TTL 1 unless configured, which also limits unicast. The encoder writes an empty String with length 0 (go-opcua: the null String, length -1), always sets MessageIsValid and drops a DataSetMessage without it; the JSON encoder leaves out the `UaType` the DataSetMetaData implies (go-opcua decodes it since v1.9.0). Discovery answers DataSetMetaData and DataSetWriterConfiguration probes only. No SKS, no PublishSubscribe information model, no Ethernet, no AMQP.

### UA-.NETStandard 1.5.378 (GDS)

The Global Discovery Server and GDS client (Opc.Ua.Gds.*.Common 1.5.378.182, opcua-interop adapter dotnet-gds; the 2.0.1 GDS packages are unreleased):

- The CRL of its ECC CA names sha256WithRSAEncryption inside the TBSCertList and ecdsa-with-SHA256 outside; crypto/x509 (and `uapolicy.ParseRevocationList`) refuse it (RFC 5280 §5.1.1.2). The RSA CA's CRL is well formed.
- CheckRevocationStatus checks online and does not read its own CRL: a revoked certificate is `Bad_CertificateRevocationUnknown`.
- One certificate request per application: a new request reuses the RequestId. UnregisterApplication revokes the application's certificates. FindApplications needs an authenticated user.
- The client reads a TrustList with the MethodIds of FileType (Part 4 §5.11.2.2), which the go-opcua server resolves since v1.22.0.

### node-opcua 2.187.12

- After a SecureChannel renewal the server answers a request under the token the request used. The go-opcua client copes; open62541's client stalls.
- A Read with an IndexRange on a scalar returns `Good` (want `BadIndexRangeNoData`).
- Event queues are revised to at least 100, so a small event queue overflows late.
- Alarms & Conditions: RefreshStart / RefreshEnd go only to event items on the Server object (monitor `i=2253` for ConditionRefresh), the source of a condition must be a HasEventSource target, Message is rewritten by each method, and a repeated Acknowledge answers `Bad_EventIdUnknown`.
- A Write with a SourceTimestamp is accepted (`Good`).
- UserName over a None endpoint works only with an encrypted password.
- Push management: of the Part 12 1.05 additions only the DefaultUserTokenGroup trust list; the DefaultHttpsGroup TrustList is an empty file, a TransactionDiagnostics variable fails to encode (`Bad_DataTypeIdUnknown`), ResetToServerDefaults answers `Bad_InternalError`, PEM keys only, no GetCertificates, CreateSelfSignedCertificate or certificate alarms.
- The server registers only with a discovery server that has a certificate, and reports success when the registration failed: give the go-opcua LDS a secured endpoint (the default) and check `Server.RegisteredServers()`.
- The server answers AddNodes, DeleteNodes, AddReferences, DeleteReferences, HistoryUpdate and Query with `BadServiceUnsupported`; no ECC, no open-source PubSub, no Part 6 XML codec.

### opcua-asyncio (asyncua) 2.1.0

- **Read and Browse:** TimestampsToReturn and IndexRange are ignored; Browse ignores RequestedMaxReferencesPerNode (no continuation points); a Write to an unknown node answers `BadUserAccessDenied` and a Browse of one `BadNodeIdInvalid` (want `BadNodeIdUnknown`); a Write with a SourceTimestamp is accepted.
- **Subscriptions:** no sampling (every write is reported, the revised SamplingInterval is the publishing interval); MonitoringMode Sampling still reports, so the effect of SetTriggering cannot be observed; ModifySubscription and ModifyMonitoredItems are not applied; the absolute deadband is compared with the previous sample, a percent deadband is accepted and not applied; no EventQueueOverflow event.
- **Republish** of a sequence number the server does not hold answers `Good` with an empty message (want `BadMessageNotAvailable`).
- **TransferSubscriptions** checks no identity: a user's subscription moves to an anonymous session.
- **HistoryRead** with NumValuesPerNode truncates without a continuation point.
- **Discovery:** RegisterServer with IsOnline=false keeps the server listed; no mDNS.
- **Sessions:** MaxRequestMessageSize is revised to 65536; there are no server diagnostics.
- **Strings:** go-opcua encodes an empty Go string as a null String, which asyncua reads as `None`.
- Node management is served to the `Admin` role only; no ECC, no reverse connect, no Part 6 JSON codec, PubSub is experimental (UADP over UDP).

## go-opcua defects found by interop

Fixed; listed so that you can tell whether an upgrade helps with a symptom.

| Symptom | Found with | Fixed in |
|---|---|---|
| Strict clients (UaExpert, Prosys) reject encrypted channels: empty ReceiverCertificateThumbprint in OPN responses | UaExpert, Prosys | v1.1.1 |
| Sessions die at 75 % of the channel lifetime (`could not verify signature`): server-side renewal reused the TokenId and swapped keys in place | open62541, Milo | v1.5.0 |
| An open62541 renewal is rejected with `BadSecureChannelTokenUnknown` | open62541 | v1.5.0 |
| A Variable added through AddNodes reads back null (SpecifiedAttributes 0 means all) | open62541, Milo | v1.5.0 |
| An XmlElement inherits the document's default namespace | Milo | v1.6.0 |
| About one channel in 1023 starts at sequence number 1024 (must be below 1024 for the RSA policies) | async-opcua | v1.8.1 |
| Aes256_Sha256_RsaPss asymmetric messages split into blocks of the wrong size (SHA-512 padding for RSA-OAEP-SHA256) | UA-.NETStandard | v1.8.1 |
| CreateSession returns no ServerEndpoints when the client dialled a host name no endpoint matches | UA-.NETStandard | v1.8.1 |
| `WithClientCertificateTrustList` reads only the first certificate of a client's chain | UA-.NETStandard | v1.8.1 |
| The client drops the caller's `ReturnDiagnostics` and `AuditEntryId` | all peers (no diagnostics returned) | v1.8.1 |
| A scheduled renewal renews a token that `Renew` already replaced, from a used sequence number | asyncua | v1.8.1 |
| A Republish answered without the requested message rewinds the subscription's sequence numbers | asyncua | v1.8.1 |
| A JSON DataValue field without `UaType` fails to decode when the reader has DataSetMetaData | UA-.NETStandard | v1.9.0 |
| A Call with the MethodId of the ObjectType (the InstanceDeclaration) on an instance answers `Bad_MethodInvalid` | UA-.NETStandard (GDS client) | v1.22.0 |
