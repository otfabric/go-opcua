# Limitations

What go-opcua does not do, and what has not been verified. The workarounds, the
behaviour you may notice, and the deviations of peers are in
[docs/interop-gaps.md](docs/interop-gaps.md); the evidence per capability is in
[INTEROP.md](INTEROP.md) and the ledger [interop/COVERAGE.md](interop/COVERAGE.md).

## Scope not implemented

- The OpenAPI mapping of the UA JSON services. UA JSON over HTTPS and
  WebSockets (`https-uajson`, `wss-uajson`) and the binary `opc.https` and
  `opc.wss` transports are implemented.
- Push certificate management keeps its changes in memory unless
  `PushManagement.Store` is set; `server/pushstore` stores them in a local
  directory (no network file systems) with the private keys unencrypted, as
  0600 files. It does not keep the pending transaction, the rejected list or
  the key a CreateSigningRequest generated: after a restart UpdateCertificate
  with the certificate of such a request fails (`Bad_SecurityChecksFailed`)
  unless it brings its key. ApplyChanges does not return `Bad_InvalidState`
  for a TrustList still open for writing (Part 12 §7.10.9), and returns
  Good, not `Bad_NothingToDo`, without a transaction.
- Dynamic decoding of custom structures (`opcua.DynamicTypeDecoding`) reads
  the DataTypeDefinition Attribute only: a server that describes its types
  with a DataTypeDictionary (OPC 10000-5 Annex D, the 1.03 mechanism) and not
  with the Attribute is not supported, and its structures stay
  ExtensionObject bodies. A JSON-encoded body (the UA JSON transports) of a
  type without a Go type is still a decoding error; binary bodies inside JSON
  and XML are decoded.
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
  evidence and run journal; after a restart it re-proves the records
  (what it cannot prove stays Unverified or Unresolved and is never
  closed or adopted), does the owed work in the first step of the next
  Process or Reconcile (an owed set change by Reconcile only, nothing
  resent) and keeps proven endpoints of an unchanged configuration in
  place; an endpoint whose record was lost is Unresolved, never adopted,
  and adoption is all or nothing for a run. A close or enable whose
  outcome cannot be proven by its postcondition stays Unresolved until
  `Settle`, and is never resent. Two ServerAddresses of one server are
  fenced as one only once a record or intent made over each shows the
  same ApplicationUri; adoption compares the PubSub properties of the
  endpoint's own reader, writer, groups and connections, not the rest of
  the server's PubSub configuration, and never adopts a configuration
  with transport or broker settings, group or connection properties,
  key services or a PublishingOffset, which it cannot compare
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
- Time-scheduled Ethernet (TSN) and AMQP over WebSockets.
- The PubSub configuration of a server (`server.WithPubSub`, the configuration
  Methods and the PubSubConfiguration file) lives in memory unless
  `server.WithPubSubStore` persists it (Part 14 §9.1.2, `server/pubsubstore`,
  v1.43.0). The store keeps the configuration of PublishSubscribe, its
  PublishedDataSets and PubSubConnections with their groups, writers and
  readers; not the SecurityGroups, their keys and the PubSubKeyPushTargets
  (§8), and not the ID reservations of ReserveIds, which end with their
  session (§9.1.3.7.5). A change made on the runtime directly
  (`Server.PubSub()`) is written with the next change made through the
  server, or by `Server.PersistPubSubConfiguration`. A component another
  mechanism adds below a component a UAFX EstablishConnections call created
  is persisted by neither store (docs/uafx.md). A restored secured group
  gates its SecurityGroup until a newer key is current, so a SecurityGroup
  with static keys stays closed after a restart. With `ua.StatusBadInternalError`
  for a store that does not write, the Methods of §9.1.3 answer with a code
  their tables do not list (none of them covers a store failure): a library
  interpretation.
- mDNS has no probing or conflict resolution.
- History Annotations (Part 11 §5.1.2): the SourceTimestamp identifies an
  Annotation, so a node has at most one per time (§6.9.3 leaves the choice to
  the server). The Annotations Property has a null value; deleting the node or
  the Property does not delete the Annotations of the provider. An empty
  userName is the user of the session, not left empty.
- Change audit events (Part 4 §6.5.7, §6.5.8; Part 11 §5.8): the OldValues
  of an event update or delete are null (the provider keeps no event before
  an update) and a modified raw delete has none. The OldValues of a data
  update are read from the provider before the update, outside the update:
  a concurrent writer can change them in between. An event insert names the
  EventIds of the inserted events in the Message. A Write or HistoryUpdate
  the service refuses as a whole reports one event, with the Server object as
  SourceNode.
- Part 13 Aggregates: the AggregateFilter of a monitored item (Part 4
  §7.22.4) reads no history, and refuses AnnotationCount, which "applies to
  Historical Aggregates only" (Part 13 Table 5). A startTime in the past
  is revised to the first boundary after the creation of the item. The
  server does not wait for late samples before it calculates an interval
  (Part 13 §4.3.2 allows that). An item keeps at most 65536 raw values
  between two calculations. Beyond that the oldest are dropped.
  A processed read returns all its intervals at once (at most
  `aggregate.MaxIntervals`), without continuation points, and the server
  searches bounding values one ProcessingInterval beyond the request of a
  raw-only provider.
- Part 20 files: the server adds no FileSystem Object of its own (the
  application adds one with `AddFileDirectory`); a FileDirectory reads the
  backend when it is added and follows only the changes of its Methods; the
  generated Method contracts (`uamethod`) cover FileType and
  FileDirectoryType, the other Method handlers and clients keep their
  argument code. `filetransfer.Directory.Entries` recognizes the Objects
  whose TypeDefinition is FileType or FileDirectoryType, not those of a
  subtype. The FileType Methods are tested against go-opcua only, besides
  the TrustList reads and writes of the interop suite.
- The client session keep-alive (`SessionKeepAlive`) runs only for a client
  that `Connect` connected, not for a session set up with `Dial`,
  `CreateSession` and `ActivateSession`, and it does not act on the value of
  the ServerStatus State it reads (a server in Shutdown or Failed is not
  treated differently); see
  [docs/client-guide.md](docs/client-guide.md#session-keep-alive).
- Model change events (`server`): only nodes with a NodeVersion Property are
  reported (Part 3 §9.32.2); the server has no View other than the default,
  so the events go to the Server Object only. `ImportNodeSetXML` reports
  nothing. A Value of a Property with the SemanticChange bit that a
  `SetValueFunc` or another data source changes is not seen, only a Write or
  `Node.SetAttribute`.
- NamespaceMetadata (`server`): a `MapNamespace` has none; NamespaceFile and
  ConfigurationVersion are not provided; StaticNodeIdTypes,
  StaticNumericNodeIdRange and StaticStringNodeIdPattern promise no static
  node. Reading the RolePermissions, UserRolePermissions or
  AccessRestrictions Attribute of a node without its own does not answer
  with the defaults of its namespace, which are read from the
  NamespaceMetadata Object.
- Managed RoleSet (`server.WithRoleManagement`, OPC 10000-18): the
  configuration of the roles lives in memory and is lost when the process
  ends (persistence is phase 4 of docs/roadmap.md). The roles of namespace 0
  cannot be removed; Anonymous, AuthenticatedUser and TrustedApplication
  cannot be changed. Browse and Read of the role Properties are limited to
  administrators only by the `RBACAccessController` (or an own
  `AccessController`), through the RolePermissions of the nodes, not by the
  RoleSet itself (§4.4.1). CustomConfiguration is always FALSE: no vendor-specific
  mapping. The RoleMapper is not called again when a role changes: an active
  session keeps the RoleMapper roles of its last ActivateSession. Thumbprint
  rules use SHA-1 (Part 6 §3.1.1, the hash where no SecurityPolicy
  applies). Role and GroupId rules need JWT issued tokens and read the
  `roles`, `groups` and `iss` claims only. A session whose endpointUrl
  names no configured Endpoint gets no role that has Endpoints. The added
  role nodes have no NodeVersion, so AddRole and RemoveRole report no
  GeneralModelChangeEvent (Part 3 §9.32.2). RoleSet and `rolemgmt` are tested against go-opcua only: no peer of the
  pinned opcua-interop release manages roles.
- Durable subscriptions (`server`, SetSubscriptionDurable, OPC 10000-5 §9.3):
  the subscription, its MonitoredItems and their queues live in memory. They
  outlive the session for the revised lifetime and another session takes
  them over with TransferSubscriptions, but a restart of the server loses
  them (OPC 10000-4 §6.8 lets a Server store them; this one does not). The
  retransmission queue for Republish keeps the last 10 NotificationMessages,
  as for every subscription. Limits: `server.DurableSubscriptions` (24 hours
  and 10000 values by default).
- RequestServerStateChange (`server`, OPC 10000-5 §9.4) changes the
  ServerStatus only: the application's `server.ServerStateChangeFunc` decides
  whether to accept a change, and stops or restarts the server itself;
  without one every request is Bad_InvalidState. Administrative rights are
  the ConfigureAdmin and SecurityAdmin roles of the session (from the
  RoleMapper and, with `server.WithRoleManagement`, the RoleSet).
- The Methods of the Server Object (GetMonitoredItems, ResendData,
  SetSubscriptionDurable, RequestServerStateChange) are tested against
  go-opcua only.

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
- UAFX ConfigurationData of a persistent ConnectionEndpoint (OPC 10000-81
  §6.2.4.3.7): SetConfigurationDataCmd writes the values, but
  SetStoredVariables (§6.4.6.3), which the clause requires for an
  endpoint with IsPersistent set, is not implemented, so the values are
  not stored and a restart does not apply them again. The endpoint
  itself is restored.
- UAFX CloseConnections after `Connections.Close` returns the Method
  status `Bad_InvalidState`; OPC 10000-81 Table 23 lists only Uncertain,
  so this is a library interpretation using the general code of Part 4.
- UAFX persistence: a required write the store refuses for good (over its
  Limits) leaves the records of the AutomationComponent out of line with
  the runtime (`PersistenceStatus.Diverged`) until a later write or a
  restart replaces them; the store is not fenced.
- Part 13 Aggregates (`server/aggregate`) follow the clauses where the
  examples of Annex A (AggregateExamples.csv) give other results, in 64 of
  its 1358 rows, each listed with its clause in
  `server/aggregate/deviations_test.go`: TimeAverage and Total extrapolate
  after the end of data (Tables 54 and 56); Total is always sloped
  (§5.4.3.8; the file steps for a Stepped Variable); the PercentTime status
  of four TimeAverage2/Total2 intervals is Bad at 60 % Bad data with
  PercentDataBad 50 (§5.4.3.2.1); Maximum, MaximumActualTime and Range are
  Uncertain when an Uncertain value exceeds the maximum (Tables 59, 61, 62);
  MinimumActualTime and MaximumActualTime set Calculated when Uncertain
  (Tables 60, 61); Count and NumberOfTransitions set Calculated when Bad
  (Tables 69, 72); the first region of DurationBad/PercentBad takes the
  status of the value at or before the start (§5.4.3.32); WorstQuality2
  includes the start bound only and ignores TreatUncertainAsBad (§5.4.3.36).
  Where the clauses leave room the package reads them as the file and
  UA-.NETStandard do: a leading Bad_NoData raw value marks the start of the
  history, an Uncertain value never counts as Good for PercentValues, an
  all-zero aggregateConfiguration is no override, WorstQuality sets
  MultipleValues only when the worst status is not Good, DurationInState
  counts no region that starts with a non-Good value or bound, and the
  end bound of MinimumActualTime2/MaximumActualTime2 is Interpolated.
  TimestampsToReturn Both is accepted for processed reads, although Part 13
  §5.4.3.1 names the source timestamp only.
- ECC follows open62541, not Part 6 1.05.07, for curve25519 key material
  and ChannelThumbprint
  ([docs/interop-gaps.md](docs/interop-gaps.md)).
- PubSub chunked NetworkMessages and UADP discovery use the layout of the OPC
  Foundation .NET stack 2.x where the specification is ambiguous; open62541
  1.5.10 sends and accepts neither.
- PubSub over AMQP sends ExactlyOnce as AtLeastOnce.
