# go-opcua roadmap

Status of 27 November 2026, checked against main at 140a14d (v1.41.0). It
orders the work that makes the client, the server, PubSub and UAFX equally
complete, with the contracts generated from the OPC Foundation models. Each
item lands as its own PR and release; a phase is done when every item meets
the definition below.

## Definition of complete

A capability is complete when it has:

1. its contract (types, NodeIds, Method arguments, mandatory children, state
   machines) generated from a pinned NodeSet, not written by hand;
2. the server runtime and a typed client API, symmetric;
3. a command in opcuactl;
4. ledger rows against at least one independent peer of opcua-interop
   (INTEROP.md), or a recorded reason why no peer can test it;
5. its documentation, and no entry left in LIMITATIONS.md.

## Phase 0: correctness and documentation

Small fixes that customers run into today.

| Item | Evidence | Reference |
|---|---|---|
| UserRolePermissions returns the full RolePermissions, not those of the session's roles | `server/node.go:227` | Part 3, UserRolePermissions Attribute |
| Cancel drops the cancelled Publish requests without a response; requests put back are lost when the queue is full | `server/session_service.go:600-622` | Part 4 §5.6.5 |
| A re-created subscription comes back with PublishingEnabled true and without its triggering links | `subscription.go:655`, LIMITATIONS.md | Part 4, CreateSubscription, SetTriggering |
| `ImportNodeSetXML` does not remap the namespace indexes of the document and does not reuse a namespace URI the server has | `server/nodeset2_import.go:81-94`; the remapper `internal/nodeset/remap.go` is used by UAFX only | Part 6 Annex F |
| DeleteRawModified deletes the sample at EndTime, which ReadRaw never returns | `server/historian_ext.go:117-154`, `server/historian.go:175` | Part 11, ReadRawModifiedDetails and DeleteRawModifiedDetails |
| The IssuedToken policy advertises an empty IssuedTokenType | `server/server.go:1066` | Part 4, UserTokenPolicy |
| docs/interop-gaps.md says it was checked against v1.31.0 | its header | |

The clause of each fix is read in the specification before the PR (AGENTS.md
rule 3).

Done in v1.42.0 (PR #61): all seven items. The IssuedTokenType is set with
`server.WithIssuedTokenPolicy` and stays empty without it; the clauses are
cited in RELEASE.md. The review of the fixes added four more, also in
v1.42.0: a BrowseName without a prefix is in namespace 0 (Part 6 §5.1.12),
a raw delete without a valid range is refused (Part 11 §6.9.5.1), a full
Publish queue answers its oldest request (Part 4 §5.14.5.1), and
SetTriggering removes links before it adds them (Part 4 §5.13.5.2).

## Phase 1: generation foundation

| Item | Today |
|---|---|
| Pin every input of `schema/update-schema.sh` to a UA-Nodeset commit, with ModelUri, Version, PublicationDate and SHA-256 in a manifest; regeneration from committed inputs only | every input comes from the `latest` branch, no record |
| Check that the RequiredModel versions of the vendored models agree | UAFX requires UA 1.05.06, DI UA 1.05.04, the vendored UA is 1.05.07 |
| One NodeSet model reader shared by the generators and the runtime import | three readers: `cmd/uafx/model.go`, `internal/schema/uaNodeSet.go` (xgen output edited by hand, never regenerated), `internal/nodeset/remap.go` |
| `make check-gen` also fails on new untracked generated files | it runs `git diff --quiet` |
| Use or drop `schema/Opc.Ua.PredefinedNodes.xml` and `schema/UANodeSet.xsd` | no consumer; the XSD is not downloaded either |

Done in v1.42.0 (PR #61, with the work of #60 and #62): all five items. The
inputs are pinned in `schema/manifest.json` and checked by `make gen`; both
unused files are dropped; `internal/nodeset.Parse` is the one reader of
`cmd/uafx` and `server.ImportNodeSetXML`, and
`TestImportedAddressSpaceGolden` holds the imported address space identical
to that of the old reader.

## Phase 2: generated Method contracts

Generate, from InputArguments and OutputArguments of the NodeSets: typed
argument structs with pack and unpack, server binding helpers and client
stubs. Also generate the event each Method generates (AlwaysGeneratesEvent),
the mandatory children of a type (ModellingRule Mandatory) and state machine
transitions (HasTransition, FromState, ToState). Handwritten code keeps the
behaviour: transactions, access checks, persistence.

Today the argument positions are written by hand in every Method handler
(`server/pubsub_sks.go`, `server/alarms_methods.go`, `server/push_methods.go`,
`server/trustlist_object.go`, `server/pubsub_config_file.go`,
`uafx/fxserver/cmfile.go`) and in the GDS client (`gds/pull.go`, `gds/gds.go`,
`gds/trustlist.go`); the audit event of each alarm Method is a table
(`server/alarms_methods.go:45-73`), the shelving transitions a switch
(`server/alarms.go:56-90`), the mandatory children of UAFX lists
(`uafx/inspect.go`, `uafx/fxcm/verify.go`).

The pilot is a public Part 20 FileType and FileDirectoryType, server and
client, which replaces the four FileType implementations (TrustList, push,
PubSub configuration file, ConnectionManager file). Then SKS, push, GDS,
alarms and UAFX.

Progress (v1.43.0): the generator `cmd/methods` (run by `make gen`) emits
the contracts of the Methods of the ObjectTypes `cmd/methods/config.go`
selects into package `uamethod`: typed Input and Output structs with Pack
and Unpack (the count, built-in type and ValueRank checks of the Call
service), the NodeIds of the Method and its ObjectType, the clause, and a
call function. The pilot is done: `server.FileObject` (`AddFile`,
`ServeFile`, `NewFile`, `AddFileDirectory`) and package `filetransfer` are
built on the FileType and FileDirectoryType contracts, and the four FileType
implementations and the `gds` and `pubsub/remote` clients of their files use
them. The second families are done too: TrustListType (OpenWithMasks,
CloseAndUpdate, AddCertificate, RemoveCertificate) for `ServeTrustList`,
push certificate management and the `gds` client;
PubSubConfigurationType (ReserveIds, CloseAndUpdate) for the
PubSubConfiguration file and `pubsub/remote`; PubSubKeyServiceType
(GetSecurityKeys, GetSecurityGroup) for the SKS and `pubsub/sks`. The
RoleSet, Role and ServerType Methods are generated as well. What remains:
the GDS DirectoryType and CertificateDirectoryType, whose arguments are
DataTypes outside namespace 0 (ApplicationRecordDataType of the GDS
NodeSet) or subtypes of built-in types the GDS NodeSet alone does not
resolve (`TestNextFamilies`), need the generator to read a NodeSet with
the one of namespace 0 and a contracts package per namespace; the
Methods of ServerConfigurationType, SecurityGroupFolderType and
PubSubKeyPushTargetType, still written by hand, and those of alarms and
UAFX; and the events a Method generates, mandatory children and state
machine transitions, which are not generated.

## Phase 3: core symmetry

| Item | Today |
|---|---|
| DataTypeDefinition Attribute on every DataType, imported and ns=0 | done in v1.43.0 |
| Client decoding of structures it has no Go type for, from DataTypeDefinition, per session and namespace URI | done in v1.43.0, opt in (`opcua.DynamicTypeDecoding`) |
| Part 13 aggregates and AggregateFilter in monitored items | HistoryRead processed: every standard Aggregate (`server/aggregate`, v1.43.0), AnnotationCount over the Annotations of an `AnnotationHistoryProvider`, for the Historian and any raw-only provider, checked against every example of Annex A; AggregateFilter of monitored items with the same calculation, at the publishing interval, AnnotationCount refused as historical only (v1.43.0); no ledger row (no peer of opcua-interop v0.20.0 reads processed history or aggregates monitored items) |
| Part 5 Methods: GetMonitoredItems, ResendData, SetSubscriptionDurable, RequestServerStateChange | done in v1.43.0 (Part 5 §9.1–§9.4), with typed client calls; durable subscriptions in memory only (LIMITATIONS.md); no ledger row (not tested against an independent stack) |
| ModelChange and SemanticChange events | done in v1.43.0 |
| NamespaceMetadata, DefaultRolePermissions | done in v1.43.0 |
| RoleSet Methods (AddRole, AddIdentity and the others) | done in v1.43.0, opt in (`server.WithRoleManagement`; client package `rolemgmt`); persisted with `server.WithRoleSetStore` (`server/rolestore`, phase 4, v1.43.0); no ledger row (no peer of opcua-interop manages roles) |
| AuditWriteUpdate, AuditHistoryUpdate, AuditNodeManagement events | done in v1.43.0, with auditing on (`server.WithChangeAuditing(false)` turns them off); no ledger row |
| History annotations (UpdateStructureData) | done in v1.43.0: UpdateStructureDataDetails, ReadAnnotationDataDetails, the Annotations Property (`EnableAnnotations`), `AnnotationHistoryProvider`, client helpers; no ledger row |
| Client session keepalive while idle | done in v1.43.0 |
| ServerProfileArray | done in v1.43.0: every Mandatory ServerCapabilities Property has a value (Part 5 §6.3.2); ServerProfileArray from `WithServerProfiles`, else the Profiles phase 5 evidences, none yet |

Done in v1.43.0: the DataTypeDefinition Attribute of every Structure, Union,
Enumeration and OptionSet DataType of namespace 0 and of the imported models,
from the NodeSet Definition with the fields of the supertypes (Part 3 §5.8.3,
Part 6 §F.12); see docs/server-guide.md. GeneralModelChangeEvents for the
nodes that have a NodeVersion, with the NodeVersion maintained, and
SemanticChangeEvents with the SemanticsChanged bit (Part 3 §9.32, §9.33).
NamespaceMetadata Objects for every namespace of a NodeNameSpace, from the
NodeSet Models, and DefaultRolePermissions and DefaultAccessRestrictions
applied to the nodes without their own (Part 3 §5.2.9, §5.2.11; Part 5
§6.3.13; Part 6 §F.2).

Also in v1.43.0: the client decodes the Structures and Unions it has no Go
type for from that Attribute, opt in (`opcua.DynamicTypeDecoding`), with
the DataTypes kept by namespace URI; see docs/client-guide.md. Not done: a
DataTypeDictionary (Part 5 Annex D), JSON-encoded bodies, and ledger rows
against an independent server.

Also in v1.43.0: the client session keep-alive. A connected client reads
the ServerStatus State after half the revised session timeout without a
request (`SessionKeepAlive`, Part 4 §5.7.2.1 and §6.7), and a keep-alive
without response is a lost connection; see docs/client-guide.md.

Also in v1.43.0: the managed RoleSet of OPC 10000-18, opt in
(`server.WithRoleManagement`). AddRole and RemoveRole (§4.2.2, §4.2.3),
the Role Methods AddIdentity to RemoveEndpoint (§4.4.5 to §4.4.10) and the
Properties of the roles (§4.4.1), with the roles granted at ActivateSession
next to those of the RoleMapper and re-evaluated for the active sessions on
every change; the client package `rolemgmt`; see docs/server-guide.md and
docs/client-guide.md. Not done: persistence of the configuration (below),
a CustomConfiguration, ledger rows against an independent stack.

## Phase 4: durable administration

One persistence package for the server, PubSub and UAFX, from
`uafx/fxstore` (Store, Batch, Domain):

- a file store for push certificate management, with an ApplyChanges that is
  atomic in the store too: done in v1.43.0. `server/pushstore` writes each
  ApplyChanges and ResetToServerDefaults in one `fxstore.Domain.Apply`,
  `server.New` restores it, and a failed ApplyChanges applies nothing and
  discards its transaction (Part 12 §7.10.2); the persistence package stays
  at `uafx/fxstore` (docs/architecture.md, Persistence);
- persistence of the PubSub configuration of the server, with NotPersisted
  (Part 14 §9.1.2), for the Go API, the configuration Methods and the
  configuration file: done in v1.43.0. `server.WithPubSubStore` with
  `server/pubsubstore` writes each change of any of them in one
  `fxstore.Domain.Apply` and restores it when the server starts; a write
  that fails undoes the change (`Bad_InternalError`). The components
  EstablishConnections creates stay with `uafx/fxserver`
  (`server.PubSubComponentOwner`; docs/architecture.md, Persistence);
- persistence of the managed RoleSet (`server.WithRoleManagement`): the
  roles AddRole added and the Identities, Applications and Endpoints of
  every role, kept in memory since v1.43.0: done in v1.43.0.
  `server.WithRoleSetStore` with `server/rolestore` writes each change in
  one `fxstore.Domain.Apply` after it succeeded and restores the roles,
  their NodeIds and namespaces by URI, when the server starts; a write that
  fails changes nothing (`Bad_InternalError`);
- restart, failed commit and concurrent change tests through each entry
  point.

## Phase 5: profiles and evidence

A profile, conformance unit and test inventory, from which the server
computes ServerProfileArray. First targets: Micro Embedded Device 2025 Server
and Standard UA Client 2025, then the Part 14 UDP UADP Periodic Fixed
publisher and subscriber.

Progress (v1.43.0): the inventory exists for the two first targets
([profiles.md](profiles.md)). `internal/profiles` reads the Profiles from a
pinned export of the Released UACore 1.05 profile group of the OPC
Foundation profile database, expands each target through the Profiles it
includes and maps every ConformanceUnit, mandatory or optional, to tests and
verified rows of `interop/coverage.json`, as evidenced, partial or missing;
`make gen` renders the report and the default ServerProfileArray, and
`go test ./internal/profiles` fails on a test that no longer exists or a
ConformanceUnit without an entry. The first slice left Micro Embedded Device
2025 Server with 16 of 30 mandatory ConformanceUnits evidenced, 10 partial
and 4 missing.

The second slice (v1.43.0) closed 11 of those mandatory server gaps, each
with tests:

- AccessLevel, UserAccessLevel, Historizing and AccessLevelEx on every
  Variable, and WriteFullArrayOnly (Address Space Base, Atomicity and Full
  Array Only).
- ServerArray, ServiceLevel and RedundancySupport (Core Structure 2).
- MaxArrayLength, MaxStringLength, MaxByteStringLength,
  MaxMonitoredItemsQueueSize and the ModellingRules and AggregateFunctions
  Folders (Server Capabilities 2, MaxMonitoredItemsQueueSize and
  Subscriptions).
- The profileUris filter (Get Endpoints).
- The requestHandle of every ServiceFault and the timeoutHint of Publish
  (Session General Service Behaviour).
- The capacities and time synchronization documentation (Core Capacities,
  Time Sync - Support).

The server Profile now has 27 of 30 evidenced, 3 partial and none missing.
Standard UA Client 2025 has 33 of 48 evidenced, 12 partial and 3 missing.
Neither is claimed, so the computed ServerProfileArray is empty; the gaps are
listed in the report and in LIMITATIONS.md.

Next slices: close the three partial units of the server Profile. These are
sessions served in parallel (Session Multiple), a default certificate
(Security Default ApplicationInstance Certificate) and the SemanticsChanged
bit for a value from a data source (SemanticChange Bit). Then close the gaps
of the client Profile; make a claim depend on the
configuration of the server (a Profile is claimed only for the endpoints,
security and limits it is configured with), and only then serve the
ConformanceUnits Property; ledger rows against independent peers for the
units tested Go to Go only; the Part 14 UDP UADP Periodic Fixed publisher
and subscriber Profiles.

## Phase 6: UAFX Part 84

On the persistence of phase 4: SecurityKeyServer of the ConnectionManager
wired to `pubsub/sks`, ConnectionManager and AutomationComponent logs,
publisher QoS, ConfigurationData and VariableStorage persisted. See the
limits in [uafx.md](uafx.md#limits).

Progress (v1.43.0): the SecurityKeyServer of the ConnectionManager is wired
to `pubsub/sks` with the pull model (Part 81 §6.7.3.2, §6.7.3.3, E.5):
`fxcm.Options.SecurityKeyServer` (`RemoteSKS`, `LocalSKS`) adds and removes
the SecurityGroups of a set, kept as `sks/` records of the Store, and names
the SKS in the SecurityKeyServices; `fxserver.ConnectionOptions.SecurityKeys`
(`sks.Puller`, `sks.EndpointDialer`) pulls the keys on the
AutomationComponents. Not done: the push model and PubSubKeyPushTargets;
no ledger row (no peer of opcua-interop implements UAFX). Next: the logs.

## Later, on demand

OpenAPI mapping (Part 6 Annex G), Parts 82 and 83, TSN, AMQP over
WebSockets, generation of the service types from Opc.Ua.NodeSet2.Services.xml
instead of Opc.Ua.Types.bsd (with the BSD output as the oracle).
