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
them. Not generated yet: the events a Method generates, mandatory children
and state machine transitions. The next families, TrustListType
(OpenWithMasks, CloseAndUpdate, AddCertificate, RemoveCertificate),
PubSubConfigurationType (ReserveIds, CloseAndUpdate) and
PubSubKeyServiceType (GetSecurityKeys, GetSecurityGroup), resolve with the
generator as it is (`TestNextFamilies`): adding them to the config and
moving their handlers and clients is the work. The GDS DirectoryType and
CertificateDirectoryType need DataTypes outside namespace 0
(ApplicationRecordDataType of the GDS NodeSet) and a contracts package per
namespace.

## Phase 3: core symmetry

| Item | Today |
|---|---|
| DataTypeDefinition Attribute on every DataType, imported and ns=0 | done in v1.43.0 |
| Client decoding of structures it has no Go type for, from DataTypeDefinition, per session and namespace URI | done in v1.43.0, opt in (`opcua.DynamicTypeDecoding`) |
| Part 13 aggregates and AggregateFilter in monitored items | HistoryRead processed: every standard Aggregate but AnnotationCount (`server/aggregate`, v1.43.0), for the Historian and any raw-only provider, checked against every example of Annex A; AggregateFilter of monitored items with the same calculation, at the publishing interval (v1.43.0); no ledger row (no peer of opcua-interop v0.20.0 reads processed history or aggregates monitored items) |
| Part 5 Methods: GetMonitoredItems, ResendData, SetSubscriptionDurable, RequestServerStateChange | done in v1.43.0 (Part 5 §9.1–§9.4), with typed client calls; durable subscriptions in memory only (LIMITATIONS.md); no ledger row (not tested against an independent stack) |
| ModelChange and SemanticChange events | done in v1.43.0 |
| NamespaceMetadata, DefaultRolePermissions | done in v1.43.0 |
| RoleSet Methods (AddRole, AddIdentity and the others) | roles only from the Go RoleMapper |
| AuditWriteUpdate, AuditHistoryUpdate, AuditNodeManagement events | not emitted |
| History annotations (UpdateStructureData) | not dispatched |
| Client session keepalive while idle | done in v1.43.0 |
| ServerProfileArray | done in v1.43.0: every Mandatory ServerCapabilities Property has a value (Part 5 §6.3.2); ServerProfileArray from `WithServerProfiles`, empty by default, until phase 5 computes it |

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

## Phase 4: durable administration

One persistence package for the server, PubSub and UAFX, from
`uafx/fxstore` (Store, Batch, Domain):

- a file store for push certificate management, with an ApplyChanges that is
  atomic in the store too (today it writes group by group,
  `server/push.go:659-706`, and a failed group leaves the earlier ones
  written);
- persistence of the PubSub configuration of the server, with NotPersisted
  (Part 14 §9.1.2), for the Go API, the configuration Methods and the
  configuration file;
- restart, failed commit and concurrent change tests through each entry
  point.

## Phase 5: profiles and evidence

A profile, conformance unit and test inventory, from which the server
computes ServerProfileArray. First targets: Micro Embedded Device 2025 Server
and Standard UA Client 2025, then the Part 14 UDP UADP Periodic Fixed
publisher and subscriber.

## Phase 6: UAFX Part 84

On the persistence of phase 4: SecurityKeyServer of the ConnectionManager
wired to `pubsub/sks`, ConnectionManager and AutomationComponent logs,
publisher QoS, ConfigurationData and VariableStorage persisted. See the
limits in [uafx.md](uafx.md#limits).

## Later, on demand

OpenAPI mapping (Part 6 Annex G), Parts 82 and 83, TSN, AMQP over
WebSockets, generation of the service types from Opc.Ua.NodeSet2.Services.xml
instead of Opc.Ua.Types.bsd (with the BSD output as the oracle).
