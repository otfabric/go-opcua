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

## Phase 3: core symmetry

| Item | Today |
|---|---|
| DataTypeDefinition Attribute on every DataType, imported and ns=0 | Read returns Bad_AttributeIdInvalid; the importer parses the definition and drops it |
| Client decoding of structures it has no Go type for, from DataTypeDefinition, per session and namespace URI | one process-wide registry keyed by NodeId; unknown bodies stay raw |
| Part 13 aggregates and AggregateFilter in monitored items | HistoryRead processed: every standard Aggregate but AnnotationCount (`server/aggregate`, v1.43.0), for the Historian and any raw-only provider, checked against every example of Annex A; AggregateFilter is refused; no ledger row (no peer of opcua-interop v0.20.0 reads processed history) |
| Part 5 Methods: GetMonitoredItems, ResendData, SetSubscriptionDurable, RequestServerStateChange | not implemented |
| ModelChange and SemanticChange events | never emitted |
| NamespaceMetadata, DefaultRolePermissions | not implemented; a node without RolePermissions is allowed |
| RoleSet Methods (AddRole, AddIdentity and the others) | roles only from the Go RoleMapper |
| AuditWriteUpdate, AuditHistoryUpdate, AuditNodeManagement events | not emitted |
| History annotations (UpdateStructureData) | not dispatched |
| Client session keepalive while idle | only silent subscriptions are found |
| ServerProfileArray | no value; Read returns Bad_AttributeIdInvalid |

Done in v1.43.0: the DataTypeDefinition Attribute of every Structure, Union,
Enumeration and OptionSet DataType of namespace 0 and of the imported models,
from the NodeSet Definition with the fields of the supertypes (Part 3 §5.8.3,
Part 6 §F.12); see docs/server-guide.md.

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
