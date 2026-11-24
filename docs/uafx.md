# OPC UA FX (UAFX)

go-opcua reads and serves the information model of OPC UA FX, OPC 10000-81
version 1.00.04 (Connecting Devices and Information Model), and it
establishes and closes non-persistent UAFX connections with PubSub: a
server answers EstablishConnections and CloseConnections (Part 81 §6.2.4,
§6.2.5), and a client calls them, with the ControlGroups of §6.5.
Of the ConnectionManager (§6.7 to §6.16) there is the configuration model
of package `uafx/fxcm` ([ConnectionManager configuration](#connectionmanager-configuration)):
it validates ConnectionConfigurationSets and reads and writes their files,
but establishes nothing yet. Persistent connections are not implemented,
and none of the profiles of Part 84 is claimed. What is missing is listed under [Limits](#limits).

| Package | What it holds |
|---|---|
| `uafx` | `Inspect`: reads the UAFX model of a server into a `Report`; `EstablishConnections` and `CloseConnections` call the Methods of an AutomationComponent; the DataTypes of the UAFX namespaces, generated from the NodeSets, with their binary encoding ([Structures](#structures)) |
| `uafx/fxcm` | The configuration model of a ConnectionManager: `NewConfig` validates a ConnectionConfigurationSet, `DecodeFile` and `EncodeFile` read and write its file (Annex F), the state machine of a set, the edit of §6.7.4, and the ownership and diagnostics rules |
| `uafx/fxserver` | `AddModel`: adds the UAFX model to a `server.Server`; `ImportNodeSet` imports NodeSets that build on it; `EnableConnections` serves EstablishConnections and CloseConnections |
| `uafx/fxdataid`, `uafx/fxacid`, `uafx/fxcmid` | NodeIds of the UAFX Data, AutomationComponent (AC) and ConnectionManager (CM) namespaces |
| `di/diid` | NodeIds of the Devices (DI) model of OPC 10000-100, which the UAFX model builds on |

The NodeSets are those the OPC Foundation publishes in the
[UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset) repository
(folders `UAFX` and `DI`, MIT license), embedded in `uafx/internal/model`.
`schema/update-schema.sh` downloads them, `make gen` generates the NodeId
packages and the DataTypes.

## Inspecting a server

```go
r, err := uafx.Inspect(ctx, client, uafx.Limits{})
if err != nil {
	return err // a service call failed
}
fmt.Println("UAFX namespaces:", r.HasFXNamespaces(), "UAFX server:", r.IsFXServer())
for _, ac := range r.AutomationComponents {
	if h := ac.AggregatedHealth; h != nil {
		fmt.Println(ac.BrowseName.Name, h.AggregatedDeviceHealth, h.AggregatedOperationalHealth)
	}
	for _, fe := range ac.FunctionalEntities {
		for _, ep := range fe.ConnectionEndpoints {
			fmt.Println("  ", fe.BrowseName.Name, ep.BrowseName.Name, ep.Status)
		}
	}
}
for _, f := range r.Findings {
	fmt.Println(f) // e.g. "Broken: AutomationComponent has no mandatory Assets (Part 81 §6.2.2)"
}
```

`Inspect` reads:

| What | Where |
|---|---|
| The namespaces DI, UAFX Data, AC and CM, with the version and publication date of their NamespaceMetadata | NamespaceArray, Server/Namespaces (Part 81 §14.1) |
| The server capability identifiers (FXAC, FXCM) | ServerConfiguration/ServerCapabilities |
| FxRoot | Part 81 §12.2 |
| AutomationComponents organized by FxRoot, of AutomationComponentType or a subtype: ConformanceName, AggregatedHealth, Descriptors | §6.2.2 |
| Their Assets (FxAssetType): the nameplate (Manufacturer, Model, SerialNumber, revisions, ...) | §6.3.2 |
| Their FunctionalEntities and SubFunctionalEntities: author, version, OperationalHealth | §6.4.2 |
| The ConnectionEndpoints of the FunctionalEntities: Status, IsPersistent, CleanupTimeout | §6.6.2, §6.6.3 |
| The ConnectionManager organized by FxRoot and its ConnectionConfigurationSets | §6.7.2, §12.3 |

A type is recognised by the HasSubtype chain of the server, so vendor
subtypes count; a supertype the server cannot tell ends the inspection
with `ErrInspect` instead of leaving the node out. A member of a type is
matched by its BrowseName in the namespace of the standard that defines it
(Part 81 §14.2): the members of the UAFX types in AC or CM, the nameplate
of an asset in DI. A vendor child with the same name in another namespace
is not taken for it. The structures AggregatedHealthDataType and FxVersion are
decoded with the namespace index the server has for AC: their encoding
NodeIds differ from server to server, so they are not registered with
package `ua`, and other UAFX structures stay undecoded ExtensionObjects.

### Findings

A Finding is a deviation from Part 81 that the address space shows:

- the UAFX Data namespace without AC and CM or without DI, or AC or CM
  without Data (§14.2);
- the Data namespace without FxRoot (§12.2);
- more than one ConnectionManager under FxRoot (§12.3);
- an AutomationComponent, ConnectionEndpoint, PubSubConnectionEndpoint or
  ConnectionManager without one of its mandatory members (§6.2.2, §6.6.2,
  §6.6.3, §6.7.2), by the ModellingRules of the NodeSets (a test checks the
  lists against the embedded NodeSets);
- an AggregatedHealth or AuthorAssignedVersion value that cannot be decoded
  (§10.1, §10.28).

Findings are not a conformance test: the OPC Foundation's UAFX test
scripts check far more, including behaviour.

### Limits

`HasFXNamespaces` tells whether the server has the namespaces Part 81
§14.2 requires (DI, Data, and AC or CM); `IsFXServer` whether it also has
FxRoot (§12.2). Neither is a conformance statement.

`Limits` bounds what `Inspect` reads from a large or hostile server:
`MaxComponents` (AutomationComponents and ConnectionManagers, default
256), `MaxChildren` (children of one node, default 1024), `MaxDepth`
(nesting of SubFunctionalEntities, default 8) and `MaxNodes` (nodes in
the report, default 10000). `Report.Truncated` tells that a limit was
reached. A node the server shows in two places, or in a cycle, is
reported once; the HasSubtype chain is followed for at most 32 levels.
Every page of a Browse counts against the limits, the first one
included. Continuation points are always released, with a context of
their own when the context of `Inspect` is done, and a server that
returns an empty page with a continuation point ends the paging. No
Read asks for more nodes than the MaxNodesPerRead of the server
(Part 5 §6.3.11).

## Adding the model to a server

```go
srv, _ := server.New(server.EndPoint("localhost", 4840), server.ApplicationURI("urn:example:my-device"))
ns, err := fxserver.AddModel(srv) // namespace 1, DI, Data, AC and CM
if err != nil {
	return err
}
// The AutomationComponent of this server, as a NodeSet in its own
// namespace that refers to the UAFX types.
if err := fxserver.ImportNodeSet(srv, myComponentNodeSet); err != nil {
	return err
}
_ = srv.Start(ctx)
```

`AddModel(srv, fxserver.ModelAC)` or `fxserver.ModelCM` adds only one of the
two optional namespaces (Part 81 §14.2); the CM model brings the
ConnectionManager instance of §12.3.

Namespace index 1 is the namespace of the local server (Part 81 §14.2,
Table 260), and its URI is the ApplicationUri of the server (Part 5
§6.3.1). On a server with no namespace besides namespace 0, `AddModel`
adds it first, named by the ApplicationUri (`server.ApplicationURI` or the
URI of its certificate). A server without an ApplicationUri, or whose
namespace 1 has another URI, is refused with `ErrModel`.

A DI namespace the server has already is used if it holds the DI nodes
the UAFX model refers to (the ObjectTypes FunctionalGroupType,
LockingServicesType, SoftwareUpdateType, the nameplate and health
interfaces, and the Methods of LockingServicesType), each with the
NodeClass of the DI NodeSet; otherwise `AddModel` fails with `ErrModel`
before it imports anything.

`ImportNodeSet` maps the namespace table of a NodeSet document to the
namespace indexes of the server (Part 6 §F.2): a namespace the server has
keeps its index, a new one is added. The table is the one NamespaceUris
element of the document element; a document with two is refused. Only the places where Part 6 Annex F
puts a NodeId or a QualifiedName are rewritten: NodeId attributes,
reference targets, aliases, BrowseName prefixes, the NamespaceIndex of a
QualifiedName value, and the Identifier of a NodeId in a value: of a
NodeId or ExpandedNodeId value, of the TypeId of an ExtensionObject, and
of the NodeId fields of Argument, StructureField, StructureDefinition and
RolePermissionType bodies. The body of any other structure is copied as
it is, since the document does not give the types of its fields: a NodeId
field of a vendor structure keeps the index of the document. Descriptions,
strings, comments and Extensions are copied as they are, whatever they
hold. `server.ImportNodeSetXML` does not map
indexes; it adds every namespace of the document and takes the NodeIds as
they are.

## Connections

A UAFX connection is a pair of ConnectionEndpoints, one on each
AutomationComponent, whose FunctionalEntities exchange their input and
output Variables (Part 81 §5.5). A client, usually an engineering tool or
a ConnectionManager, establishes each side by calling EstablishConnections
on the AutomationComponent; the data then flows over PubSub, not over the
client's session.

### Serving the Methods

```go
srv, _ := server.New(server.EndPoint("localhost", 4840),
	server.ApplicationURI("urn:example:my-device"),
	server.WithPubSub(rt)) // the PubSub runtime and its information model
ns, err := fxserver.AddModel(srv)
if err != nil {
	return err
}
if err := fxserver.ImportNodeSet(srv, myComponentNodeSet); err != nil {
	return err
}
conns, err := fxserver.EnableConnections(srv, ns, fxserver.ConnectionOptions{
	MaxConnections: 16,
	Interval:       100 * time.Millisecond,
})
if err != nil {
	return err
}
defer conns.Close()
_ = srv.Start(ctx)
```

`EnableConnections` registers EstablishConnections and CloseConnections on
every AutomationComponent below FxRoot. It adopts the
PubSubConnectionEndpoints the AutomationComponents have already
(preconfigured, §5.5.5): their Status follows the DataSetReader and
DataSetWriter their ToDataSetReader and ToDataSetWriter References point
to. When an instance of a Method has no InputArguments or OutputArguments
property, it gets those of the Method of AutomationComponentType, which the
Call service checks the arguments against.

EstablishConnections runs the commands of its CommandMask in the order of
§6.2.4.3.1:

| Command | What the server does |
|---|---|
| VerifyAssetCmd | Calls `ConnectionOptions.AssetVerifier` for each Asset (§6.3.3); without one `Bad_NotSupported` |
| VerifyFunctionalEntityCmd | Compares the expected values with those of the FunctionalEntity, as its Verify Method does (§6.4.3, Table 45); see [Verification](#verification) |
| ReserveCommunicationIdsCmd | Reserves WriterGroupIds and DataSetWriterIds as ReserveIds does (Part 14 §9.1.3.7.5); the TransportSpecificInfo of UDP-UADP is `ConnectionOptions.UDPPort` |
| CreateConnectionEndpointCmd | Creates a PubSubConnectionEndpoint in the ConnectionEndpoints folder of the FunctionalEntity, or takes the preconfigured one of that name when it is not in use (§6.2.4.3.5, Table 12) |
| EstablishControlCmd | See [ControlGroups](#controlgroups) |
| SetConfigurationDataCmd | Writes the ConfigurationData Variables with the rights of the caller (`server.WriteValue`) |
| ReassignControlCmd | See [ControlGroups](#controlgroups) |
| SetCommunicationConfigurationCmd | Applies the PubSub configuration as CloseAndUpdate does (Part 14 §9.1.3.7.4) and links each endpoint to its DataSetReader and DataSetWriter, after checking that they exist and that their DataSets carry the Variables of the endpoint |
| EnableCommunicationCmd | Enables the DataSetReaders and DataSetWriters of the endpoints and their groups and connections |

The PubSub commands and the writes run with the session of the caller, as
the PubSubConfiguration Methods and the Write service would for that
session: the `AccessController`, the AccessRestrictions of the Method
nodes, the `PubSubAuthorizer` and the access levels apply; the server has
no privileged path. A refused write is `Bad_UserAccessDenied`.

When a command fails the call is aborted (§6.2.4.3.11): it returns
Uncertain, the failed elements have their Bad code, the commands that did
not run have `Bad_NothingToDo`, and what the call did is undone as Table 21
asks: the components it enabled are disabled, the PubSub configuration it
applied is reverted, the References it set are removed and the endpoints it
created are deleted, a preconfigured endpoint gets its RelatedEndpoint,
CleanupTimeout and IsPersistent back. ConfigurationData it wrote and ids it
reserved stay, as Table 21 says. A Bad status of the call (Table 9) is
returned for arguments that do not fit Table 8, for a call over
`MaxConnectionsPerCall` (`Bad_TooManyOperations`), and, with
`CommandBundleRequired`, for a call without CreateConnectionEndpointCmd and
SetCommunicationConfigurationCmd together (§6.2.4.3.1).

CloseConnections (§6.2.5) disables the DataSetReader and DataSetWriter of
each endpoint that no other endpoint references and stops its
CleanupTimeout. With Remove it also removes the reader and writer the
connection's calls configured, unless another endpoint references them,
and deletes the endpoint unless it is preconfigured: a preconfigured
endpoint keeps its nodes, loses its RelatedEndpoint and can be used again.
The groups, PubSubConnections and PublishedDataSets stay. An endpoint of
another AutomationComponent is `Bad_NodeIdUnknown`, a node that is not a
ConnectionEndpoint `Bad_InvalidArgument` (Table 24).

When a PubSub operation of the close fails, the result of that endpoint is
the StatusCode of the runtime's error, or `Bad_InternalError` when it has
none, and the call returns Uncertain (Table 23). Table 24 has no code for
a failed close. The endpoint is then not deleted and keeps its References
to the reader and writer that are left, and a preconfigured one keeps its
RelatedEndpoint, so that the caller can see the endpoint and close it
again. A reader or writer that is disabled already, or gone, is not a
failure, and a removal that succeeds after a failed disable stops the
component as well.

### Status, health and cleanup

Every `ConnectionOptions.Interval` (100 ms by default) the Status of each
endpoint follows its DataSetReader and DataSetWriter (§6.6.3, Figures 31 to
33): Initial without them, Ready while they are disabled or paused,
PreOperational, Operational and Error as their PubSub state. The CommHealth
of the ConnectionEndpoints folders (§6.4.8, §10.9), bits 0 to 15 of the
OperationalHealth of the FunctionalEntities (§10.34) and the
AggregatedOperationalHealth of the AutomationComponents (§9.1.2) follow.
Bits 16 to 31 of an OperationalHealth are the application's; call
`Connections.RefreshHealth` after changing them or the FunctionalEntities:
between calls of the Methods the health is recomputed when the Status of
an endpoint changes.

The CleanupTimeout of an endpoint starts when its Status leaves
Operational (§6.6.2); when it expires before the endpoint is Operational
again, the server closes the endpoint as CloseConnections with Remove
does, and reports an AuditConnectionCleanupEventType event (§8.3) when it
audits. An endpoint that was never Operational is not cleaned up, nor one
whose CleanupTimeout is negative. The expiry is checked every Interval,
and decided while no EstablishConnections or CloseConnections runs: an
endpoint a CloseConnections closed after the CleanupTimeout expired, or
one that is Operational again, is not removed. When the close of the
cleanup fails, the event has Status false, the endpoint stays, and the
cleanup is tried again after another CleanupTimeout, one second at the
earliest.

A server that audits reports an AuditUpdateMethodResultEventType event for
each call of EstablishConnections and CloseConnections (§6.2.4.2, §6.2.5.1, §8.4), with the
AutomationComponent as its SourceNode.

### Verification

VerifyFunctionalEntityCmd compares each NodeIdValuePair with the value of
its Variable (§6.4.3, Table 45). It reads the value with the rights of the
caller (`server.ReadValue`): the `AccessController` (CheckRead), the
AccessRestrictions and the UserAccessLevel apply as for a Read by that
session. A Variable the caller may not read fails with the status the Read
service would return, such as `Bad_UserAccessDenied`, whether the expected
value is right or not, so that verification does not tell a value the
caller cannot read. Table 45 has no code for this. A pair with a null
value checks that the node exists and needs no read.

String values, and the elements of String arrays, are compared without
their leading and trailing whitespace. An ApplicationIdentifier of a
FunctionalEntity (a Variable with the BrowseName ApplicationIdentifier of
the AC namespace) is compared by the UniqueIdentifier of each element
alone; its Name is ignored. This needs the binary encoding of
ApplicationIdentifierDataType (§10.3), which a client sends; a value the
server holds in another encoding is compared as a whole. An
ExtensionObject of a structure package `ua` does not know (the UAFX and
other companion structures) is compared by its TypeID and binary body.
Other values are compared as they are, with the ArrayIndex of §10.31.

The server does its own comparison: a handler an application registers on
the Verify Method of a FunctionalEntity is not called by
VerifyFunctionalEntityCmd, and Verify called on its own is not
implemented. VerifyAssetCmd calls `ConnectionOptions.AssetVerifier`,
which is given the context of the call and is the application's to
restrict.

### ControlGroups

A ControlGroup (Part 81 §6.5) restricts Variables and Methods of a
FunctionalEntity with the LockingServices of OPC 10000-100 §7. Its
ControlItemFolders ListToBlock and ListToRestrict each have a Lock and
organize the Variables, Methods and Objects they cover. `EnableConnections`
serves the ControlGroups in the ControlGroups folders of the
FunctionalEntities:

| While the Lock of… | is held | Others get |
|---|---|---|
| ListToBlock | no one writes its Variables or calls its Methods, the owner neither | `Bad_Locked` |
| ListToRestrict | only the owner writes its Variables and calls its Methods | `Bad_Locked` |

The check applies to the Write service, `server.WriteValue` and the Call
service, after the `AccessController` (a `server.Guard`, see below). An
owner's write or call renews its Lock. The owner is a client application,
known by the ApplicationUri it sent with CreateSession (the LockingClient;
the LockingUser is the user name, the subject of an X.509 identity,
`Issued` or `Anonymous`), or a ConnectionEndpoint, whose Locks have the
LockingClient of its NodeId and the LockingUser `UAFX` (§6.5.2).

An Object in a list stands for its hierarchy: the Lock covers the Object,
the Variables, Methods and Objects it reaches with HierarchicalReferences
(Part 3 §7.3), ControlGroups excepted, and the Methods called on any of
them. §6.5.2 allows Objects in the lists and locks the "Variables or Methods
in the hierarchical structure of instances", without saying more; this is
the library's reading. The nodes are found when `EnableConnections` runs: a
node added below such an Object later is not covered. An item that stands
for more than 4096 nodes makes `EnableConnections` fail with
`ErrConnections` instead of protecting a part of it.

Who may administer control:

| Operation | Allowed by default to |
|---|---|
| EstablishControl, ReleaseControl, ReassignControl, and EstablishControlCmd and ReassignControlCmd of EstablishConnections | sessions with the well-known Role ConnectionAdmin (§5.9), as §6.5.3 to §6.5.5 recommend |
| BreakLock | sessions with ConnectionAdmin (OPC 10000-100 §7.8: users with administrator rights) |
| CloseConnections with Remove of a ConnectionEndpoint that controls ControlGroups, which releases them (§6.2.5.2) | sessions with ConnectionAdmin; the others get `Bad_UserAccessDenied` for that endpoint, and nothing of it is closed |
| SetConfigurationDataCmd writing, as an existing ConnectionEndpoint, a Variable of a Lock that endpoint holds | sessions with ConnectionAdmin; the others get `Bad_UserAccessDenied` for that value (Table 14) |
| InitLock, RenewLock, ExitLock | anyone the `AccessController` allows; RenewLock and ExitLock only the owner |

The others get `Bad_UserAccessDenied`. A `server.RoleMapper`
(`server.WithRoleMapper`) grants ConnectionAdmin, whose NodeId is
`Namespaces.ConnectionAdmin()` (i=5019 of the Data namespace). A
`ConnectionOptions.ControlAuthorizer` replaces the default: it gets each
operation with the ControlGroup, the Lock of BreakLock, the LockContext
and the caller, so an application can, for example, let clients control
groups for themselves (an empty LockContext or their own ApplicationUri)
but not for others. EstablishConnections and CloseConnections themselves,
which §6.2.4.1 and §6.2.5.1 also recommend restricting to ConnectionAdmin,
stay with the `AccessController` and RolePermissions, as in v1.37.0: the
default `server.DefaultAccessController` lets any session call them, so a
client without ConnectionAdmin can still create, close and remove
ConnectionEndpoints that control no ControlGroups. A deployment that
restricts connections sets `server.WithAccessController` (or
RolePermissions) as well.

| Method | What the server does |
|---|---|
| EstablishControl(LockContext) | Takes both Locks for the owner, all or none: the caller for a null LockContext, the client of that ApplicationUri otherwise, a ConnectionEndpoint of the server for its NodeId (§6.5.3). LockStatus -1 when a Lock, or a Lock of another ControlGroup on the same item, is held by another owner; -2 for a NodeId that is not a ConnectionEndpoint. Sets IsControlled |
| ReleaseControl() | Releases both Locks and clears IsControlled (§6.5.4); the controller only, else `Bad_UserAccessDenied` |
| ReassignControl(LockContext) | Gives the held Locks to another owner (§6.5.5); the controller only. LockStatus -1 when no Lock is held, -2 when the new owner holds another item of the group through another ControlGroup; a null LockContext or a NodeId that is not a ConnectionEndpoint is `Bad_InvalidArgument` |
| InitLock, RenewLock, ExitLock, BreakLock of each Lock | As OPC 10000-100 §7.5 to §7.8: E_AlreadyLocked and E_NotLocked are -1. RenewLock and ExitLock are the owner's (`Bad_UserAccessDenied`); InitLock on the Lock of a group controlled by someone else is `Bad_UserAccessDenied`. BreakLock releases any held Lock, for a ConnectionAdmin. ExitLock, BreakLock and a timeout leave IsControlled as it is |

A Lock without activity of its owner goes after the MaxInactiveLockTime of
its ControlItemFolder (§6.5.6), else that of the ServerCapabilities (OPC
10000-100 §7.4). `ConnectionOptions.MaxInactiveLockTime` sets the latter
and writes it to the ServerCapabilities; without it the value of the
property counts, else one minute. The Locks a client session took go when
the session ends (OPC 10000-100 §7.2). The Locks of a ConnectionEndpoint
are renewed while its Status is not Error, and its ControlGroups have a
Controls Reference from the endpoint. A ControlGroup a client controls has
none: §6.5.2 wants one from "the Object associated with the Client
connection" (OPC 10000-100), which a go-opcua server does not have; the
LockingClient of its Locks names the client.

A lock request is refused while an operation runs that the Lock would
prevent (OPC 10000-100 §7.2): InitLock and EstablishControl return
LockStatus -1 (EstablishControlCmd `Bad_Locked`) while a write or call of
an item runs that is not the new owner's, or any for ListToBlock. §7.2
gives no LockStatus for it; -1, which a client tries again, is the
library's choice. The server handles requests one at a time, so this is a
Write a `server.ValueWriter` takes, which runs after its request handler
returned, until it is answered; the Lock follows the operations with a
`server.OperationGuard`. ReassignControl is not a lock request and is not
refused. Expiry and the end of a
session wait for an EstablishConnections or CloseConnections call in
progress, so the Locks EstablishControlCmd took are still there for the
ReassignControlCmd of the same call.

In EstablishConnections:

| Command | What the server does |
|---|---|
| EstablishControlCmd | EstablishControl for the caller on each ControlGroup of the element (§6.2.4.3.6). LockStatus -1 is `Bad_Locked`, -2 `Bad_InvalidState`: Tables 13 and 15 list no code for them, so this mapping is the library's |
| SetConfigurationDataCmd | Writes as the ConnectionEndpoint of the element: a Variable it may not write because of a Lock is `Bad_UserAccessDenied` (Table 14) |
| ReassignControlCmd | ReassignControl to the ConnectionEndpoint (§6.2.4.3.8), from the caller or from that endpoint; a ControlGroup controlled by someone else is `Bad_UserAccessDenied`, one that is not controlled `Bad_InvalidState` |

Table 8 requires at least one ConnectionEndpointConfiguration with
ControlGroups when EstablishControlCmd or ReassignControlCmd is set; an
element with an empty list is a no-op, and a ControlGroup the
FunctionalEntity does not have is `Bad_NodeIdUnknown`. When the call
aborts, the ControlGroups its EstablishControlCmd controlled are released;
ReassignControlCmd is not undone (Table 21). The ControlGroups a
ConnectionEndpoint controls are changed only through EstablishConnections
and CloseConnections: their Methods answer `Bad_UserAccessDenied` to
clients. CloseConnections with Remove releases them (§6.2.5.2), also when
the CleanupTimeout closes the endpoint; without Remove they stay.

The checks run in a `server.Guard`, which the server consults after the
`AccessController` for every write and call; `server.SessionEndGuard`
learns when sessions end. An application can add its own with
`Server.AddGuard`.

### Persistence

Persistent connections are not supported: the AutomationComponents keep
their SupportsPersistence false, and a ConnectionEndpointDefinition with
IsPersistent is `Bad_NotSupported` (Table 12). Endpoints and PubSub
configuration a call created do not survive a server restart.

### Calling the Methods

```go
res, err := uafx.EstablishConnections(ctx, client, acNodeID, &uafx.EstablishConnectionsRequest{
	CommandMask: uafx.CreateConnectionEndpointCmd | uafx.SetCommunicationConfigurationCmd |
		uafx.EnableCommunicationCmd,
	ConnectionEndpointConfigurations: []*uafx.ConnectionEndpointConfiguration{cfg},
	CommunicationConfigurations:      []*uafx.PubSubCommunicationConfiguration{pubsubCfg},
})
if err != nil {
	return err // a Bad status of the call (errors.As with a ua.StatusCode), or a transport error
}
if res.Status == ua.StatusUncertain {
	// The call was aborted: the per-element results say what failed.
}
endpoint := res.ConnectionEndpointConfigurationResults[0].ConnectionEndpointID
// ...
status, results, err := uafx.CloseConnections(ctx, client, acNodeID, []*ua.NodeID{endpoint}, true)
```

The client finds the Method by its BrowseName in the AC namespace and
encodes the structures with the index the server has for the UAFX Data
namespace. `EncodeEstablishConnectionsRequest` and the other codecs are
for a server or proxy of its own.

## Structures

The enumerations, OptionSets and structures of the UAFX Data, AC and CM
namespaces (Part 81 §10 and the CM namespace) are generated by `cmd/uafx` from the NodeSets
in `uafx/internal/model`, with their binary encoding (Part 6 §5.2.6 to
§5.2.8):

- A structure is a pointer to a Go struct. The fields of a supertype come
  first, as in the encoding.
- An optional field is a pointer, a slice or an interface, nil when it is
  absent; the EncodingMask is written from the fields that are set. An
  optional array that is present but null (length -1) decodes as an empty
  slice, so it stays present when it is encoded again, with the length 0:
  Part 6 §5.1.11 makes null and empty arrays semantically the same, but an absent
  field differs from a present one. An optional structure of an abstract
  DataType that is present but a null ExtensionObject is `ErrCodec`, as a
  union option is; there is none in the NodeSets of version 1.00.04.
- A union is a struct with one field per option, all pointers, slices or
  interfaces: at most one is set, none for the null union. Encoding a
  union with two set is an error.
- An abstract structure, such as `ConnectionEndpointParameter` or
  `ReserveCommunicationIDs`, is an interface its concrete structures
  implement. A field of that DataType, or one that allows subtypes, is an
  ExtensionObject on the wire and takes any of them; a decoder accepts only
  those.
- The names and docs of the types of v1.37.0 are kept
  (`cmd/uafx/config.go`).

Package `ua` cannot register these structures: their encoding NodeIds
depend on the namespace indexes of each server. `EncodeStructure` and
`DecodeStructure` take them as `NamespaceIndexes`:

```go
ns := uafx.NamespaceIndexes{Data: dataIdx, AC: acIdx, CM: cmIdx} // from the server's NamespaceArray
eo, err := uafx.EncodeStructure(&uafx.ApplicationIdentifier{
	Name:             ua.NewLocalizedText("controller"),
	UniqueIdentifier: &uafx.ApplicationID{IDString: &id},
}, ns)
// ...
v, err := uafx.DecodeStructure(eo, ns) // a *uafx.ApplicationIdentifier, or ErrCodec
```

`DecodeStructure` takes input from the other side of a connection: an
array length beyond the bytes that are left, an undefined EncodingMask
bit, a SwitchField beyond the options, a nested structure of another
DataType than the field's and bytes after the structure are `ErrCodec`;
nesting is bounded by the DataTypes, which do not contain themselves.

The generated code is checked against sources it is not generated from:
the Binary Schemas of the same NodeSets (`schema/opc.ua.fx.*.nodeset2.bsd`,
`TestSchemaMatchesBinarySchema`: every DataType, the order of the fields,
the EncodingMask bits, the SwitchValues, which fields are ExtensionObjects,
and the names and values of the enumerations and the bits and width of the
OptionSets against the Go constants), byte fixtures written by hand from Part 6
(`TestStructureFixtures`), and the bytes of the EstablishConnections
arguments of v1.37.0 (`TestGoldenReleaseB`).

## ConnectionManager configuration

Package `uafx/fxcm` is the first stage of a ConnectionManager (Part 81
§6.7). It holds the model a ConnectionManager works on; it makes no calls
to a server, and nothing is established yet. The design of the whole
ConnectionManager, with the stages that follow, is in
`docs/design/uafx-connection-manager.md` (go-opcua pull request 44).

A set is the Annex F structure `uafx.ConnectionConfigurationSetConf`.
`NewConfig` validates it and returns an immutable `Config`, Version 1
(§6.8.2: a set that is added or replaced has Version 1). An invalid set is
a `*ConfigError` with one `Finding` per defect, each with its path in the
set and the clause it breaks; `ErrConfig`, `ua.StatusBadConfigurationError`
and the FxError ConnectionConfigurationSetInvalid go with it.

```go
cfg, err := fxcm.NewConfig(set)
var ce *fxcm.ConfigError
if errors.As(err, &ce) {
	for _, f := range ce.Findings {
		fmt.Println(f.Path, f.Problem, f.Clause)
	}
}
```

What `NewConfig` checks:

| Rule | Clause |
|---|---|
| One or more Connections, CommunicationFlows, ServerAddresses and AutomationComponentConfigurations | §6.8.2 Table 89 (MandatoryPlaceholder) |
| The names of the Connections are unique: ConnectionsDiagnostics are linked to them by name | §6.8.2 |
| Every index refers to an element (a negative one is no reference), an AutomationComponent has a ServerAddress, an endpoint has an AutomationComponent, InboundFlowIndex has the flow and its SubscriberConfiguration | F.1.2.1, §6.8.2 Table 90, F.1.5 Table F.5 |
| The namespace index of every NodeId and RelativePath is in the Namespaces of the ServerAddress of its AutomationComponent | F.1.2.2 |
| Endpoints: a FunctionalEntityNode, a Name, a ConnectionEndpointTypeId, InputVariableIds or OutputVariableIds; a preconfigured DataSet only with PubSubConnectionEndpointType; no two endpoints with the same Name in the same FunctionalEntity | §6.11, §6.12, F.1.5 |
| Flows: an Address in the flow or in the SubscriberConfiguration; ReceiveQos only with Qos; a unicast flow has one SubscriberConfiguration and one subscriber | §6.13.3 |
| AutomationComponentNode, AssetToVerify and the verification variables are NodeIdentifiers | §6.14, §6.15, F.1.15 |
| A ServerAddress has a DiscoveryUrl and a usable SecurityMode; a SecurityKeyServer has an Address | §9.2, §9.3 |

Library interpretations, each named in its Finding: the set, its Folders
and its elements need a non-empty BrowseName, unique among the elements of
one kind; a SelectionList whose Modify field is absent or FALSE
(RestrictToList TRUE) has its current value among its Selection (F.1.2.3);
a flow has one publisher; a flow is unicast or multicast by the kind of its
IP address, and one with a host name is not checked; index 0 of the
Namespaces of a ServerAddress is the OPC UA namespace, as in a
NamespaceArray; the SecurityKeyServer field, a structure that cannot be
null on the wire, is absent when it has its default value. Before the
nodes are resolved, endpoints with the same AutomationComponentIndex and
FunctionalEntityNode are in the same FunctionalEntity.

`DecodeFile` and `EncodeFile` read and write the file of F.2: a
UABinaryFileDataType whose Body is an array of
ConnectionConfigurationSetConfDataType. A defect in a file is `ErrConfig`
with `ua.StatusBadTypeMismatch` (Table F.40). Part 5 §12.31 gives the
first entry of the Namespaces of the file the index 1, and F.2 asks for the
OPC UA and CM namespaces in it; `EncodeFile` writes the OPC UA, Data, AC
and CM namespaces with the indexes 1 to 4. **Library interpretation**: a
file written as a NamespaceArray (the OPC UA namespace with index 0) is
read too, when its Body does not decode the other way. Files are limited to
`MaxFileSize`, 16 MiB.

An `EditSlot` is the edit of §6.7.4 without the address space: `Start`
gives the Lock and a working copy to a `LockOwner` (StartEditing again by
the owner changes nothing; another owner is `Bad_InvalidState`); `Commit`
turns the working copy into the next Version (incremented on every commit)
and `Discard` drops it; both are ignored for a set that is not in edit;
`LockLost` is a Lock that went for any reason, treated as DiscardUpdates.
**Library interpretation**: a working copy that is not valid, or that
renames the set, is not committed and stays in edit. `Renamed` lists the
endpoints whose Name an edit changes, which a ConnectionManager refuses
while their Connection is established (§6.12).

The state machine of a set (§6.9.2) is `State` (Ready, Processing, Error)
and `Transition`, with the NodeIds of the state machine type and the event
type each transition has (Table 92). `Start` and `Finish` return the
transition of a set, and `Start` of a set in Processing is
`Bad_InvalidState` (Table 86).

The decisions of a ConnectionManager over the endpoints it finds are pure
functions (design §5.3 to §5.5):

- `Ownership`: KnownOwned, TakenPreconfigured, Unresolved, Foreign; only
  the first two may be closed. `Classify` and `Scan` give the class of an
  endpoint found under a Name and what the first step of a run does with it:
  create, close first, take a free preconfigured endpoint, or fail the
  Connection with `Bad_BrowseNameDuplicated`. An endpoint with the
  ApplicationUri of this ConnectionManager that it has no record of is
  Unresolved: §6.6.2 identifies an application, not a call.
- `ResolveLostResponse`: after a call whose response was lost, an endpoint
  is KnownOwned only when the Name was absent before, exactly one endpoint
  is there now, its ConnectionManagerApplicationUri is ours, the
  FunctionalEntity was serialized for the run, and the deployment asserts
  that no other ConnectionManager uses that ApplicationUri; otherwise it is
  Unresolved.
- `RetryAllowed`: a set in Error is processed again by the
  ConnectionManager itself only when every failure of its last run was
  transient and the run left no Unresolved endpoint.

`Diagnose` makes the ConnectionDiagnostics of a Connection after a
processing by the rules of §10.19, and `ConnectionStateOf` its
ConnectionState from the Status of its endpoints (§10.20, Figures 58 and
59).

## Examples

[`examples/uafx/server`](../examples/uafx/server) runs a server with the
UAFX model and one AutomationComponent, a controller with a drive as its
Asset and a Motion FunctionalEntity with a preconfigured
PubSubConnectionEndpoint (`controller.xml`), and serves EstablishConnections
and CloseConnections; every few seconds the device health changes.
[`examples/uafx/inspect`](../examples/uafx/inspect) prints the report of
`Inspect`:

```sh
go run ./examples/uafx/server -port 4855 &
go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855
go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855 -json
```

## Tests

| What | Where |
|---|---|
| Unit tests, the findings of a broken model, faults of every service call, Browse paging | `uafx`, `uafx/fxserver`, `internal/nodeset` |
| Connections end to end with UDP PubSub: data flowing between two endpoints, Status and health, a failure injected at every command with the state after the abort checked, preconfigured and shared readers and writers surviving CloseConnections, CleanupTimeout, ControlGroups, access control, audit events | `uafx/fxserver` |
| The mandatory members of the inspector against the ModellingRules of the embedded NodeSets | `uafx` (`TestMandatoryMatchesModel`) |
| Every generated structure: the Binary Schemas, hand-written byte fixtures, the bytes of v1.37.0, a round trip of each with its optional fields and union options, the errors of the decoder | `uafx` (`TestSchemaMatchesBinarySchema`, `TestStructureFixtures`, `TestGoldenReleaseB`, `TestStructuresRoundTrip`, `TestStructureErrors`) |
| The configuration model of a ConnectionManager: each validation rule, the file of F.2 in both namespace layouts and its errors, the edit, the state machine, the ownership and retry rules, the diagnostics and the ConnectionState | `uafx/fxcm` |
| Fuzz: the ConnectionConfigurationSet file (`FuzzDecodeFile`) | `uafx/fxcm` |
| Fuzz: a hostile server (`FuzzInspectHostileServer`), the UAFX structures (`FuzzDecodeStructures`, and every generated structure with `FuzzDecodeStructure`), the arguments of EstablishConnections (`FuzzDecodeEstablishConnections`), the namespace mapping of NodeSet documents (`FuzzRemap`, and `FuzzScanners` against the regular expressions its scanners replace) | `uafx`, `internal/nodeset` |
| End to end: every RSA and ECC security policy in both secure modes, anonymous and username identity, multi-chunk responses, concurrent clients, OperationLimits of one node | [`conformance/uafx`](../conformance/uafx) |
| Chaos: connection faults over SignAndEncrypt, values and FunctionalEntities changing during `Inspect`, a server closing; parallel EstablishConnections and CloseConnections, and both under connection faults, leaving the server as it was | [`chaos/uafx`](../chaos/uafx) |

The test address space is `internal/testutil/fxtest`.

## Limits

- EstablishConnections and CloseConnections are implemented with the
  PubSub communication model only. Verify and VerifyAsset called on their
  own and the Methods of the ConnectionManager answer `Bad_MethodInvalid`
  on a go-opcua server; VerifyAssetCmd needs an `AssetVerifier`.
- ControlGroups keep their Locks in memory; ListOfRelated is not
  interpreted. A ControlGroup a client controls has no Controls Reference
  (§6.5.2 wants it from the Object of the client connection, which the
  server does not have). An item in two lists of one ControlGroup is not
  refused. No persistent connections ([Persistence](#persistence)), no ConnectionManager behaviour
  (§6.7: `uafx/fxcm` validates ConnectionConfigurationSets but none is
  established, and a server has no ConnectionManager Methods), no
  AutomationComponent log.
- CloseConnections with Remove removes the DataSetReaders and
  DataSetWriters of a connection, not the groups, PubSubConnections and
  PublishedDataSets its calls configured.
- The CleanupTimeout and the Status are checked every `Interval`, so they
  lag by up to one Interval.
- No offline engineering descriptors (Part 83), no networking or time
  synchronization of Part 82, no Part 84 profile.
- `Inspect` decodes AggregatedHealthDataType and FxVersion; other UAFX
  structures in values it reads are left as ExtensionObjects
  (`DecodeStructure` decodes them).
- There is no interoperability evidence: none of the stacks of
  [opcua-interop](https://github.com/otfabric/opcua-interop) implements
  UAFX, so `Inspect`, the connection Methods and `fxserver` are tested
  against go-opcua only.
