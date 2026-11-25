# OPC UA FX (UAFX)

go-opcua reads and serves the information model of OPC UA FX, OPC 10000-81
version 1.00.04 (Connecting Devices and Information Model), and it
establishes and closes non-persistent UAFX connections with PubSub: a
server answers EstablishConnections and CloseConnections (Part 81 §6.2.4,
§6.2.5), and a client calls them, with the ControlGroups of §6.5.
Package `uafx/fxcm` is a ConnectionManager (§6.7 to §6.16) as a Go
library: it validates ConnectionConfigurationSets and reads and writes their
files ([ConnectionManager configuration](#connectionmanager-configuration)),
and a `Manager` establishes, enables, disables and removes their
Connections on AutomationComponents
([Running a ConnectionManager](#running-a-connectionmanager)), and
`fxserver.EnableConnectionManager` serves it on a server, with its sets,
Methods, events and file
([Serving a ConnectionManager](#serving-a-connectionmanager)). Persistent connections are not implemented,
and none of the profiles of Part 84 is claimed. What is missing is listed under [Limits](#limits).

| Package | What it holds |
|---|---|
| `uafx` | `Inspect`: reads the UAFX model of a server into a `Report`; `EstablishConnections` and `CloseConnections` call the Methods of an AutomationComponent, `EditConnectionConfigurationSets` and `ProcessConnectionConfigurationSets` those of a ConnectionManager; the DataTypes of the UAFX namespaces, generated from the NodeSets, with their binary encoding ([Structures](#structures)) |
| `uafx/fxcm` | A ConnectionManager: `NewConfig` validates a ConnectionConfigurationSet, `DecodeFile` and `EncodeFile` read and write its file (Annex F), the state machine of a set, the edit of §6.7.4, the ownership and diagnostics rules, and `Manager`, which processes the sets against the AutomationComponents |
| `uafx/fxserver` | `AddModel`: adds the UAFX model to a `server.Server`; `ImportNodeSet` imports NodeSets that build on it; `EnableConnections` serves EstablishConnections and CloseConnections; `EnableConnectionManager` serves a `Manager` as the ConnectionManager of the server |
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
A group, PubSubConnection or PublishedDataSet that an EstablishConnections
call created for the removed reader or writer goes as well once nothing
uses it ("all related communication model Objects if not referenced from
other ConnectionEndpoints", §6.2.5.2): a group without readers and
writers, then a PubSubConnection without groups, and a PublishedDataSet no
DataSetWriter publishes. A component is the call's when the call adds it
(an ElementAdd reference) and the call's update created it in the
runtime, as `server.PubSubConfigurationUpdate.Created` records while the
update applies the configuration. A preconfigured component, one the call
matched or modified, and one another client added while the call ran are
not the call's and stay. Repeated establishes and removes therefore leave
the runtime as it was. A removal that fails there is the result of the
endpoint, as for the reader and writer below: the endpoint stays, and a
later CloseConnections with Remove removes what is left. An endpoint of
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

Package `uafx/fxcm` holds the model a ConnectionManager works on (Part 81
§6.7); this part of it makes no calls to a server. The `Manager` that
processes the sets is under
[Running a ConnectionManager](#running-a-connectionmanager). The design of
the whole ConnectionManager is in `docs/design/uafx-connection-manager.md`
(go-opcua pull request 44).

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
and CM namespaces with the indexes 1 to 4. A compatibility tolerance, not
a reading of F.2: a file written with the indexes of a NamespaceArray (the
OPC UA namespace with index 0) is read too, when its Body does not decode
the other way, and so is a file without the OPC UA namespace. Hand-written
files of each layout are the fixtures of `TestFileFixtures`. `DecodeFile`
reads and `EncodeFile` writes at most `MaxFileSize`, 16 MiB (larger is
`Bad_EncodingLimitsExceeded` when encoding).

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
  Unresolved: §6.6.2 identifies an application, not a call. A preconfigured
  endpoint this ConnectionManager took becomes Unresolved when it is in use
  by another ConnectionManager or carries another
  ConnectionManagerApplicationUri: §6.2.5.2 keeps preconfigured objects,
  which does not make closing another ConnectionManager's Connection safe.
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
processing by the rules of §10.19, keeping the StatusCode of a failure as
reported (Uncertain too; only a Good one becomes Bad), and `ConnectionStateOf` its
ConnectionState from the Status of its endpoints (§10.20, Figures 58 and
59).

## Running a ConnectionManager

A `Manager` holds ConnectionConfigurationSets and processes them against
the AutomationComponents of their ServerAddresses (§6.7.3, §6.7.5). It
needs a `Dialer` and the `ApplicationURI` its sessions present: the
AutomationComponents write it into the ConnectionManagerApplicationUri of
the endpoints it creates (§6.6.2).

```go
m, err := fxcm.New(fxcm.Options{
	Dialer: &fxcm.ClientDialer{Options: []opcua.Option{
		opcua.ApplicationURI("urn:example:cm"),
		opcua.CertificateFile("cm.crt"), opcua.PrivateKeyFile("cm.key"),
	}},
	ApplicationURI: "urn:example:cm",
	Monitor:        &fxcm.MonitorOptions{Interval: time.Second},
})
cfg, err := m.Add(set)
started := m.Process(uafx.ActionEstablishConnectionsEnabled, cfg.Key())
res, err := started[0].Run.Wait(ctx)
fmt.Println(res.State, res.Failures)
```

`ClientDialer` calls GetEndpoints on the Address of a ServerAddress, takes
the endpoint `opcua.SelectEndpoint` selects for its SecurityMode and
SecurityPolicyUri (§13.2.1), checks a ServerUri that is set against the
ApplicationUri of that endpoint (`Bad_ServerUriInvalid`, §9.2), and opens an
`opcua.Client`, which reconnects and recovers its session (§13.1). For
SecurityMode None its `Options` need `opcua.InsecureNoSecurity()`, as for
any client; the Dialer does not add it. Its identity is that of the
application: grant it the Role ConnectionAdmin on the AutomationComponents
(Part 81 §5.9). One session per ServerAddress is shared by the runs.

Sets come in with `Add`, `Replace`, `Remove` and `Update`, a batch of
operations as CloseAndUpdate of the file applies it (F.3.3). `Replace` and
`Remove` close the Connections of the old set (CloseConnections with Remove
TRUE) first; when a close fails, the old set stays, in Error. `StartEdit`,
`CommitEdit`, `DiscardEdit` and `EditLockLost` are the edit of §6.7.4; a
commit that changes the Name of an established endpoint is refused
(§6.12). A set in edit is processed with its last committed Version.

`Process(action, keys...)` starts one `Run` per set and returns at once
(§6.7.5; a set in Processing is `Bad_InvalidState`, Table 86). `Run.Wait`
returns its `RunResult`: the state it ended in, the ConnectionsDiagnostics
(§10.19), a `Failure` per failed endpoint, and the endpoints it created,
closed or could not decide. `Status` is the live state of a set, `Counters`
the call counters of §6.7.2. Every call of a run carries the AuditEntryId
`fxcm:<set>:run:<n>` (§6.7.3.2).

| Action | What the run does |
|---|---|
| EstablishConnections, …Enabled, …Disabled | Dial and resolve every AutomationComponent, find what is under the Names of the endpoints, reserve the communication ids, configure; with RollbackOnError a failure closes every endpoint of the set the run may close (§6.7.3.2, §6.8.2, F.1.3) |
| EnableConnections | EstablishConnections with EnableCommunicationCmd for the endpoints of the set (§6.7.5.3.3) |
| DisableConnections, RemoveConnections | CloseConnections with Remove FALSE or TRUE for the endpoints of the set; one failure does not stop the others (§6.7.5.3.2, §6.7.5.3.4) |
| `Reconcile` | Closes the endpoints the committed Version no longer has, pending closes and the survivors of a failed run, and checks the Unresolved endpoints again |

An establish run works in the order of E.2.2: the identifiers of the set
are resolved on each server (NodeIds by the Namespaces of their
ServerAddress, RelativePaths with TranslateBrowsePathsToNodeIds, the
placeholders of the Translation namespace through the TranslationTable,
§6.16.3, §13.3), cached per server with its NamespaceArray and
NamespacePublicationDates; ReserveCommunicationIdsCmd gives the ids, the
DataSetReaders of the subscribers of each flow get the PublisherId,
WriterGroupId and DataSetWriterId of its publisher, and one call per
AutomationComponent verifies, creates the endpoints and configures them
(§6.2.4). The AutomationComponents are called in parallel, up to
`Parallelism`; runs on one FunctionalEntity are serialized. An
AutomationComponent with a MaxConnectionsPerCall gets its endpoints in
several calls, never separating the commands of one endpoint
(CommandBundleRequired, §6.2.6). An aborted call (Uncertain,
§6.2.4.3.11) fails the endpoint whose command failed; the diagnostics of
the others of the call say they were stopped (§10.19).

Ownership (design §5.3 and §5.4): a run closes only endpoints it knows it
made (KnownOwned) or took preconfigured (TakenPreconfigured). An endpoint
found under the Name of one of the set's endpoints that is in use, or
carries another ConnectionManagerApplicationUri, fails that Connection with
`Bad_BrowseNameDuplicated`. When the response of a call is lost, the run
reads the FunctionalEntity again: with `ExclusiveApplicationURI` an
endpoint that is there now with our ApplicationUri, and was not before, is
ours; without it, it is Unresolved. Unresolved endpoints are never closed
and keep a remove run in Error; `Settle(key, ep, SettleOwned)` or
`SettleForeign` is the administrator's decision, never the Manager's.

`Retry` processes a set in Error again, with jittered exponential backoff,
only when every failure was transient and nothing is Unresolved
(`RetryAllowed`). `Monitor` reads the Status of the established endpoints
every Interval and makes the ConnectionState of the diagnostics from it
(§10.20; without it, ConnectionNotMonitored); with `Reestablish`, an
endpoint that disappeared starts the last establish action again.
The `Observer` receives the transitions, calls, endpoints, settles, retries
and monitor findings; it must not block and is called from several
goroutines at once. `Logger` logs the same at Debug and failures at Warn.
`Close` stops runs, retries and the monitor; a call in progress is left
with an unknown outcome and its run ends in Error.

**Library interpretations** (Part 81 leaves them open):

- A set's AutomationComponent needs a PubSubCommunicationModelConfiguration
  for the endpoints with CommunicationLinks; one is not generated from the
  flows (E.2.1 is informative). An endpoint without CommunicationLinks uses
  what its AutomationComponent has (a preconfigured endpoint). A
  configuration with SecurityGroups or PubSubKeyPushTargets is
  ConnectionConfigurationSetInvalid with `Bad_NotSupported`: the
  ConnectionManager does not configure an SKS.
- The Mode of a PubSubConnectionEndpoint comes from its flows
  (ToOutboundFlow and ToInboundFlow), else from its CommunicationLinks.
- The RelatedEndpoint (§10.42) names the other endpoint of the Connection:
  its server's Address, the BrowsePath of its FunctionalEntityNode (empty
  when that is a NodeId) and its Name; an autonomous publisher or
  subscriber gets the Address of its flow.
- An endpoint is preconfigured by its IsPreconfigured Property, else when it
  has no ConnectionManagerApplicationUri; it is in use when its
  RelatedEndpoint names another end than ours.
- PubSubConnections and groups are matched (ElementMatch); readers,
  writers and PublishedDataSets cannot be (OPC 10000-14 §9.1.3.7.2), so a
  WriterGroup that sends the GroupHeader needs a null Name in the set, and
  a PublishedDataSet the AutomationComponent already has under the same
  Name is reused rather than added again, but only when its PublishedData
  (PublishedVariable, AttributeId, IndexRange, DeadbandType,
  DeadbandValue, SubstituteValue and MetaDataProperties of each item,
  OPC 10000-14 §6.2.3.7.1) and its DataSetMetaData Fields (Name,
  FieldFlags, BuiltInType, DataType, ValueRank, ArrayDimensions,
  MaxStringLength, Properties, DataSetFieldId; OPC 10000-14 §6.2.3.2.4)
  and DataSetClassId equal the set's (§9.1.4). A DataSetFieldId or
  DataSetClassId the set leaves null is the publisher's and matches any;
  one it names must be equal, since subscribers map fields by
  DataSetFieldId (§6.2.10.2.3). Descriptions, SamplingIntervalHints and
  the ConfigurationVersion are not compared. Otherwise that Connection fails with
  SetCommunicationConfigurationError and `Bad_BrowseNameDuplicated`. A
  reused PublishedDataSet is shared: the ConnectionManager never changes
  or removes it. When the endpoints of an
  AutomationComponent are split over several calls, the first call adds
  the PubSubConnections, groups and PublishedDataSets, and each later call
  adds the readers and writers its endpoints link to, inside them by the
  names the server assigned.
- When a PubSubConnection matched one with another PublisherId than the
  subscribers were configured with (a DataSetReader with a null
  PublisherId, or that of its publisher; one that names another keeps it),
  the ConnectionManager adapts the subscribers (§6.16.3): after the establish calls it sends one more
  EstablishConnections call to each subscribing AutomationComponent, with
  SetCommunicationConfigurationCmd on the endpoint's Node and an
  ElementModify of each DataSetReader that now names the matched
  PublisherId; a Bad result of that call, nested ones included, fails the
  Connection. An AutomationComponent with CommandBundleRequired cannot
  take that call (§6.2.6): it is configured after the
  AutomationComponents whose flows it subscribes to, with the PublisherIds
  their calls returned. Only bundled AutomationComponents that subscribe
  to each other in a cycle, or to themselves, cannot wait (those that
  wait on a cycle still go after it); on a mismatch there that Connection
  fails with SetCommunicationConfigurationError and
  `Bad_ConfigurationError`. With null PublisherIds the
  AutomationComponent's DefaultPublisherId is used on both sides.
- CloseConnections answering `Bad_NodeIdUnknown` for an endpoint (Table 24:
  it does not exist) counts as closed.
- CloseConnections removes the readers and writers of an endpoint
  (§6.2.5.2); readers and writers a set adds without linking them to an
  endpoint stay on the AutomationComponent, and establishing the set again
  collides with them.
- The monitor polls the Status with Read; it does not subscribe.

## Serving a ConnectionManager

`fxserver.EnableConnectionManager` exposes a `Manager` on a server with the
UAFX CM model (`AddModel` with `ModelCM`) as FxRoot.ConnectionManager
(§6.7, §12.3): its sets as ConnectionConfigurationSetType Objects,
EditConnectionConfigurationSets and ProcessConnectionConfigurationSets, the
events of the set state machines, AggregatedCurrentState, the Diagnostics
counters and Capabilities, and, with `File`, ConnectionManagerConfiguration
(F.3). The nodes follow the Manager: a set added, replaced, edited or
removed through the Go API appears, changes or goes (`Flush` waits for it).

```go
ns, err := fxserver.AddModel(srv, fxserver.ModelCM)
cm, err := fxserver.EnableConnectionManager(srv, ns, fxserver.ConnectionManagerOptions{
	Manager: m, Editable: true, File: true,
})
defer cm.Close()
// A client:
set, _ := cm.SetNode(fxcm.SetKey{Folder: []string{"Plant"}, Name: "Line1"})
sc, results, err := uafx.ProcessConnectionConfigurationSets(ctx, c, uafx.ActionEstablishConnectionsEnabled, []*ua.NodeID{set})
```

Call `EnableConnectionManager` before the server starts: it adds a Guard
that releases the Lock of a set in edit when its session ends.
`uafx.EditConnectionConfigurationSets`, `uafx.ProcessConnectionConfigurationSets`
and `uafx.ConnectionManagerNode` call the Methods from a client; they
return the status of the call and one result per set.

### The sets in the address space

Each set is an Object below ConnectionConfigurationSets, in Folders named
by its ConnectionConfigurationSetFolder, with the members of §6.8.2
Table 89 and the References of Table 90 between them: its
ServerAddresses, AutomationComponentConfigurations, CommunicationFlows
with their SubscriberConfigurations, and Connections with their two
endpoint configurations. The NodeIds are String NodeIds of the CM
namespace, `cm.set:<folder>/<name>` and a path per member
(`cm.set:Plant/Line1.Flow[Flow1].PublishingInterval`). The names in it
are escaped (`%`, `/`, `.`, `[` and `]` as `%25`, `%2F`, `%2E`, `%5B` and
`%5D`), so a set named `Line1.Version` or a Folder named `a/b` has
NodeIds of its own.

- The fields a client may configure are SelectionListType Variables (OPC
  10000-5 §7.18, §6.8.1): the value, its Selections and RestrictToList,
  TRUE unless the set's `<Var>Modify` is TRUE (F.1.2.3). A field without
  a Selection has its value as its only Selection. CleanupTimeout and
  IsPersistent are shown, not writable.
- A MessageSecurityMode is shown as an Int32 (Part 6 §5.2.4).
- A NodeIdentifier is shown as the PortableNodeIdentifier the NodeSet
  gives the Variable (CM DataType 3012): its namespace indexes are mapped
  to the NamespaceUris of the set's ServerAddress (F.1.2.2), index 0 being
  the OPC UA namespace. A written PortableNodeIdentifier that names a
  namespace the ServerAddress lacks is `Bad_InvalidArgument`.
- Version, Edit (with `Editable`), RollbackOnError, ConnectionsDiagnostics
  and the state machine (CurrentState, LastTransition, §6.9.2) follow the
  Manager; LastTransition is the transition the set took last
  (`fxcm.Status.Transition`). Each Connection has a ProcessingResult (library
  interpretation): Good, or the first Bad status of its endpoints in the
  diagnostics of the last run.

### Editing

EditConnectionConfigurationSets (§6.7.4, Tables 80 to 82) works on sets
with the Edit Property, which `Editable` adds; without it a set is
`Bad_InvalidState`. A set not in edit is locked to the ConnectionManager
(§6.8.2): its Lock (OPC 10000-100 §7) has the LockingClient of the
ConnectionManager's NodeId and the LockingUser `CM`, and a write is
`Bad_Locked`.

- StartEditing gives the Lock to the calling session, with the client's
  ApplicationUri and user. The owner writes the SelectionList Variables;
  a value RestrictToList does not allow is `Bad_OutOfRange`, another
  DataType `Bad_TypeMismatch`. A write or RenewLock renews the Lock;
  after `MaxInactiveLockTime` without either (the server's
  MaxInactiveLockTime of DI, else one minute) the Lock goes and the edit
  is discarded. The deadline is checked on every write, RenewLock and
  edit call, not only by the periodic check: a write after it is
  `Bad_Locked`, RenewLock answers -1, and CommitUpdates is
  `Bad_InvalidState` (library interpretation). InitLock answers -1: the Lock is taken with StartEditing.
  ExitLock discards the edit; BreakLock needs the authorizer.
- CommitUpdates makes the working copy the next Version and returns the
  Lock to the ConnectionManager. The changed flow Variables are reflected
  onto the PubSubConfigurations of the AutomationComponents (§6.13.1,
  §6.16.3; CS-19, a library interpretation of the mapping):
  PublishingInterval, HeaderLayoutUri, SecurityMode and SecurityGroupId to
  the publisher's WriterGroup, TransportProfileUri and Address to its
  PubSubConnection; HeaderLayoutUri, SecurityMode, SecurityGroupId and
  MessageReceiveTimeout to the subscribers' DataSetReaders,
  TransportProfileUri and the Address (the SubscriberConfiguration's, else
  the flow's when it is multicast) to their PubSubConnections. Two flows
  that reflect different values onto one field are a Finding. Qos and
  ReceiveQos are not reflected.
- **Library interpretation**: a working copy that is not valid, or whose
  reflection conflicts, is not committed: the result is `Bad_InvalidState`
  (Table 82 has no code for it) and the set stays in edit.
- DiscardUpdates, the end of the owner's session and a lost Lock drop the
  working copy. A commit does not process the set: the Connections change
  at the next ProcessConnectionConfigurationSets.

### Processing

ProcessConnectionConfigurationSets (§6.7.5, Tables 84 to 86) starts a run
per set and returns; an Action that is no FxProcessEnum value is
`Bad_NotSupported`, a set in Processing `Bad_InvalidState`. The outcome is
in the events and the state of the set:

- ConnectionConfigurationSetProcessingStartedEventType,
  ProcessingSucceededEventType and ProcessingFailedEventType (§8.6 to
  §8.9) on transitions 1 and 4, 2 and 3 of §6.9.2, SourceNode the
  ConnectionManager, with ConnectionConfigurationSetNode, Name and Action.
- AggregatedCurrentState is TRUE while one or more sets are in Error
  (§6.7.2).
- The Diagnostics FunctionalGroup holds EstablishCallCount,
  EstablishCallFailedCount, CloseCallCount and CloseCallFailedCount of the
  Manager (§6.7.2).
- Capabilities (§6.7.6, HasCMCapability): MaxConnectionConfigurationSets
  of the Manager; MonitorsLocalConnectionEndpoints and
  MonitorsAllConnectionEndpoints are TRUE with `Options.Monitor`, which
  reads the Status of every endpoint the Manager made, wherever it is.

Both Methods return Good when every set's result is Good,
`Bad_UserAccessDenied` when every set was refused for that, else
Uncertain (Tables 81 and 85). With auditing on (`server.WithAuditing`),
every call reports an AuditUpdateMethodResultEventType event, also one
refused before it reaches a set (bad arguments, an unknown Action, a
ConnectionManager that is closing), and every write of a set an AuditUpdateConnectionConfigurationSetEventType event
(§8.5).

### The configuration file

ConnectionManagerConfiguration (F.3, a FileType of OPC 10000-20) reads and
writes the sets as the file of F.2. Open takes Read (0x01), which reads
the sets of the Manager, or Write with EraseExisting (0x06), which needs
the authorizer (F.3.2); other modes are `Bad_InvalidArgument`. There is
one writer, and no reader beside it. Handles belong to their session
(OPC 10000-20 §4.2.1): they go when it ends, so a writer that went away
does not block the next. CloseAndUpdate (F.3.3, Tables F.39 to
F.41) closes the written file and applies its sets, one operation per Body
element (library interpretation of the length), with `Manager.Update`:
RequireCompleteUpdate TRUE changes nothing unless every operation is
applied (see below). CloseAndUpdate asks the authorizer again ("The Client shall be
authorized to modify the configuration"), so a right revoked after Open
is `Bad_UserAccessDenied`; the handle is closed and nothing changes. It
returns ChangesApplied (Table F.39), a result per operation and the
ConnectionConfigurationSet Objects. A file holds at most 16 MiB.

- RequireCompleteUpdate FALSE: the operations that fail are dropped, the
  others applied. ChangesApplied is TRUE when one or more were applied,
  FALSE when none was.
- RequireCompleteUpdate TRUE: all or nothing; ChangesApplied is TRUE when
  all were applied, FALSE when none was. The sets the batch removes or
  replaces are claimed first, so that no run or edit starts on them, and
  the Names it adds are reserved. Closing Connections cannot be undone,
  so a batch that would close the Connections of more than one set is
  `Bad_InvalidState` (library interpretation: the ConnectionManager could
  not keep the batch whole). The one close runs first: when it fails,
  nothing changes and the set stays, in Error. Then the batch is applied
  at once. The other operations of a refused batch are
  `Bad_InvalidState`.

A Replace or Remove through the Go API claims its set in the same way
until it is done.

### Access

By default Edit, Process, the writes of a set, a file opened for writing,
its CloseAndUpdate and BreakLock need the well-known Role ConfigureAdmin
(Part 3 §4.9.2,
`fxserver.ConfigureAdmin()` for a `server.RoleMapper`), as §6.8.2 and
F.3.2 recommend; the others get `Bad_UserAccessDenied`.
`ConnectionManagerOptions.Authorizer` (`CMAuthorizer`, `CMRequest`,
`CMOperation`) replaces that policy.

## Examples

[`examples/uafx/server`](../examples/uafx/server) runs a server with the
UAFX model and one AutomationComponent, a controller with a drive as its
Asset and a Motion FunctionalEntity with a preconfigured
PubSubConnectionEndpoint (`controller.xml`), and serves EstablishConnections
and CloseConnections; every few seconds the device health changes.
[`examples/uafx/cm`](../examples/uafx/cm) runs a ConnectionManager server
whose sets a client writes through ConnectionManagerConfiguration or which
`-set` loads from a file of F.2.
[`examples/uafx/inspect`](../examples/uafx/inspect) prints the report of
`Inspect`:

```sh
go run ./examples/uafx/server -port 4855 &
go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855
go run ./examples/uafx/inspect -endpoint opc.tcp://localhost:4855 -json
go run ./examples/uafx/cm -port 4856
```

## Tests

| What | Where |
|---|---|
| Unit tests, the findings of a broken model, faults of every service call, Browse paging | `uafx`, `uafx/fxserver`, `internal/nodeset` |
| Connections end to end with UDP PubSub: data flowing between two endpoints, Status and health, a failure injected at every command with the state after the abort checked, preconfigured and shared readers and writers surviving CloseConnections, the groups, connections and PublishedDataSets a call created removed with it (five establish and remove cycles leaving the runtime as it was, preconfigured and shared ones staying, a failed removal), CleanupTimeout, ControlGroups, access control, audit events | `uafx/fxserver` |
| The mandatory members of the inspector against the ModellingRules of the embedded NodeSets | `uafx` (`TestMandatoryMatchesModel`) |
| Every generated structure: the Binary Schemas, hand-written byte fixtures, the bytes of v1.37.0, a round trip of each with its optional fields and union options, the errors of the decoder | `uafx` (`TestSchemaMatchesBinarySchema`, `TestStructureFixtures`, `TestGoldenReleaseB`, `TestStructuresRoundTrip`, `TestStructureErrors`) |
| The configuration model of a ConnectionManager: each validation rule, the file of F.2 in both namespace layouts and its errors, the edit, the state machine, the ownership and retry rules, the diagnostics and the ConnectionState | `uafx/fxcm` |
| Fuzz: the ConnectionConfigurationSet file (`FuzzDecodeFile`) | `uafx/fxcm` |
| The Manager end to end against `fxserver` AutomationComponents with UDP PubSub: establish, enable, disable, remove and re-establish, data flowing; BrowsePaths and placeholders, asset and FunctionalEntity verification, MaxConnectionsPerCall and CommandBundleRequired; preconfigured endpoints; the rollback; a PublishedDataSet name collision with other content and the comparison of every item and field member; a DataSetReader that names its publisher's PublisherId adapted; a SecurityKeyServer refused; the PublisherId adaptation, with CommandBundleRequired after the publisher, its nested results and a failing call; Close waiting for a Remove; every use of every service failed in turn; every call's response lost; two Managers with the same ApplicationUri; the monitor re-establishing; the retry policy; the ClientDialer | `uafx/fxcm` |
| The ConnectionManager server: the nodes and References of a set, the SelectionList writes and their RestrictToList, the PortableNodeIdentifier view, the Lock (ownership, renewal, expiry on the clock of the test, the end of a session, BreakLock), commit with CS-19 reflection and its conflicts, Process and its events, the audit events (also of calls refused early), the file and its argument errors, ChangesApplied of a partial update, handles dropped at the end of their session, the Lock deadline between two checks, escaped NodeIds, the authorizer, the nodes following the Manager; on a SignAndEncrypt Basic256Sha256 endpoint with user names, an authorized user and a viewer, and a right revoked between Open and CloseAndUpdate (`TestConnectionManagerSecure`) | `uafx/fxserver` |
| Headline (design §7.1): AC1, AC2 and a ConnectionManager server, each its own server, driven only through the Methods, the SelectionList Variables and the file, over SignAndEncrypt sessions with a ConnectionAdmin user: add by file, establish, disable, enable, edit the PublishingInterval and see it on the AC after a new establish, remove (`TestConnectionManagerLifecycle`) | `uafx/fxcm` |
| Multicast (four servers): AC1 publishes to a UDP multicast group, AC2 and AC3 subscribe, one DataSetWriter serves both, Remove removes all three sides (`TestConnectionManagerMulticast`). It needs an interface that carries multicast (`GO_OPCUA_MULTICAST_IFACE`, else the first that works) and skips without one; `GO_OPCUA_MULTICAST_REQUIRE=1`, set in the CI `server` job, makes that a failure. Run on macOS on en0 and lo0 | `uafx/fxcm` |
| Fuzz: a hostile server (`FuzzInspectHostileServer`), the UAFX structures (`FuzzDecodeStructures`, and every generated structure with `FuzzDecodeStructure`), the arguments of EstablishConnections (`FuzzDecodeEstablishConnections`), the namespace mapping of NodeSet documents (`FuzzRemap`, and `FuzzScanners` against the regular expressions its scanners replace) | `uafx`, `internal/nodeset` |
| End to end: every RSA and ECC security policy in both secure modes, anonymous and username identity, multi-chunk responses, concurrent clients, OperationLimits of one node | [`conformance/uafx`](../conformance/uafx) |
| Chaos: connection faults over SignAndEncrypt, values and FunctionalEntities changing during `Inspect`, a server closing; parallel EstablishConnections and CloseConnections, and both under connection faults, leaving the server as it was | [`chaos/uafx`](../chaos/uafx) |

The test address space is `internal/testutil/fxtest`.

## Limits

- EstablishConnections and CloseConnections are implemented with the
  PubSub communication model only. Verify and VerifyAsset called on their
  own answer `Bad_MethodInvalid` on a go-opcua server; VerifyAssetCmd
  needs an `AssetVerifier`.
- ControlGroups keep their Locks in memory; ListOfRelated is not
  interpreted. A ControlGroup a client controls has no Controls Reference
  (§6.5.2 wants it from the Object of the client connection, which the
  server does not have). An item in two lists of one ControlGroup is not
  refused. No persistent connections ([Persistence](#persistence)), no
  AutomationComponent log.
- The ConnectionManager (`uafx/fxcm`, served by `EnableConnectionManager`)
  keeps its sets, their Versions and the records of its endpoints in
  memory. It does not configure a SecurityKeyServer, ask a GDS (no
  GlobalDiscoveryServers), resolve AliasNames (AliasNameProcessingError),
  generate a PubSub configuration from the flows
  ([Running a ConnectionManager](#running-a-connectionmanager)), or
  reflect Qos and ReceiveQos of an edited flow
  ([Editing](#editing)). It has no ConnectionManagerLog (LogObject).
- The CleanupTimeout and the Status are checked every `Interval`, so they
  lag by up to one Interval.
- No offline engineering descriptors (Part 83), no networking or time
  synchronization of Part 82, no Part 84 profile.
- `Inspect` decodes AggregatedHealthDataType and FxVersion; other UAFX
  structures in values it reads are left as ExtensionObjects
  (`DecodeStructure` decodes them).
- There is no interoperability evidence: none of the stacks of
  [opcua-interop](https://github.com/otfabric/opcua-interop) implements
  UAFX, so `Inspect`, the connection Methods, `fxserver` and the
  ConnectionManager are tested against go-opcua only.
