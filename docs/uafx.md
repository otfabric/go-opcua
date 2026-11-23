# OPC UA FX (UAFX)

go-opcua reads and serves the information model of OPC UA FX, OPC 10000-81
version 1.00.04 (Connecting Devices and Information Model). It does not
implement the behaviour of the model: no Method of Part 81 is implemented,
so go-opcua cannot establish, verify or close UAFX connections, and none of
the profiles of Part 84 is claimed. What is missing is listed under
[Limits](#limits).

| Package | What it holds |
|---|---|
| `uafx` | `Inspect`: reads the UAFX model of a server into a `Report` |
| `uafx/fxserver` | `AddModel`: adds the UAFX model to a `server.Server`; `ImportNodeSet` imports NodeSets that build on it |
| `uafx/fxdataid`, `uafx/fxacid`, `uafx/fxcmid` | NodeIds of the UAFX Data, AutomationComponent (AC) and ConnectionManager (CM) namespaces |
| `di/diid` | NodeIds of the Devices (DI) model of OPC 10000-100, which the UAFX model builds on |

The NodeSets are those the OPC Foundation publishes in the
[UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset) repository
(folders `UAFX` and `DI`, MIT license), embedded in `uafx/internal/model`.
`schema/update-schema.sh` downloads them, `make gen` generates the NodeId
packages.

## Inspecting a server

```go
r, err := uafx.Inspect(ctx, client, uafx.Limits{})
if err != nil {
	return err // a service call failed
}
fmt.Println("UAFX server:", r.IsFXServer())
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
subtypes count. The structures AggregatedHealthDataType and FxVersion are
decoded with the namespace index the server has for AC: their encoding
NodeIds differ from server to server, so they are not registered with
package `ua`, and other UAFX structures stay undecoded ExtensionObjects.

### Findings

A Finding is a deviation from Part 81 that the address space shows:

- the UAFX Data namespace without AC and CM, or AC or CM without Data (§14.2);
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

`Limits` bounds what `Inspect` reads from a large or hostile server:
`MaxComponents` (AutomationComponents and ConnectionManagers, default
256), `MaxChildren` (children of one node, default 1024), `MaxDepth`
(nesting of SubFunctionalEntities, default 8) and `MaxNodes` (nodes in
the report, default 10000). `Report.Truncated` tells that a limit was
reached. A node the server shows in two places, or in a cycle, is
reported once; the HasSubtype chain is followed for at most 32 levels.
Continuation points of Browse are always released, and a server that
returns an empty page with a continuation point ends the paging. No
Read asks for more nodes than the MaxNodesPerRead of the server
(Part 5 §6.3.11).

## Adding the model to a server

```go
srv, _ := server.New(opts...)
ns, err := fxserver.AddModel(srv) // DI, Data, AC and CM
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
ConnectionManager instance of §12.3. A DI namespace the server has already
is used as it is.

`ImportNodeSet` maps the namespace table of a NodeSet document to the
namespace indexes of the server (Part 6 §F.2): a namespace the server has
keeps its index, a new one is added. `server.ImportNodeSetXML` does not map
indexes; it adds every namespace of the document and takes the NodeIds as
they are.

## Examples

[`examples/uafx/server`](../examples/uafx/server) runs a server with the
UAFX model and one AutomationComponent, a controller with a drive as its
Asset and a Motion FunctionalEntity with a PubSubConnectionEndpoint
(`controller.xml`); every few seconds the AggregatedHealth changes.
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
| The mandatory members of the inspector against the ModellingRules of the embedded NodeSets | `uafx` (`TestMandatoryMatchesModel`) |
| Fuzz: a hostile server (`FuzzInspectHostileServer`), the UAFX structures (`FuzzDecodeStructures`), the namespace mapping of NodeSet documents (`FuzzRemap`) | `uafx`, `internal/nodeset` |
| End to end: every RSA and ECC security policy in both secure modes, anonymous and username identity, multi-chunk responses, concurrent clients, OperationLimits of one node | [`conformance/uafx`](../conformance/uafx) |
| Chaos: connection faults over SignAndEncrypt, values and FunctionalEntities changing during `Inspect`, a server closing | [`chaos/uafx`](../chaos/uafx) |

The test address space is `internal/testutil/fxtest`.

## Limits

- No Method of Part 81 is implemented: EstablishConnections,
  CloseConnections, Verify, VerifyAsset and the Methods of the
  ConnectionManager answer `Bad_MethodInvalid` on a go-opcua server, and
  the client has no API for them.
- No logical connections (§5.5): no mapping of a UAFX connection to a
  PubSub configuration, no offline engineering descriptors (Part 83), no
  networking or time synchronization of Part 82, no Part 84 profile.
- UAFX structures other than AggregatedHealthDataType and FxVersion are
  not decoded.
- There is no interoperability evidence: none of the stacks of
  [opcua-interop](https://github.com/otfabric/opcua-interop) implements
  UAFX, so `Inspect` and `fxserver` are tested against go-opcua only.
