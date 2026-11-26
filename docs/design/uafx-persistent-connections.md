# Design: UAFX persistent connections (C3)

Status: **draft, waiting for the maintainer's decisions (§10)**. No runtime
code is written until they are made. Target release: v1.40.0, after the
last stage (§7).

This document designs persistent connections in go-opcua: ConnectionEndpoints
with IsPersistent TRUE that an AutomationComponent (AC) restores after a
restart (OPC 10000-81 §5.5.5, §6.6.2, §6.2.6, §6.12), and a ConnectionManager
(CM) whose sets, Versions and endpoint records survive its own restart.
Both store through a backend the application supplies, and both
**reconcile** what they stored with what they find after the restart instead
of replaying an old snapshot. It continues the C2 design
([uafx-connection-manager.md](uafx-connection-manager.md), §8 "What C3 needs
from C2") and keeps its rules: the transactional rollback of
EstablishConnections (Table 21), the endpoint ownership classes and the
proof of a lost response (C2 §5.3, §5.4), and the ControlGroup and Lock
rules of C1.

Sources read for it:

| Source | Version |
|---|---|
| OPC 10000-81 UAFX Connecting Devices and Information Model, [reference.opcfoundation.org](https://reference.opcfoundation.org/specs/OPC-10000-81/): §5.5.4, §5.5.5, §6.2.4.2 (Tables 9 to 19), §6.2.4.3.5, §6.2.4.3.9.2, §6.2.5, §6.2.6, §6.4.6, §6.4.7, §6.6, §6.7.3, §6.7.5.3.2, §6.8, §6.9, §6.11, §6.12, §6.13, §8.3, §10.17, §10.27, Annex E.3, E.6.6, Annex F.1 | 1.00.04 |
| OPC 10000-84 UAFX Profiles: §5.2.3 (Table 4), §5.2.5 (Table 6), §5.2.6 (Table 7), §6.6.2.2 (Table 16), §6.6.4.6 (Table 45), §6.6.4.7 (Table 46) | 1.00.04 |
| OPC 10000-14 PubSub: §6.2.2 (Table 4, NotPersisted) | 1.05.06 |
| OPC 10000-100 Devices: §7 LockingServices, as C1 implements them | as cited by C1 |
| go-opcua v1.39.1 (`a70742e`): `uafx`, `uafx/fxcm`, `uafx/fxserver`, `server` (PubSub configuration, `CertificateStore`), docs/uafx.md, LIMITATIONS.md | |

The statements of §5.5.5, §6.2.4.3.9.2, §6.2.5, §6.2.6, §6.4.6.3, §6.6.2 and
OPC 10000-14 Table 4 that this design leans on were checked against the text
of the pages, not a summary. Where the specification says nothing and the
library has to choose, the choice is marked **library interpretation**.
Clauses are of Part 81 unless another Part is named.

## 1. What exists

| Release | What it brought that C3 builds on |
|---|---|
| v1.37.0 | `fxserver.EnableConnections`: EstablishConnections and CloseConnections on the AC side, backed by the server's PubSub; endpoint Status, health, CleanupTimeout (§6.6.2), AuditConnectionCleanupEventType (§8.3) |
| v1.38.0 | ControlGroups (§6.5) with the LockingServices of OPC 10000-100 §7; control an endpoint established (EstablishControlCmd) is owned by that endpoint (`lockOwner.endpoint`), control a client established by its session |
| v1.39.0 | `uafx/fxcm` (the CM engine: Config, Manager, runs, endpoint records with ownership classes, `Reconcile`, `Settle`), `fxserver.EnableConnectionManager` (the CM in the address space, Edit, Process, F.3) |
| v1.39.1 | Fixes to the CM projection |

What v1.39.1 does with persistence today:

- `fxserver` answers an endpoint with IsPersistent TRUE with Bad_NotSupported
  in its ConnectionEndpointResult (`establish.go` createOne; docs/uafx.md
  "Persistence"). The ACs have no SupportsPersistence, so they "do not
  support persistent Connections" (§6.2.6).
- `fxserver` does **not** run the check of §6.2.4.3.9.2 (the DataSetReader
  and DataSetWriter of an endpoint, and their parents, must be persisted when
  IsPersistent is TRUE and not persisted when it is FALSE). See §2.2: this is
  a gap of v1.37.0 to v1.39.1, not only a C3 feature.
- The server's PubSub configuration lives in memory; nothing in `server`
  stores it.
- `fxserver` endpoints have no Diagnostics Object, so no CreationTime or
  ModificationTime (Table 74, optional; `endpoint.go`). §5.4 needs
  CreationTime to tell a restored endpoint from one re-created under the
  same Name, so C3.1 adds it.
- `fxcm.Manager` keeps its sets, their Versions, its endpoint records and
  its RunIDs in memory. A restarted Manager knows no endpoint as its own,
  so it closes nothing it did not create in its own lifetime (C2 §5.3, §8):
  safe, but its earlier endpoints become survivors it never touches.
- The precedent for an application-supplied backend is
  `server.CertificateStore` (push certificate management): the server calls
  it, the application decides where the data lives, and without one nothing
  is persisted.

## 2. Requirements catalogue

### 2.1 The AutomationComponent (§5.5.5, §6.2.6, §6.6.2, §6.12)

| ID | Requirement | Clause |
|---|---|---|
| AP-1 | Persistence is the ability of an AC "to store configuration" so that the Objects of a logical connection can be restored "after a power cycle or other restart" | §5.5.5 |
| AP-2 | Each Connection can be marked for persistence with IsPersistent; an AC "indicates support for persistent Connections" with SupportsPersistence | §5.5.5, §6.6.2, §6.2.6 |
| AP-3 | SupportsPersistence (Boolean, optional, HasCapability of the AutomationComponentCapabilities): absent or FALSE means the AC does not support persistent Connections | §6.2.6 Table 26 |
| AP-4 | IsPersistent (Boolean, mandatory) of a ConnectionEndpoint "indicates if the ConnectionEndpoint shall be persistent"; IsPersistent of the ConnectionEndpointParameter: the created endpoint "shall be persistent" | §6.6.2 Table 73, §6.12 Table 96 |
| AP-5 | Persistent endpoints "shall be restored following a power cycle by the AutomationComponent", and the restoration shall include: the ConnectionEndpoint with its references to ControlGroups and communication model Objects; the established control on the related ControlGroups; the communication model Objects | §6.6.2 |
| AP-6 | Non-persistent endpoints, after a power cycle, behave as if CloseConnections had been called with Remove TRUE; if not persistent, the parts created at establishment are deleted "on clean-up or on a power cycle", preconfigured Objects remain | §6.6.2, §5.5.5 |
| AP-7 | "For a persistent ConnectionEndpoint, the CleanupTimeout shall be set to a negative number"; a negative CleanupTimeout means no clean-up | §6.6.2 |
| AP-8 | A preconfigured endpoint taken by EstablishConnections gets IsPersistent, CleanupTimeout and RelatedEndpoint from the Parameter | §6.2.4.3.5 |
| AP-9 | CloseConnections with Remove TRUE removes what EstablishConnections created, "and all persisted items"; preconfigured Objects and Objects referenced by other endpoints are not removed | §6.2.5.2 |
| AP-14 | CreationTime and ModificationTime (DateTime, optional) in the Diagnostics of a ConnectionEndpoint; CUs "UAFX ConnectionEndpoint Diagnostics CreationTime" and "... ModificationTime" | §6.6.2 Table 73/74; OPC 10000-84 Table 6 |
| AP-10 | CloseConnections disables the CleanupTimeout processing | §6.2.5.2 ("shall be disabled"); §6.6.2 says "may be disabled" |
| AP-11 | Table 12 (ConnectionEndpointResult) has Bad_NotSupported for "The requested IsPersistent was not supported." | §6.2.4.2 Table 12 |
| AP-12 | Stored values of ConfigurationData Variables: "The FunctionalEntity shall apply the stored values to the configuration variables after a power cycle" (SetStoredVariables, ClearStoredVariables, ListStoredVariables; all three or none) | §6.4.6.2 to §6.4.6.5; CU "UAFX ConfigurationDataFolder VariableStorage" |
| AP-13 | What is done with ConfigurationData applied by a Connection when it is closed is vendor-specific | §6.2.5.2 |

### 2.2 The persisted check of SetCommunicationConfigurationCmd (§6.2.4.3.9.2)

| ID | Requirement | Clause |
|---|---|---|
| PC-1 | With IsPersistent TRUE, EstablishConnections "shall verify" that the endpoint references a DataSetReader and/or DataSetWriter that are persisted, "including all parent Objects": WriterGroup, ReaderGroup, PubSubConnection and PublishSubscribe | §6.2.4.3.9.2 |
| PC-2 | With IsPersistent FALSE it "shall verify" that the DataSetReader and/or DataSetWriter are not persisted (parents not named) | §6.2.4.3.9.2 |
| PC-3 | Otherwise: Bad_InvalidState in the CommunicationLinksResult of the endpoint, and the call aborts (§6.2.4.3.11) | §6.2.4.3.9.2, Table 16 |
| PC-4 | "Persisted" is the PubSub configuration property 0:NotPersisted (Boolean), a KeyValuePair of the properties of a PubSub component: "If this property is not present the default value is false and the component configuration is persisted." | OPC 10000-14 §6.2.2 Table 4 |

PC-4 makes PC-2 strict: a PubSub configuration that does not mention
NotPersisted is **persisted**, so a non-persistent endpoint needs
`0:NotPersisted = TRUE` on its DataSetReader or DataSetWriter. No set
v1.39.1 is tested with does that, and `fxserver` does not check it. Taking
PC-2 literally in a minor release would refuse with Bad_InvalidState every
establish that works today. Decision C3-D2.

### 2.3 The ConnectionManager (§6.7, §6.8, §6.9, Annex F)

| ID | Requirement | Clause |
|---|---|---|
| CR-1 | The CM creates persistent endpoints by putting IsPersistent TRUE (and a negative CleanupTimeout, AP-7) in the ConnectionEndpointParameter of the set | §6.12, §6.6.2 |
| CR-2 | Annex F defines DataTypes that "can, for example, be used for persisting" a ConnectionConfigurationSet; they are semantically equivalent to ConnectionConfigurationSetType minus the state machine, Edit and Lock | F.1.1 |
| CR-3 | Version is monotonically increasing, +1 per change, 1 on add or replace | §6.8.2 Table 89 |
| CR-4 | RollbackOnError TRUE: on an abort, the CM calls CloseConnections with Remove TRUE for the endpoints established so far | §6.7.3.2 |
| CR-5 | ActionRemoveConnections calls CloseConnections with Remove TRUE for every endpoint of the set | §6.7.5.3.2 |
| CR-6 | NodeId namespace handling when sets are loaded or saved (PubSubConfiguration NodeIds, NamespaceArray) is vendor-specific | Annex E.6.6 |

### 2.4 What the specification does not say

Every behaviour below is a **library interpretation** in this design, and
each is named where it is decided.

| Gap | Not said |
|---|---|
| G1 | Whether a CM persists its sets across a restart. F.1.1 only offers a serialization ("can ... be used") |
| G2 | What state a set is in after a CM restart. §6.9 defines Ready, Processing and Error and their transitions, nothing about start-up |
| G3 | When and in what order an AC restores persistent endpoints, and the Status a restored endpoint starts with |
| G4 | Who holds a restored control. §6.6.2 restores "established control"; a client's control is a Lock of its session (OPC 10000-100 §7.2), which does not survive a restart |
| G5 | "Power cycle" (§6.6.2, §6.4.6.3) versus "power cycle or other restart" (§5.5.5) |
| G6 | The PubSub runtime state after a restore: Enabled, PubSubState, sequence numbers, security keys. OPC 10000-14 defines NotPersisted but no restart behaviour and no storage |
| G7 | What CloseConnections with Remove FALSE does to a persistent endpoint: whether it stays persisted, and disabled after a restart |
| G8 | §6.2.4.3.5 says only for a preconfigured endpoint that IsPersistent is set from the Parameter; for a created one it follows from "Variables ... according to Parameter" |
| G9 | Changing IsPersistent of an established endpoint |
| G10 | EstablishConnections with IsPersistent TRUE and a CleanupTimeout of zero or more: §6.6.2 says it shall be negative, no clause gives the reaction or a code |
| G11 | The status code when SupportsPersistence is absent or FALSE and IsPersistent TRUE is requested. Table 12's row says "The requested IsPersistent was not supported" and continues with the feedback signal case of §6.4.7; no row ties a code to SupportsPersistence |
| G12 | A persistent endpoint whose restoration fails (the FunctionalEntity, a Variable or a ControlGroup is gone after an update, the PubSub configuration conflicts) |
| G13 | No ConformanceUnit names IsPersistent or CleanupTimeout. Part 84 has "UAFX AutomationComponent SupportsPersistence" (the Variable present and TRUE), optional in the AutomationComponent 2024 Facet; the ConnectionManager 2024 Facet has no persistence unit |

## 3. Conformance matrix

Status: **v1.39.1** what the release does, **C3.n** the stage that does it
(§7), **out** not planned.

| ID | Requirement | v1.39.1 | C3 | Stage | Test |
|---|---|---|---|---|---|
| AP-2, AP-3 | SupportsPersistence | absent | TRUE when the AC has a ConnectionStore (C3-D1), absent otherwise | C3.1 | address space read with and without a store |
| AP-4, AP-8 | IsPersistent on a created and a taken preconfigured endpoint | Bad_NotSupported | written from the Parameter | C3.1 | establish both kinds, read IsPersistent |
| AP-5 | Restore after a restart: endpoint, control, communication model Objects | no | reconcile at `EnableConnections` (§4.3) | C3.1 | restart e2e: data flows again, control held by the endpoint, NodeIds unchanged |
| AP-6 | Non-persistent endpoints gone after a restart | yes (memory only) | yes, and their PubSub components are not stored | C3.1 | restart e2e |
| AP-7, G10 | Negative CleanupTimeout for persistent | n/a | C3-D4 | C3.1 | establish with CleanupTimeout 0 and 5 s |
| AP-9 | Remove TRUE removes persisted items | n/a | the store entry goes in the same transaction | C3.1 | close, restart, nothing restored |
| AP-10 | CloseConnections disables CleanupTimeout | yes | unchanged | — | existing |
| AP-14 | Endpoint Diagnostics CreationTime | no Diagnostics | Diagnostics with CreationTime (and ModificationTime), CreationTime kept by a restore | C3.1 | read before and after a restart |
| AP-11, G11 | IsPersistent without support | Bad_NotSupported | unchanged without a store (library interpretation, Table 12 text) | C3.1 | existing test kept |
| AP-12 | SetStoredVariables / Clear / List | no | C3-D7 (recommended: out of C3) | out | — |
| AP-13 | ConfigurationData on close | vendor-specific, kept | not stored with the endpoint (§4.6) | C3.1 | doc |
| PC-1 | Persisted reader/writer and parents for IsPersistent TRUE | no check | enforced | C3.1 | Bad_InvalidState for each parent with NotPersisted TRUE |
| PC-2 | Not persisted for IsPersistent FALSE | no check | C3-D2 | C3.1 | per decision |
| PC-3 | Bad_InvalidState in CommunicationLinksResult and abort | n/a | yes, with the rollback of Table 21 | C3.1 | rollback leaves nothing stored |
| CR-1 | The CM creates persistent endpoints | passes IsPersistent through (`plan.go`) | unchanged; fxcm can fill NotPersisted (C3-D2) | C3.2 | fxcm e2e against a persistent AC |
| CR-2, G1 | Sets survive a CM restart | no | fxcm.Store (§5) | C3.2 | restart e2e |
| CR-3 | Version kept across a restart | no | stored with the Config | C3.2 | Version after restart, next edit +1 |
| CR-4, CR-5 | Remove TRUE on rollback and remove | yes | unchanged; the endpoint records and intents are stored | C3.2 | crash during rollback |
| G2 | State of a set after a CM restart | n/a | Ready with Unverified records, then a verify pass (C3-D5) | C3.3 | restart e2e |
| — | Endpoint records and run journal survive a restart | no | stored, write-ahead intent (§5.3) | C3.2 | crash injection at each window of §6 |
| — | Ownership after restart | lost | re-proved (§5.4), never assumed | C3.3 | restart with a foreign endpoint of the same Name |
| — | Keep in place (C2 Q1) | no | adopt known-owned endpoints that match (§5.5, C3-D6) | C3.3 | re-run without data interruption |
| G13 | Part 84 | no Facet | "UAFX AutomationComponent SupportsPersistence" claimable; no Facet claim | — | — |

None of the pinned references of opcua-interop implements UAFX, so all of
this is tested against go-opcua only.

## 4. The AutomationComponent: `fxserver`

### 4.1 The store

```text
// ConnectionStore keeps the persistent ConnectionEndpoints of the
// AutomationComponents of a server (Part 81 §5.5.5, §6.6.2). The server
// calls it; the application decides where the data lives.
type ConnectionStore interface {
	// Load returns every entry, at EnableConnections.
	Load(ctx context.Context) (map[string][]byte, error)
	// Apply makes puts and deletes durable, all or none, before it
	// returns.
	Apply(ctx context.Context, puts map[string][]byte, deletes []string) error
}

type ConnectionOptions struct {
	...
	// Store makes the AutomationComponents support persistent Connections
	// (SupportsPersistence TRUE). Nil: IsPersistent TRUE is Bad_NotSupported,
	// as today.
	Store ConnectionStore
}
```

Recommended shape (C3-D3): a **byte key-value store with one atomic Apply**,
the records encoded by the library. The application needs no knowledge of
UAFX to implement it (a file written to a temporary name and renamed, a
table in its database, a key-value service), and the library owns the
format, its version byte and its migration. The records are decoded as
untrusted input: a fuzz target for the record decoder, and a defect is a
restore failure of that record (§4.4), never a panic.

The library ships fxserver.MemoryConnectionStore (tests and reference)
and an example file store under `examples/uafx/`; it binds no database
(maintainer requirement).

### 4.2 What a record holds

One record per persistent endpoint, keyed by its NodeId:

| Field | Why |
|---|---|
| NodeId, FunctionalEntity NodeId, Name (BrowseName) | restore the endpoint at the same NodeId (§4.4) |
| The ConnectionEndpointParameter as established (type, Mode, InputVariables, OutputVariables, RelatedEndpoint, CleanupTimeout) | AP-5: the endpoint with its Variables |
| ConnectionManagerApplicationUri, CreationTime | the CM's proof of ownership after a restart (§5.4, C2 §5.4) |
| The ControlGroups whose control the endpoint established (EstablishControlCmd, ReassignControlCmd to it) | AP-5: established control |
| The communication model Objects the endpoint references: its DataSetReader and/or DataSetWriter with their parents (WriterGroup or ReaderGroup, PubSubConnection) and the PublishedDataSets the call created, as the PubSubConfiguration2DataType elements they were applied with, in UA Binary | AP-5: communication model Objects |
| Enabled (EnableCommunicationCmd ran, no Remove FALSE close since) | G6, G7: restored enabled or disabled (C3-D8) |
| The ids reserved for it (WriterGroupId, DataSetWriterIds) | the restored PubSub configuration keeps its ids |

Not stored: ConfigurationData (AP-13 makes it vendor-specific; §6.4.6 has a
mechanism of its own, C3-D7), security keys (they come from the
SecurityKeyServer again), sequence numbers and Status (G6: a restored
endpoint starts as §4.4 says).

A shared component is stored once, with the endpoints that reference it
(§6.2.5.2 removes a component only when no other endpoint references it, and
the store follows that rule).

### 4.3 Writing: inside the transaction of EstablishConnections

EstablishConnections and CloseConnections are atomic per call (§6.2.4.3.9.1,
§6.2.4.3.10.1, §6.2.5.2) and v1.39.1 serializes them (`Connections.call`).
The store write joins that transaction:

1. The call runs its commands in memory as today, and collects the puts and
   deletes of the persistent endpoints it changed.
2. Before the result is returned, one `Apply` writes them.
3. If `Apply` fails, the call is aborted and rolled back as Table 21 says,
   as if the last command had failed: Uncertain for the Method,
   Bad_ResourceUnavailable in the ConnectionEndpointResult of the first
   persistent endpoint (**library interpretation**: Table 12 has
   Bad_ResourceUnavailable for an exhausted resource; no row covers a
   failed store), Bad_NothingToDo for the steps it skips.

So a persistent endpoint exists in the store only if the call that made it
succeeded, and a rollback never needs to undo a store write. CloseConnections
with Remove TRUE deletes the record in the same way (AP-9); if the delete
fails, the endpoint is closed but not removed: its result is
Bad_ResourceUnavailable and it stays, disabled, so that the store and the
address space agree (**library interpretation**).

The CleanupTimeout of a persistent endpoint is negative (AP-7), so the
monitor never removes one by itself. A crash between step 2 and the
response leaves a persistent endpoint the CM did not hear about: that is the
lost response of C2 §5.4, which the CM resolves with
ConnectionManagerApplicationUri and CreationTime (§5.4).

### 4.4 Restoring: reconcile at `EnableConnections`

The order of a server that persists: `server.New`, `fxserver.AddModel`,
`EnableConnections` with the Store, `srv.Start`. `EnableConnections` loads
the records and restores them before the server answers any request, so no
client sees a half-restored AC (G3, **library interpretation**: restoration
at start-up, before the Methods are served).

For each record it **checks before it creates**:

1. The FunctionalEntity exists, the Variables of the endpoint are in its
   InputData and OutputData, the ControlGroups exist, and no endpoint of
   that Name or NodeId exists (a preconfigured endpoint the record took
   must exist and be free, §6.2.4.3.5).
2. The stored PubSub elements against the server's current PubSub
   configuration: a component of the same id that is equal is adopted (the
   application may restore its own PubSub configuration before
   `EnableConnections`); one that differs is a conflict; a missing one is
   added.
3. The control: the record's ControlGroups are not locked by someone else.

Then, all or nothing per record: the PubSub elements are applied with
`ChangePubSubConfiguration`, the endpoint node is created at its NodeId with
the stored Variables (IsPersistent TRUE, the negative CleanupTimeout), the
control is established with the endpoint as owner (C1 `lockOwner.endpoint`;
G4: only control an endpoint holds is restored, a client's control is a
Lock of its session and is not), and the reader or writer is enabled if the
record says Enabled. The Status then follows the DataSetReader and
DataSetWriter as for any endpoint (§6.6.3): Initial until they run, so a
CM sees a restored endpoint come back as its data does.

A record that fails a check is not restored and not deleted: it is reported
(§4.5) and kept until the application removes it or a later start restores
it (G12, **library interpretation**: AP-5 says "shall be restored"; deleting
the record would hide the failure, half-restoring it would leave Objects
without an endpoint). The NodeId counter starts above the restored NodeIds.

### 4.5 Reporting

`EnableConnections` returns `*Connections` as today; Connections.Restored()
returns the outcome per record (restored, adopted components, or the
failure with its reason). The Logger logs each failure at Warn. If the AC
has an AutomationComponentLog in a later release, the failures go there
too; v1.39.1 has none, so no event type is invented for them.

### 4.6 What C3 does not change on the AC

- ConfigurationData: not stored with the endpoint (AP-13). SetStoredVariables
  is a separate ConformanceUnit (C3-D7).
- Non-persistent endpoints: as today, memory only (AP-6 holds by
  construction). Their PubSub components are not stored.
- Changing IsPersistent of an established endpoint (G9): an establish of an
  existing Name fails as today (Bad_BrowseNameDuplicated); there is no other
  way to change it.

## 5. The ConnectionManager: `fxcm`

### 5.1 The store

```text
// Store keeps the sets, Versions, endpoint records and run intents of a
// Manager across its restarts. The Manager encodes the entries.
type Store interface {
	Load(ctx context.Context) (map[string][]byte, error)
	Apply(ctx context.Context, puts map[string][]byte, deletes []string) error
}

type Options struct {
	...
	// Store makes the sets, their Versions and the endpoint records
	// survive a restart. Nil: memory only, as today.
	Store Store
}
```

The same shape as the AC store (C3-D3), so one application implementation
serves both. A Manager owns its store: two Managers on one store are not
supported (**library interpretation**), and `New` refuses a store whose
entries name another ApplicationURI.

### 5.2 What is stored, and when

| Entry | Content | Written |
|---|---|---|
| Set | SetKey, Version, the committed Conf (the F.2 binary encoding of `ConnectionConfigurationSetConf`, CR-2) | Add, Replace, Remove, Update (F.3) and a committed edit: **before** the change is visible; a failed Apply fails the operation |
| Endpoint record | The `EndpointRecord` of C2 (set, AC ServerUri, FunctionalEntity, Name, NodeId, Class, Run, Version, ClosePending) and the AC's CreationTime when exposed | when a step changes it, together with the intent's end (§5.3) |
| Intent | RunID, set, AC, the call (Establish or Close), the Names and NodeIds it may create or close | **before** each EstablishConnections or CloseConnections call |
| Run counter | the last RunID | with each intent, so RunIDs stay unique across restarts |

Not stored: the state machine state, runs in progress, edits (the Lock of an
edit belongs to a session, OPC 10000-100 §7.2: an edit in progress at a
restart is discarded), Counters (Table 78), monitor readings.

A failed Apply fails the operation with a status the caller already handles
(**library interpretation**): Add, Replace, Remove and Update return
`ua.StatusBadResourceUnavailable` (F.3: in OperationResults); a committed edit
answers CommitUpdates Bad_ResourceUnavailable for that set and keeps the
edit open, so the client can retry or discard; an intent that cannot be
written stops the step before the call, the run goes to Error with nothing
sent.

### 5.3 The intent rule

C2 §5.4 handles a lost response inside one Manager lifetime. A crash is a
lost response of every call in flight: the intent written before the call is
what tells the restarted Manager that a call may have happened. After a
restart, every intent without an end is an unknown outcome of C2 §5.4, never
"not done": its Names are checked by the proof of §5.4 below, and closes it
recorded are pending. The rollback of a run (CR-4) writes its own intents,
so a crash during a rollback leaves the closes pending, as D9 of C2 says for
a failed close.

### 5.4 Restart: verify before trusting (G2)

`New` with a Store loads the entries and builds the sets with their Configs
and Versions (CR-3). Every set starts in **Ready** with its records marked
**Unverified** (**library interpretation**: §6.9 has no start-up state and
Ready is the only state without a run). An Unverified record is treated like
Unresolved: reported, never closed. Then a **verify pass** (C3-D5) browses,
per AC, the FunctionalEntities of the records and the pending intents, and
re-proves each:

- **KnownOwned again** when the endpoint of that Name is there and is the
  one the record names: its CreationTime is the stored one, or the AC has no
  CreationTime and the NodeId is the stored one and its
  ConnectionManagerApplicationUri is ours with ExclusiveApplicationURI (the
  safeguard of C2 Q2). A persistent endpoint restored by a go-opcua AC keeps
  its NodeId and CreationTime (§4.4).
- **Gone**: the record is dropped (a non-persistent endpoint after an AC
  restart, AP-6, or a cleanup).
- **Proven ours** for an unended intent: the C2 §5.4 proof, with "absent at
  step 0" read from the intent.
- **Anything else**: Unresolved, as in C2: `Reconcile` re-checks it, `Settle`
  decides it.

The pass only reads; it closes nothing and starts no run. Whether the
Manager runs it by itself at `New`, or the application calls it, is C3-D5.
After it, `Process` and `Reconcile` work as in C2, on the restored records:
a set the CM had established is Ready with its endpoints KnownOwned, and
`ActionRemoveConnections` closes them (CR-5) as if there had been no restart.

### 5.5 Keeping endpoints in place (C2 Q1)

C2 re-creates the known-owned endpoints of a set it processes again, which
interrupts the data (C2 Q1, accepted for C2 with keep-in-place left to C3).
With records that survive restarts, the planner can **adopt**: an endpoint
is left in place when it is KnownOwned, its record has the Version of the
Config being processed, and the AC shows it with Status Operational or
Ready; the run then only enables what is disabled. Anything that differs
(another Version, an endpoint in Error, a record ClosePending) is re-created
as in C2. This is the same planner path as step 0, with one more class of
step. C3-D6 decides whether it is in C3.

### 5.6 Persistent endpoints from the CM

The CM needs nothing new to ask for a persistent endpoint: IsPersistent and
CleanupTimeout come from the set (`plan.go` passes them, CR-1). Two
additions, both C3-D2:

- validation: a set with IsPersistent TRUE and a CleanupTimeout of zero or
  more is a ConfigError (AP-7, finding with clause §6.6.2);
- NotPersisted: the CM can fill `0:NotPersisted` on the DataSetReaders and
  DataSetWriters of the set's PubSub configuration from IsPersistent when the
  set does not state it, so that a strict AC (PC-2) accepts sets written
  without it.

## 6. Failure windows

| Where it stops | AC | CM |
|---|---|---|
| Before the store write of a call | nothing stored; the in-memory changes are lost with the process; the CM sees a lost response and proves the Names absent | intent stored, no end: unknown outcome, checked at restart |
| After the store write, before the response | the endpoint is restored at start-up; the CM proves it ours by CreationTime or URI (§5.4) | as above |
| During a rollback | closes not yet made: the records stay (Remove TRUE not applied) and the endpoints are restored; the CM finds them KnownOwned and its pending closes close them | close intents without an end: closes pending |
| Store Apply fails | the call aborts, Table 21 rollback | the operation fails, memory unchanged |
| A record cannot be restored | not restored, kept, reported (§4.4) | n/a |
| A store entry cannot be decoded | that record fails (§4.4); the others restore | `New` fails, naming the entry (**library interpretation**: a CM must not run on a partial view of its sets) |

## 7. Stages

Each stage is one PR from main, merged in turn; one release, v1.40.0, after
the last (C3-D9).

### C3.1 The AutomationComponent

ConnectionStore, MemoryConnectionStore, the record codec with its fuzz
target, SupportsPersistence, the Diagnostics of an endpoint with
CreationTime and ModificationTime (AP-14), IsPersistent on created and taken preconfigured
endpoints, the PC-1 and PC-2 checks per C3-D2, the CleanupTimeout rule per
C3-D4, the store write in the call transaction, restore and reconcile at
`EnableConnections`, Restored, the example file store, docs/uafx.md
(Persistence), LIMITATIONS.md, RELEASE.md.

### C3.2 The ConnectionManager store

fxcm.Store, the entry codec with its fuzz target, sets and Versions
written before they are visible, endpoint records, intents and the run
counter, `New` loading them, the set validation of §5.6 and the NotPersisted
filling per C3-D2, docs/uafx.md, RELEASE.md.

### C3.3 Recovery and adoption

The verify pass (§5.4) per C3-D5, Unverified records, intents resolved after
a restart, adoption (§5.5) per C3-D6, the fxserver projection of restored
sets (Version, state, ConnectionsDiagnostics), docs, RELEASE.md, FEATURE-STATUS.

## 8. Test plan

A restart in a test is a server or Manager closed and a new one started on
the same store; a crash is a Manager or Connections abandoned without
`Close`, with the store write hooked to stop at a chosen point.

- **AC restart, headline**: a CM establishes a set with a persistent and a
  non-persistent Connection between two go-opcua ACs; the publishing AC is
  restarted on its store; the persistent endpoint is back at its NodeId with
  IsPersistent TRUE, a negative CleanupTimeout, its control held by the
  endpoint, its PubSub components, and data flows again; the non-persistent
  one is gone. CloseConnections with Remove TRUE, restart: nothing restored.
- **Persisted check**: NotPersisted TRUE on the reader, the writer, and each
  parent for IsPersistent TRUE gives Bad_InvalidState in
  CommunicationLinksResult with the Table 21 rollback and nothing stored;
  IsPersistent FALSE per C3-D2.
- **Store failures**: Apply failing in EstablishConnections, in
  CloseConnections, in Add, Update, a commit and an intent; each leaves
  memory and store in agreement.
- **Restore failures**: a FunctionalEntity, a Variable, a ControlGroup
  removed between two starts; a PubSub component changed; a corrupt record.
  The others restore, the failed one is reported and kept.
- **CM restart**: sets, Versions, records back; a set established before the
  restart is removed after it with Remove TRUE; a foreign endpoint of the
  same Name created while the CM was down stays Unresolved and untouched;
  without ExclusiveApplicationURI and without CreationTime nothing is
  re-proved.
- **Crash windows of §6**: each window, with a crash injected at the store
  hook, then a restart, then the expected class of every endpoint.
- **Adoption**: a re-run of an established set at the same Version leaves the
  endpoints and the data in place; a new Version re-creates them.
- **Fuzz**: the AC record decoder and the CM entry decoder.
- Race and the `server` CI job as for C2 (AGENTS.md rule 6).

### What the tests cannot show

That a restart of a real device is a "power cycle" (G5): the tests restart a
process on the same store. And, since none of the pinned references of
opcua-interop implements UAFX, that another AC or CM reads persistence the
way go-opcua does.

## 9. What opcua-interop could add

The same as C2 §9: the peer search for UAFX implementations comes first.
For C3 an AC peer matters most: a CM restart against an AC that is not
go-opcua tests the re-proof of §5.4 against an independent reading of
CreationTime and ConnectionManagerApplicationUri.

## 10. Decisions

| # | Question | Recommendation |
|---|---|---|
| C3-D1 | SupportsPersistence: TRUE exactly when a ConnectionStore is configured, per server (all its ACs) | Yes. Per-AC stores add nothing a key prefix does not |
| C3-D2 | PC-2 (IsPersistent FALSE needs NotPersisted TRUE, and absent means persisted) refuses every establish that works in v1.39.1 | Enforce PC-1 always. Enforce PC-2 behind ConnectionOptions.StrictNotPersisted (default false in v1.x, documented as a deviation in LIMITATIONS.md and docs/uafx.md). fxcm fills NotPersisted from IsPersistent where the set does not state it, on by default, so a go-opcua CM works with a strict AC. Alternative: enforce PC-2 now and call it a breaking fix |
| C3-D3 | Store shape: byte key-value with one atomic Apply, records encoded by the library; or typed records (Go structs) the application encodes | Byte key-value: the application needs no UAFX knowledge, the library owns format and migration. One interface shape for AC and CM |
| C3-D4 | IsPersistent TRUE with a CleanupTimeout of zero or more (G10) | Refuse: Bad_InvalidArgument in the ConnectionEndpointResult (Table 12 uses it for parameters that do not fit); fxcm validation rejects such a set. Alternative: accept and store -1 |
| C3-D5 | The verify pass after a CM restart: run by `New` in the background, or only when the application calls Verify | `New` starts it; `Process` of a set waits for its verification; the Observer reports it |
| C3-D6 | Adoption (keep-in-place, §5.5) in C3 | Yes, in C3.3: it needs the records C3 makes durable, and C2 Q1 deferred it here |
| C3-D7 | SetStoredVariables, ClearStoredVariables, ListStoredVariables (§6.4.6, AP-12) | Out of C3: a separate ConformanceUnit about ConfigurationData, not Connections. It can use the same store later |
| C3-D8 | A persistent endpoint closed with Remove FALSE (G7): restored disabled, or not restored | Restored disabled: Remove FALSE keeps the Objects, and the record says Enabled FALSE; Remove TRUE removes it |
| C3-D9 | Delivery: three stage PRs from main, one release v1.40.0 after C3.3 | Yes, as for C2 |
| C3-D10 | A record that cannot be restored (G12) | Keep and report (§4.4), never half-restore or delete |
