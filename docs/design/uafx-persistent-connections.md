# Design: UAFX persistent connections (C3)

Status: **revision 2, waiting for re-review**. The maintainer's review of
revision 1 (PR #52, 2026-11-26) approved the architecture
(application-supplied storage, the control model of C1, the ownership
safeguards of C2, three stage PRs and one release v1.40.0), decided C3-D1 to
C3-D10 (§11) and asked for nine revisions, which this version makes
(§11.2). No runtime code is written until this revision is approved.
Target release: v1.40.0, after the last stage (§8).

This document designs persistent connections in go-opcua: ConnectionEndpoints
with IsPersistent TRUE that an AutomationComponent (AC) restores after a
restart (OPC 10000-81 §5.5.5, §6.6.2, §6.2.6, §6.12), and a ConnectionManager
(CM) whose sets, Versions, endpoint records and owed work survive its own
restart. Both store through a backend the application supplies, and both
**reconcile** what they stored with what they find after the restart instead
of replaying an old snapshot. It continues the C2 design
([uafx-connection-manager.md](uafx-connection-manager.md), §8 "What C3 needs
from C2") and keeps its rules: the transactional rollback of
EstablishConnections (Table 21), the endpoint ownership classes and the
proof of a lost response (C2 §5.3, §5.4), no implicit retry of an
ambiguous call, and the ControlGroup and Lock rules of C1.

Sources read for it:

| Source | Version |
|---|---|
| OPC 10000-81 UAFX Connecting Devices and Information Model, [reference.opcfoundation.org](https://reference.opcfoundation.org/specs/OPC-10000-81/): §5.5.4, §5.5.5, §6.2.4.2 (Tables 9 to 19), §6.2.4.3.5, §6.2.4.3.9.2, §6.2.5, §6.2.6, §6.4.6, §6.4.7, §6.6, §6.7.3, §6.7.5, §6.8, §6.9, §6.11, §6.12, §6.13, §8.3, §10.17, §10.27, Annex E.3, E.6.6, Annex F.1 | 1.00.04 |
| OPC 10000-84 UAFX Profiles: §5.2.3 (Table 4), §5.2.5 (Table 6), §5.2.6 (Table 7), §6.6.2.2 (Table 16), §6.6.4.6 (Table 45), §6.6.4.7 (Table 46) | 1.00.04 |
| OPC 10000-14 PubSub: §6.2.2 (Table 4, NotPersisted), §9.1.2 (configuration behaviours), §7.2.3 and §7.2.4.4.3 (MessageNonce, SequenceNumber) | 1.05.06 |
| OPC 10000-100 Devices: §7 LockingServices, as C1 implements them | as cited by C1 |
| go-opcua v1.39.1 (`a70742e`): `uafx`, `uafx/fxcm`, `uafx/fxserver`, `server` (PubSub configuration transaction, `CertificateStore`), `pubsub` (nonce counter and tracker, `pubsub/nonce.go`), docs/uafx.md, LIMITATIONS.md | |

The statements of Part 81 §5.5.5, §6.2.4.3.9.2, §6.2.5, §6.2.6, §6.4.6.3,
§6.6.2 and of Part 14 §6.2.2 Table 4 and §9.1.2 were checked against the text
of the pages, not a summary. Where the specification says nothing and the
library has to choose, the choice is marked **library interpretation**.
Clauses are of Part 81 unless another Part is named. API sketches are in
`text` blocks: they are proposals, not the current API.

## 1. What exists

| Release | What it brought that C3 builds on |
|---|---|
| v1.37.0 | `fxserver.EnableConnections`: EstablishConnections and CloseConnections on the AC side, backed by the server's PubSub; endpoint Status, health, CleanupTimeout (§6.6.2), AuditConnectionCleanupEventType (§8.3) |
| v1.38.0 | ControlGroups (§6.5) with the LockingServices of OPC 10000-100 §7; control an endpoint established (EstablishControlCmd) is owned by that endpoint, control a client established by its session |
| v1.39.0 | `uafx/fxcm` (Config, Manager, runs, endpoint records with ownership classes, `Reconcile`, `Settle`, the resolution caches of CL-5, CL-6 with NamespaceArray and NamespacePublicationDates), `fxserver.EnableConnectionManager` |
| v1.39.1 | Fixes to the CM projection |

What v1.39.1 does with persistence today:

- `fxserver` answers an endpoint with IsPersistent TRUE with Bad_NotSupported
  (`establish.go` createOne). The ACs have no SupportsPersistence (§6.2.6).
- `fxserver` does **not** run the check of §6.2.4.3.9.2 (§2.2): a gap of
  v1.37.0 to v1.39.1.
- `fxserver` endpoints have no Diagnostics Object, so no CreationTime
  (Table 73/74, optional; `endpoint.go`).
- The server's PubSub configuration lives in memory: **the server does not
  meet Part 14 §9.1.2**, which wants the latest PubSub configuration
  persisted and available after a restart (§2.4). Every change to it,
  whatever the mechanism (CloseAndUpdate of the PubSubConfiguration file,
  UpdatePubSubConfiguration, the PubSub Methods, `fxserver`), runs inside
  one transaction, `server.Server.ChangePubSubConfiguration`: the
  coordination point of §9.1.2 exists.
- The MessageNonce of a secured writer group is four random bytes and a
  sequence number per SecurityTokenId that starts at 1 and is kept in memory
  only (`pubsub/nonce.go`, Part 14 §7.2.4.4.3). Receivers keep the last
  sequence number per sender and token in memory and ignore what is not
  newer (§7.2.3).
- Namespaces: the UAFX Conf structures carry their namespace indexes through
  `uafx.NamespaceIndexes` and the Namespaces of the F.2 file (`fxcm`);
  NodeSet XML through `nodeset.Remap`. Nothing remaps the NodeIds inside
  PubSub configuration structures.
- `fxcm.Manager` keeps its sets, Versions, endpoint records and RunIDs in
  memory. A restarted Manager knows no endpoint as its own and closes
  nothing it did not create in its own lifetime (C2 §5.3).
- The precedent for an application-supplied backend is
  `server.CertificateStore`.

## 2. Requirements catalogue

### 2.1 The AutomationComponent (§5.5.5, §6.2.6, §6.6.2, §6.12)

| ID | Requirement | Clause |
|---|---|---|
| AP-1 | Persistence is the ability of an AC "to store configuration" so that the Objects of a logical connection can be restored "after a power cycle or other restart" | §5.5.5 |
| AP-2 | Each Connection can be marked for persistence with IsPersistent; an AC indicates support with SupportsPersistence | §5.5.5, §6.6.2, §6.2.6 |
| AP-3 | SupportsPersistence (Boolean, optional, HasCapability): absent or FALSE means the AC does not support persistent Connections | §6.2.6 Table 26 |
| AP-4 | IsPersistent (Boolean, mandatory) of a ConnectionEndpoint, and of the ConnectionEndpointParameter: the created endpoint "shall be persistent" | §6.6.2 Table 73, §6.12 Table 96 |
| AP-5 | Persistent endpoints "shall be restored following a power cycle by the AutomationComponent", including: the ConnectionEndpoint with its references to ControlGroups and communication model Objects; the established control on the related ControlGroups; the communication model Objects | §6.6.2 |
| AP-6 | Non-persistent endpoints, after a power cycle, behave as if CloseConnections had been called with Remove TRUE; preconfigured Objects remain | §6.6.2, §5.5.5 |
| AP-7 | "For a persistent ConnectionEndpoint, the CleanupTimeout shall be set to a negative number" | §6.6.2 |
| AP-8 | A preconfigured endpoint taken by EstablishConnections gets IsPersistent, CleanupTimeout and RelatedEndpoint from the Parameter | §6.2.4.3.5 |
| AP-9 | CloseConnections disables the communication model Objects of the endpoint (only those no other endpoint references; parents left as they are); with Remove TRUE it removes what EstablishConnections created, "and all persisted items", and releases the ControlGroup restrictions; preconfigured Objects and Objects referenced by other endpoints are not removed | §6.2.5.2 |
| AP-10 | CloseConnections disables the CleanupTimeout processing | §6.2.5.2 ("shall"); §6.6.2 ("may") |
| AP-11 | Table 12 has Bad_NotSupported for "The requested IsPersistent was not supported." | §6.2.4.2 Table 12 |
| AP-12 | Stored ConfigurationData values are applied "after a power cycle" (SetStoredVariables, ClearStoredVariables, ListStoredVariables) | §6.4.6.2 to §6.4.6.5 |
| AP-13 | What happens to the ConfigurationData of a closed Connection is vendor-specific | §6.2.5.2 |
| AP-14 | CreationTime and ModificationTime (DateTime, optional) in the Diagnostics of a ConnectionEndpoint; CUs "UAFX ConnectionEndpoint Diagnostics CreationTime" and "... ModificationTime" | §6.6.2 Table 73/74; OPC 10000-84 Table 6 |

### 2.2 The persisted check of SetCommunicationConfigurationCmd (§6.2.4.3.9.2)

| ID | Requirement | Clause |
|---|---|---|
| PC-1 | With IsPersistent TRUE, the endpoint's DataSetReader and/or DataSetWriter "which are persisted, including all parent Objects": WriterGroup, ReaderGroup, PubSubConnection and PublishSubscribe | §6.2.4.3.9.2 |
| PC-2 | With IsPersistent FALSE, the DataSetReader and/or DataSetWriter "are not persisted" (parents not named) | §6.2.4.3.9.2 |
| PC-3 | Otherwise Bad_InvalidState in the CommunicationLinksResult, and the call aborts (§6.2.4.3.11) | §6.2.4.3.9.2, Table 16 |
| PC-4 | 0:NotPersisted (Boolean) is a configuration property of a PubSub component: "If this property is not present the default value is false and the component configuration is persisted." | OPC 10000-14 §6.2.2 Table 4 |

PC-4 makes PC-2 strict: a non-persistent endpoint needs `0:NotPersisted =
TRUE` on its reader or writer. No set v1.39.1 is tested with has it. C3-D2
(§11) decides how this is handled.

### 2.3 The ConnectionManager (§6.7, §6.8, §6.9, Annex F)

| ID | Requirement | Clause |
|---|---|---|
| CR-1 | The CM creates persistent endpoints with IsPersistent TRUE (and a negative CleanupTimeout, AP-7) in the ConnectionEndpointParameter | §6.12, §6.6.2 |
| CR-2 | Annex F's DataTypes "can, for example, be used for persisting" a set | F.1.1 |
| CR-3 | Version: monotonic, +1 per change, 1 on add or replace | §6.8.2 Table 89 |
| CR-4 | RollbackOnError TRUE: on an abort the CM calls CloseConnections with Remove TRUE for the endpoints established so far | §6.7.3.2 |
| CR-5 | ActionRemoveConnections: CloseConnections with Remove TRUE for every endpoint; ActionEstablishConnections, ActionEstablishConnectionsEnabled/Disabled, ActionEnable, ActionDisable as §6.7.5.3 defines them | §6.7.5.3 |
| CR-6 | NodeId namespace handling when sets are loaded or saved is vendor-specific | Annex E.6.6 |

### 2.4 PubSub configuration persistence (Part 14)

| ID | Requirement | Clause |
|---|---|---|
| PS-1 | "The latest configuration shall be persisted by the OPC UA Server and shall be available after a restart of the OPC UA Server. PubSub components are not persisted, if the component has the optional NotPersisted property set with a value of true." | OPC 10000-14 §9.1.2 |
| PS-2 | Modifications can come from different mechanisms (FileType access, Method sequences of other information models); "The PubSub application should ensure that all mechanisms coordinate access to the configuration", delaying rather than failing parallel access | OPC 10000-14 §9.1.2 |
| PS-3 | A publisher resets the MessageNonce SequenceNumber to 1 when the key and SecurityTokenId are updated; a receiver ignores a message that is not newer | OPC 10000-14 §7.2.4.4.3, §7.2.3 |

PS-1 is a requirement on the server as a whole, which v1.39.1 does not
meet. C3 does not build the general Part 14 persistence (maintainer scope),
but its records are designed so that a later server-wide PubSub store takes
over the component configuration without a second source of truth (§5).

### 2.5 What the specification does not say

Each is a **library interpretation** where this design decides it.

| Gap | Not said |
|---|---|
| G1 | Whether a CM persists its sets across a restart (F.1.1 is permissive) |
| G2 | The state of a set after a CM restart (§6.9 has no start-up state) |
| G3 | When and in what order an AC restores, and the Status a restored endpoint starts with |
| G4 | Who holds a restored control: a client's control is a Lock of its session (OPC 10000-100 §7.2) |
| G5 | "Power cycle" (§6.6.2, §6.4.6.3) versus "power cycle or other restart" (§5.5.5) |
| G6 | The PubSub **runtime** state after a restart (PubSubState, sequence numbers, keys). Part 14 §9.1.2 covers the configuration (PS-1); it says nothing about runtime state. Revision 1 claimed Part 14 required no persistence: that was wrong |
| G7 | CloseConnections with Remove FALSE on a persistent endpoint: whether it stays persisted, and disabled |
| G8 | IsPersistent on a created (not preconfigured) endpoint follows only from "Variables ... according to Parameter" |
| G9 | Changing IsPersistent of an established endpoint |
| G10 | IsPersistent TRUE with a CleanupTimeout of zero or more: no reaction or code given |
| G11 | The code when SupportsPersistence is absent and IsPersistent TRUE is requested (Table 12's row continues with the FeedbackSignalRequired case) |
| G12 | A persistent endpoint whose restoration fails |
| G13 | No ConformanceUnit names IsPersistent or CleanupTimeout; "UAFX AutomationComponent SupportsPersistence" is optional in the AC 2024 Facet; the CM 2024 Facet has no persistence unit |
| G14 | A persisted component referenced by a persistent and a non-persistent endpoint |

## 3. The storage contract (C3-D3)

### 3.1 Interface

One package, proposed as uafx/fxstore, used by both sides:

```text
package fxstore

// Store keeps the durable state of one AutomationComponent server or one
// ConnectionManager. One writer: the process that opened it.
type Store interface {
	// Load returns the last committed state: every key with its value.
	Load(ctx context.Context) (map[string][]byte, error)
	// Apply makes puts and deletes durable, all or none.
	Apply(ctx context.Context, b Batch) error
}

type Batch struct {
	Puts    map[string][]byte
	Deletes []string
}

// ErrNotCommitted wraps an Apply error that guarantees nothing of the
// batch was made durable. Any other error from Apply is an unknown outcome.
var ErrNotCommitted = errors.New(...)

// ErrLocked: the store is owned by another writer.
var ErrLocked = errors.New(...)

// MemoryStore and FileStore implement Store; storetest.Run checks any
// implementation against this contract.
```

### 3.2 Semantics

| Property | Contract |
|---|---|
| Durability | Apply returns nil only when the batch survives a process crash and, for a backend on stable storage, a power loss of the machine. FileStore: the data file and its directory are fsynced (§3.4) |
| Atomicity | All puts and deletes of a batch, or none |
| Outcomes | nil: **committed**. An error that `errors.Is` ErrNotCommitted: **definitely not committed**, the state is as before. Any other error: **unknown**: the batch may or may not be durable |
| Unknown | The caller reconciles (§3.3); when it still cannot tell, the protocols of §4 and §6 treat the outcome as unknown, never as "not done". A Load after an unknown Apply returns either the old or the new values of the whole batch |
| Cancellation | A context done before the backend starts writing: ErrNotCommitted. A context done while it writes: the backend may still commit: unknown unless it can prove otherwise |
| Read-your-writes | Load after a committed Apply returns its values |
| Single writer | One process owns a store. FileStore takes an exclusive lock on its directory (ErrLocked for a second opener); other backends document how they enforce it. The library refuses a store whose meta key names another owner identity (the CM's ApplicationURI, the AC server's ApplicationUri) |
| Key namespaces | The AC writes only keys under `ac/`, the CM only under `cm/`; each refuses foreign keys at Load. One backend may hold both when the application gives each its own Store value over it |
| Versioned format | Every value starts with a format byte and a schema version; a `<ns>/meta` key holds the store format version and the owner identity. A newer version than the library knows, or an undecodable meta key, fails the start of the persistent subsystem (C3-D1); older versions are migrated in memory and written back in one committed Apply before anything else is written |
| Bounds | A value is at most 4 MiB, a store at most 64 Ki keys (configurable lower); decoding uses the limits of the ua decoder; a value over a bound is a failed record (§4.7), not a panic. The decoders have fuzz targets |
| Sensitive data | Values hold PubSub configuration, which can carry broker credentials in its properties (the server redacts them in its address space; the store holds them as configured). The library stores no security keys, no private keys and no session secrets. FileStore creates its directory 0700 and files 0600 and refuses a directory others can write. An application that needs encryption at rest wraps the Store |
| Resources | Load reads the whole state once at start; Apply writes one batch; neither starts goroutines that outlive the call |

### 3.3 Reconciling an unknown outcome

After an unknown Apply the library calls Load with a deadline (at most
10 s by default, configurable) and compares the batch keys: all new values
present means committed, all old values present means not committed, a
Load that fails leaves it unknown. Neither side retries the Apply itself:
an unknown outcome follows the protocol of its operation (§4.3 to §4.5,
§6.2, §6.3).

### 3.4 FileStore (reference implementation)

A directory with an exclusive lock file and one data file. Apply writes the
whole new state to a temporary file, fsyncs it, renames it over the data
file and fsyncs the directory. An error before the rename is
ErrNotCommitted (the temporary file is removed); an error at or after the
rename, including the directory fsync, is unknown. It is meant for the scale
of a configuration (a few MiB): Apply is O(state). It is in the library
because the contract tests and the crash tests (§9) need a durable backend
(C3-D12); applications may use another.

## 4. The AutomationComponent: `fxserver`

### 4.1 Start-up (C3-D1)

A Store in the ConnectionOptions (proposed field) makes the ACs of the
server support persistent Connections. EnableConnections with a Store:

1. Loads the store and checks the meta key (format, owner). A Load error, an
   incompatible format or a foreign owner fails EnableConnections with an
   error: no silent downgrade to memory only.
2. Decodes every record. A record that does not decode, exceeds a bound or
   fails its checks (§4.6) is quarantined, not deleted (§4.7).
3. Completes durable removals (§4.4) and restores the others (§4.6).
4. Only then sets SupportsPersistence TRUE in the AutomationComponentCapabilities
   of each AC. Without a Store, SupportsPersistence stays absent and
   IsPersistent TRUE stays Bad_NotSupported (AP-11; G11, library
   interpretation of the Table 12 text).

The application must call EnableConnections before the server starts, so no
client sees a half-restored AC (G3, library interpretation). Record failures
do not fail the start; they are reported (§4.7).

### 4.2 Records and provenance

Keys and records (all values versioned, §3.2):

| Key | Record |
|---|---|
| `ac/meta` | format version, owner (server ApplicationUri) |
| `ac/ep/<id>` | one persistent endpoint: NodeId, FunctionalEntity, Name, the ConnectionEndpointParameter as established (type, Mode, InputVariables, OutputVariables, RelatedEndpoint, CleanupTimeout), ConnectionManagerApplicationUri, CreationTime, ModificationTime, the ControlGroups it controls, the components it references, **Enabled**, **State** (Active or RemovePending, §4.4), and the NamespaceArray of the record (§4.8) |
| `ac/pc/<component>` | one PubSub component a persistent endpoint references: its kind and id (PubSubConnection, WriterGroup, ReaderGroup, DataSetWriter, DataSetReader, PublishedDataSet), its configuration as the PubSubConfiguration2DataType element it was applied with, its **provenance**, its **references** (the persistent endpoints that use it), a source field (§5) and its NamespaceArray |
| `ac/q/<id>` | a quarantined record and its diagnostics (§4.7) |

Provenance decides the delete semantics (§6.2.5.2):

| Provenance | Meaning | Removed when its last reference goes |
|---|---|---|
| Created | an EstablishConnections call added it (SetCommunicationConfigurationCmd) | yes |
| Preconfigured | it existed before as a preconfigured Object of the AC | never; only the reference is dropped |
| Adopted | it existed before, from the application or another configuration mechanism, and the endpoint referenced it | never; only the reference is dropped |

A shared component has one record with every reference; removing one
endpoint drops one reference and never deletes a component another endpoint
still needs (AP-9). The restore of endpoints that share a component adds
that component once, in dependency order (§4.6).

### 4.3 Establish: validate, stage, persist, activate

EstablishConnections is atomic per call and serialized. For a call with
persistent endpoints:

1. **Validate before any mutation**: everything v1.39.1 checks, plus PC-1 and
   PC-2 (C3-D2), C3-D4 (IsPersistent TRUE with a CleanupTimeout that is zero,
   positive, NaN or infinite: Bad_InvalidArgument in the
   ConnectionEndpointResult), and the persistence needs of shared components
   (§4.9). A failure here changes nothing, in memory or in the store.
2. **Stage** in memory, in the command order of §6.2.4.3.1: create the endpoint
   nodes, establish control, write ConfigurationData, apply the PubSub
   configuration with the components disabled, reserve the ids. Nothing
   publishes yet.
3. **Persist**: one Apply with the endpoint and component records (State
   Active, Enabled as EnableCommunicationCmd will set it). This is the
   commit point.
4. **Activate** after a committed Apply: EnableCommunicationCmd enables the
   components. The call returns Good.

The outcomes of step 3:

| Apply | Runtime | Result |
|---|---|---|
| committed | activate (4) | Good |
| definitely not committed | the Table 21 rollback of the staged changes | Uncertain; Bad_ResourceUnavailable in the ConnectionEndpointResult of the first persistent endpoint, Bad_NothingToDo for the skipped ones (library interpretation, C3-D13) |
| unknown, and §3.3 cannot tell | the Table 21 rollback; the Names, NodeIds and PubSub ids of the batch are **quarantined** until a reconciliation settles them (a later Load, a Discard, or the next start) | Uncertain; Bad_InternalError in that ConnectionEndpointResult (library interpretation, C3-D13), which `fxcm` treats as an unknown outcome (C2 §5.4) |

Activation can fail after the commit (the PubSub runtime refuses to
enable). The call then rolls back, and the rollback of a committed endpoint
is the durable removal of §4.4; until that commits, the endpoint is
disabled, RemovePending in memory and its resources quarantined.

What a failed call can leave, stated plainly:

- **Durable state**: nothing after a definite non-commit; possibly the whole
  batch after an unknown outcome, which the next start then restores and its
  CM proves (§6.5). A failed call is not claimed to have left the store
  unchanged unless the Apply definitely did not commit.
- **Runtime state**: rolled back as Table 21 says.
- **External effects**, which no rollback undoes: ConfigurationData written
  to the FunctionalEntity (Table 21, AP-13), the restriction a ControlGroup
  imposed while it was controlled, and values a reader received. No message
  is published before the commit point (step 4), so no PubSub message has to
  be taken back.

### 4.4 Disable and removal (C3-D8)

Persist the intent first, then act; once a removal or a disable is durable,
no restart brings communication back.

| Operation | 1. Apply | 2. Runtime | 1 definitely not committed | 1 unknown |
|---|---|---|---|---|
| CloseConnections, Remove FALSE (disable) | record Enabled FALSE | disable the components no other enabled endpoint needs; control kept | nothing changes; result Bad_ResourceUnavailable | disable anyway (safe direction); the record is marked for reconciliation; result Bad_InternalError |
| CloseConnections, Remove TRUE | record State RemovePending | disable, remove the nodes, release control, drop component references, remove Created components with no reference left | nothing changes; result Bad_ResourceUnavailable | disable and remove anyway; the Name, NodeId and ids stay quarantined until reconciled; result Bad_InternalError |
| then, after a committed RemovePending | Apply: delete the endpoint record, update the component records | | the RemovePending record stays; the next start completes the removal | same |
| EnableCommunicationCmd on an existing persistent endpoint | record Enabled TRUE | enable | nothing changes | not enabled (safe direction); result Bad_InternalError |

At start-up, a RemovePending record is never restored: the removal is
completed (its Created components removed if no other record references
them) and the record deleted. An Active record with Enabled FALSE is
restored disabled with its control. A component other endpoints need keeps
the state they need (enabled if an enabled endpoint uses it).

The one window the protocol cannot close: an unknown outcome of the
Enabled FALSE or RemovePending write after which the record is in fact
unchanged. The next start then restores the endpoint as it was before, and
its CM, which got Bad_InternalError, holds the close as pending (C2 D9) and
repeats it. This is the lost response of C2 §5.4 applied to the store, and
it is tested (§9).

CleanupTimeout is negative for persistent endpoints (AP-7), so the monitor
never removes one.

### 4.5 Changes from other configuration mechanisms (PS-2)

A persistent endpoint's components can be changed or removed by
CloseAndUpdate, UpdatePubSubConfiguration or the PubSub Methods. All of
them run in the transaction of ChangePubSubConfiguration, and C3.1 adds a
hook to it: inside the transaction, after a change is validated and before
it is committed to the runtime, `fxserver` writes the component records the
change touches in one Apply.

- A modified component: its record follows the new configuration
  (provenance unchanged). If the Apply is definitely not committed, the change
  is refused with Bad_ResourceUnavailable (library interpretation) so the
  store and the runtime agree; if unknown, the change stands and the record
  is reconciled.
- A removed component: the endpoints that referenced it lose their reader or
  writer and go to Status Initial (§6.6.3); their records keep the reference
  marked "removed by another mechanism", and a restart does not re-create the
  component (the latest configuration wins, PS-1).
- 0:NotPersisted set to TRUE on a component a persistent endpoint
  references: refused with Bad_InvalidState (PC-1 would be broken).

So each component has one source of truth: the PubSub runtime, mirrored into
the store in the same transaction.

### 4.6 Restore and reconcile

For each Active record, in dependency order (PubSubConnection, groups,
PublishedDataSets, writers and readers, endpoint, control, enablement), it
**checks before it creates**:

1. Namespaces: every URI of the record's NamespaceArray is in the server's
   NamespaceArray; the NodeIds are remapped (§4.8).
2. The FunctionalEntity, its InputData and OutputData Variables and the
   ControlGroups exist; no endpoint of that Name or NodeId exists, unless it
   is the preconfigured endpoint the record took and it is free.
3. Each component: one of the same id that is equal is adopted (the
   application may have configured it first); one that differs is a conflict;
   a missing Created component is added.
4. The ControlGroups are not controlled by someone else.
5. The secure-restart rule (§4.10).

Then, all or nothing per endpoint: components, the endpoint node at its
NodeId with its CreationTime (AP-14), the control with the endpoint as owner
(G4: only control an endpoint holds is restored), and enablement. A failure
during that rolls back only what this restore created, never an adopted or
preconfigured component. Status then follows the readers and writers
(§6.6.3): Initial until they run.

### 4.7 Quarantine (C3-D10)

A record that fails is not restored, not half-restored and not deleted. It
moves to `ac/q/<id>` (one Apply; if that does not commit, it stays where it
is and is quarantined in memory). A quarantined record **reserves** its
NodeId, its Name in its FunctionalEntity (an establish of that Name gets
Bad_BrowseNameDuplicated) and its PubSub ids (excluded from ReserveIds and
from new components) until an administrator decides.

```text
func (c *Connections) Quarantined() []QuarantinedEndpoint
// QuarantinedEndpoint: the endpoint (NodeId, FunctionalEntity, Name),
// the reason (the check of §4.6 that failed, with the clause), the reserved
// resources, Retryable (TRUE when the cause can go away: a component
// conflict, a ControlGroup in use, a namespace not loaded yet), and how to
// remove it: Discard.
func (c *Connections) RetryRestore(ctx context.Context, id string) error
func (c *Connections) Discard(ctx context.Context, id string) error
```

Discard deletes the record and releases its reservations in one committed
Apply, and removes nothing at runtime that the record did not create. The
Logger reports each quarantine at Warn. No OPC UA event type is invented.

### 4.8 Namespace-safe records

Every record carries the NamespaceArray (URIs) it was written with, as the
F.2 file carries its Namespaces; every NodeId in it is stored with an index
into that array. At load the indexes are mapped to the server's current
NamespaceArray. That covers the FunctionalEntity, the Input and
OutputVariables, the ControlGroups, the NodeIds inside RelatedEndpoint, and
the NodeIds nested in the PubSub structures (the PublishedVariables of
PublishedDataSets, the TargetVariables of readers, ...). The UAFX Conf
structures reuse `uafx.NamespaceIndexes` and the F.2 namespace handling of
`fxcm`; the PubSub structures need a NodeId walker over the ua types, new in
C3.1 and tested over every NodeId field of PubSubConfiguration2DataType. A
URI the server no longer has quarantines the record (Retryable).

### 4.9 Shared components and NotPersisted (C3-D2)

PC-1 is always enforced. PC-2 is enforced only with a StrictNotPersisted
connection option (proposed; false by default in v1.x: a documented
conformance deviation in LIMITATIONS.md and docs/uafx.md). A component
referenced by a persistent and a non-persistent endpoint (G14) needs
persisted for one and not persisted for the other: with StrictNotPersisted
it is refused (Bad_InvalidState, PC-3); without, it is persisted, restored
for the persistent endpoint, and the non-persistent endpoint is gone after a
restart (AP-6). The decision is made at validation (§4.3 step 1), never by
whichever endpoint wrote last.

### 4.10 Secure restart (PS-3)

No keys and no sequence numbers are stored. A restored **secured writer
group** would start its MessageNonce sequence at 1 under the token current
at the restart: four random bytes make a repeated nonce under the same key
unlikely but not impossible, and receivers ignore the restarted sequence
(§7.2.3). So a restored secured writer group does not publish under any
SecurityTokenId that was current or earlier when it was restored: it waits
for the next key of its SecurityGroup, and until then its endpoints stay at
Status Initial with the reason in the restore report and the Logger. A
restored **secured reader group** has lost its replay records: it accepts
messages only under a SecurityTokenId newer than the one current at the
restore (C3-D11). The SecurityMode is never lowered and nothing is sent
unsecured. C3.1 checks the PubSub runtime's initialization for these rules
and adds the "not before the next token" gate where it is missing. The cost:
a restored secured endpoint is not Operational for up to one KeyLifetime.

### 4.11 What C3 does not change on the AC

- ConfigurationData is not stored with the endpoint (AP-13). The
  VariableStorage Methods are out of C3 (C3-D7); the store can serve them
  later under its own key prefix.
- Non-persistent endpoints: memory only (AP-6 by construction).
- IsPersistent of an established endpoint cannot change (G9): an establish of
  an existing Name fails as today (Bad_BrowseNameDuplicated).

## 5. Boundary with the server's PubSub configuration

| Source | Owns | C3 |
|---|---|---|
| The PubSub runtime (`server`) | the live configuration, changed only in ChangePubSubConfiguration | unchanged; the single coordination point (PS-2) |
| `fxserver` records (`ac/pc/`) | the durable copy of the components persistent endpoints reference, with provenance | written in the same transaction as the runtime change (§4.3, §4.5) |
| The application's own configuration, applied before EnableConnections | components it configures and persists itself | adopted by a restore when equal; never deleted by UAFX |
| A future server-wide Part 14 store (PS-1) | every persisted component | not built in C3; the source field of `ac/pc/` records lets them become references to it, so there is never a second copy |

Rules: one durable copy per component; UAFX never deletes what it did not
create; the latest configuration of a component, whoever changed it, is
what is stored and restored; components with NotPersisted TRUE are never
stored.

## 6. The ConnectionManager: `fxcm`

### 6.1 Records

A Store in the Options (proposed field); nil keeps today's memory-only
Manager.

| Key | Record | Written |
|---|---|---|
| `cm/meta` | format, owner ApplicationURI, the generation counter, the RunID counter | with every Apply that advances a counter |
| `cm/set/<key>` | SetKey, Version, **generation** (a Manager-wide counter, +1 on every committed change of any set, never reset), **fingerprint** (SHA-256 of the canonical F.2 encoding of the set), the committed Conf | before the change is visible (§6.2) |
| `cm/ep/<id>` | the EndpointRecord of C2 plus the evidence of §6.5 (server identity, namespace-qualified NodeId, CreationTime, ConnectionManagerApplicationUri, the generation and fingerprint of the endpoint configuration) and its Class | with the run step that changes it |
| `cm/run/<id>` | RunID, set, generation, action, RollbackOnError, **phase** (§6.3), the endpoints established or closed so far | at each phase change |
| `cm/call/<id>` | call intent: RunID, AC, Establish or Close, the Names and NodeIds it may create or close | before each EstablishConnections or CloseConnections; ended after its result |

Not stored: the state machine state, edits in progress (their Lock is a
session's, OPC 10000-100 §7.2), Counters (Table 78), monitor readings.
Remote NodeIds are stored URI-qualified.

Version (CR-3) resets on Replace; the generation does not, so a Replace
with a set of the same Version is a different configuration to adoption
(§6.6).

### 6.2 Configuration changes

Add, Replace, Remove, Update (F.3) and a committed edit write the new set
record before the change is visible. Replace and Remove of a set with
Connections, and an Update that replaces or removes such sets, close the
old Connections on the ACs (F.3.3.2, C2 §5.8) before the new configuration
becomes the current one: those remote effects come **before** the local
change is durable. Such a change is therefore a run with a run record that
holds the old and the new generation, written in phase planned before the
first close: a crash leaves the obligation to finish the closes and the
switch in the store.

A failed Apply: definitely not committed fails the operation with
Bad_ResourceUnavailable (Update: in its OperationResults; a commit:
CommitUpdates answers it and the edit stays open); unknown keeps the
change out of memory and reports Bad_InternalError; the next Load (§3.3)
tells which configuration is current.

### 6.3 Run journal and call intents

C2 §5.4 handles a lost response within one Manager lifetime; a crash is a
lost response of every call in flight plus the loss of the run's
obligations. The run record keeps both, for Process (all actions), Replace,
Remove and Update. Phases (names illustrative):

| Phase | Meaning | Owed after a restart |
|---|---|---|
| planned | the run will call ACs; nothing sent | nothing; the record is deleted |
| executing | calls in flight or done; the endpoints so far are in the record and the call intents | with RollbackOnError TRUE: the set-wide rollback (CR-4); otherwise a Reconcile of the unended calls; for a set change: its remaining closes and the switch |
| rollback-required | a call aborted with RollbackOnError TRUE; the rollback has not finished | the rollback |
| reconciling | a Reconcile of this run is in progress | the Reconcile |
| completed | ended; the record is deleted in the same Apply as the final endpoint records | nothing |

A crash before the first rollback-close intent no longer loses the rollback:
the phase is rollback-required (or executing with RollbackOnError TRUE). The
owed work is **exposed, not executed**: after a restart the set is in Error
with its recovery status (§6.4) naming the owed work, and the next Process
or Reconcile of the set does it. An unended call intent is an unknown
outcome (C2 §5.4): its Names are re-proved (§6.5), never resent (no implicit
retry of an ambiguous call). An intent that cannot be written (not committed
or unknown) stops the step before the call: nothing is sent, and the run
ends in Error.

### 6.4 Restart and verification (C3-D5, C3-D9)

New loads the records without contacting any AC: a reachable AC is not a
precondition. Every endpoint record becomes **Unverified**, which is
treated like Unresolved: reported, never closed, never adopted, never
changed. Sets start in Ready, or in Error when a run record shows owed work
(G2, library interpretation: §6.9 has no start-up state).

Then a read-only verification starts in the background:

- per AC, a deadline per attempt (30 s by default) and bounded concurrency
  (the Manager's Parallelism by default);
- an AC that cannot be reached leaves its records Unverified and is tried
  again with a bounded backoff; Close cancels the verification;
- it re-proves each record (§6.5) and resolves the unended call intents.

Recovery status per set, through the Go API and the Observer. No OPC UA
"Verifying" state is invented: the state machine stays Ready, Processing,
Error.

```text
type Recovery struct {
	Pending    int           // records not yet verified
	Unverified []EndpointRef // could not be verified (AC unreachable, read failed)
	Owed       []OwedWork    // rollback, reconcile, pending close, set change to finish
	Done       bool
}
// returned with the set's status
```

ProcessConnectionConfigurationSets never blocks its Method handler: the run
is accepted as in C2, and its first step verifies the set's Unverified
records with the same bounds. Records still Unverified when that step ends
are treated as Unresolved for the rest of the run: an establish fails the
Connections whose Names they hold, a removal closes only KnownOwned
endpoints and leaves the set in Error with diagnostics naming the unverified
ones. Nothing unverified is ever closed or adopted.

C3-D9: C3.2 stores and loads records but has no verifier; in C3.2 every
loaded record stays Unverified, so no intermediate main trusts a restored
ownership record.

### 6.5 Re-proving ownership (identity)

CreationTime is evidence of an incarnation, not an identity (clock
corrections, its resolution, backups, a replaced device, a reused NodeId).
A record is KnownOwned again only when **all** of these hold:

| Evidence | Check |
|---|---|
| Server identity | the session's server is the record's: same ApplicationUri, and the same certificate thumbprint when the record was made over a secured channel |
| FunctionalEntity and Name | the endpoint of the record's Name is under the record's FunctionalEntity (by namespace-qualified NodeId, resolved through the caches of CL-5, CL-6) |
| NodeId | the namespace-qualified NodeId is the record's |
| ConnectionManagerApplicationUri | when the AC exposes it: equal to ours. A contradictory value makes the endpoint Foreign, whatever else matches, a matching CreationTime included |
| Incarnation | CreationTime, when the AC exposes it, equal to the record's; without CreationTime, ExclusiveApplicationURI must be asserted (the C2 Q2 safeguard) |
| Configuration | the endpoint's Variables (Mode, InputVariables, OutputVariables, RelatedEndpoint, IsPersistent, CleanupTimeout) match the record's generation and fingerprint |

Limits of the fallback without CreationTime (NodeId and URI under
ExclusiveApplicationURI): an AC that was reset and on which another client
using our ApplicationURI re-created an endpoint of the same Name at the same
NodeId cannot be told apart. ExclusiveApplicationURI is the deployment's
assertion that no other client uses that URI; docs/uafx.md says so.

Never: a failed Browse or Read taken for absence (the record stays
Unverified); an Unresolved record made KnownOwned by a reload. Unresolved
stays Unresolved unless new evidence of this table proves it or Settle
decides it. A record whose endpoint is verifiably absent (the Browse
succeeded and found no endpoint of that Name) is dropped.

### 6.6 Keep-in-place adoption (C3-D6)

An endpoint is adopted (left in place) only when it is KnownOwned after
verification, its record has the generation and fingerprint of the Config
being processed, and its actual configuration matches: the §6.5
configuration check, its communication links, its control ownership, its
persistence properties and its RelatedEndpoint's identity. What adoption
does follows the action (§6.7.5.3):

| Action | With an adoptable endpoint |
|---|---|
| ActionEstablishConnectionsEnabled | keep it and enable communication |
| ActionEstablishConnectionsDisabled | keep it and disable communication |
| ActionEstablishConnections | keep it and apply the enablement the set configures |
| ActionEnable / ActionDisable | act on it without removing it |
| ActionRemoveConnections | remove it; never adopt as a substitute |
| Any action, configuration changed | the reconfigure or re-create rules of C2 |

An adopted endpoint belongs to the run: with RollbackOnError TRUE, an abort
of the run closes it too (CR-4). An Unverified or Unresolved endpoint is
never adopted or changed.

### 6.7 Persistent endpoints from the CM (C3-D2, C3-D4)

- Validation: IsPersistent TRUE with a CleanupTimeout that is zero,
  positive, NaN or infinite is a ConfigError (§6.6.2); the planner refuses
  it too.
- NotPersisted: where the set's PubSub configuration does not state
  0:NotPersisted for a reader or writer (and, for persistent endpoints, its
  parents), the CM fills it from IsPersistent before it sends the
  configuration. An explicit value that contradicts IsPersistent is a
  ConfigError, never overwritten. A reader, writer or parent shared by a
  persistent and a non-persistent endpoint is a ConfigError (G14).

## 7. Failure windows

Each row is a point where the process stops (crash) or a store write fails.

### 7.1 AutomationComponent

| Where | After a restart | Tested (§9) |
|---|---|---|
| establish, before the commit Apply | nothing stored; no phantom endpoint; the CM sees a lost response and proves the Names absent | kill |
| establish, Apply committed, before the response | restored with the Enabled of the call; the CM proves it its own | kill |
| establish, Apply committed, acknowledgement lost (unknown) | restored; the CM got Bad_InternalError or no response and proves it | fault injection |
| disable (Remove FALSE), before the Apply | still enabled; nothing changed | kill |
| disable, after the Apply | restored disabled, control kept | kill |
| Remove TRUE, before the RemovePending Apply | restored as before; the CM holds the close as pending | kill |
| Remove TRUE, after RemovePending, before the runtime removal | removal completed at start-up; nothing restored | kill |
| Remove TRUE, after the runtime removal, before the record delete | as above | kill |
| Remove TRUE, RemovePending Apply unknown and not landed | restored as before; the CM repeats the close | fault injection |
| a change from another mechanism, before or after its record Apply | the latest committed configuration | fault injection |
| restore of a corrupt or conflicting record | quarantined, resources reserved; the others restored | file corruption |
| secured writer group restored | Initial until the next key; no nonce under an earlier token | kill |

### 7.2 ConnectionManager

| Where | After a restart | Tested (§9) |
|---|---|---|
| Add, Replace, Remove, Update, commit: before the set Apply | old configuration | kill |
| after the set Apply | new configuration | kill |
| Replace or Remove of a set with Connections, during the closes | run record, phase executing: the remaining closes and the switch owed; no endpoint forgotten | kill |
| establish, before the first call intent | run planned: nothing owed | kill |
| establish, call intent written, call in flight | unknown outcome: re-proved, never resent | kill |
| establish aborted, before the first rollback-close intent | phase rollback-required (or executing with RollbackOnError TRUE): rollback owed | kill |
| during the rollback | rollback owed with the closes still to do | kill |
| CM restarts while an AC is down | records Unverified, nothing closed; verification retries with bounds | AC stopped |
| AC restarts while the CM runs | the monitor sees the endpoints come back (persistent) or go (non-persistent); C2 rules | AC kill |
| both restart | both recover independently; the CM verifies against the restored AC | kill both |

## 8. Stages and gates

Three PRs from main, merged in turn; one release v1.40.0 after the final
review (C3-D9). Each stage brings its docs (docs/uafx.md, LIMITATIONS.md)
and its RELEASE.md entry.

| Stage | Content | Gate |
|---|---|---|
| C3.1 persistent AC | the store package (contract, MemoryStore, FileStore, contract tests), the AC record codecs with fuzz targets and namespace mapping (the PubSub NodeId walker), SupportsPersistence and start-up (§4.1), endpoint Diagnostics with CreationTime (AP-14), validate-stage-persist-activate (§4.3), durable disable and removal (§4.4), the transaction hook for other mechanisms (§4.5), restore and quarantine (§4.6, §4.7), shared components and provenance, PC-1 and StrictNotPersisted (§4.9), C3-D4, the secure-restart gate (§4.10) | persistent endpoints survive an abrupt restart (subprocess kill) with the right control and communication state, and no durable removal or disable is undone by a restart |
| C3.2 durable CM | the CM records with generation and fingerprint (§6.1), configuration changes before visibility (§6.2), run journal and call intents (§6.3), loading with every record Unverified (§6.4), C3-D2 and C3-D4 validation (§6.7) | a restarted CM keeps its configuration and its owed work, and trusts no ownership record |
| C3.3 recovery and adoption | the verification pass with deadlines, concurrency and cancellation (§6.4), re-proof (§6.5), owed work through Process and Reconcile, action-aware adoption (§6.6), recovery status, the CM projection after a restart, FEATURE-STATUS | CM and AC restart independently without an unsafe removal or a needless interruption |

## 9. Test plan

### 9.1 Crash tests

A real crash: the test binary re-executes itself as a child process that
runs an AC or a CM on a FileStore; the child stops at a named fault point and
tells the parent over a pipe, and the parent kills it with SIGKILL; a new
child starts on the same directory. Abandoning a Manager or Connections in
process is not a crash (its goroutines keep running) and is used only for
fault injection of store outcomes.

| Scenario | Expectation |
|---|---|
| AC killed before the commit | no phantom endpoint |
| AC killed after the commit, before the response | endpoint restored; CM proves it |
| store committed, acknowledgement lost | endpoint restored; CM treats the result as unknown and proves it |
| Remove interrupted at each boundary of §4.4 | never restored active |
| Remove FALSE, restart | restored disabled with its control |
| CM killed before the first rollback intent | rollback owed after the restart |
| CM killed during Replace or Remove | no ownership lost; closes owed |
| CM restarts while an AC is down | nothing destructive; bounded verification; Unverified reported |
| AC restarts while the CM runs | monitor and C2 rules |
| simultaneous restart | both recover |
| a foreign endpoint reusing the Name or the NodeId | never removed automatically |
| NamespaceArray reordered between two starts | records remapped and restored |
| a writer shared by two endpoints | removing one leaves the other communicating, before and after a restart |
| a corrupt record | quarantined, its resources reserved, no partial restore, the others restored |
| secured publisher restart | no message under the token current at the restore; Operational after the next key |
| repeated establish with the same configuration | adopted, no interruption of data |
| adoption with ActionEstablishConnectionsDisabled | stays disabled |

### 9.2 Other tests

- Contract tests against MemoryStore, FileStore and a fault store that
  returns each outcome (committed, not committed, unknown) at a chosen
  call; the AC and CM protocols run against the fault store.
- Fuzz targets for the AC record decoder, the CM record decoder and the
  FileStore data file.
- Race: the `server` CI job as for C2 (AGENTS.md rule 6).
- Bounds and cancellation: verification deadlines, Close during
  verification, Load and Apply with cancelled contexts, oversized values,
  bounded backoff of verification retries.
- Persisted check: NotPersisted TRUE on each parent for IsPersistent TRUE;
  StrictNotPersisted on and off; mixed sharing (G14).
- Changes from another mechanism: CloseAndUpdate modifying and removing a
  component a persistent endpoint references.

### 9.3 What the tests cannot show

That a process restart is a "power cycle" (G5), and, since none of the
pinned references of opcua-interop implements UAFX, that another AC or CM
reads persistence the way go-opcua does.

## 10. What opcua-interop could add

The peer search of C2 §9 first. For C3 an AC peer matters most: a CM
restart against an AC that is not go-opcua tests the re-proof of §6.5
against an independent reading of CreationTime and
ConnectionManagerApplicationUri.

## 11. Decisions

### 11.1 Outcomes of the first review (2026-11-26)

| # | Question | Decision |
|---|---|---|
| C3-D1 | SupportsPersistence | TRUE when a store is configured **and** initialized (loaded, compatible format, own owner); an init failure fails the start of the persistent subsystem, never a silent memory-only fallback; record failures are reported apart (§4.1) |
| C3-D2 | NotPersisted | PC-1 always; PC-2 behind StrictNotPersisted (default false in v1.x, documented deviation); the CM fills a missing NotPersisted and rejects a contradictory explicit one; shared-component conflicts detected at validation and planning (§4.9, §6.7) |
| C3-D3 | Store | Byte key-value with an atomic Apply, library-owned serialization and migration, no database dependency, with the contract of §3; shared interface and contract tests; MemoryStore and a FileStore with file and directory fsync |
| C3-D4 | CleanupTimeout | Bad_InvalidArgument for IsPersistent TRUE with zero, positive, NaN or infinite, before any mutation; `fxcm` validates too; never normalized (§4.3, §6.7) |
| C3-D5 | Verification | Revised: starts after New without needing the ACs, bounded and cancellable, recovery status per set; Process accepts the run and verifies inside it (§6.4) |
| C3-D6 | Adoption | In C3.3 with safeguards: generation and fingerprint, actual configuration verified, action-aware, subject to RollbackOnError, never unverified (§6.6) |
| C3-D7 | VariableStorage Methods | Out of C3; the store is reusable for them |
| C3-D8 | Remove FALSE | Restored disabled with control, disabled state durable, every enable and disable persisted, Remove TRUE prevents restoration; shared components keep what other endpoints need (§4.4) |
| C3-D9 | Delivery | Three stage PRs, one release; each intermediate main safe (C3.2 trusts no loaded record, §6.4) |
| C3-D10 | Failed records | Kept, reported, quarantined with their resources reserved until an administrative decision (§4.7) |

### 11.2 The nine revisions

| # | Revision | Where |
|---|---|---|
| 1 | Durable outcomes: committed, definitely not committed, unknown; reconciliation; durable atomicity, runtime rollback and external effects kept apart; stage, persist, activate | §3.2, §3.3, §4.3, §6.2 |
| 2 | Persistent deletion and disable: intent first, RemovePending, every crash boundary, failure to persist the intent | §4.4, §7.1 |
| 3 | CM run-level recovery: run record with phases for Process, Replace, Remove and Update, owed work exposed, no implicit retry | §6.2, §6.3, §7.2 |
| 4 | Identity and ownership: evidence set, a URI contradiction wins, fallback limits, a failed read is not absence | §6.5 |
| 5 | Part 14 coordination: PS-1 and PS-2, G6 corrected, one source of truth, the transaction hook, room for a server-wide store | §2.4, §2.5, §4.5, §5 |
| 6 | Shared components and provenance: canonical records, references, delete semantics, restore order, restore rollback | §4.2, §4.6 |
| 7 | Secure restart: no nonce under a token current at the restore, no downgrade, non-operational with a reason | §4.10 |
| 8 | Namespace-safe records: NamespaceArray per record, PubSub NodeId walker, reorder test | §4.8, §6.1, §9.1 |
| 9 | Crash testing: subprocess kill with FileStore and the listed scenarios; race, fuzz, bounds, cancellation and contract tests | §9 |

### 11.3 New questions

| # | Question | Recommendation |
|---|---|---|
| C3-D11 | A restored secured **reader** group has lost its replay records (§4.10). Accept only tokens newer than the one current at the restore (safe; the endpoint receives nothing until the publisher's next key), or accept the current token and document the replay window opened by a restart | The safe rule, as for writers |
| C3-D12 | FileStore in the library (needed by the contract and crash tests) or only under `examples/` | In the library: a tested reference, no external dependency, optional to use |
| C3-D13 | The codes for a store failure in a Method result: Bad_ResourceUnavailable (definitely not committed) and Bad_InternalError (unknown outcome), both library interpretations | As proposed; `fxcm` maps Bad_InternalError on an endpoint to an unknown outcome |
