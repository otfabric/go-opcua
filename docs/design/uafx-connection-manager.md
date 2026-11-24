# Design: UAFX ConnectionManager (C2)

Status: **proposal, for the maintainer's review**. No runtime code is
written until this design is approved. Target release: v1.39.0.

This document designs the ConnectionManager of OPC UA FX in go-opcua: the
ConnectionManagerType of OPC 10000-81 §6.7, the ConnectionConfigurationSets
of §6.8 and their state machine of §6.9, with the clauses a
ConnectionManager has to follow besides (§6.2.4, §6.10 to §6.16, §8, §9.2,
§9.3, §10.19, §10.20, §10.25, §10.26, §10.30, §12.3, §13, Annexes E and F).
It has a requirements catalogue with clause citations, a conformance
matrix, the package layout and public API, the concurrency and failure
model, the stages C2.1 to C2.3, the test plan, what C3 (persistent
connections) needs from C2, and what opcua-interop could add.

Sources read for it:

| Source | Version |
|---|---|
| OPC 10000-81 UAFX Connecting Devices and Information Model, [reference.opcfoundation.org](https://reference.opcfoundation.org/specs/OPC-10000-81/) | 1.00.04 |
| OPC 10000-84 UAFX Profiles (ConformanceUnits and Facets of the ConnectionManager, §5.2.6 Table 7, §6.6.4) | 1.00.04 |
| The CM NodeSet `uafx/internal/model/opc.ua.fx.cm.nodeset2.xml` | 1.00.04 |
| go-opcua v1.38.0 (`9f06022`): `uafx`, `uafx/fxserver`, `fxcmid`, `fxacid`, `fxdataid`, `docs/uafx.md`, `LIMITATIONS.md`, RELEASE.md v1.36.0 to v1.38.0 | |

Where Part 81 says nothing and the library has to choose, the choice is
marked **library interpretation**. Clauses are of Part 81 unless another
Part is named.

## 1. What exists

| Release | What it brought |
|---|---|
| v1.36.0 | `uafx.Inspect` (the UAFX model of a server, Findings), `fxserver.AddModel` (DI, Data, AC, CM namespaces; the ConnectionManager instance of §12.3 with `ModelCM`), `fxserver.ImportNodeSet` |
| v1.37.0 | `fxserver.EnableConnections`: EstablishConnections (§6.2.4, all nine commands, the order of §6.2.4.3.1, `CommandBundleRequired`, `MaxConnectionsPerCall`, the abort and the rollback of Table 21) and CloseConnections (§6.2.5) on the AutomationComponent side, backed by PubSub; endpoint Status, health, CleanupTimeout; `uafx.EstablishConnections` and `uafx.CloseConnections` on the client side |
| v1.38.0 | The DataTypes of the Data, AC and CM namespaces generated from the NodeSets, with their binary codecs, among them the Annex F configuration structures (`ConnectionConfigurationSetConf`, `ConnectionConfigurationConf`, `ConnectionEndpointConfigurationConf`, `AutomationComponentConfigurationConf`, `PubSubCommunicationFlowConfigurationConf`, `SubscriberConfigurationConf`, `ServerAddressConf`, `SecurityKeyServerAddressConf`, `AssetVerificationConf`, `PubSubCommunicationModelConfiguration`, `NodeIdentifier`, ...), the diagnostics types (`ConnectionDiagnostics`, `ConnectionState`, `FxError`, `LastActivityMask`) and the enumerations `FxEdit`, `FxProcess`, `ConnectionConfigurationSetOperation`; ControlGroups (§6.5) with the LockingServices of OPC 10000-100 §7 and the ConnectionAdmin authorization |

What is missing for a ConnectionManager is everything on the CM side: the
CM serves no Methods (`Bad_MethodInvalid` today, docs/uafx.md Limits),
holds no ConnectionConfigurationSets, has no state machine, and nothing
calls EstablishConnections on several AutomationComponents from a set.

## 2. Requirements catalogue

Each requirement has an id, the clause, its strength (S = shall, R =
should/recommended, M = may/optional), and what it asks, paraphrased. The
matrix in §3 says what C2 does with each.

### 2.1 The ConnectionManager object (§6.7.2, §6.7.6, §12.3)

| Id | Clause | S | Requirement |
|---|---|---|---|
| CM-1 | §12.3 Table 256 | S | A server that exposes a ConnectionManager has exactly one instance, `ConnectionManager`, organized by FxRoot, of ConnectionManagerType |
| CM-2 | §6.7.2 Table 77 | S | Mandatory Folder `ConnectionConfigurationSets`; it holds only ConnectionConfigurationSetType instances and Folders that organise them; it may be empty |
| CM-3 | §6.7.2 | S | The string part of the BrowseName of a ConnectionConfigurationSet is unique within its ConnectionConfigurationSets Folder |
| CM-4 | §6.7.2 | S | All processing of sets, by Method or by vendor-specific means, follows §6.7 |
| CM-5 | §6.7.2 | S | `AggregatedCurrentState` (optional) is TRUE when one or more state machines are in Error; it says nothing about the Connections |
| CM-6 | §6.7.2 Table 78 | S | Diagnostics counters (optional): EstablishCallCount, EstablishCallFailedCount (a call where any command failed), CloseCallCount, CloseCallFailedCount, counting local and remote calls |
| CM-7 | §6.7.2 | S | `GlobalDiscoveryServers` (optional): the GDS endpoints the CM shall use, in order of access (see CL-3) |
| CM-8 | §6.7.2 | S | `ConnectionManagerLog` (optional LogObject, OPC 10000-26): when supported, LogRecords for every call of Edit/ProcessConnectionConfigurationSets, every EstablishConnections and CloseConnections call and related calls, every error; the CM passes a SpanContextDataType with each EstablishConnections call |
| CM-9 | §6.7.6 Table 88 | S | Capabilities (optional): `MaxConnectionConfigurationSets`; `MonitorsLocalConnectionEndpoints` (the CM model reports the status of the Connections it created with an endpoint on this server); `MonitorsAllConnectionEndpoints` (all endpoints of the Connections it created), only with MonitorsLocalConnectionEndpoints |
| CM-10 | §6.7.2 | — | `ConnectionManagerConfiguration` (optional, Annex F.3) adds, removes and replaces sets through a file (see FC-1 to FC-6) |

### 2.2 ConnectionConfigurationSets (§6.8, §6.10 to §6.16, §9.2, §9.3)

| Id | Clause | S | Requirement |
|---|---|---|---|
| CS-1 | §6.8.2 Table 89 | S | Mandatory: `ConnectionConfigurationSetStateMachine`, `RollbackOnError`, `Lock` (LockingServicesType), one or more `<Connection>`, `<CommunicationFlow>`, `<ServerAddress>`, `<AutomationComponentConfiguration>`. Optional: `Edit`, `SecurityKeyServer`, `SecurityGroups`, `PubSubKeyPushTargets`, `Version`, `ConnectionsDiagnostics` |
| CS-2 | §6.8.2 | S | A set not in editable mode is locked to the CM and blocked from any change: the LockingClient is the NodeId of the ConnectionManager, the LockingUser `CM` |
| CS-3 | §6.8.1 | S | Standard clients change a set only through the SelectionListType Variables (OPC 10000-5): with RestrictToList TRUE, only to one of the Selections; a fixed value has itself as the only Selection and RestrictToList TRUE. Vendors may make other Variables writable, restricted by Role permissions |
| CS-4 | §6.8.1 | S | With Auditing, an AuditUpdateConnectionConfigurationSetEventType event (§8.5) for every modification of set data |
| CS-5 | §6.8.1 | S | With the log, a LogRecord for every change (SourceNode the Variable, the old and new value) |
| CS-6 | §6.8.2 | S | `Version`: monotonic, +1 on each change of the set whatever its source, ServerTimestamp the time of the change; 1 when a set is added or replaced |
| CS-7 | §6.8.2, §10.19 | S | `ConnectionsDiagnostics`: one element per `<Connection>`, linked by Name; updated each time processing of the set finishes, and, when the CM monitors endpoints, when it learns something new about them; by the rules of §10.19 (see DG-1 to DG-7) |
| CS-8 | §6.8.2 Table 90 | S | References: ServerAddress `ToAutomationComponentConfiguration` AutomationComponentConfiguration; AutomationComponentConfiguration `ToConnectionEndpointConfiguration` Endpoint1/Endpoint2; `ToOutboundFlow` present when an outbound PubSub flow is configured, `ToInboundFlow` when an inbound one is; at most one of each per endpoint |
| CS-9 | §6.8.2 | R | Clients that configure sets use the Role ConfigureAdmin; the modifiable content is writable for ConfigureAdmin (§5.9 Table 2) |
| CS-10 | §6.8.2 | S | `RollbackOnError` TRUE: on an error during establishment, processing of the set stops and all Connections of the set established so far are closed (§6.7.3.2, EC-11) |
| CS-11 | §6.10 Table 94 | S | A `<Connection>` has `Endpoint1` and optionally `Endpoint2` |
| CS-12 | §6.11 Table 95 | S | An endpoint configuration has `FunctionalEntityNode` (a relative path starts at FxRoot), `ConnectionEndpoint` (its parameters), and optionally `ExpectedVerificationVariables`, `ControlGroups`, `ConfigurationData`, whose relative paths start at FunctionalEntityNode |
| CS-13 | §6.12 Table 96 | S | ConnectionEndpointParameter: `Name` unique in the FunctionalEntity's ConnectionEndpoints Folder; the CM rejects a change of Name while the Connection is established. At least one of InputVariableIds, OutputVariableIds, each non-empty when present; their relative paths start at FunctionalEntityNode. PreconfiguredPublishedDataSet and PreconfiguredSubscribedDataSet only for PubSubConnectionEndpointType |
| CS-14 | §6.13.3 | S | Flow configuration: unicast, the subscriber references the single SubscriberConfiguration; the configuration is invalid without an Address in the flow and in its SubscriberConfiguration; a missing HeaderLayoutUri means UADP-Periodic-Fixed; a missing TransportProfileUri means the default transport of the Address; ReceiveQos of a SubscriberConfiguration only when the flow has Qos, and it overrides it; AvailableRanges excludes RestrictToList TRUE |
| CS-15 | §6.14 Table 101 | S | AutomationComponentConfiguration: `AutomationComponentNode` (relative to FxRoot), `CommandBundleRequired` (TRUE: the CM shall bundle commands to this AC), AssetVerifications, `CommunicationModelConfig` |
| CS-16 | §6.15 | S | AssetVerification: AssetToVerify relative to AutomationComponentNode; ExpectedAdditionalVerificationVariables relative to the Asset |
| CS-17 | §6.16.3 | S | PubSubCommunicationModelConfiguration: `Namespaces` maps the namespace indexes of PubSubConfiguration to the target server; NodeIds of the namespace `http://opcfoundation.org/UA/FX/CM/Translation/` are placeholders, resolved in two steps (TranslationTable to PortableNodeIdentifier, then on the target server per §13); a path of a published or subscribed Variable starts at the hosting AutomationComponent; `ConfigurationReferences` say add/match/modify/remove; `ConfigurationValues` hold the names and ids EstablishConnections assigned for null names and 0 ids |
| CS-18 | §6.16.3 | R/S | Null names and ids are recommended; PubSubConnections with ElementAdd and ElementMatch, null name and null PublisherId; when one matches, its PublisherId is used, and the CM shall adapt the subscribers' configuration to the returned PublisherIds; ElementAdd for groups |
| CS-19 | §6.16.3 | S | After a set is edited, the CM shall update the PubSubConfiguration (the flow Variables are reflected into CommunicationModelConfig, §6.13.1) |
| CS-20 | §9.2 | S | ServerAddress: Address a DiscoveryUrl; the CM shall resolve host names; SecurityMode and SecurityPolicyUri selection lists with RestrictToList TRUE; an empty SecurityPolicyUri means the best policy both support; ServerUri, when not null, verifies the server |
| CS-21 | §9.3 | S | SecurityKeyServer: Address, SecurityPolicyUri, ServerUri, UsePushModel; the connection to the SKS is always SignAndEncrypt; a co-located SKS may be reached by internal means |
| CS-22 | Table 94 vs NodeSet | — | §6.9.2 points at a `ProcessingResult` Property of ConnectionConfigurationType for per-Connection success; Table 94 has none, the NodeSet 1.00.04 has an optional `ProcessingResult` (StatusCode), and F.1.4 says it is Good when a set is loaded. **Library interpretation**: expose it and set it per Connection after each processing |

### 2.3 State machine and events (§6.9, §8.5 to §8.9)

| Id | Clause | S | Requirement |
|---|---|---|---|
| SM-1 | §6.9.2 Table 91, 93 | S | FiniteStateMachineType (OPC 10000-16) with states Ready (1), Processing (2), Error (3) and transitions ReadyToProcessing (1), ProcessingToReady (2), ProcessingToError (3), ErrorToProcessing (4); LastTransition mandatory |
| SM-2 | §6.9.2 | S | Transitions 1 and 4 are started by ProcessConnectionConfigurationSets, or by vendor-specific means |
| SM-3 | §6.9.2 | S | Transition 2 when processing of all Connections of the set succeeded; transition 3 when processing of any Connection failed; both only internally |
| SM-4 | §6.9.1 | — | Transient errors are cleared by processing the set again; a permanent error needs the integrator |
| SM-5 | §6.9.2 Table 92 | S | Events, when eventing is supported: ProcessingStarted on transitions 1 and 4, ProcessingSucceeded on 2, ProcessingFailed on 3 |
| SM-6 | §8.6 Table 114 | S | ConnectionConfigurationSetEventType: SourceNode the ConnectionManager; properties ConnectionConfigurationSetNode, Name, Action (FxProcessEnum) |
| SM-7 | §6.9.2, §8.6 | S | With the log: a LogRecord per transition with HasEffect; the event types map to LogRecords |
| SM-8 | §F.1.3 | S | A set created from a ConnectionConfigurationSetConfDataType starts in Ready, Edit FALSE, the Lock with the CM |

### 2.4 EditConnectionConfigurationSets (§6.7.4)

| Id | Clause | S | Requirement |
|---|---|---|---|
| ED-1 | §6.7.4 | S | StartEditing sets Edit TRUE and gives the Lock to the client session of the call; a set without the Edit Property is `Bad_InvalidState` |
| ED-2 | §6.7.4 | S | The Lock behaves as OPC 10000-100 §7: renewal, released when the session ends; when the Lock goes for any reason, the set is treated as DiscardUpdates |
| ED-3 | §6.7.4 | S | StartEditing on a set already in edit and locked to this session: no action, Good |
| ED-4 | §6.7.4 | S | CommitUpdates: Edit FALSE; the CM processes only committed updates; the Lock back to the CM; Version +1 when supported; rejected when the caller does not hold the Lock |
| ED-5 | §6.7.4 | S | DiscardUpdates: Edit FALSE, updates discarded, the Lock back to the CM; rejected when the caller does not hold the Lock |
| ED-6 | §6.7.4 | S | Commit or Discard of a set whose Edit is FALSE: the call is ignored for that set |
| ED-7 | Tables 80 to 82 | S | Results has the length of the input; Good, Bad_NodeIdUnknown, Bad_NodeIdInvalid, Bad_InvalidArgument (not a set), Bad_UserAccessDenied, Bad_InvalidState (locked by another client); the call is Bad_UserAccessDenied or Uncertain when an element failed |
| ED-8 | §6.7.4 | S | With Auditing, AuditUpdateMethodResultEventType for every call, SourceNode the CM; with the log, a LogRecord per set |

### 2.5 ProcessConnectionConfigurationSets (§6.7.5)

| Id | Clause | S | Requirement |
|---|---|---|---|
| PR-1 | §6.7.5.2 | S | Starts transition 1 or 4 on every requested set, returns at once; the result is reported by the events of §8.7 to §8.9 |
| PR-2 | Tables 84 to 86 | S | Results has the length of the input; Good, Bad_NodeIdInvalid, Bad_NodeIdUnknown, Bad_InvalidArgument, Bad_UserAccessDenied, Bad_InvalidState (the state does not allow processing); the call is Bad_UserAccessDenied, Bad_NotSupported (Action not supported) or Uncertain |
| PR-3 | §6.7.5.3.1 | S | ActionEstablishConnectionsEnabled: establish with a disabled communication model (DataSetReaders and DataSetWriters Enabled FALSE, everything else TRUE) and EnableCommunicationCmd in the sequence |
| PR-4 | §6.7.5.3.1 | S | ActionEstablishConnectionsDisabled: the same without EnableCommunicationCmd |
| PR-5 | §6.7.5.3.1 | S | ActionEstablishConnections: apply the communication model as configured, without EnableCommunicationCmd |
| PR-6 | §6.7.5.3.2 | S | ActionRemoveConnections: CloseConnections with Remove TRUE for all endpoints of the set (§6.7.3.3) |
| PR-7 | §6.7.5.3.3 | S | ActionEnableConnections: EstablishConnections with EnableCommunicationCmd for all endpoints of the set |
| PR-8 | §6.7.5.3.4 | S | ActionDisableConnections: CloseConnections with Remove FALSE for all endpoints of the set |
| PR-9 | §6.7.5.2 | S | With Auditing, AuditUpdateMethodResultEventType, SourceNode the CM; with the log, a LogRecord per set |
| PR-10 | Part 84 Table 7 | — | The ConformanceUnit needs Remove, Enable and Disable and at least one of the three establish actions |

### 2.6 Establishing and closing (§6.7.3, §6.2.4, §6.2.6, Annex E)

| Id | Clause | S | Requirement |
|---|---|---|---|
| EC-1 | §6.7.3.2 | S | The CM calls EstablishConnections on the involved AutomationComponents, one or more calls |
| EC-2 | §6.7.3.2, Figure 36 | S | Order per endpoint: CreateConnectionEndpointCmd, EstablishControlCmd, SetConfigurationDataCmd, ReassignControlCmd, SetCommunicationConfigurationCmd; in one call (the AC keeps the order) or in successive calls (the CM keeps it). VerifyAssetCmd, VerifyFunctionalEntityCmd, ReserveCommunicationIdsCmd and EnableCommunicationCmd at any time, in any order |
| EC-3 | §6.7.3.2 | S | A command whose configuration entry is null or empty is skipped |
| EC-4 | §6.7.3.2, §6.2.6 | S | The connections per call may be limited by the AC's `MaxConnectionsPerCall`; service limits (MaxMessageSize, MaxByteStringLength) may need SetConfigurationDataCmd split over calls |
| EC-5 | §6.7.3.2, §6.2.4.3.1, §6.2.6, §6.14 | S | With `CommandBundleRequired`, all required bundled commands (CreateConnectionEndpointCmd and SetCommunicationConfigurationCmd mandatory; EstablishControlCmd, SetConfigurationDataCmd, ReassignControlCmd optional) go in one call; the AC returns Bad_InvalidArgument for a bundled command sent alone |
| EC-6 | §6.7.3.2 | R | All required commands in one call; calls to several ACs in parallel |
| EC-7 | §6.7.3.2 Table 79 | S | The arguments are built from the set as Table 79 says (AssetVerifications from AssetVerificationType, ExpectedVerificationVariables, ConnectionEndpoint from the Parameter, ControlGroups, ConfigurationData, CommunicationConfigurations from CommunicationModelConfig, CommunicationLinks) |
| EC-8 | §6.7.3.2, §13 | S | The CM resolves the identifiers of the set into the arguments (CL-5 to CL-8) |
| EC-9 | §6.7.3.2, §13.4, E.5 | S | When an endpoint needs SKS configuration, the CM calls the SKS and adds SecurityGroups and/or PushTargets; the CM shall be able to configure an SKS for push distribution |
| EC-10 | §6.7.3.2 | S | On Uncertain from EstablishConnections (an abort, §6.2.4.3.11) or a fatal OPC UA communication error, the CM stops the sequence and takes ProcessingToError |
| EC-11 | §6.7.3.2 | S | With RollbackOnError TRUE it then calls CloseConnections with Remove TRUE for all endpoints established so far; with FALSE it does nothing more |
| EC-12 | §6.7.3.2 | S | With Auditing, an AuditClientUpdateMethodResultEventType event for every EstablishConnections call, and the AuditEntryId passed with the call |
| EC-13 | §6.7.3.2 | S | With the log, LogRecords for EstablishConnections calls: SourceNode the set, SourceName the Connection, one per error, ErrorCodeNode the related node |
| EC-14 | §6.7.3.2, §6.2.4.1, §5.9 | R | The CM has the Role ConnectionAdmin on the ACs |
| EC-15 | §6.7.3.3 | S | Closing uses CloseConnections; the CM may remove or disable. On any error the CM completes closing all Connections of the set, then takes ProcessingToError |
| EC-16 | §6.7.3.3 | S | When removed endpoints had SKS configuration, the CM removes it from the SKS |
| EC-17 | E.2.1 | — (informative) | Without a PubSubCommunicationModelConfiguration in the set the CM creates one from the flow configurations; with one, the CM resolves it and reflects the flows and SubscriberConfigurations in it; SecurityGroups and PushTargets go to the SKS, not to the AC |
| EC-18 | E.2.2 | — (informative) | Id flow between publisher and subscribers: reserve ids on the publisher, configure the subscriber with them, then configure the publisher with the ids the subscriber's call returned; calls to different ACs in parallel |
| EC-19 | F.1.5 | S | When InputVariableIds/OutputVariableIds are not NodeIds, the CM fills the source and target NodeIds of PublishedDataSetData and SubscribedDataSetData after resolving them |

### 2.7 Client functionality (§13)

| Id | Clause | S | Requirement |
|---|---|---|---|
| CL-1 | §13.1 | S | The CM behaves as a standard client and can recover an interrupted session; Call, Browse, TranslateBrowsePathsToNodeIds and Read; all node resolution options |
| CL-2 | §13.2.3 | M | Session-less calls are allowed, not for ReserveCommunicationIdsCmd (ids are released with the session) |
| CL-3 | §13.2.1 | S | With GlobalDiscoveryServers, the GDSs are asked in order (QueryApplications, GetEndpoints) until the server is found; else an error or a direct connection |
| CL-4 | §13.2.1, §13.2.2 | S | Endpoint selection: empty SecurityPolicyUri, the endpoint with the highest SecurityLevel the CM supports with the requested SecurityMode; else the one matching mode and policy. The session supports authentication, encryption and Roles. A server that is the CM's own may be called by vendor-specific means |
| CL-5 | §13.3.2 | S | PortableNodeId: map NamespaceUris through the target's NamespaceArray; an empty URI is index 1; the cache includes the NamespaceArray |
| CL-6 | §13.3.3 | S | PortableRelativePath: build BrowsePaths, TranslateBrowsePathsToNodeIds; cache with NamespaceArray and NamespacePublicationDate; resolve again when a namespace changed; several results for a path are an error |
| CL-7 | §13.3.4 | S | AliasName: FindAlias at the GDS (or the server itself), which returns server and NodeId |
| CL-8 | §13.3.1 | R | Cache resolutions; resolve again on a new configuration, a model change or an error |
| CL-9 | §13.4 | S | The CM can talk to a remote SKS and configure it for push |
| CL-10 | §13.5 | S | Errors of server lookup, connection, resolution, SKS and AutomationComponent calls go to ConnectionsDiagnostics |
| CL-11 | Part 84 Table 42 | — | Client facet: Read (optional), TranslateBrowsePath, Call, AliasName (optional), NTP time sync, DNS |

### 2.8 Diagnostics (§10.19, §10.20, §10.25, §10.30, §8.10, §8.11)

| Id | Clause | S | Requirement |
|---|---|---|---|
| DG-1 | §10.19 | S | At the end of processing: set the LastActivity bit of the action, clear the others |
| DG-2 | §10.19 | S | A Connection whose operations all succeeded: Error bit clear, ErrorEndpointN NoError, EndpointNStatus Good |
| DG-3 | §10.19 | S | A Connection where not all operations succeeded: Error bit set; affected endpoints get their FxError and StatusCode |
| DG-4 | §10.19 | S | Operations skipped because of an unrelated failure: ProcessingStopped, status Good |
| DG-5 | §10.19 | S | Established, then removed by rollback: Error bit, Rollback, status Good |
| DG-6 | §10.19 | M | Errors outside processing (RuntimeError of monitored endpoints, LocalSksKeyPushError) may overwrite the endpoint fields at any time |
| DG-7 | §10.20, Figures 58, 59 | S | ConnectionState: NotMonitored when the CM does not monitor; NotEstablished before establishment, after removal, or when an endpoint disappeared (cleanup, power cycle); otherwise from the endpoint Status: for bidirectional and unidirectional (with heartbeat) Connections, Initial when either endpoint is Initial, else Error when either is Error, else the lower of Ready < PreOperational < Operational (Figure 58); for autonomous publisher and subscriber, the Status of the one endpoint (Figure 59) |
| DG-8 | §10.30 | S | LastActivityMask: one activity bit (EstablishEnabled, EstablishDisabled, Establish, Remove, Enable, Disable) plus Error; establishing includes resolution and SKS work |
| DG-9 | §8.10, §8.11 | M | EstablishConnectionErrorEventType and CloseConnectionErrorEventType (BaseLogEventType): optional, a mapping of errors to LogRecords |

### 2.9 File configuration (Annex F)

| Id | Clause | S | Requirement |
|---|---|---|---|
| FC-1 | F.1.2 | S | References between structure arrays are Int32 indexes, negative for none; NodeIds and RelativePaths use the namespace array of their ServerAddressConf; SelectionLists are `<Var>`, `<Var>Selection`, `<Var>Modify` |
| FC-2 | F.2 Table F.37 | S | A file is a UABinaryFileDataType whose Body is an array of ConnectionConfigurationSetConfDataType; Namespaces has at least the UA and CM namespaces |
| FC-3 | F.3.2 | S | Open supports only Read (0x01) and Write+EraseExisting (0x06); writing needs authorization (ConfigureAdmin recommended) |
| FC-4 | F.3.3 Tables F.39 to F.41 | S | CloseAndUpdate(FileHandle, RequireCompleteUpdate, Operations) returns ChangesApplied, OperationResults, ConfigurationObjects; Bad_TypeMismatch, Bad_InvalidArgument, Bad_InvalidState, Bad_UserAccessDenied, Bad_NothingToDo; per operation Bad_BrowseNameDuplicated, Bad_NoMatch, Bad_NothingToDo, Bad_InvalidArgument, Bad_UserAccessDenied, Bad_InvalidState (being processed or edited) |
| FC-5 | F.3.3.2 | S | ElementAdd creates missing Folders and does not process; ElementRemove and ElementReplace call CloseConnections with Remove TRUE for all Connections of the set; Replace does not process the new set |
| FC-6 | F.3.4 | S | Exactly one operation bit; more than one fails |

## 3. Conformance matrix

Status: **C2.1**, **C2.2**, **C2.3** planned in that stage; **later** a
named later stream; **out** out of scope with the reason. "Partial" says
what part is planned.

| Req | Clause | Status | Reason or note |
|---|---|---|---|
| CM-1 | §12.3 | C2.3 | `AddModel(ModelCM)` already adds the instance; C2.3 serves it |
| CM-2, CM-3 | §6.7.2 | C2.1 (model), C2.3 (nodes) | Uniqueness checked on add, replace and BrowseName edits |
| CM-4 | §6.7.2 | C2.2 | One engine serves the Method, the Go API and the file |
| CM-5 | §6.7.2 | C2.3 | |
| CM-6 | §6.7.2 | C2.2 (counting), C2.3 (nodes) | |
| CM-7 | §6.7.2 | later | Needs CL-3; see decision D3 |
| CM-8 | §6.7.2 | out (C2) | go-opcua has no LogObject (OPC 10000-26). The engine reports the same facts to an `Observer` and `slog`, so a later LogObject can be fed from them |
| CM-9 | §6.7.6 | C2.3 | MaxConnectionConfigurationSets; MonitorsLocal/All only if monitoring is in C2 (D3) |
| CM-10, FC-1 to FC-6 | Annex F | C2.1 (F.2 codec), C2.3 (F.3 file) | The file codec is how sets get in; the FileType Methods follow `server/pubsub_config_file.go` |
| CS-1 | §6.8.2 | C2.3 | |
| CS-2 | §6.8.2 | C2.3 | Reuses the LockingServices of `fxserver/control.go` (C1) |
| CS-3 | §6.8.1 | C2.3 | SelectionListType writes checked against Selections and RestrictToList; no vendor-writable Variables besides them |
| CS-4 | §6.8.1 | C2.3 | When the server audits |
| CS-5 | §6.8.1 | out (C2) | LogObject, as CM-8 |
| CS-6 | §6.8.2 | C2.1 | |
| CS-7 | §6.8.2 | C2.2 | |
| CS-8 | §6.8.2 | C2.1 (validation), C2.3 (References) | The Conf indexes are the References (F.1.2.1) |
| CS-9 | §6.8.2 | C2.3 | Default authorization, D8 |
| CS-10, CS-11, CS-12, CS-13, CS-15, CS-16 | §6.8 to §6.15 | C2.1 | Validation of a set; Name change refused while established |
| CS-14 | §6.13.3 | C2.1 (validation), C2.2 (use) | |
| CS-17, CS-18 | §6.16.3 | C2.2 | Translation table, namespace mapping, null names and ids, PubSubConnection match and PublisherId propagation |
| CS-19 | §6.16.3 | C2.3 | On CommitUpdates |
| CS-20 | §9.2 | C2.2 | DNS through the Go resolver; ServerUri checked against the server certificate and the ApplicationUri of the endpoint |
| CS-21 | §9.3 | later | With the SKS work, D3 |
| CS-22 | §6.9.2 / NodeSet | C2.2 | Library interpretation |
| SM-1 to SM-3, SM-8 | §6.9 | C2.1 (machine), C2.3 (nodes) | Pure state machine in C2.1 |
| SM-4 | §6.9.1 | C2.2 | Re-processing; optional retry policy, D5 |
| SM-5, SM-6 | §6.9, §8.6 to §8.9 | C2.3 | Events through the server's event emitter |
| SM-7 | §6.9.2 | out (C2) | LogObject |
| ED-1 to ED-8 | §6.7.4 | C2.3 | Audit part when the server audits |
| PR-1 to PR-9 | §6.7.5 | C2.2 (engine), C2.3 (Method) | All six actions |
| PR-10 | Part 84 | C2.3 | Met by PR-3 to PR-8 |
| EC-1 to EC-8 | §6.7.3.2 | C2.2 | |
| EC-9, EC-16 | §6.7.3, §13.4, E.5 | partial | C2.2: a set whose flows need no security, or whose SKS keys are already in place (SecurityMode None, or keys provisioned outside the CM). Configuring an SKS (AddSecurityGroup, AddPushTarget, ConnectSecurityGroups, removal) is later, D3. A set that needs SKS configuration the CM cannot do is `ConnectionConfigurationSetInvalid`, not silently established |
| EC-10, EC-11, EC-15 | §6.7.3 | C2.2 | See §5 |
| EC-12 | §6.7.3.2 | C2.2 (AuditEntryId, `opcua.WithAuditEntryID`), C2.3 (client audit event on the CM's server) | |
| EC-13 | §6.7.3.2 | out (C2) | LogObject |
| EC-14 | §6.7.3.2 | C2.2 | The Dialer's identity is the application's; the docs say to grant ConnectionAdmin |
| EC-17, EC-18, EC-19 | Annex E, F.1.5 | C2.2 | E.2.2 is informative: the order is a library choice within EC-2 |
| CL-1 | §13.1 | C2.2 | `opcua.Client` reconnect and session recovery; an interrupted Call is an unknown outcome (§5.4) |
| CL-2 | §13.2.3 | out | go-opcua has no session-less service invocation |
| CL-3 | §13.2.1 | later | `gds.PullClient.QueryApplications` exists; D3 |
| CL-4 | §13.2 | C2.2 | `opcua.SelectEndpoint` with mode and policy; GetEndpoints on the Address (§13.2.2 via the server's own Discovery Services); LDS FindServersOnNetwork later |
| CL-5, CL-6, CL-8 | §13.3.2, §13.3.3 | C2.2 | Cache per server with NamespaceArray and NamespacePublicationDate |
| CL-7 | §13.3.4 | later | go-opcua has no FindAlias client; a set with an Alias is `AliasNameProcessingError` until then |
| CL-9 | §13.4 | later | D3 |
| CL-10 | §13.5 | C2.2 | |
| CL-11 | Part 84 | partial | NTP and DNS are the host's |
| DG-1 to DG-5, DG-8 | §10.19, §10.30 | C2.2 | |
| DG-6, DG-7 | §10.19, §10.20 | C2.2 if monitoring is in (D3), else ConnectionNotMonitored | |
| DG-9 | §8.10, §8.11 | out (C2) | LogObject |
| ClientServer communication model | §6.13.4, §6.16.4 | out | Not defined in Part 81 1.00.04 |
| Persistent connections (IsPersistent TRUE) | §6.12, §5.5.5 | later (C3) | The AC side refuses them today (`Bad_NotSupported`, docs/uafx.md Persistence) |

## 4. Package layout and public API

### 4.1 Layout

| Package | What it gets | Why there |
|---|---|---|
| `uafx/fxcm` (new) | The ConnectionManager engine: the configuration model of a set built from `uafx.ConnectionConfigurationSetConf`, validation, the §6.9 state machine, resolution (§13.3), planning (Table 79, ordering, bundling, splitting), execution against the AutomationComponents, rollback, diagnostics, the F.2 file codec. A client-side component: no `server` import | §4.7.1: a CM can be a standalone application, part of a vendor application, or exposed on a server. The engine must work without a server (an application that only wants "establish this set") and be what the server serves |
| `uafx/fxserver` | `EnableConnectionManager`: exposes a `*fxcm.Manager` as the ConnectionManager of §6.7: the sets as ConnectionConfigurationSetType instances, the state machines, Edit and Process Methods, events, Diagnostics, Capabilities, AggregatedCurrentState, the F.3 file | Next to `EnableConnections`; reuses the LockingServices and Guard of C1 |
| `uafx` | Client wrappers `EditConnectionConfigurationSets`, `ProcessConnectionConfigurationSets`, `ReadConnectionsDiagnostics`, like `EstablishConnections` | Same place as the AC client calls |

`uafx` keeps its existing API unchanged (AGENTS.md rule 5). `fxcm` depends
on `uafx` and `opcua`; `fxserver` on `fxcm`. No cycle: `uafx` does not import
`fxcm`.

### 4.2 Configuration model

The input of the engine is the Annex F structure
`uafx.ConnectionConfigurationSetConf`, generated in v1.38.0. It is the one
serialised form the specification defines (F.1.1 lists persistence, files
and CM configuration as its uses), it is what an engineering tool writes
(F.2), and it already has the binary codec and the round-trip tests. The
address-space form of §6.8 is a projection of it that C2.3 builds and
writes back on CommitUpdates. **Library interpretation**: the Conf form is
canonical inside the library; F.1.3 calls the two "semantically
equivalent".

The engine converts a Conf once into an immutable `fxcm.Set` (resolved
indexes, the SelectionList current values, the namespace tables of
F.1.2.2), validates it, and processes only such snapshots. An edit creates a
new snapshot on CommitUpdates; a run that is in progress keeps the snapshot
it started with (ED-4: only committed updates are processed).

### 4.3 API sketch

Names are proposals; the shape is what this review is about. The blocks
are sketches of code that does not exist yet, so they are not Go blocks
(docsync compiles those).

```text
package fxcm

// Manager is a UAFX ConnectionManager (OPC 10000-81 §6.7). It is safe for
// concurrent use.
type Manager struct{ /* ... */ }

type Options struct {
	// Dialer opens the client of a ServerAddress (§9.2, §13.2). The default
	// dials with opcua.NewClient, GetEndpoints on the Address and
	// opcua.SelectEndpoint with the SecurityMode and SecurityPolicyUri of
	// the set, and checks the ServerUri.
	Dialer Dialer
	// Parallelism bounds the AutomationComponents called at the same time
	// within one run (§6.7.3.2 recommends parallel calls). Default 8.
	Parallelism int
	// MaxConnectionConfigurationSets limits the sets (§6.7.6). 0: 256.
	MaxConnectionConfigurationSets int
	// Retry re-processes a set in Error after a delay (§6.9.1, transition 4
	// by vendor-specific means). Nil: never; see decision D5.
	Retry *RetryPolicy
	// Monitor watches the ConnectionEndpoints of established Connections
	// (§4.7.2, §10.20). Nil: ConnectionState is ConnectionNotMonitored.
	Monitor *MonitorOptions
	// Observer receives transitions, calls and errors; it must not block.
	Observer Observer
	Logger   *slog.Logger
}

func New(opts Options) (*Manager, error)
func (m *Manager) Close() error // stops runs and monitors, closes sessions

// Sets (F.3.3.2 semantics, used by the file and by applications).
func (m *Manager) Add(conf *uafx.ConnectionConfigurationSetConf) (*Set, error)
func (m *Manager) Replace(ctx context.Context, conf *uafx.ConnectionConfigurationSetConf) (*Set, error) // removes the Connections of the old set first (FC-5)
func (m *Manager) Remove(ctx context.Context, key SetKey) error                                         // the same
func (m *Manager) Sets() []*Set
func (m *Manager) Set(key SetKey) (*Set, bool)

// Process starts the processing of the sets (§6.7.5) and returns at once,
// one error per set (Table 86 as ua.StatusCode: Bad_InvalidState while a
// set is Processing). Wait or the Observer gives the outcome.
func (m *Manager) Process(action uafx.FxProcess, keys ...SetKey) []error
func (m *Manager) Wait(ctx context.Context, key SetKey) (RunResult, error)

// SetKey is the identity of a set across replaces and restarts: the
// string BrowseName and the ConnectionConfigurationSetFolder (§6.7.2, F.3.3.2).
type SetKey struct {
	Folder []string
	Name   string
}

type Set struct{ /* immutable snapshot */ }

func (s *Set) Key() SetKey
func (s *Set) Version() uint32
func (s *Set) State() State // Ready, Processing, Error (§6.9)
func (s *Set) Diagnostics() []*uafx.ConnectionDiagnostics
func (s *Set) Conf() *uafx.ConnectionConfigurationSetConf // a copy

// Edit is the transactional edit of §6.7.4 for an application that holds
// the set in Go; fxserver maps EditConnectionConfigurationSets onto it.
func (m *Manager) Edit(key SetKey, owner LockOwner) (*Edit, error)
func (e *Edit) SetSelection(path SelectionPath, value any) error // RestrictToList checked
func (e *Edit) Commit() (*Set, error)                            // Version+1, re-derives CommunicationModelConfig (CS-19)
func (e *Edit) Discard()

// Dialer and Session are what the engine needs of a server (§13.1).
type Dialer interface {
	Dial(ctx context.Context, addr *uafx.ServerAddress) (Session, error)
}
type Session interface {
	NamespaceArray(ctx context.Context) ([]string, error)
	Read(ctx context.Context, req *ua.ReadRequest) (*ua.ReadResponse, error)
	Browse(ctx context.Context, req *ua.BrowseRequest) (*ua.BrowseResponse, error)
	TranslateBrowsePaths(ctx context.Context, req *ua.TranslateBrowsePathsToNodeIDsRequest) (*ua.TranslateBrowsePathsToNodeIDsResponse, error)
	Call(ctx context.Context, req *ua.CallMethodRequest) (*ua.CallMethodResult, error)
	Close(ctx context.Context) error
}

// Files (F.2).
func DecodeFile(b []byte) ([]*uafx.ConnectionConfigurationSetConf, error)
func EncodeFile(sets []*uafx.ConnectionConfigurationSetConf) ([]byte, error)
```

```text
package fxserver

type ConnectionManagerOptions struct {
	Manager *fxcm.Manager
	// Editable adds the Edit Property to every set (§6.8.2, §6.7.4).
	Editable bool
	// File adds ConnectionManagerConfiguration (Annex F.3).
	File bool
	// Authorizer decides Edit, Process, SelectionList writes and file
	// writes. Nil: sessions with ConfigureAdmin (D8).
	Authorizer CMAuthorizer
}

func EnableConnectionManager(srv *server.Server, ns Namespaces, opts ConnectionManagerOptions) (*ConnectionManager, error)
func (c *ConnectionManager) Close() error
```

```text
package uafx

func EditConnectionConfigurationSets(ctx context.Context, c *opcua.Client, action FxEdit, sets []*ua.NodeID) (ua.StatusCode, []ua.StatusCode, error)
func ProcessConnectionConfigurationSets(ctx context.Context, c *opcua.Client, action FxProcess, sets []*ua.NodeID) (ua.StatusCode, []ua.StatusCode, error)
```

Errors follow the package convention: one sentinel per package
(ErrConfig for an invalid set, ErrManager for the rest), with
a `ua.StatusCode` in the chain where the specification gives one.

## 5. Concurrency and failure model

### 5.1 Units of work

- **Run**: the processing of one set for one action, from transition 1 or
  4 to transition 2 or 3. At most one run per set; `Process` on a set in
  Processing is `Bad_InvalidState` (Table 86). Runs of different sets are
  independent and may run at the same time.
- **Step**: one EstablishConnections or CloseConnections call to one
  AutomationComponent. Steps of a run are ordered by a plan (§5.2); steps
  on different AutomationComponents run in parallel up to
  the Parallelism option (§6.7.3.2).
- **Session pool**: one client session per ServerAddress (address,
  SecurityMode, SecurityPolicyUri, ServerUri), shared by runs and the
  monitor, reference-counted. ReserveCommunicationIdsCmd and the later
  SetCommunicationConfigurationCmd that uses the ids go on the same session
  (CL-2: the ids are released with the session).

Locks: one Manager mutex for the set table, one mutex per set for its state
and diagnostics. No lock is held across a network call or a call of the
Observer. The server side (C2.3) handles requests one at a time: the
ProcessConnectionConfigurationSets handler only takes the transition and
starts the run, and the run writes the state, events and diagnostics to the
address space from its own goroutine through the server's thread-safe node
API. This is also what makes a co-located AutomationComponent work: the run
calls EstablishConnections on its own server over a loopback session after
the Process handler has returned (D10).

### 5.2 The plan of an establish run

Per run, after validation of the snapshot:

1. **Connect and resolve** (C2.2): open or reuse the session of each
   ServerAddress; read NamespaceArray and NamespacePublicationDates; resolve
   AutomationComponentNode, FunctionalEntityNode, the variable, ControlGroup,
   ConfigurationData and verification identifiers (CL-5, CL-6) and the
   translation placeholders of the PubSub configuration (CS-17). Read the
   capabilities MaxConnectionsPerCall and CommandBundleRequired of each AC
   (§6.2.6). Failures: TargetServerConnectionError, ResolvingNamespacesError,
   ResolvingPathsError for the Connections of that AC.
2. **Verify and reserve**: per AC, one call with VerifyAssetCmd,
   VerifyFunctionalEntityCmd and ReserveCommunicationIdsCmd for the
   publishing ACs (E.2.2 step 1). These commands may be issued at any time
   (EC-2). An AC with CommandBundleRequired gets them too: they are not in
   the bundle (§6.2.4.3.1).
3. **Subscribers**: per subscribing AC, the bundle (Create, EstablishControl,
   SetConfigurationData, ReassignControl, SetCommunicationConfiguration with
   the reserved publisher ids and null ids of its own publishing side), plus
   EnableCommunicationCmd for ActionEstablishConnectionsEnabled.
4. **Publishers**: per AC that publishes to a subscriber of step 3, a call
   with the configuration completed with the ids step 3 returned (E.2.2
   step 3). An AC that is both is handled in two calls when its counterpart
   assigns ids; when all ids are reserved up front, one call per AC (E.2.2.2).
5. **Finish**: diagnostics (§5.5), ProcessingResult, transition 2 or 3,
   counters, events.

Splitting: the ConnectionEndpointConfigurations of a step are split at the
AC's MaxConnectionsPerCall; a split never separates a bundle of one
endpoint (EC-5). When `CommandBundleRequired` is TRUE in the set (§6.14) or
in the AC's capabilities (§6.2.6), the bundle is used; **library
interpretation**: either one suffices, since an AC that requires bundles
refuses split commands anyway.

Remove, Enable and Disable runs have one step per AC: CloseConnections
(Remove TRUE or FALSE) or EstablishConnections with EnableCommunicationCmd,
for the endpoints of the set on that AC, found by (FunctionalEntity, Name)
when the run has no NodeId for them (a restart, or a set added after the
Connections were made).

### 5.3 Partial failure and rollback

A step fails when the call returns Uncertain (the AC aborted and undid that
call itself, Table 21), Bad, or a fatal communication error (EC-10). Then:

1. No new step of the run starts. Steps already in flight on other ACs are
   allowed to finish (**library interpretation**: cancelling a Call in
   flight makes its outcome unknown, which is worse; see D6).
2. Transition 3 is decided; before it is taken, with RollbackOnError TRUE,
   every endpoint that a finished step of this run established is closed
   with CloseConnections Remove TRUE, per AC, in parallel (EC-11). Endpoints
   established by earlier runs are not touched: "established so far" is read
   as "by this processing" (**library interpretation**).
3. A failure of a rollback close is recorded (CloseConnectionError on that
   endpoint, the StatusCode) and not retried within the run; the endpoint
   stays in the run's journal as an orphan, and the next run of the set, or
   C3's reconciliation, closes it first (D9).
4. With RollbackOnError FALSE nothing more is called; the established
   endpoints stay and the diagnostics say which ones failed.

For close-type runs (Remove, Disable, the close of a Replace or Remove of a
set) a failure does not stop the run: all steps are attempted, then
transition 3 (EC-15).

### 5.4 Unknown outcomes and reconnection

An EstablishConnections call whose response is lost (the channel breaks
after the request was sent) has an unknown outcome. `opcua.Client`
reconnects and recovers the session (CL-1), but the engine does not
re-send a state-changing call (OT Fabric rule: no implicit retry of
state-changing operations). It treats the step as failed (fatal
communication error, EC-10) and, for rollback, looks the endpoints of the
step up by (FunctionalEntity, Name), which §6.12 makes unique, and closes
those it finds. The Name is the identity that survives a lost response, a
CM restart and an AC restart; NodeIds are a cache.

A session that cannot be re-established fails the steps of that AC with
TargetServerConnectionError; other ACs continue as in §5.3.

### 5.5 Retries and re-processing

Part 81 leaves re-processing to the Process Method or vendor-specific means
(SM-2, SM-4). The engine never retries by itself unless
the Retry option is set: then a set that ended in Error is processed again
(transition 4) after a jittered, capped exponential delay, up to a maximum
number of attempts, and only for errors classed transient
(TargetServerConnectionError, a fatal communication error, Bad_Locked,
Bad_TooManyOperations from a busy AC); a configuration or verification
error is permanent and needs the integrator (§6.9.1). See D5.

### 5.6 Monitoring (if D3 includes it)

The monitor subscribes to the Status of each endpoint of an established
Connection (§6.6.2), on the pooled sessions, and keeps ConnectionState per
§10.20 (DG-7). An endpoint that disappears (the NodeId is unknown, or a
browse by Name finds nothing: cleanup §5.5.4 or a restarted AC) makes the
Connection ConnectionNotEstablished and the endpoint RuntimeError (DG-6).
Re-establishing it is the application's decision (§4.7.2: the CM "could"
trigger it): with the Reestablish monitor option the monitor processes the
set again with the action of its last establish; without it, the state is
only reported. MonitorsLocalConnectionEndpoints and
MonitorsAllConnectionEndpoints follow what is monitored.

### 5.7 Diagnostics mapping

Which FxErrorEnum value a failure gives (§10.25) is fixed per stage;
Part 81 names the values, the stage that produces each is the library's
mapping:

| Failure | FxError | Endpoint status |
|---|---|---|
| Set invalid (validation, a feature the library lacks: Alias, SKS config, ClientServer) | ConnectionConfigurationSetInvalid, or AliasNameProcessingError for an Alias | Bad_ConfigurationError / Bad_NotSupported |
| Session to the AC's server | TargetServerConnectionError | the service or dial StatusCode |
| NamespaceArray, missing namespace | ResolvingNamespacesError | Bad_NoMatch |
| BrowsePath not found, or more than one node (CL-6) | ResolvingPathsError | the TranslateBrowsePaths status, or Bad_BrowseNameDuplicated for several |
| Command results of EstablishConnections | VerifyAssetError ... EnableCommunicationError (the command that failed, §10.25 values 13 to 21) | the StatusCode of the element |
| CloseConnections | CloseConnectionError | the element's StatusCode |
| Skipped because of another Connection's failure | ProcessingStopped | Good (DG-4) |
| Established, then rolled back | Rollback | Good (DG-5) |

## 6. Stages

C2 is three stages on the branch `feat/uafx-connection-manager`, released
together as v1.39.0 (D11). Each stage ends with its tests, docs and
coverage at the gates (90 % per package, 94 % merged).

### C2.1 Configuration model and state machine

- `fxcm.Set` from `uafx.ConnectionConfigurationSetConf`: index resolution
  (F.1.2.1), namespace scopes (F.1.2.2), SelectionList current values
  (F.1.2.3), validation of CS-8 and CS-10 to CS-16 with one finding per
  defect (ErrConfig, ConnectionConfigurationSetInvalid).
- SetKey, Version (CS-6), the edit snapshot model (ED-1 to ED-6 without the
  server: owner, commit, discard).
- The §6.9 state machine as a pure type: states, transitions, which
  transitions an action may start, the event each one has (SM-1 to SM-5).
- Diagnostics model: ConnectionDiagnostics per Connection, LastActivity,
  the §10.19 update rules, ConnectionState from endpoint Status (Figures 58
  and 59).
- F.2 file codec with a fuzz target (`FuzzDecodeFile`): untrusted input.
- No network, no server. Tests are table-driven.

### C2.2 Orchestration engine

- Dialer, endpoint selection and ServerUri check (CL-4, CS-20); session pool.
- Resolver with cache and namespace-change detection (CL-5, CL-6, CL-8, CS-17).
- Planner: Table 79 arguments, command order across calls, bundling,
  splitting, the E.2.2 id flow, PublisherId propagation (EC-2 to EC-7,
  EC-17 to EC-19, CS-18).
- Executor: parallel steps, stop on failure, rollback, unknown outcomes,
  close runs, the six actions (PR-3 to PR-8, EC-10, EC-11, EC-15).
- Diagnostics and counters, AuditEntryId on the calls (EC-12), Observer and
  slog, optional Retry and Monitor.
- The Go API of §4.3 is usable at the end of C2.2 without a server.

### C2.3 Public ConnectionManager Methods

- fxserver EnableConnectionManager: the sets as ConnectionConfigurationSetType
  instances in the ConnectionConfigurationSets Folder (with sub-Folders),
  their References (Table 90), SelectionListType Variables, Version,
  ConnectionsDiagnostics, ProcessingResult, the state machine Variables
  (CurrentState, LastTransition).
- EditConnectionConfigurationSets (ED-1 to ED-8) with the Lock of C1;
  SelectionList writes; CommitUpdates re-derives the PubSub configuration
  (CS-19); AuditUpdateConnectionConfigurationSetEventType.
- ProcessConnectionConfigurationSets (PR-1, PR-2, PR-9), the events of
  §8.6 to §8.9, AggregatedCurrentState, the Diagnostics counters,
  Capabilities.
- ConnectionManagerConfiguration (F.3): Open, Write, CloseAndUpdate with
  ElementAdd, ElementRemove, ElementReplace.
- Client wrappers in `uafx`; `Inspect` reads the set states and diagnostics.
- docs/uafx.md ConnectionManager section, LIMITATIONS.md, RELEASE.md,
  FEATURE-STATUS, an example (`examples/uafx/cm`).

## 7. Test plan

### 7.1 Headline: a full lifecycle across three servers

`uafx/fxcm` end-to-end test (and the same scenario in `conformance/uafx`
over every security policy): two go-opcua servers AC1 and AC2, each its own
`server.Server` with its own PubSub runtime, `fxserver.EnableConnections`
and an AutomationComponent with a FunctionalEntity, started independently
on their own ports; a third server CM with `EnableConnectionManager`; a
test client that drives the CM only through its Methods and the F.3 file.
The CM's sessions to AC1 and AC2 use SignAndEncrypt and a user with
ConnectionAdmin; the test client has ConfigureAdmin on the CM.

Lifecycle, each step checked on all three servers (endpoints, PubSub
components, Status, data, state, events, diagnostics, Version):

1. Write a file with one set (a bidirectional Connection AC1 <-> AC2, with
   asset and FE verification, a ControlGroup, ConfigurationData, null ids)
   and CloseAndUpdate ElementAdd: the set is Ready, Version 1, Edit FALSE,
   locked to the CM.
2. Process ActionEstablishConnectionsEnabled: Started, then Succeeded
   events; endpoints on both ACs, data flows both ways over UDP;
   diagnostics EstablishEnabled, NoError, Good; ConnectionOperational with
   monitoring.
3. ActionDisableConnections: data stops, endpoints stay, ConnectionReady.
4. ActionEnableConnections: data flows again.
5. Edit: StartEditing, change PublishingInterval to another Selection,
   CommitUpdates: Version 2, the derived PubSub configuration changed;
   process again and see the new interval on the wire.
6. ActionRemoveConnections: endpoints and the readers and writers the CM
   configured are gone on both ACs; ConnectionNotEstablished.

Failure scenarios in the same harness:

| Scenario | Expected |
|---|---|
| AC2's FunctionalEntity does not verify, RollbackOnError TRUE | AC2 aborts its call; AC1's endpoint closed by the CM; AC1 Connection diagnostics Rollback/Good, AC2 VerifyFunctionalEntityError; Failed event; Error; AggregatedCurrentState TRUE |
| The same, RollbackOnError FALSE | AC1's endpoint stays; diagnostics say which side failed |
| AC2 not running at the first Process | TargetServerConnectionError, Error; start AC2, Process again (transition 4): Ready. With a Retry policy, without the second Process |
| The CM-AC1 connection cut after the EstablishConnections request (chaos proxy) | Unknown outcome treated as failure; rollback finds the endpoint by Name and removes it |
| AC2 restarted after establishment | The monitor reports ConnectionNotEstablished and RuntimeError; with Reestablish the set is processed again and data flows |
| Process twice on a set in Processing | Second Bad_InvalidState |
| Edit by client A, commit by client B | Bad_InvalidState for B; A's session ends: the edit is discarded |
| CommandBundleRequired AC, MaxConnectionsPerCall 1 with three Connections | Calls split per Connection, never inside a bundle |
| ElementReplace of an established set | The old Connections are removed first; the new set is Ready, not processed |

### 7.2 Unit and component tests

- State machine: every (state, trigger) pair, legal and illegal.
- Validation: every defect of CS-8 to CS-16 and FC-1 alone, on a valid set.
- Planner: golden plans (command masks per call, call order, splitting,
  bundles) for the Annex E topologies: one Connection, two ACs with several
  Connections, three ACs (E.1.3), autonomous publisher and subscriber,
  unidirectional with heartbeat.
- Executor with a fake Session: a failure injected at every step of every
  AC, for each action and both RollbackOnError values, checking the calls
  made after the failure and the diagnostics of every Connection (DG-1 to
  DG-5).
- ConnectionState: the 25 cells of Figure 58 and the 5 rows of Figure 59.
- Edit: Tables 80 to 82, lock expiry and session end.
- Resolver: PortableNodeId, relative paths with several results, a changed
  NamespaceArray, a changed publication date.
- File codec: round trip, Table F.40/F.41 codes, `FuzzDecodeFile`.
- Leak checks (`leak_main_test.go`) in every new package; the race job
  runs `uafx/fxcm`; long e2e tests that start three servers go beside the
  `server` job if they push the shared race job's time (AGENTS.md rule 6).
- Chaos (`chaos/uafx`): parallel runs of several sets sharing ACs under
  connection faults leave no orphan endpoints after a final Remove.

### 7.3 What the tests cannot show

Everything is go-opcua against go-opcua. None of the pinned references of
opcua-interop implements UAFX, so no claim of interoperability follows from
these tests (AGENTS.md rule 4).

## 8. What C3 needs from C2

C3 adds persistent connections and a CM that survives restarts, through an
application-supplied backend that reconciles the desired with the actual
state. C2 prepares for it without persisting anything:

- **Stable identities**: SetKey for sets; (AC, FunctionalEntity path, Name)
  for endpoints. NodeIds are caches that C3 re-resolves (CL-8).
- **Desired state** is the committed Conf with its Version: exactly what a
  backend stores (F.1.1 names persistence as a use of the Conf types).
- **Run journal**: each run records per step what it created, reserved and
  closed, with ids and Names; C2 keeps it in memory and in the Observer,
  C3 gives it to the backend and replays it after a crash.
- **Planner as a diff**: the planner takes the desired Connections and an
  observed state (which endpoints exist, their Status) and plans the steps
  between them. In C2 the observed state of an establish run is "nothing"
  (or what D4 decides); C3 fills it from a scan of the ACs, which makes
  reconciliation the same code path.
- **Resolution cache with NamespaceArray and publication dates** (CL-5,
  CL-6) so that a reloaded cache can be checked before use.
- **AC side**: IsPersistent TRUE (`Bad_NotSupported` today) and
  SupportsPersistence on `fxserver` are C3's AC part, with the same backend
  interface.

## 9. What opcua-interop could add

- **Peer search**: none of the pinned references of opcua-interop
  (open62541, Milo, node-opcua, asyncua, async-opcua, .NET) implements UAFX.
  A search should cover each upstream for UAFX AC or CM work (branches,
  issues, companion-model support) and other open implementations of Part 81
  and Part 84 before C2.3 is released; a found AC implementation lets the CM
  be tested against an AutomationComponent that is not go-opcua, which is the
  evidence that matters most here (an AC peer exercises our CM client side;
  a CM peer our `fxserver` side).
- **Fixtures**: a ConnectionConfigurationSet file (F.2) written by an
  engineering tool that is not ours would test the Conf codec and the
  validation against an independent reading of Annex F.
- **Own image**: an `own` container that runs a go-opcua AC and a go-opcua
  CM (ADR-0012), so that consumers and future peers can run the lifecycle of
  §7.1 against the released library.

## 10. Decisions for the maintainer

| # | Question | Proposal |
|---|---|---|
| D1 | Package: engine in a new `uafx/fxcm`, server exposure in `fxserver`, client wrappers in `uafx`? | Yes |
| D2 | The Annex F Conf structure as the canonical model, the §6.8 address space a projection? | Yes |
| D3 | Scope of C2. In: Edit, Process (all six actions), events, diagnostics, counters, Capabilities, F.3 file, endpoint monitoring with MonitorsLocal/All. Later: SKS configuration (CS-21, EC-9, EC-16, CL-9; needed for the "UAFX ConnectionManager 2024" Facet), GDS lookup (CM-7, CL-3), AliasName (CL-7), LogObject (CM-8 and the log rows). Out: session-less, ClientServer | As listed; SKS is the first item after C2 |
| D4 | Establish when an endpoint of that Name already exists on the FunctionalEntity (a re-run, another CM) | C2: fail with CreateConnectionEndpointError, no adoption; C3 adds reconciliation that adopts endpoints this CM made |
| D5 | Retries | None by default; opt-in `RetryPolicy` (jittered, capped, transient errors only) that uses transition 4 |
| D6 | On a failure, let parallel calls in flight finish, then roll back | Yes |
| D7 | Process while a set is being edited | Process the last committed snapshot (ED-4), do not refuse |
| D8 | Default authorization of Edit, Process, SelectionList writes and file writes | ConfigureAdmin (§6.8.2, F.3.2), with an Authorizer to replace it, as C1 did for ConnectionAdmin |
| D9 | A rollback close that fails | Record it, no retry in the run; closed first by the next run of the set |
| D10 | A co-located AutomationComponent | Loopback client session in C2; an in-process path later if needed |
| D11 | Delivery | One branch, three stage PRs reviewed in turn, one release v1.39.0 after C2.3 |
| D12 | ProcessingResult (in the NodeSet, not in Table 94) | Expose it, set per Connection |
| D13 | CommandBundleRequired from the set (§6.14) or the AC (§6.2.6) | Bundle when either is TRUE |
