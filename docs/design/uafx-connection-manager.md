# Design: UAFX ConnectionManager (C2)

Status: **approved 2026-11-24** after two reviews on PR #44 (the
first approved the architecture and asked for the revisions of rollback
scope, endpoint ownership, reprocessing, run identity, multicast, branch
mechanics and F.3 Replace; the second accepted them and Q1 to Q4, with the
ownership safeguard of §5.4). See §10. Implementation starts with C2.1.
Target release: v1.39.0.

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
| CS-10 | §6.8.2, F.1.3 | S | `RollbackOnError` TRUE: on an error during establishment, processing of the set stops and all established Connections that are part of the set are closed (§6.8.2, F.1.3: "all established Connections that are part of this set"; §6.7.3.2, EC-11) |
| CS-11 | §6.10 Table 94 | S | A `<Connection>` has `Endpoint1` and optionally `Endpoint2` |
| CS-12 | §6.11 Table 95 | S | An endpoint configuration has `FunctionalEntityNode` (a relative path starts at FxRoot), `ConnectionEndpoint` (its parameters), and optionally `ExpectedVerificationVariables`, `ControlGroups`, `ConfigurationData`, whose relative paths start at FunctionalEntityNode |
| CS-13 | §6.12 Table 96 | S | ConnectionEndpointParameter: `Name` unique in the FunctionalEntity's ConnectionEndpoints Folder; the CM rejects a change of Name while the Connection is established. At least one of InputVariableIds, OutputVariableIds, each non-empty when present; their relative paths start at FunctionalEntityNode. PreconfiguredPublishedDataSet and PreconfiguredSubscribedDataSet only for PubSubConnectionEndpointType |
| CS-14 | §6.13.3 | S | Flow configuration, unicast (1:1) and multicast (1:N, §6.13.3.2): the publisher references the flow with ToOutboundFlow; unicast, the subscriber references the single SubscriberConfiguration; multicast, each subscriber references its own or a shared SubscriberConfiguration, and a SubscriberConfiguration without Address takes the multicast Address of the flow; the configuration is invalid without an Address in the flow and in its SubscriberConfiguration; a missing HeaderLayoutUri means UADP-Periodic-Fixed; a missing TransportProfileUri means the default transport of the Address; ReceiveQos of a SubscriberConfiguration only when the flow has Qos, and it overrides it; AvailableRanges excludes RestrictToList TRUE |
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
| EC-11 | §6.7.3.2, §6.8.2, F.1.3 | S | With RollbackOnError TRUE it then calls CloseConnections with Remove TRUE for all ConnectionEndpoints established so far, which §6.8.2 and F.1.3 state as all established Connections that are part of the set; with FALSE it does nothing more |
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
| CM-9 | §6.7.6 | C2.3 | MaxConnectionConfigurationSets; MonitorsLocal/All from the Monitor option |
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
| CS-11, CS-12, CS-13, CS-15, CS-16 | §6.8 to §6.15 | C2.1 | Validation of a set; Name change refused while established |
| CS-10 | §6.8.2, F.1.3 | C2.2 | Set-wide over the endpoints this CM owns (§5.3); an endpoint whose ownership is not proven is reported, not closed (§5.4) |
| CS-14 | §6.13.3 | C2.1 (validation), C2.2 (use) | Unicast and multicast flows, and all five Connection types of §5.5.1 (bidirectional, unidirectional, unidirectional with heartbeat, autonomous publisher, autonomous subscriber) |
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
| EC-10, EC-15 | §6.7.3 | C2.2 | See §5 |
| EC-11 | §6.7.3.2 | C2.2 | As CS-10 |
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
| DG-6, DG-7 | §10.19, §10.20 | C2.2 | ConnectionNotMonitored when the Monitor option is not set | |
| DG-9 | §8.10, §8.11 | out (C2) | LogObject |
| ClientServer communication model | §6.13.4, §6.16.4 | out | Not defined in Part 81 1.00.04 |
| Persistent connections (IsPersistent TRUE) | §6.12, §5.5.5 | later (C3) | The AC side refuses them today (`Bad_NotSupported`, docs/uafx.md Persistence) |

What v1.39.0 claims: the ConformanceUnits of the rows marked C2.x, by
name, in docs/uafx.md and FEATURE-STATUS. It claims **no Part 84 Facet or
Profile**: the UAFX ConnectionManager 2024 Facet needs the UAFX SKS Push
Facet and the Logging Facet (Part 84 Table 45), which are later; the
Connection Monitoring Facet is covered by C2 but not claimed on its own. A set that
needs a later feature (SKS configuration, an AliasName, a ClientServer
flow) is refused as ConnectionConfigurationSetInvalid (or
AliasNameProcessingError), with a test for each.

## 4. Package layout and public API

### 4.1 Layout

| Package | What it gets | Why there |
|---|---|---|
| `uafx/fxcm` (new) | The ConnectionManager engine: the configuration model of a set built from `uafx.ConnectionConfigurationSetConf`, validation, the §6.9 state machine, resolution (§13.3), planning (Table 79, ordering, bundling, splitting), execution against the AutomationComponents, rollback, diagnostics, the F.2 file codec. A client-side component: no `server` import | §4.7.1: a CM can be a standalone application, part of a vendor application, or exposed on a server. The engine must work without a server (an application that only wants "establish this set") and be what the server serves |
| `uafx/fxserver` | `EnableConnectionManager`: exposes the Manager of package fxcm (C2.2) as the ConnectionManager of §6.7: the sets as ConnectionConfigurationSetType instances, the state machines, Edit and Process Methods, events, Diagnostics, Capabilities, AggregatedCurrentState, the F.3 file | Next to `EnableConnections`; reuses the LockingServices and Guard of C1 |
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

The engine converts a Conf once into an immutable `fxcm.Config` (resolved
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
	// ApplicationURI is the ApplicationUri of this ConnectionManager, the
	// one its sessions present. ACs record it in the
	// ConnectionManagerApplicationUri of the endpoints the CM creates
	// (§6.6.2); the ownership checks of §5.3 compare against it. Required.
	ApplicationURI string
	// ExclusiveApplicationURI asserts that no other ConnectionManager uses
	// ApplicationURI, so a matching ConnectionManagerApplicationUri can
	// prove ownership after a lost response (§5.4). Default false: such
	// endpoints stay unresolved.
	ExclusiveApplicationURI bool
	// CallTimeout bounds each EstablishConnections and CloseConnections
	// call (D6). Default 30 s. RollbackTimeout bounds the rollback of a run
	// as a whole. Default 2 minutes.
	CallTimeout, RollbackTimeout time.Duration
	// Parallelism bounds the AutomationComponents called at the same time
	// within one run (§6.7.3.2 recommends parallel calls). Default 8.
	Parallelism int
	// MaxConnectionConfigurationSets limits the sets (§6.7.6). 0: 256.
	MaxConnectionConfigurationSets int
	// Retry re-processes a set in Error after a delay (§6.9.1, transition 4
	// by vendor-specific means), only when its last run left no unresolved
	// endpoint (§5.5). Nil: never; see decision D5.
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
func (m *Manager) Add(conf *uafx.ConnectionConfigurationSetConf) (*Config, error)
func (m *Manager) Replace(ctx context.Context, conf *uafx.ConnectionConfigurationSetConf) (*Config, error) // validates first, then removes the Connections of the old set (FC-5, §5.8)
func (m *Manager) Remove(ctx context.Context, key SetKey) error                                            // the same
// Update applies a CloseAndUpdate batch (F.3.3) with RequireCompleteUpdate.
func (m *Manager) Update(ctx context.Context, ops []Operation, requireComplete bool) (applied bool, results []error)
func (m *Manager) Keys() []SetKey

// Config is the committed configuration of a set: immutable, one per
// Version. Status is the live part: state, diagnostics, runs, endpoints.
func (m *Manager) Config(key SetKey) (*Config, bool)
func (m *Manager) Status(key SetKey) (Status, bool)

// Process starts the processing of the sets (§6.7.5) and returns at once,
// one Start per key in the order of keys. Err is the Table 86 outcome as a
// ua.StatusCode (Bad_InvalidState while a set is Processing); Run is set
// when the run was accepted. The UA Method maps Err to its Results.
func (m *Manager) Process(action uafx.FxProcess, keys ...SetKey) []Start

type Start struct {
	Run *Run
	Err error
}

// Run is one processing of one set: an id unique within the Manager,
// the SetKey, the Version of the Config it processes, the Action.
type Run struct{ /* ... */ }

func (r *Run) ID() RunID // monotonic per Manager
func (r *Run) Key() SetKey
func (r *Run) Version() uint32
func (r *Run) Action() uafx.FxProcess
func (r *Run) Done() <-chan struct{}
func (r *Run) Wait(ctx context.Context) (*RunResult, error)

// RunResult is what a finished run did: the end state (Ready or Error),
// per Connection the diagnostics, the endpoints it created, closed and
// could not resolve (§5.4), and whether a rollback ran and completed.
type RunResult struct{ /* ... */ }

// Status is a copy of the live state of a set.
type Status struct {
	State       State // Ready, Processing, Error (§6.9)
	Version     uint32
	Diagnostics []*uafx.ConnectionDiagnostics
	Current     *Run // the run in progress, if any
	Last        *Run // the last finished run
	Endpoints   []EndpointRecord // known-owned and unresolved endpoints (§5.3)
}

// Reconcile closes the known-owned endpoints of a set that no committed
// configuration needs (survivors of RollbackOnError FALSE, of a failed
// rollback, of a removed Connection) and re-checks the unresolved ones
// (§5.4). It is a run (Processing, events) without an Action of
// FxProcessEnum: transition 1 or 4 by vendor-specific means.
func (m *Manager) Reconcile(key SetKey) Start

// Settle decides an unresolved endpoint the engine could not prove to be
// its own: Owned makes it known-owned (the next run closes it), Foreign
// forgets it (never touched).
func (m *Manager) Settle(key SetKey, ep EndpointRef, verdict Verdict) error

// SetKey is the identity of a set across replaces and restarts: the
// string BrowseName and the ConnectionConfigurationSetFolder (§6.7.2, F.3.3.2).
type SetKey struct {
	Folder []string
	Name   string
}

type Config struct{ /* immutable snapshot of one Version */ }

func (c *Config) Key() SetKey
func (c *Config) Version() uint32
func (c *Config) Conf() *uafx.ConnectionConfigurationSetConf // a copy

// Edit is the transactional edit of §6.7.4 for an application that holds
// the set in Go; fxserver maps EditConnectionConfigurationSets onto it.
func (m *Manager) Edit(key SetKey, owner LockOwner) (*Edit, error)
func (e *Edit) SetSelection(path SelectionPath, value any) error // RestrictToList checked
func (e *Edit) Commit() (*Config, error)                         // Version+1, re-derives CommunicationModelConfig (CS-19)
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
  4 to transition 2 or 3, with a RunID unique within the Manager and the
  Version of the Config it processes. At most one run per set; `Process`
  on a set in Processing is `Bad_InvalidState` (Table 86). Runs of
  different sets are independent and may run at the same time; two runs
  of different sets that use the same AutomationComponent are serialized
  per (AC, FunctionalEntity) for their scan and create steps, so that the
  absent-before check of §5.4 cannot race between them.
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

0. **Scan and reconcile** (§5.3): after step 1 has resolved the
   FunctionalEntities, browse each one for the endpoint Names of the set
   and classify what exists. Known-owned survivors of the set are closed
   with Remove TRUE before anything is created; a Connection with a
   foreign or unresolved endpoint of that Name fails with
   CreateConnectionEndpointError and Bad_BrowseNameDuplicated without a
   call, and the rest of the set goes on or stops as §5.3 says.
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
5. **Finish**: diagnostics (§5.7), ProcessingResult, transition 2 or 3,
   counters, events.

Splitting: the ConnectionEndpointConfigurations of a step are split at the
AC's MaxConnectionsPerCall; a split never separates a bundle of one
endpoint (EC-5). When `CommandBundleRequired` is TRUE in the set (§6.14) or
in the AC's capabilities (§6.2.6), the bundle is used; **library
interpretation**: either one suffices, since an AC that requires bundles
refuses split commands anyway.

Remove, Enable and Disable runs have one step per AC: CloseConnections
(Remove TRUE or FALSE) or EstablishConnections with EnableCommunicationCmd,
for the known-owned endpoints of the set on that AC (§5.3). Endpoints this
Manager has no record of (a CM restart, a set added after the Connections
were made by someone else) are reported, not acted on: adopting them is C3.

Multicast (CS-14): one publisher's outbound flow serves several Connections;
its WriterGroup and DataSetWriter are configured once, on the publisher's
step, and the ids it reserved or returned go into every subscriber's step
(E.2.2.2). The subscribers' steps run in parallel.

### 5.3 Endpoint ownership

Every endpoint the engine finds under the Name of an endpoint
configuration of the set is in one of these classes. Only the first may
be closed with Remove TRUE.

| Class | Proof | May the engine |
|---|---|---|
| **Known-owned** | This Manager created it: the EstablishConnections result returned its NodeId (ConnectionEndpointConfigurationResults), or the lost-response check of §5.4 proved it; and its ConnectionManagerApplicationUri (§6.6.2), when the AC exposes it, is the ApplicationURI option | close it, disable, enable, remove |
| **Taken preconfigured** | The set says IsPreconfigured TRUE (Table 79: "use a preconfigured ConnectionEndpoint") and this Manager's step took it (its result named it) | close it with Remove TRUE: §6.2.5.2 keeps preconfigured objects, so this releases it and does not delete it |
| **Unresolved** | It carries our ApplicationUri, or a step of ours may have created it, but there is no proof (§5.4) | report it (RunResult, Status, diagnostics), never close it; `Reconcile` re-checks it, `Settle` decides it |
| **Foreign** | Anything else: another ConnectionManagerApplicationUri, none on an endpoint this Manager has no record of, a preconfigured endpoint the set does not name as preconfigured, a preconfigured endpoint in use by someone else (RelatedEndpoint set, not by us) | never touch it; a Connection that needs that Name fails (D4) |

The records live in memory in C2 (keyed by SetKey, AC ServerUri,
FunctionalEntity path and Name, with the NodeId, the RunID and the Version
that created it). C3 persists them. A record of a known-owned endpoint
outlives the run, so "the endpoints of the set" is a set-wide notion, not a
per-run one.

### 5.4 Unknown outcomes

An EstablishConnections call whose response is lost (the channel breaks
after the request was sent, or the CallTimeout expires) has an unknown
outcome. `opcua.Client` reconnects and recovers the session (CL-1); the
engine never re-sends a state-changing call (OT Fabric rule: no implicit
retry of state-changing operations). It fails the step (fatal
communication error, EC-10), then, on the recovered or a new session,
browses each FunctionalEntity of the step for the Names the step meant to
create:

- **Proven ours** (made known-owned): the scan of step 0 of this run found
  the Name absent, the browse now finds exactly one endpoint of that Name,
  the AC exposes ConnectionManagerApplicationUri and it equals ours, and the
  (AC, FunctionalEntity) was serialized for this run (§5.1), so no other
  run of this Manager can have made it; **and** the deployment asserts
  that this Manager is the only ConnectionManager that uses its
  ApplicationUri (the ExclusiveApplicationURI option, false by default).
  §6.6.2 makes ConnectionManagerApplicationUri the identity of a
  ConnectionManager application, not of a transaction: the serialization
  of §5.1 works inside one Manager only and cannot exclude a second
  instance with the same ApplicationUri (a redundant pair, a copied
  configuration). Without the assertion the endpoint is unresolved even
  when the URI matches.
- **Absent**: nothing was created; nothing to do.
- **Anything else** (the AC has no ConnectionManagerApplicationUri, the
  Name was present before, the URI differs, the URI matches but the
  ownership is not asserted exclusive): unresolved: fail closed. A preconfigured
  endpoint the step meant to take is unresolved unless its RelatedEndpoint
  is the one the step set.

Never: closing whatever has the Name. §6.12 makes the Name unique within a
FunctionalEntity, which identifies an endpoint, not who made it.

`Settle` is an administrative decision, never an automatic recovery: the
engine itself never calls it, Retry and the monitor do not, and C2.3 does
not expose it as a UA Method. An application that offers it to operators
authorizes the caller itself; the Observer reports every Settle with its
verdict.

A timeout (CallTimeout, RollbackTimeout, a cancelled context) only stops
the engine waiting: it does not cancel the request at the AC, which may
still complete. The outcome is unknown and handled as above, never as
"not done".

A session that cannot be re-established fails the steps of that AC with
TargetServerConnectionError; its endpoints of this run stay unresolved
until a later Reconcile or run can check them.

### 5.5 Partial failure, rollback and reprocessing

A step fails when the call returns Uncertain (the AC aborted and undid that
call itself, Table 21), Bad, or a fatal communication error or timeout
(EC-10). Then:

1. No new step of the run starts. Steps in flight on other ACs finish or
   reach their CallTimeout (D6); a step that times out is an unknown
   outcome (§5.4).
2. With RollbackOnError TRUE, the engine closes with CloseConnections Remove
   TRUE **every known-owned and taken-preconfigured endpoint of the set**,
   not only those of this run (CS-10, EC-11: §6.8.2 and F.1.3 say "all
   established Connections that are part of this set"), per AC, in
   parallel, within RollbackTimeout. Unresolved and foreign endpoints are
   not closed; the Connections they belong to are reported with their
   FxError and Bad status, and the RunResult lists them.
3. A rollback close that fails or times out is recorded (CloseConnectionError
   and the StatusCode, DG-3) and not retried in the run; the endpoint stays
   known-owned with a close pending.
4. With RollbackOnError FALSE nothing more is called; the established
   endpoints stay known-owned and the diagnostics say which Connections
   failed.
5. Transition 3, events, diagnostics.

For close-type runs (Remove, Disable, the close of a Replace or Remove of a
set) a failure does not stop the run: every known-owned endpoint is
attempted, then transition 3 (EC-15). A remove run also closes known-owned
endpoints of Connections that a newer Version no longer has.

**Reprocessing.** One rule serves a re-run, a retry and the cleanup of
survivors: every establish run starts with step 0 (§5.2). It closes the
known-owned survivors of the set (from a run with RollbackOnError FALSE, a
failed rollback, an earlier Version) and establishes the Connections anew;
it fails, without calls, a Connection whose Name is taken by a foreign or
unresolved endpoint. A re-run of an established set therefore interrupts its
data flow: C2 does not keep endpoints in place (D4). Disable, Enable and
Remove act on known-owned endpoints only; an endpoint of the set that is
not known-owned is left alone and reported.

**Retries** (D5). Without the Retry option the engine never processes a
set by itself. With it, a set in Error is processed again (transition 4)
after a jittered, capped exponential delay, up to a maximum number of
attempts, only when (a) every failure of the last run was transient
(TargetServerConnectionError, a communication error or timeout, Bad_Locked,
Bad_TooManyOperations) and (b) the last run left **no unresolved
endpoint**. An unresolved endpoint stops automatic retries until `Reconcile`
or `Settle` clears it. A retry is a new run with step 0, never a replay of
a call.

### 5.6 Monitoring

The monitor subscribes to the Status of each endpoint of an established
Connection (§6.6.2), on the pooled sessions, and keeps ConnectionState per
§10.20 (DG-7). An endpoint that disappears (the NodeId is unknown, or a
browse by Name finds nothing: cleanup §5.5.4 or a restarted AC) makes the
Connection ConnectionNotEstablished and the endpoint RuntimeError (DG-6).
Re-establishing it is the application's decision (§4.7.2: the CM "could"
trigger it): with the Reestablish monitor option the monitor processes the
set again with the action of its last establish, a normal run with step 0;
without it, the state is only reported. A vanished endpoint's record is
dropped: the AC no longer has it. MonitorsLocalConnectionEndpoints and
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
| Lost response, ownership not proven (§5.4) | the FxError of the command of the step | Bad_CommunicationError or Bad_Timeout; listed as unresolved |
| The Name is taken by a foreign or unresolved endpoint | CreateConnectionEndpointError | Bad_BrowseNameDuplicated (no call made) |

### 5.8 Adding, replacing and removing sets (F.3)

CloseAndUpdate (FC-4, FC-5) and `Manager.Update` work in two phases:

1. **Validate the whole batch** before anything changes: decode the file
   (Bad_TypeMismatch), check every operation's bits (one bit, FC-6:
   Bad_InvalidArgument; none: Bad_NothingToDo), names (Bad_BrowseNameDuplicated
   for Add, Bad_NoMatch for Remove and Replace), authorization, the state of
   the target (Processing or Edit TRUE: Bad_InvalidState), and validate every
   new Conf (CS-8 to CS-16). With RequireCompleteUpdate TRUE, one failure
   ends the call here: ChangesApplied FALSE, nothing closed, nothing changed.
   With FALSE, the failed operations are dropped and the rest go on.
2. **Apply**: for Remove and Replace, close the known-owned endpoints of the
   old set (CloseConnections Remove TRUE, FC-5), then change the set table:
   Add and Replace give Version 1, state Ready, Edit FALSE, the Lock with the
   CM (SM-8); nothing is processed (F.3.3.2.2, F.3.3.2.4).

A remote close can still fail in phase 2, after validation. Table F.41 has
no code for it. **Library interpretation**: that operation's result is the
StatusCode of the failed close (as `fxserver` does for CloseConnections),
the old set stays in the table in state Error with CloseConnectionError in
its diagnostics, and the new Conf of a Replace is not installed. Closes are
not undone: with RequireCompleteUpdate TRUE, ChangesApplied is FALSE when
any operation failed, but the Connections already closed stay closed, which
the diagnostics and the AuditUpdateMethodResult event show. Operations are
applied in file order; an operation after a failed close still runs when
RequireCompleteUpdate is FALSE and is skipped (Bad_InvalidState) when it is
TRUE.

## 6. Stages

C2 is three stages, each its own branch and PR from main, merged to main
in turn: C2.1 on `feat/uafx-cm-model`, C2.2 on `feat/uafx-cm-engine`
started from main after C2.1 is merged, C2.3 on `feat/uafx-cm-server`
likewise (D11). Each PR is reviewable on its own and leaves main green with
coverage at the gates (90 % per package, 94 % merged). The exported API of
`uafx/fxcm` may still change between the stage PRs: gorelease compares
against the released v1.38.0, and v1.39.0 is released once, after C2.3,
with one RELEASE.md section that each stage PR extends.

### C2.1 Configuration model and state machine

- `fxcm.Config` from `uafx.ConnectionConfigurationSetConf`: index resolution
  (F.1.2.1), namespace scopes (F.1.2.2), SelectionList current values
  (F.1.2.3), validation of CS-8 and CS-10 to CS-16 with one finding per
  defect (ErrConfig, ConnectionConfigurationSetInvalid).
- SetKey, Version (CS-6), the edit snapshot model (ED-1 to ED-6 without the
  server: owner, commit, discard).
- The §6.9 state machine as a pure type: states, transitions, which
  transitions an action may start, the event each one has (SM-1 to SM-5).
- The endpoint ownership classes and the record of §5.3, and the
  decision rules of §5.4 and §5.5 (what a run may close, when a retry is
  allowed), as pure functions over scan results.
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
- Executor: scan and reconcile (step 0), parallel steps with CallTimeout,
  stop on failure, set-wide rollback within RollbackTimeout, unknown
  outcomes and the ownership proof, close runs, the six actions, multicast
  flows, `Reconcile` and `Settle` (PR-3 to PR-8, EC-10, EC-11, EC-15,
  CS-10).
- Run handles (RunID, Version, Wait), Config and Status (§4.3); the batch
  update of §5.8 without the file Methods.
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
| The CM-AC1 connection cut after the EstablishConnections request (chaos proxy) | Unknown outcome; the endpoint is proven ours (absent before, our ConnectionManagerApplicationUri) and removed by the set-wide rollback |
| The same, but AC1 does not expose ConnectionManagerApplicationUri | The endpoint is unresolved: not removed, listed in RunResult and Status; Retry does not fire; `Settle(Owned)` then `Reconcile` removes it |
| An endpoint of the set's Name made beforehand by another client (another ApplicationUri), and a preconfigured endpoint the set does not name as preconfigured | Foreign: that Connection fails with CreateConnectionEndpointError and Bad_BrowseNameDuplicated, no call; the endpoints are untouched after the run, the rollback and a Remove |
| Run 1 establishes Connection A, fails on B with RollbackOnError FALSE; RollbackOnError set TRUE by an edit; run 2 fails on B again | Run 2's step 0 closes A's survivors, re-creates A, fails on B, and the set-wide rollback removes A again: no endpoint of the set is left |
| A rollback close of AC1 times out (AC1 stalled by the chaos proxy) | The run ends within RollbackTimeout; AC1's endpoint stays known-owned with a close pending; the next run's step 0 closes it |
| Two Managers with the same ApplicationUri on one AC; Manager 1's response lost | Without ExclusiveApplicationURI the endpoint is unresolved for Manager 1 and foreign for Manager 2, neither closes it; with the option on Manager 1 only, Manager 1 reclaims it |
| Two Process calls on the same set; `Wait` on each Run | Different RunIDs; the second is refused (Bad_InvalidState) while the first runs; after it, a new run has a new RunID and Version |
| A multicast flow: AC1 publishes to a UDP multicast group, AC2 and AC3 subscribe (four servers) | One WriterGroup and DataSetWriter on AC1, both subscribers receive; Remove removes all three sides |
| AC2 restarted after establishment | The monitor reports ConnectionNotEstablished and RuntimeError; with Reestablish the set is processed again and data flows |
| Process twice on a set in Processing | Second Bad_InvalidState |
| Edit by client A, commit by client B | Bad_InvalidState for B; A's session ends: the edit is discarded |
| CommandBundleRequired AC, MaxConnectionsPerCall 1 with three Connections | Calls split per Connection, never inside a bundle |
| ElementReplace of an established set | The old Connections are removed first; the new set is Ready, not processed |
| A CloseAndUpdate batch with RequireCompleteUpdate TRUE whose second operation is invalid | Nothing is closed or changed, ChangesApplied FALSE |
| A Replace whose remote close fails | The old set stays in Error with CloseConnectionError; the new Conf is not installed; the operation result is the close StatusCode |
| A set with an AliasName, with an SKS configuration to apply, with a ClientServer flow | Refused as §3 says, no call made |

### 7.2 Unit and component tests

- State machine: every (state, trigger) pair, legal and illegal.
- Ownership: every row of the classes of §5.3 and every condition of the
  proof of §5.4 alone false, as table tests of the pure rules; the retry
  gate of §5.5.
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
- **Endpoint records and run journal**: the known-owned and unresolved
  records of §5.3 and, per run, what each step created, reserved and
  closed, with ids and Names. C2 keeps them in memory and reports them to
  the Observer; C3 gives them to the backend, writes the intent before each
  call, and uses them after a restart. Without them a restarted C2 Manager
  knows no endpoint as its own, so it closes nothing it did not create in
  its own lifetime (§5.3): safe, but it leaves survivors to C3.
- **Planner as a diff**: the planner takes the desired Connections and an
  observed state (which endpoints exist, their Status) and plans the steps
  between them. In C2 step 0 classifies the observed endpoints and closes
  the known-owned ones; C3 adds adoption (keep an endpoint in place when it
  matches the desired Version) and durable records, through the same code
  path.
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

## 10. Decisions

The maintainer reviewed the first version of this document on 2026-11-24
(PR #44). The table records the outcome and where the document changed.

| # | Question | Decision |
|---|---|---|
| D1 | Package: engine in a new `uafx/fxcm`, server exposure in `fxserver`, client wrappers in `uafx` | Accepted |
| D2 | The Annex F Conf structure as the canonical model, the §6.8 address space a projection | Accepted |
| D3 | Scope of C2. In: Edit, Process (all six actions), events, diagnostics, counters, Capabilities, F.3 file, endpoint monitoring, unicast and multicast flows. Later: SKS configuration, GDS lookup, AliasName, LogObject. Out: session-less, ClientServer | Accepted with limits: v1.39.0 claims no Part 84 Facet; the ConformanceUnits are listed by name; sets that need a later feature are refused with a test (§3). Multicast is in (CS-14, §5.2, §7.1) |
| D4 | An endpoint of that Name already exists | Revised: known-owned endpoints of the set are closed by step 0 and re-created; foreign and unresolved ones are never touched and fail their Connection; taking a preconfigured endpoint the set names as preconfigured stays (§5.3, §5.5) |
| D5 | Retries | Revised: opt-in only, transient errors only, and only when the last run left no unresolved endpoint; a retry is a new run with step 0, never a replay (§5.5) |
| D6 | On a failure, let parallel calls in flight finish, then roll back | Accepted with bounds: CallTimeout per call, RollbackTimeout per rollback; a timeout is an unknown outcome (§5.4, §5.5) |
| D7 | Process while a set is being edited | Accepted: the last committed Config |
| D8 | Default authorization of Edit, Process, SelectionList writes and file writes | Accepted: ConfigureAdmin, replaceable |
| D9 | A rollback close that fails | Revised: bounded by RollbackTimeout, recorded, the endpoint stays known-owned with a close pending; the next run's step 0 or `Reconcile` closes it (§5.5) |
| D10 | A co-located AutomationComponent | Accepted: loopback session |
| D11 | Delivery | Revised: three branches and PRs from main, merged in turn; one release v1.39.0 after C2.3 (§6) |
| D12 | ProcessingResult | Accepted |
| D13 | CommandBundleRequired from the set or the AC | Accepted: either |
| — | Rollback scope | Revised: set-wide over the known-owned endpoints (CS-10, EC-11, §5.5) |
| — | Unknown outcome | Revised: a Name match is not ownership; the proof of §5.4 or nothing is closed |
| — | Async API | Revised: Run handles with RunID and Version; Config (immutable) and Status (live) apart (§4.3) |
| — | F.3 Replace | Revised: validate the batch, then close, then change; RequireCompleteUpdate and close failures as §5.8 |

The four questions left by the revision were decided on 2026-11-24:

| # | Question | Decision |
|---|---|---|
| Q1 | A re-run of an established set re-creates its known-owned endpoints and interrupts the data flow (§5.5). Acceptable for C2, with keep-in-place left to C3? | Accepted: docs/uafx.md states the interruption; Retry stays opt-in |
| Q2 | Proof of ownership after a lost response needs ConnectionManagerApplicationUri, which §6.6.2 makes optional; without it the endpoint stays unresolved until `Settle`. Acceptable? | Accepted with a safeguard: a matching URI proves ownership only with ExclusiveApplicationURI; otherwise fail closed. `Settle` is an explicit administrative decision (§5.4). C2.2 adds a test with two Managers that share an ApplicationUri |
| Q3 | Defaults CallTimeout 30 s, RollbackTimeout 2 min | Accepted: configurable; a timeout keeps the outcome unknown (§5.4) |
| Q4 | The multicast end-to-end test needs four servers and UDP multicast with loopback; where CI cannot do multicast, the test is skipped with a REQUIRE switch like `pubsub-eth` | Accepted: validation and planner tests of multicast always run; only the UDP end-to-end test is skipped; no end-to-end multicast claim before it ran on a real network (C2.3) |
