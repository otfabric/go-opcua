# go-opcua Releases

## v1.43.0

**Date:** 2026-11-28
**Previous release:** v1.42.1

Phase 2 of docs/roadmap.md, the items of phase 3 and the first item of phase 4.

- Generated Method contracts, with their pilot, Part 20 files. A generator emits typed contracts of Methods from the NodeSet; a public FileType and FileDirectoryType on the server and in a new client package `filetransfer` are built on them, and the four FileType implementations of the library (the TrustLists of push management and `ServeTrustList`, the PubSubConfiguration file, the UAFX ConnectionManagerConfiguration) and the clients of their files now share them.
- The server gives every Structure, Union, Enumeration and OptionSet DataType its DataTypeDefinition Attribute, from the Definition of the NodeSet it imports. A client decodes the Structures and Unions it has no Go type for with that Attribute, opt in (`opcua.DynamicTypeDecoding`).
- HistoryRead processed with the Part 13 Aggregates: the new package `server/aggregate` calculates every standard Aggregate of OPC 10000-13 §5.4.3, for the built-in `*Historian` and for any `HistoryProvider` that has raw reads only. Its evidence is Annex A: the tests calculate all 1358 rows of the 159 example tables of AggregateExamples.csv (pinned in `schema/manifest.json`); 1294 match the file in value, timestamp and StatusCode, and the 64 others are rows where the file conflicts with a clause and the package follows the clause, each listed with it. A monitored item with an AggregateFilter (Part 4 §7.22.4) calculates the same Aggregates the same way, once per publishing interval.
- History Annotations and change audit events. The server keeps Annotations (Part 11 §5.1.2, §6.6.6) of the nodes with the Annotations Property: HistoryUpdate UpdateStructureDataDetails (§6.9.3) writes them, HistoryRead ReadAnnotationDataDetails (§6.5.6) and a raw read of the Property read them, the raw values at their times carry the ExtraData bit, and the AnnotationCount Aggregate (Part 13 §5.4.3.20) counts them; the client has helpers for both services. With auditing on, the server reports the audit events of Write (AuditWriteUpdateEventType, Part 4 §6.5.8), HistoryUpdate (the AuditHistoryUpdateEventType subtypes, Part 11 §5.8) and NodeManagement (the AuditNodeManagementEventType subtypes, Part 4 §6.5.7), for successful and failed calls.
- The client session keep-alive while idle: a connected client keeps its session open when it sends nothing, and notices a connection that is gone without being closed (on by default, `SessionKeepAlive(0)` turns it off).
- The server reports changes of its address space in GeneralModelChangeEvents and SemanticChangeEvents and maintains the NodeVersion of its nodes, and it has a NamespaceMetadata Object for each namespace, whose DefaultRolePermissions and DefaultAccessRestrictions apply to the nodes without their own.
- The managed RoleSet of OPC 10000-18, opt in (`server.WithRoleManagement`): AddRole and RemoveRole, the Role Methods and the Properties of the roles, with the roles granted at ActivateSession next to those of the RoleMapper and applied to the active sessions on every change; the client package `rolemgmt`. Without the option the roles come from the RoleMapper alone, as before.
- The Methods of the Server Object (OPC 10000-5 §9): GetMonitoredItems, ResendData, SetSubscriptionDurable and RequestServerStateChange, served on the Server Object and called with typed contracts generated for ServerType, from `*opcua.Client` and `*opcua.Subscription`. A durable subscription lives in memory, for up to 24 hours by default, with queues of up to 10000 values.
- Every Mandatory Property of the ServerCapabilities (OPC 10000-5 §6.3.2) has a value: ServerProfileArray, LocaleIdArray, MinSupportedSampleRate, MaxHistoryContinuationPoints and SoftwareCertificates had none.
- Push certificate management that survives a restart (phase 4 of docs/roadmap.md): the new package `server/pushstore` keeps the trust lists, certificates and keys of every certificate group in a directory, writes each ApplyChanges in one atomic write and restores it in `server.New`; a failed ApplyChanges applies nothing and discards its transaction (Part 12 §7.10.2).

### Added

- server: the DataTypeDefinition Attribute (AttributeId 23) of the DataTypes of namespace 0 and of every model `ImportNodeSetXML` imports. "The Attribute shall be mandatory for DataTypes derived from Structure and Union", with a StructureDefinition, and "for DataTypes derived from Enumeration, OptionSet and subtypes of UInteger representing an OptionSet", with an EnumDefinition (OPC 10000-3 §5.8.3, Table 16). "The DataTypeDefinition Attribute can be populated from the DataTypeDefinition belonging to a UADataType" (OPC 10000-6 §F.12), which lists only the fields the DataType adds: the importer follows the HasSubtype Reference to the supertype, in the document or already in the address space (namespace 0, a model imported before or a DataType a program gave the Attribute), and puts its fields first, "this list shall begin with the fields of the baseDataType followed by the fields of this StructureDefinition" (Part 3 §8.48).
  - StructureDefinition: BaseDataType is the direct supertype; DefaultEncodingId the DataTypeEncoding with the BrowseName `0:Default Binary` (Part 3 §5.8.3), null for an abstract DataType ("If the DataType is abstract the DefaultEncodingId shall be null", §8.48) and for one without that encoding; StructureType from IsUnion, IsOptional and AllowSubTypes by OPC 10000-6 §F.12 Table F.13, over the inherited fields as well, as "the subtypes extend the EncodingMask defined for the parent" (Part 6 §5.2.7); a StructureField per field with its Name, Description, DataType (an alias resolved, BaseDataType when absent), ValueRank, ArrayDimensions (one 0, "unknown", per dimension when the NodeSet gives none; null for a scalar, Part 3 §8.51), MaxStringLength and IsOptional, which is the field's IsOptional in a StructureWithOptionalFields, its AllowSubTypes in a StructureWithSubtypedValues or UnionWithSubtypedValues and false otherwise (§8.51). Union (`i=12756`) and its subtypes are unions.
  - EnumDefinition: an EnumField per field with its Name, Value, DisplayName and Description (Part 3 §8.50, §8.52); for an OptionSet the Value is the number of the bit, as the NodeSet writes it. A subtype of an Enumeration without a Definition of its own has the fields of its supertype.
  - A Definition that cannot be mapped is logged at Warn and the DataType has no Attribute; the import goes on. These are a combination of flags Table F.13 does not have ("Any combination of flags that does not have a mapping is invalid and an error should be raised"), a field DataType that is no NodeId or alias, a ValueRank that is neither -1 nor ≥ 1 ("It shall be Scalar (-1) or a fixed rank Array (>=1)", §8.51), ArrayDimensions with another number of dimensions than the ValueRank or that are not UInt32s, a Definition with fields on a DataType that is no Structure, Enumeration or OptionSet (Part 6 §F.11) and a Structure whose supertype has no StructureDefinition.
- `server/aggregate`: `Request` (Aggregate, Start, End, ProcessingInterval, `Config`) with `Check`, `Intervals`, `Interval`, `Window`, `Calculate` and `CalculateIntervals`; `Config` with `DefaultConfig`, `Valid`, `Override` and `AggregateConfiguration`; `Supported`, `Functions`, `Name` and `Description`. It implements the intervals of Part 13 §5.4.2.2 (Table 49, reverse reads, ProcessingInterval 0), Interpolated and Simple Bounding Values (§3.1.8, §3.1.9) with sloped and stepped interpolation and extrapolation, the PercentValues and PercentTime StatusCode calculation (§5.4.3.2), the Partial bit (§5.3.3.2), the EffectiveEndTime of a 1 ms resolution (§5.4.2.4) and the result types of Table 50.
- `ua`: the HistorianBits of Part 4 §7.38.1, Table 177: `StatusCodeHistorianCalculated`, `StatusCodeHistorianInterpolated`, `StatusCodeHistorianDataLocation`, `StatusCodeHistorianPartial`, `StatusCodeHistorianExtraData`, `StatusCodeHistorianMultiValue` and `StatusCodeHistorianBits`.
- server: `AggregateConfigProvider` (the configuration of a Variable's Aggregates) and `AggregateFunctionLister` (the Aggregates of a `ProcessedHistoryReader`); `Historian.SetAggregateConfig`, `Historian.AggregateConfig` and `Historian.AggregateFunctions`.
- server: the AggregateFunctions folder of the HistoryServerCapabilities organizes the Aggregates of the history provider (Part 11 §5.7.2) and follows `SetHistorian`; the AggregateFunction Objects have the Description of Part 13 Table 5 (mandatory, §4.2.2.2).
- server: the AggregateFilter of a data monitored item (Part 4 §7.22.4). The item keeps its samples as raw values. When the publishing timer expires it queues one value per completed interval: "The MonitoredItem only reports values for intervals that have completed when the publish timer expires". The value is calculated as a HistoryRead over the same raw values would calculate it ("in the same manner as a historical read with the Partial Bit set", Part 13 §4.3.2). Its ServerTimestamp is the end of the interval. The `AggregateFilterResult` returns the revised startTime, processingInterval and aggregateConfiguration:
  - a processingInterval of 0 becomes the publishing interval (Part 13 §5.4.3.1), at least 100 ms and twice the revised sampling interval (Part 4 Table 147), at most a day;
  - the startTime becomes the first boundary startTime + n × processingInterval after the creation;
  - the configuration of the Variable comes from the history provider (Part 13 §4.3.1).
- server: the AggregateFunctions folder of the ServerCapabilities (Part 5 §6.3.2), "an entry point to browse to all AggregateFunctions supported by the Server", organizes the 37 Aggregates of `aggregate.Functions()`; a monitored item can use all of them but AnnotationCount.
- `server/aggregate`: the AnnotationCount Aggregate (Part 13 §5.4.3.20, Table 68): the number of Annotations in each interval, an Int32 with the Calculated bit and the StartTime of the interval, Partial for an incomplete interval (§5.3.3.2) and `Bad_NoData` before the first and after the last raw value; no bounding values. `Request.CalculateWithAnnotations` and `Request.CalculateIntervalsWithAnnotations` take the Annotations next to the raw values, by their SourceTimestamp (Bad ones are not counted); `Calculate` counts none. `HistoricalOnly` reports the Aggregates Table 5 describes as applying "to Historical Aggregates only", AnnotationCount. `Functions` holds all 37 standard Aggregates.
- server: Annotations (Part 11 §5.1.2). `Server.EnableAnnotations` adds the Annotations Property (BrowseName `0:Annotations`, DataType Annotation `i=891`, ValueRank -2, AccessLevel CurrentRead, HistoryRead and HistoryWrite, a null value, PropertyType) to a Variable or Object; a Property is `Bad_NodeClassInvalid`. The optional provider interface `AnnotationHistoryProvider` (`UpdateAnnotations`, `ReadAnnotations`, `ReadRawAnnotations`), implemented by `*Historian` for the nodes it keeps history of. The InsertAnnotationCapability of the HistoryServerCapabilities reports it.
  - HistoryUpdate UpdateStructureDataDetails (§6.9.3) on the node or on its Property: Insert `Good_EntryInserted` / `Bad_EntryExists`, Replace `Good_EntryReplaced` / `Bad_NoEntryExists`, Update either Good, Remove `Good` / `Bad_NoEntryExists`; in the Historian an Annotation older than the oldest value of a full history is `Bad_OutOfRange`. §6.9.3 leaves what makes an Annotation unique to the server, with a timestamp as one example; the server takes its SourceTimestamp. A value that is no Annotation is `Bad_TypeMismatch`, one without a SourceTimestamp `Bad_InvalidArgument`; an empty annotationTime is the time of the update, an empty userName the user of the session.
  - HistoryRead ReadAnnotationDataDetails (§6.5.6): one DataValue per reqTime in the order of the request, `Bad_NoData` for a time without one; `Bad_HistoryOperationUnsupported` for a node without the Property or a provider without Annotations. ReadRawModifiedDetails on the Property returns the Annotations of a range in time order, with continuation points (§5.1.2); IsReadModified is `Bad_HistoryOperationUnsupported`.
  - The raw values at a time with an Annotation have the ExtraData bit (Part 4 §7.38.1, Table 177).
  - HistoryRead processed with AnnotationCount reads the Annotations of an `AnnotationHistoryProvider`, for the Historian and for a provider with raw reads only.
- server: change audit events, with auditing on (`WithAuditing`, `SetAuditing`), "for both successful and failed Service invocations" (Part 4 §6.5.7, §6.5.8), to the Server object and the sessions an `EventAccessController` allows. Each carries ActionTimeStamp, Status, ServerId, ClientAuditEntryId and ClientUserId (Part 5 §6.4.3).
  - AuditWriteUpdateEventType (Part 4 §6.5.8, Part 5 §6.4.25), one per WriteValue: SourceName `Attribute/Write`, SourceNode the node, AttributeId, IndexRange, OldValue (read before the write, limited to the IndexRange) and NewValue.
  - The AuditHistoryUpdateEventType subtypes (Part 11 §5.8, Part 5 §6.4.26), one per HistoryUpdateDetails: SourceName `Attribute/HistoryUpdate`, ParameterDataTypeId the DataType of the details; AuditHistoryValueUpdateEventType, AuditHistoryAnnotationUpdateEventType, AuditHistoryEventUpdateEventType, AuditHistoryRawModifyDeleteEventType, AuditHistoryAtTimeDeleteEventType and AuditHistoryEventDeleteEventType with their fields. OldValues are the values the provider held before a Replace, Update or delete. The EventIds of inserted events are in the Message, as Part 11 §5.8.1 asks for the EventId of an inserted event.
  - The AuditNodeManagementEventType subtypes (Part 4 §6.5.7, Part 5 §6.4.19 to §6.4.23), one per call of AddNodes, DeleteNodes, AddReferences or DeleteReferences: SourceName `NodeManagement/<Service>`, SourceNode the Server object, the whole parameter of the call; Status is false when an item failed.
  - `WithChangeAuditing(enabled bool)` turns them off and on; on by default.
- client: `HistoryReadAnnotations` and `HistoryUpdateStructureData`, the low-level calls with the full details, and `ReadAnnotations` and `UpdateAnnotations` with `HistoryAnnotation` (Time, Annotation, Status), which follow continuation points and return a Bad status of the node as the error.
- `cmd/methods` (run by `make gen`, checked by `make check-gen`): emits the
  contracts of the Methods of the ObjectTypes `cmd/methods/config.go`
  selects, from the InputArguments and OutputArguments of the pinned
  NodeSet, into `uamethod/methods_gen.go`.
- Package `uamethod`: for FileType and FileDirectoryType (OPC 10000-20
  §4.2, §4.3), a `Method` value per Method (NodeIds of the Method and its
  ObjectType, clause, Mandatory, `InputArguments` / `OutputArguments`),
  Input and Output structs with `Pack` and `Unpack` (the argument count,
  built-in type and ValueRank checks of the Call service, as
  `*ArgumentError` with `Bad_ArgumentsMissing`, `Bad_TooManyArguments` or
  `Bad_TypeMismatch`), and `Call<Type><Method>` functions for a client
  (`*CallError` for a Bad result).
- `server`: `AddFile`, `ServeFile` and `NewFile` serve a FileType Object
  (`FileObject`): per-session handles closed at the end of the session,
  the Open rules of §4.2.2 (Table 4 modes, several readers, one writer,
  `Bad_NotWritable` / `Bad_NotReadable`), Read, Write, GetPosition,
  SetPosition, the Properties Size, Writable, UserWritable, OpenCount,
  MaxByteStringLength, MimeType and LastModifiedTime; `FileConfig` with
  Modes, MaxHandles, Authorize and OnChange; backends `MemoryFile`,
  `OSFile`, `SnapshotFile` or your own `FileBackend`; `OpenBytes` and
  `CloseAndTake` for subtypes with Methods of their own.
- `server`: `AddFileDirectory` serves a file system of FileDirectoryType
  Objects (§4.3) with CreateDirectory, CreateFile, Delete and MoveOrCopy,
  on a `MemoryDirectory`, an `OSDirectory` (`os.OpenRoot`) or your own
  `DirectoryBackend`, with an Authorize hook per operation and path.
- Package `filetransfer`: the client of FileType (`NewObject`, `Open`,
  `Read`, `Write`, `Position`, `SetPosition`, `Close`, `ReadAll`,
  `WriteAll`, `Info`, `io.Reader` and `io.Writer` adapters, `Attach` for a
  handle of OpenWithMasks or CreateFile, `ObjectFunc` for an own call path)
  and of FileDirectoryType (`NewDirectory`, `Entries`, `CreateDirectory`,
  `CreateFile`, `Delete`, `MoveOrCopy`).

- server: the Methods of the Server Object (OPC 10000-5 §9, Optional in §6.3.1), on `i=2253` and through the declarations of ServerType: `GetMonitoredItems` (§9.1) returns the serverHandles and clientHandles of the MonitoredItems of a subscription; `ResendData` (§9.2, Part 4 §6.7) puts the last value sent of every data MonitoredItem in Reporting mode in the next Publish response, or the value queued ("If no value is queued for a data MonitoredItem, the last value sent is repeated"); `SetSubscriptionDurable` (§9.3, Part 4 §6.8) makes a subscription without MonitoredItems durable and sets its LifetimeCount from the revisedLifetimeInHours ("The revisedLifetimeInHours is used to set the LifetimeCount of the Subscription"); `RequestServerStateChange` (§9.4) passes a change of state to the application. The first three answer `Bad_SubscriptionIdInvalid` for an unknown subscription and `Bad_UserAccessDenied` for a session that does not own it ("The Method was not called in the context of the Session that owns the Subscription"); `SetSubscriptionDurable` answers `Bad_InvalidState` for a subscription with MonitoredItems.
- server: `WithDurableSubscriptions(DurableSubscriptions{MaxLifetimeInHours, MaxQueueSize, Disabled})`: the longest lifetime of a durable subscription (24 hours by default; lifetimeInHours 0 "requests the highest lifetime supported by the Server") and the largest queue of its MonitoredItems (10000 values by default, where other subscriptions have 100). ModifySubscription of a durable subscription revises the lifetime between the minimum of every subscription (at least three times the keep-alive count, Part 4 §5.14.2.2) and the longest lifetime ("ModifySubscription does not change the durable mode of the Subscription"). Durable means in memory: the subscription outlives its session for its lifetime and TransferSubscriptions takes it over with its queues; a restart loses it (LIMITATIONS.md).
- server: `WithServerStateChange(ServerStateChangeFunc)` with `ServerStateChange{State, EstimatedReturnTime, SecondsTillShutdown, Reason, Restart}`: the application accepts a RequestServerStateChange with `ua.StatusOK` or refuses it with a Bad code; the library never stops or restarts the server. Only a user with the ConfigureAdmin or SecurityAdmin role may call it ("The Client shall provide credentials with administrative rights"), else `Bad_UserAccessDenied`, and the AccessRestrictions of the Method in the NodeSet (SigningRequired) refuse a channel without signing with `Bad_SecurityModeInsufficient`. Without a handler, and for a value that is no ServerState, the answer is `Bad_InvalidState` ("The requested state was not accepted by the server").
- server: `Server.SetServerState(ServerStateChange)` and `Server.EstimatedReturnTime()`: the ServerStatus State, SecondsTillShutdown (counting down to the shutdown), ShutdownReason and the EstimatedReturnTime Property (`i=12885`) of a change, also for the application without the Method. A Restart with a SecondsTillShutdown other than 0 goes to Shutdown first ("the server changes it state to SHUTDOWN_4 before the restart if secondsTillShutdown is not 0"); the EstimatedReturnTime of RUNNING_0 is the null DateTime (§9.4).
- client: `Client.GetMonitoredItems`, `Client.ResendData`, `Client.SetSubscriptionDurable`, `Client.RequestServerStateChange`, and `Subscription.GetMonitoredItems` (with the item ids `Monitor` returned), `Subscription.ResendData` and `Subscription.SetDurable`. A Bad result is a `*uamethod.CallError` that `errors.Is` matches with its StatusCode.
- uamethod: the contracts of the four Methods of ServerType (`ServerTypeGetMonitoredItems`, `ServerTypeResendData`, `ServerTypeSetSubscriptionDurable`, `ServerTypeRequestServerStateChange`, with their Input and Output types and `Call` functions), generated by `cmd/methods` with LocalizedText arguments (a nil `*ua.LocalizedText` is the null LocalizedText).
- server: `WithServerProfiles(uris ...string)` sets the ServerProfileArray of the ServerCapabilities, the URIs of the Profiles of OPC 10000-7 the server supports ("limited to the Profiles the Server supports in its current configuration", OPC 10000-5 §6.3.2); the library does not determine its Profiles, and without the option the array is empty. `WithLocaleIDs(locales ...string)` sets the LocaleIdArray, the LocaleIds "known to be supported by the Server"; without it the array is `["en"]`, the locale of the texts the server writes.
- server/pushstore: `OpenDir(ctx, dir, Options{Owner, Limits})` and `Open(ctx, fxstore.Store, Options)`: the store of push certificate management on one `fxstore.Domain` (namespace `push`, schema 1) of an `fxstore.FileStore` or any backend. It implements `server.CertificateBatchStore`, `CertificateLoadStore`, `CertificateGroupStore` and `CertificateDeleteStore`; `Settle` and `Status` resolve and report a write with an unknown outcome, `GroupName` maps a certificate group NodeId to its BrowseName. Records `tl/<group>` (LastUpdateTime and the TrustListDataType in UA Binary) and `cert/<group>/<type>` (DER certificate, PKCS #8 key, DER issuers, or a deletion); the directory 0700, the files 0600. See docs/server-guide.md and docs/security.md.
- server: `CertificateBatchStore` (`StoreChanges(ctx, CertificateChanges)`: every change of one ApplyChanges or ResetToServerDefaults in one call) and `CertificateLoadStore` (`LoadCertificates`, applied by `New` on top of the configuration, which stays the target of ResetToServerDefaults; an invalid stored trust list or certificate fails `New`), with `CertificateChanges`, `CertificateGroupTrustList` and `CertificateGroupChange` (groups by BrowseName, which does not depend on the namespace table).

### Changed

- server: a HistoryRead `ReadProcessedDetails` reads `aggregateType[i]` for node `i` (Part 11 §6.5.4.2); it read the first Aggregate for every node.
- server: for a provider without `ProcessedHistoryReader` the server calculates the Aggregates from `ReadRaw`, over one ProcessingInterval beyond the request on each side, following the provider's continuation points.
- client: `HistoryReadProcessed` asks for source timestamps (TimestampsToReturn Source, Part 13 §5.4.3.1); it asked for Both.
- The TrustList objects of push management and `ServeTrustList`, the
  PubSubConfiguration file and `fxserver`'s ConnectionManagerConfiguration
  use `server.FileObject` for their FileType Methods; `gds.ReadTrustList`,
  `gds.WriteTrustList`, `remote.ReadConfiguration` and
  `remote.UpdateConfiguration` use `filetransfer` (their errors stay
  `*gds.Error` and `*remote.Error`).
- `opcua.DynamicTypeDecoding(true)`: the values of `Read` (`ReadValue`, `ReadValues`, `Node.Value`), the output arguments of `Call` and `CallMethod`, the results of `HistoryReadRawModified`, `HistoryReadProcessed`, `HistoryReadAtTime` and `HistoryReadEvent` and the data changes and events of subscriptions hold, for a binary ExtensionObject of a type without a registered Go type, a `*ua.DynamicStructure` decoded with the StructureDefinition of its DataType (OPC 10000-3 §5.8.3, §8.48 to §8.52). The client finds the DataType of the encoding by its inverse HasEncoding Reference and reads the DataTypeDefinition, BrowseName and IsAbstract of it and of the DataTypes of its fields, and the supertypes of the DataTypes without a StructureDefinition to find their built-in type (Part 3 §5.8.2), in Reads of 30 operations and Browses of 10 nodes (below MaxNodesPerRead and MaxNodesPerBrowse, Part 5 §6.3.11, of the go-opcua server). The DataTypes are kept by namespace URI for the lifetime of the client, and given the indexes of the current namespace table; "the content of this Attribute shall not be changed once it had been provided to Clients" (§5.8.4). An encoding the server cannot resolve is not asked again until the namespace table changes; a failed request is tried again with the next value. A registered Go type comes first, also for a field. A value that cannot be decoded keeps its `RawBody`, and the call does not fail; a Read result that is decoded keeps the status of the server instead of `StatusBadDataTypeIDUnknown`.
- `Client.LoadDataTypes`, `Client.DecodeExtensionObjects` and `Client.DynamicTypes`: resolve DataTypes, decode values on request (also without the option), and make values to write or pass to a Method (`DynamicTypes().New(dataTypeID)`, `Set`, `ua.NewExtensionObject(v)`).
- `ua.DynamicTypes`, `ua.DynamicType`, `ua.DynamicStructure`, `ua.DynamicMatrix` and `ua.UndecodedBody`: the OPC UA Binary codec of a StructureDefinition, for use without a client. Structures (OPC 10000-6 §5.2.6, a nil field is its default value), optional fields with the UInt32 EncodingMask (§5.2.7; bits of no optional field are an error), Unions with the UInt32 SwitchField (§5.2.8; a value beyond the fields is an error), the subtyped values of Table F.13 (a Structure in an ExtensionObject, any other DataType in a Variant), arrays and inline matrices (§5.2.5, Table 28), Enumerations as Int32 (§5.2.4), OptionSets of a UInteger and of the OptionSet Structure, simple DataTypes as their built-in type, Number, Integer, UInteger and BaseDataType in a Variant (§5.1.6), Structure and Decimal in an ExtensionObject (§5.1.7, §5.1.10), nested ExtensionObjects of the set. Every array length is checked against the remaining input before the slice is allocated, nesting is bounded by `ua.MaxBinaryNestingDepth`, and a body must be consumed to its end. An ExtensionObject in a field that nothing decodes keeps its body as a `[]byte` Value, so that the Structure encodes back unchanged.
- The JSON and XML encoders write a `*ua.DynamicStructure` as a binary body (OPC 10000-6 §5.4.2.16, §5.3.1.16), and `ua.ExtensionObjectTypeID` gives its DefaultEncodingId.
- Not supported by the dynamic decoding: a DataTypeDictionary (OPC 10000-5 Annex D) and JSON-encoded bodies of the UA JSON transports (the JSON decoder fails on an ExtensionObject of an unknown type with a JSON body, as before). Both are in LIMITATIONS.md.

- client: `SessionKeepAlive(d)`, the session keep-alive. When the session of a client that `Connect` connected has had no request for half the revised session timeout, or for `d` when that is shorter, the client reads the State of the ServerStatus (`i=2259`). "Clients shall be prepared to submit requests in a timely manner to prevent the Session from closing automatically" (OPC 10000-4 §5.7.2.1), and without a Subscription "the connection can be monitored by periodically reading the State Variable" (Part 4 §6.7). Every request of the session counts, Publish requests too. A keep-alive without response within the `RequestTimeout` (`Bad_Timeout`), or answered with `Bad_SessionClosed`, which a server returns to the outstanding requests of a session it terminates (§5.7.2.1), is handled as a lost connection: `Disconnected`, then with `AutoReconnect` the recovery of a broken connection. Any other answer changes nothing. `SessionKeepAlive(0)` turns it off, a negative interval is an error, and an interval at or above the revised session timeout is replaced by half of it. Neither clause says when to send the request or what to do when it fails; that is this client's design (docs/client-guide.md, Session keep-alive).
- server: GeneralModelChangeEvents (Part 3 §9.32, Part 5 §6.4.32) for the AddNodes, DeleteNodes, AddReferences and DeleteReferences services and for the Go API (`NodeNameSpace.AddNode`, `DeleteNode`, `Node.AddRef`, `AddReference`, `AddObject`, `AddVariable`, `RemoveRef`), and for a change of the DataType of a Variable or VariableType by Write or `Node.SetAttribute`. "Only those Nodes of the AddressSpace having a NodeVersion shall trigger a ModelChangeEvent", and "every time a ModelChangeEvent is issued for a Node, its NodeVersion shall be changed" (Part 3 §9.32.2): the server increments the NodeVersion Property of each node it reports (Part 3 §5.5.1, §5.6.2) and reports no node without one. Each change is a ModelChangeStructureDataType with the verbs NodeAdded, NodeDeleted, ReferenceAdded, ReferenceDeleted and DataTypeChanged, both ends of a bidirectional Reference (Part 5 §12.16). The events go to the Server Object, with SourceName `Server` and Severity 1 (Part 3 §9.32.3, Part 5 §6.4.31). Our choices: a service request, or a call of the Go API, is one event with each node once and its verbs ORed (the compression of Part 3 §9.32.4, §9.32.7); a node added or deleted keeps its NodeVersion; a NodeVersion is a decimal counter; a change of the ValueRank or ArrayDimensions of a Variable, which changes its NodeVersion (Part 3 §5.6.2) but has no verb, is a BaseModelChangeEvent without Changes; an import reports nothing.
- server: `NodeNameSpace.AddNodeVersion(n)` gives a node a NodeVersion Property, "0"; `WithNodeVersionOnAddNodes(true)` gives one to every node AddNodes adds (off by default), and DeleteNodes deletes it with its node.
- server: SemanticChangeEvents (Part 3 §9.33, Part 5 §6.4.33, §12.17): when the Value of a Property whose AccessLevel has the SemanticChange bit changes, by Write or `Node.SetAttribute`, the server reports the node owning the Property and sets the SemanticsChanged bit of the next data change Notification of each monitored item of that node (Part 3 §5.6.2, Part 4 §7.38.1); a Notification a full queue drops passes the bit on. The NodeVersion does not change (Part 3 §9.33.2).
- server: a NamespaceMetadata Object (Part 5 §6.3.13) in the Namespaces Object of the Server for every namespace of a `NodeNameSpace` that has none from its NodeSet, created at `Start` or, for a namespace added later, at once, with the NodeId `s=NamespaceMetadata` (numeric in the namespace of the session diagnostics, whose string NodeIds name sessions). It has the mandatory Properties, NamespaceVersion, NamespacePublicationDate and ModelVersion from the `Model` of the imported NodeSet (null without one), IsNamespaceSubset FALSE for a namespace of the program and TRUE for one an import added ("If the completeness is unknown, this Property shall be set to TRUE"), and the static NodeId Properties empty; the server fills the missing Properties of a NodeSet's own Object the same way.
- server: `Server.SetNamespaceDefaults(uri, NamespaceDefaults)` and `Server.NamespaceDefaults(uri)`: the DefaultRolePermissions, DefaultUserRolePermissions and DefaultAccessRestrictions of a namespace, published in its NamespaceMetadata Object and applied to its nodes without RolePermissions or AccessRestrictions of their own (Part 3 §4.9.3, §5.2.9 to §5.2.11): the RolePermissions under the `RBACAccessController`, the AccessRestrictions under every controller. "The DefaultRolePermissions Property ... shall only be readable by administrators" (Part 3 §5.2.9): ConfigureAdmin and SecurityAdmin; DefaultUserRolePermissions is reduced to the roles of the session. A node imported with `HasNoPermissions` is exempt (Part 6 §F.3).
- server: `WithRoleManagement(RoleManagement)` serves the RoleSet of OPC 10000-18 v1.05.06 (`Server.ServerCapabilities.RoleSet`, §4.3) from a configuration in memory, and `Server.RoleSet()` gives the application the same configuration (`Roles`, `Role`, `AddRole`, `RemoveRole`, `AddIdentity`, `RemoveIdentity`, `AddApplication`, `RemoveApplication`, `AddEndpoint`, `RemoveEndpoint`, `SetApplicationsExclude`, `SetEndpointsExclude`; the result codes of the Methods as errors). Opt in: without it nothing changes.
  - AddRole (§4.2.2) adds an Object of RoleType below the RoleSet with its six Properties and six Methods, in the namespace `RolesNamespaceURI`, with ApplicationsExclude and EndpointsExclude TRUE; `Bad_AlreadyExists` for a role that exists (a well-known name with the OPC UA namespace URI too), `Bad_InvalidArgument` for an empty name or a NamespaceUri outside the NamespaceArray, `Bad_NotSupported` past `MaxRoles` (default 64). RemoveRole (§4.2.3) removes it and "all Permissions associated with the Role": its RolePermissions on every node and in the DefaultRolePermissions of every namespace; a role of namespace 0 is `Bad_RequestNotAllowed`.
  - AddIdentity, RemoveIdentity, AddApplication, RemoveApplication, AddEndpoint and RemoveEndpoint (§4.4.5 to §4.4.10) and the Writes of ApplicationsExclude and EndpointsExclude (§4.4.1), with `Bad_InvalidArgument` for a rule of §4.4.3 that is not valid, `Bad_AlreadyExists`, `Bad_NotFound`, `Bad_ResourceUnavailable` past `MaxEntries` (default 256), `Bad_RequestNotAllowed` for Anonymous, AuthenticatedUser and TrustedApplication (§4.3) and for an Anonymous rule on SecurityAdmin, ConfigureAdmin or SecurityKeyServerAdmin (§4.4.1).
  - All of it needs a SignAndEncrypt channel (`Bad_SecurityModeInsufficient`) and the SecurityAdmin role (`Bad_UserAccessDenied`), or what `RoleManagement.Authorizer` allows (§4.2.2).
  - At ActivateSession a session gets the roles of the RoleMapper, then the roles whose Identities, Applications and Endpoints it complies with (§4.4.1), each once, with the defaults of §4.3; a change of a role re-evaluates the roles of every active session at once ("the Role assignment to active Session shall be re-evaluated and applied", §4.4.1). The rules: UserName, Thumbprint (SHA-1 of the user certificate, Part 6 §3.1.1), X509Subject (§4.4.3 Table 10, the subject or the issuing CA of the user certificate), Application and TrustedApplication (a Client Certificate the server validated on a signed channel), Anonymous, AuthenticatedUser, and Role and GroupId from the `roles`, `groups` and `iss` claims of a JWT (Part 6 §6.5.2.3; `Bad_NotSupported` without `IssuedTokenTypeJWT`).
  - With auditing on, a change by a Role Method reports a RoleMappingRuleChangedAuditEventType event (§4.5), AddRole, RemoveRole and refused calls an AuditUpdateMethodEventType event.
- Package `uamethod`: the contracts of RoleSetType (AddRole, RemoveRole) and RoleType (AddIdentity, RemoveIdentity, AddApplication, RemoveApplication, AddEndpoint, RemoveEndpoint), generated into `uamethod/roles_gen.go` from the pinned NodeSet (OPC 10000-18 §4.2.2, §4.2.3, §4.4.5 to §4.4.10).
- Package `rolemgmt`: the client of the RoleSet (`New`, `NewRoleSet`, `Roles`, `Role`, `AddRole`, `RemoveRole`) and of a role (`Config`, `AddIdentity`, `RemoveIdentity`, `AddApplication`, `RemoveApplication`, `AddEndpoint`, `RemoveEndpoint`, `SetApplicationsExclude`, `SetEndpointsExclude`).

### Behaviour changes

- server: Read of the DataTypeDefinition Attribute of a Structure, Union, Enumeration or OptionSet DataType returns its StructureDefinition or EnumDefinition, where it returned `Bad_AttributeIdInvalid` for every DataType; 250 DataTypes of namespace 0 have it, and every DataType of the GDS, DI and UAFX models. Read of it on BaseDataType, Structure, Enumeration, Number and the other abstract, built-in and simple DataTypes still returns `Bad_AttributeIdInvalid`: the Attribute is optional for them (Part 3 §5.8.3) and the NodeSet has no fields for them. A value written to the Attribute, or set with `Node.SetAttribute`, replaces the imported one as before. A new server builds the definitions of namespace 0 at start (about 2 % more allocations in `BenchmarkNewServer`).
- `Historian.ReadProcessed` calculates all 37 Aggregates with the rules of Part 13: `Count` is an Int32 (Table 69), not a UInt32; StatusCodes carry the Aggregate bits and the InfoType DataValue (Calculated, Interpolated, Partial, MultipleValues), so a processed value is no longer exactly `Good`; Bad and Uncertain raw values change the status as the PercentDataBad and PercentDataGood of the configuration say; an interval after the end of data is Bad_NoData (or extrapolated, for Interpolative and TimeAverage and Total).
- Processed reads: an unsupported Aggregate is `Bad_AggregateNotSupported` (was `Bad_HistoryOperationUnsupported`); startTime equal to endTime, a missing time and a negative ProcessingInterval are `Bad_InvalidArgument` (were `Bad_HistoryOperationInvalid`); an endTime before the startTime reads backwards and a ProcessingInterval of 0 gives one interval (both were refused); an invalid aggregateConfiguration is `Bad_AggregateInvalidInputs`.
- HistoryRead: a `ReadProcessedDetails` whose aggregateType does not have one entry per node to read is the service result `Bad_AggregateListMismatch`; TimestampsToReturn Server or Neither is `Bad_TimestampsToReturnInvalid` per node.
- A custom provider with `ReadRaw` only now answers processed reads instead of `Bad_HistoryOperationUnsupported`, and the AggregateFunctions folder lists the Aggregates for it.
- A monitored item with an AggregateFilter is created where it was refused with `Bad_MonitoredItemFilterUnsupported`. An Aggregate the server does not calculate is `Bad_AggregateNotSupported`, an attribute other than Value `Bad_FilterNotAllowed`, and an invalid aggregateConfiguration `Bad_MonitoredItemFilterInvalid`. TimestampsToReturn Server or Neither is `Bad_TimestampsToReturnInvalid` for the item (Part 13 §5.4.3.1); Both is accepted.
- The Description of the AggregateFunction Objects in namespace 0 is set, and the AggregateFunctions folder of the ServerCapabilities organizes them. `server/testdata/nodeset_golden.txt` is rewritten for both: the digests of those 38 nodes (37 Aggregates and the folder) change, with 74 more References of namespace 0, and nothing else.
- server: with auditing on (`WithAuditing(true)` or `SetAuditing(true)`), Write, HistoryUpdate and the NodeManagement services report audit events where they reported none; a client that monitors the events of the Server object receives them. `WithChangeAuditing(false)` restores the behaviour of v1.42. With auditing off (the default) nothing changes.
- server: HistoryUpdate UpdateStructureDataDetails and HistoryRead ReadAnnotationDataDetails on a node with the Annotations Property are served, where they were `Bad_HistoryOperationUnsupported`; a node without it answers as before. HistoryRead processed with AnnotationCount answers per interval, where it was `Bad_AggregateNotSupported`: with no Annotations, or a provider without Annotations, each interval with data counts 0. A monitored item with an AggregateFilter of AnnotationCount is still `Bad_AggregateNotSupported`.
- Read with a length of zero is `Bad_InvalidArgument` on every file
  (OPC 10000-20 §4.2.4, Table 6: "Only positive values are allowed"); the
  TrustList, PubSubConfiguration and ConnectionManagerConfiguration files
  returned an empty ByteString.
  A client that wants the old result treats `Bad_InvalidArgument` of a Read
  of length 0 as an empty read.
- ConnectionManagerConfiguration: an Open for writing beside another handle
  is `Bad_NotWritable` and an Open for reading beside a writer
  `Bad_NotReadable` (§4.2.2), not `Bad_InvalidState`; a negative Read
  length is `Bad_InvalidArgument` (§4.2.4), not `Bad_InvalidState`; an Open
  outside a session is `Bad_SessionIdInvalid`. A client that matched
  `Bad_InvalidState` matches the new codes.
- Specification and resource-lifecycle fix, with no option to restore the
  old behaviour: the end of a session closes its file handles and cancels
  its push transaction at once. "When a client opens a file it gets a file
  handle that is valid while the session is open" (OPC 10000-20 §4.2.2),
  and OpenCount is "the number of currently valid file handles" (§4.2.1);
  "Transactions are automatically cancelled when the Session that created
  it is closed" (OPC 10000-12 §7.10.2), and "all pending changes are
  discarded" (§7.10.9). The TrustList, push and PubSubConfiguration files
  kept the handles of an ended session, with their buffers and the lock of
  a writer, until the next Open or OpenCount found them; a push transaction
  of an ended session stayed in the TransactionDiagnostics until another
  session started one. Neither was ever applied. Now a CloseSession, a
  session timeout, `Server.CloseSession`, a session the server reclaims and
  the shutdown of the server release the handles, buffers and locks of
  every FileType object of the server (TrustLists, push certificate groups,
  PubSubConfiguration, ConnectionManagerConfiguration, `AddFile`,
  `AddFileDirectory`), discard what was written without CloseAndUpdate,
  and end the push transaction with `Bad_SessionClosed`. A renewed
  SecureChannel and a broken connection after which the client activates
  the session again keep its handles.
- The `gds` and `pubsub/remote` clients check the output arguments of the
  FileType Methods against their declarations: an Open whose FileHandle is
  not a UInt32, or a Read whose Data is not a ByteString, is an
  `*uamethod.ArgumentError` (`Bad_TypeMismatch`); a Read result of another
  type was taken as the end of the file. `gds.ReadTrustList` beyond 64 MiB
  says `filetransfer: the file exceeds 67108864 bytes`.
- client, with `opcua.DynamicTypeDecoding` only (nothing changes without it): a Read result of a type that is decoded has the status of the server, not `StatusBadDataTypeIDUnknown`, and the first value of a new type costs a Browse, and a Read and a Browse per batch of DataTypes, during the call (in the publish loop for a subscription; while a reconnect recovers the subscriptions only the types resolved before are used, and a value is left undecoded rather than wait for a resolution in progress).

- client: a client that `Connect` connected sends a Read of the ServerStatus State when its session has been idle for half the revised session timeout (10 minutes with the default `SessionTimeout` of 20 minutes, if the server keeps it), where its session used to time out on the server; a connection that is gone without being closed now ends in `Disconnected` (and a reconnect with `AutoReconnect`) at the next keep-alive, where it was noticed at the next request of the application only. `SessionKeepAlive(0)` restores the behaviour of v1.42.1. `ClientMetrics` counts the keep-alive as a `Read`.
- server: model change events are on (Part 3 §9.32.2 "shall"): a node with a NodeVersion Property, from its NodeSet or `AddNodeVersion`, gets a new NodeVersion with each change of its References, and a GeneralModelChangeEvent goes to the Server Object; a Property with the SemanticChange bit gives SemanticChangeEvents and the SemanticsChanged bit. A server without such nodes sees no difference. `WithModelChangeEvents(false)` restores the behaviour of v1.42.
- server: the RolePermissions and AccessRestrictions of the `Model` of an imported NodeSet are the defaults of the nodes of its model ("The list of default RolePermissions for all Nodes in the model", Part 6 §F.2 Table F.1), where they were ignored: under the `RBACAccessController` a node without RolePermissions is checked against them, and every service applies the AccessRestrictions to a node without its own. None of the NodeSets the library ships (namespace 0, GDS, DI, UAFX) has them. `WithModelDefaultPermissions(false)` restores the behaviour of v1.42. A namespace without defaults behaves as before.
- server: Browse of the Namespaces Object (`i=11715`) of a started server lists a NamespaceMetadata Object for every `NodeNameSpace` of the program and of the imports, where it listed only those of the NodeSets.
- server: Read of `Server_ServerStatus_SecondsTillShutdown` (`i=2992`) returns a UInt32 and of `Server_ServerStatus_ShutdownReason` (`i=2993`) a LocalizedText, the DataTypes of the ServerStatusDataType (OPC 10000-5 §12.10), where both returned an Int32 0. Specification fix, with no option to restore the old behaviour.
- server: Read of the EstimatedReturnTime Property of the Server Object (`i=12885`) returns the null DateTime ("If no estimate is known, a null DateTime shall be provided", §9.4) or the time `SetServerState` set, where it returned no value.
- server: Read of the Mandatory ServerCapabilities Properties without a value in the NodeSet answers Good, where it was `Bad_AttributeIdInvalid` (OPC 10000-5 §6.3.2): ServerProfileArray (`i=2269`) the String[] of `WithServerProfiles`, empty by default; LocaleIdArray (`i=2271`) `["en"]` or `WithLocaleIDs`; MinSupportedSampleRate (`i=2272`) 0, the "minimum supported sample rate, including 0", as a sampling interval of 0 is exception-based sampling (OPC 10000-4 §5.13.1.2); MaxHistoryContinuationPoints (`i=2737`) 0, which "indicates that the Server does not restrict the number of parallel continuation points" (a HistoryProvider may still release those it cannot keep, OPC 10000-4 §7.9); SoftwareCertificates (`i=3704`) the empty SignedSoftwareCertificate array. Specification fix: a Mandatory Property has a value of its DataType; no option restores the error.
- server: Read of MaxBrowseContinuationPoints (`i=2735`) and MaxQueryContinuationPoints (`i=2736`) returns a UInt16, the DataType of OPC 10000-5 §6.3.2, where it returned a UInt32; a limit above 65535 is published as 65535. Specification fix, with no option to restore the old behaviour; a client that asserted a `uint32` reads a `uint16`.
- server: Call of GetMonitoredItems, ResendData, SetSubscriptionDurable and RequestServerStateChange on the Server Object answers as above, where it was `Bad_MethodInvalid`. `DurableSubscriptions{Disabled: true}` restores it for SetSubscriptionDurable; RequestServerStateChange without `WithServerStateChange` changes no state (`Bad_InvalidState`); GetMonitoredItems and ResendData have no option, as they answer only the session that owns the subscription and change nothing but what it is sent.
- server: a MonitoredItem of a durable subscription is revised to a queue of up to `DurableSubscriptions.MaxQueueSize` (10000), where every item had at most 100; only subscriptions a client made durable are affected.
- server: an ApplyChanges that fails, because the `PushManagement.Store` cannot write or because a certificate to delete is in use, discards its transaction and applies nothing ("When ApplyChanges is called the Server verifies that all the changes are consistent and can be applied without errors. If any errors are found then all changes are discarded", OPC 10000-12 §7.10.2); it kept the changes pending for another ApplyChanges. The result stays `Bad_InternalError` (store) or `Bad_InvalidState` (in use), with the errors in the TransactionDiagnostics, whose Result is now that of the discarded transaction. With `ApplyImmediately`, a change that cannot be stored is not made. Specification fix, with no option to restore the old behaviour; a client makes the changes again.
- server: ApplyChanges and CancelChanges of push certificate management return the result codes of OPC 10000-12 §7.10.9 and §7.10.11. Without an active transaction both are `Bad_NothingToDo` ("There is no active transaction"), where they were Good. From a session other than the one that created the transaction both are `Bad_SessionIdInvalid` ("The session is not valid for the active transaction"), where they were `Bad_TransactionPending`. ApplyChanges is `Bad_InvalidState` while a TrustList is open for writing: "No changes are applied and ApplyChanges can be called again after the TrustList is closed". It used to apply the changes. A client that calls ApplyChanges after a change that returned applyChangesRequired true is not affected. The `gds` client returns the codes as errors; opcuactl already takes `Bad_NothingToDo` as nothing to apply, as open62541 and node-opcua answer. Specification fix, with no option to restore the old results.
### Fixed
- server: `NodeNameSpace.GetNextNodeID` set the start of its sequence with a plain store, a data race with concurrent callers (AddNodes requests of two sessions); it is a compare-and-swap.

### Tests

- `TestDataTypeDefinition_Namespace0` (`server`): BuildInfo, EUInformation, NodeClass, AccessLevelType, OptionSet, Union, UserIdentityToken and its subtypes, LogRecord (optional fields) and PublishedDataSetDataType (subtyped values) against their NodeSet definitions; every subtype of Structure and Enumeration has the Attribute; BaseDataType, Structure, Enumeration, Number, Int32, String, Duration, UtcTime and Image have none. `TestDataTypeDefinition_Read`: the same over the wire with the go-opcua client.
- `TestDataTypeDefinition_CompanionModels`: the GDS, DI and UAFX models imported at the namespace indexes of the server (the field DataTypes, supertypes and encodings in the server's namespaces), a union, a union with subtyped values, optional fields, and the Attribute on every DataType of the models.
- `TestDataTypeDefinition_Import`, `TestDataTypeDefinition_Invalid`, `TestDataTypeDefinition_SupertypeOfAnotherImport`, `TestDataTypeDefinition_Cycle` and `TestDataTypeDefinition_Guards`: a NodeSet imported at its own and at another namespace index, inherited fields over two levels, arrays with and without ArrayDimensions, a matrix, a field without DataType, an enumeration and its subtype, an OptionSet of a UInt32, abstract types and a type without encoding, a supertype of another import and of the program, and every Definition that cannot be mapped.
- `TestImportedAddressSpaceGolden`: `testdata/nodeset_golden.txt` is rewritten for the Attribute; the dumps of the address space differ from those of v1.42.0 by the added Attribute 23 of 250 nodes of namespace 0 and of 84 nodes of the GDS, DI and UAFX models, and by the Description of the 37 AggregateFunction Objects of namespace 0 and the 37 Organizes References of the AggregateFunctions folder of the ServerCapabilities to them (see the Aggregates above), and in nothing else. AnnotationCount among them changes the two namespace 0 summary lines only: `refs` goes from 26290 to 26292 for namespace 0 alone and from 29176 to 29178 with the GDS, DI and UAFX models (the Organizes Reference of the folder `i=2997` to AggregateFunction_AnnotationCount `i=2351` and its inverse), their digests change, and AnnotationCount gets its Description; the node count and every other line stay as they were.
- `TestAnnexExamples` (`server/aggregate`): every processed table of Annex A from its raw data set and configuration; `deviations_test.go` holds the 64 rows that follow a clause, with the clause, and the test fails on a deviation that matches no row.
- `TestIntervals`, `TestWindow`, `TestReverse` (the same values backwards and forwards, §5.4.2.2), `TestNoData`, `TestGaps`, `TestInvalidInputs`, `TestBounds`, `TestBoundsReverse`, `TestActualTimeReverse`, `TestCheck`, `TestConfig`, `TestNumberAndCast`, `TestCalculateIntervals`, `TestFunctions`, and the fuzz target `FuzzCalculate` (`server/aggregate`, 100 % statement coverage).
- `TestHistoryReadProcessed`, `TestProcessedRequest` and `TestHistoryAggregateFunctions` (`server`): one Aggregate per node, the list mismatch, timestamps, raw reads in pages, the provider's configuration and its override, errors, and the AggregateFunctions folder through `SetHistorian`.
- `TestHistory_ReadProcessed` and `TestHistory_CustomProvider` (`conformance/history`): seven Aggregates with their status bits, reverse reads, one interval, invalid arguments, the list mismatch and the AggregateFunctions folder over the wire; processed reads of a provider with raw reads only.
- `TestAggregateFilter_SameAsHistoryRead` (`server`): eleven Aggregates of each kind, over Good, Uncertain and Bad values in two calculations. Each value of a monitored item equals the value of a HistoryRead of the Historian over the same raw values, in Status, SourceTimestamp and Value, and its ServerTimestamp is the end of the interval. `TestAggregateFilter_Services`, `TestAggregateFilter_ProviderConfig`, `TestNewAggregateItem`, `TestReviseProcessingInterval`, `TestReviseAggregateStart`, `TestAggregateItemRecord`, `TestAggregateItemPrune`, `TestAggregateFilter_NotCalculated`, `TestAggregateFilter_SkipsUnreachableIntervals` and `TestAggregateFilter_SourceTimestamps` cover the revisions, every error, Modify to and from a DataChangeFilter, SetMonitoringMode, the configuration of the provider, arrays and the bounds.
- `TestAggregateFilter_Wire` and `TestAggregateFilter_Errors` (`conformance/subscription`): the AggregateFilterResult and Count values over the wire, with their timestamps and bits, until every write is counted; the ServerCapabilities AggregateFunctions folder; the operation results. `TestDataChange_FilterErrors` expects `Bad_TimestampsToReturnInvalid` for its AggregateFilter with TimestampsToReturn Neither.
- `uamethod`: round trips of every contract; wrong count, type, ValueRank
  and null for each argument; the helpers of every ValueRank of Part 3
  §5.6.2 and of structures; the call functions against a fake caller;
  `FuzzUnpack`.
- `server`: FileType conformance (`TestFileOpenModes`, `TestFileHandles`,
  `TestFileReadWritePosition`, `TestFileSessionEnd`, `TestFileOpenRace`,
  `TestFileBackendErrors`, `TestFileCloseAndTake`, `TestFileProperties`,
  `TestFileMethodHandlers`, `TestOSFile`), `TestAddFile`, and
  FileDirectoryType (`TestFileDirectory`, `TestFileDirectoryBackendErrors`,
  `TestMemoryDirectory`, `TestOSDirectory`).
- `filetransfer`: the client against a server (`TestFile`,
  `TestFileOfType`, `TestDirectory`) and `TestObjectFunc`.
- The end of a session (`server`): `TestFileSessionEndPaths` and
  `TestPushSessionEndCancelsTransaction` run each end (CloseSession,
  timeout, `Server.CloseSession`, reclaim, shutdown) and check the handles,
  the count, the lock of a writer and the push transaction right after it,
  without another Open, and that nothing written without CloseAndUpdate is
  applied; `TestFileSessionEndConcurrent` ends sessions concurrently with
  CloseAll, Close and Open of other sessions (`-race`).
  `TestFileHandleSurvivesChannel` (`filetransfer`): handles stay valid
  across a token renewal and a dropped connection the client recovers
  from, and the writer keeps its lock.
- `cmd/methods`: the committed output, the next families
  (`TestNextFamilies`), load errors and clauses. CI and the release
  workflow run the tests of `cmd/` (policy CI-005); they excluded it.
- No interop ledger rows: the FileType Methods are tested against go-opcua
  only; the interop suite reads TrustLists of the peers through the
  migrated `gds` client.
- `TestDynamicTypeDecoding_Read`, `_Off`, `_Namespaces`, `_Call`, `_History` and `_Subscription` (package `opcua`, against the go-opcua server with a NodeSet of its own): a Structure with nested, array, matrix, Union, optional-field, Enumeration, Variant and EUInformation (Go type) fields; arrays of ExtensionObjects; a field that allows subtypes holding a subtype resolved in a second round; simple DataTypes, an OptionSet of a UInt32 and a subtype of OptionSet; a malformed body and an unknown encoding that keep their RawBody; a registered Go type next to the dynamic ones; the option off; the namespace table reordered and a second server with the namespace at another index; a Method that receives and returns a dynamic structure; HistoryRead; a subscription.
- `TestDynamicTypes_Supertypes`, `_Unusable`, `_Faults`, `_ResolveLimits`, `_Busy`, `_NamespaceTable` and `_Collect` (a server that answers from tables): chains, cycles and missing supertypes, definitions the client cannot use, failed and short Reads and Browses, the limit of resolutions per value and of DataTypes per resolution.
- `TestDynamicTypes_Add`, `TestDynamicStructure_RoundTrip`, `_Defaults`, `_Part6Samples` (the encodings of OPC 10000-6 Table 32 and Table 33, byte for byte), `_SubtypedValues`, `TestDynamicTypes_DecodeErrors`, `_NestingDepth`, `_HostileLengths` (a 46340 × 46340 matrix and an array of MaxInt32 GUIDs in a few bytes allocate less than 1 MiB), `TestDynamicStructure_EncodeErrors`, `_EncodeArrayTooLarge` (an array of MaxInt32 + 1 Booleans is refused before it is encoded), `_TypeID`, `_JSONAndXML`, `TestUndecodedBody` and `TestDynamicTypes_CodecOf` (package `ua`).
- `FuzzDynamicTypes` (package `ua`): untrusted bodies of nine DataTypes; what decodes encodes and decodes again.
- `TestDynamicTypes_GoToGo` (`conformance`): a value made from the DataTypeDefinition, read with the option and decoded on request without it.

- `TestSessionKeepAliveKeepsIdleSessionOpen`, `TestSessionKeepAliveOnlyWhenIdle`, `TestSessionKeepAliveDeadConnection`, `TestSessionKeepAliveDeadConnectionNoReconnect`, `TestSessionKeepAliveSessionClosed`, `TestSessionKeepAliveServerAnswers`, `TestSessionKeepAliveWithoutSession` and `TestSessionKeepAliveCloseRace` (root package, against the in-process server): an idle client keeps its session past two session timeouts and one with the keep-alive off loses it, a client in use sends none, a connection that drops everything is noticed and recovered with the same session (and without AutoReconnect ends Disconnected), `Bad_SessionClosed` makes the client recover, another fault changes nothing, nothing is sent after `CloseSession`, and Close from several goroutines during keep-alives and requests (race detector, goroutine leak check). `TestKeepAliveStep`, `TestKeepAliveFailed`, `TestKeepAliveInterval`, `TestSessionKeepAliveOption`, `TestStartKeepAliveOff` and `TestStartKeepAliveStops`: the interval, the states in which nothing is sent, which failures reach the connection monitor (not those of a replaced session or secure channel, or during a recovery; a pending error is not blocked on), and the option.
- `TestSession_TimeoutEnforced` (`conformance/session`): the idle client turns the keep-alive off, as its session is to time out.
- `TestModelChangeEventsOverTheWire` (`server`): a go-opcua client with an event monitored item on the Server Object receives the GeneralModelChangeEvent of each of AddNodes, AddReferences, DeleteReferences and DeleteNodes and of `RemoveRef`, with the verbs per node, and reads the NodeVersion going from "0" to "5"; `TestSemanticChangeOverTheWire`: the SemanticChangeEvent of a Write of an EngineeringUnits Property with the SemanticChange bit and the SemanticsChanged bit on the data change Notification of its Variable; `TestModelChangeRestoreOverTheWire`: no event with `WithModelChangeEvents(false)`.
- `TestModelChangeGoAPI`, `TestModelChangeAttributes`, `TestModelChangeNodeManagementBatch`, `TestModelChangeAddNodesWithoutNodeVersion`, `TestModelChangeImportReportsNothing`, `TestModelChangeDisabled`, `TestSemanticChange`, `TestSemanticsChangedOverflow`, `TestNodeVersionHelpers` and `TestModelChangeConcurrent` (under `-race`): every Go API call and service, one event per request, nodes without NodeVersion not reported, DataType, ValueRank and ArrayDimensions changes, a NodeVersion that is not a number, an unchanged value, the SemanticsChanged bit through both queue discard policies and a queue of one, and a request that changes nothing, which reports nothing.
- `TestNamespaceDefaultsOverTheWire`: the NamespaceMetadata Object of a namespace of the program over the wire, a Read denied and allowed by the DefaultRolePermissions under the `RBACAccessController`, DefaultRolePermissions denied to an anonymous session, DefaultUserRolePermissions reduced to its roles, DefaultAccessRestrictions refusing a channel without security, and the defaults removed; `TestNamespaceMetadataBrowsable`: an anonymous session browses the NamespaceMetadata Object of every namespace, the diagnostics namespace included, and reads its Properties; `TestNodeMgmt_NodeVersion` (`conformance/addrspace`): the NodeVersion of a node AddNodes adds, changed by AddReferences; `TestModelDefaultsRestoreOverTheWire`: the defaults of a NodeSet Model applied, and not with `WithModelDefaultPermissions(false)`.
- `TestNamespaceMetadataCreated`, `TestNamespaceMetadataTakenNodeID`, `TestSetNamespaceDefaults`, `TestNamespaceDefaultRolePermissions`, `TestNamespaceDefaultAccessRestrictions`, `TestModelDefaultsFromImport`, `TestModelDefaultsFromImportOff`, `TestModelDefaultsEdgeCases` and `TestNamespaceDefaultsConcurrent` (under `-race`): the Objects of namespaces added before and after Start, a taken NodeId, an unknown URI, `HasNoPermissions`, a node with its own permissions, empty defaults, a role of a Model that is no NodeId and no well-known role, a NodeSet's own NamespaceMetadata Object without its mandatory Properties, an invalid PublicationDate, and `SetNamespaceDefaults` over a Model's.
- `TestImportedAddressSpaceGolden`: `testdata/nodeset_golden.txt` is unchanged by the NamespaceMetadata. The NodeSets it imports carry their own NamespaceMetadata Objects with every mandatory Property and no Model defaults, and its servers are not started, so the server adds no node.
- `TestAnnotationCount` and `TestHistoricalOnly` (`server/aggregate`, 100 % statement coverage): counts per interval, forward and reverse, Partial, Bad_NoData before and after the data (an Annotation there included), Bad annotations not counted, no annotations; `TestAnnexExamples` calculates the AnnotationCount tables of Annex A with one annotation per raw value but the leading Bad_NoData "First archive entry", as the expected counts of the file are, which does not match the ANNOTATION notes of its Historian1 data set.
- `TestEnableAnnotations`, `TestAnnotationsUpdate`, `TestAnnotationsUnsupported`, `TestAnnotationsProvider`, `TestHistorianAnnotations`, `TestAnnotationCountProcessed` and `TestAnnotationHelpers` (`server`): the Property, the node and the Property as the node of an update, every operation and its results, the filled userName and annotationTime, ReadAnnotationDataDetails in request order, the raw read of the Property in pages, IsReadModified, the ExtraData bit, access by the HistoryRead and HistoryWrite bits, a provider without Annotations and one whose results are short or fail, continuation points of the wrong kind, `EnableNode` resetting the Annotations, and AnnotationCount for the Historian and a provider with raw reads only.
- `TestAuditWrite`, `TestAuditWriteValueWriter`, `TestAuditWriteOldValue`, `TestAuditOff`, `TestAuditServiceFault`, `TestAuditNodeManagement`, `TestAuditHistoryUpdate`, `TestAuditHistoryEvents`, `TestHistoryResultOK` and `TestAuditOldValuesUnavailable` (`server`): the events and their fields for each service and HistoryUpdateDetails, failed operations, IndexRange, a ValueWriter, a ServiceFault, `WithChangeAuditing(false)` and auditing off, a provider whose old values cannot be read.
- `TestClientAnnotations` and `TestClientAnnotationsMalformed` (root package): the helpers against the server, and responses that are not Annotations, without HistoryData, with another HistoryData, without a result and a ServiceFault.
- `TestAnnotations_Property`, `TestAnnotations_UpdateAndRead`, `TestAnnotations_Services`, `TestAnnotations_Unsupported` and `TestAnnotations_AnnotationCount` (`conformance/history`), and `TestAudit_HistoryUpdate`: Annotations, AnnotationCount, the AggregateFilter refusing it, and the HistoryUpdate audit events over the wire with an event monitored item on the Server object; `TestAudit_Write`, `TestAudit_WriteOff` and `TestAudit_NodeManagement` (`conformance/addrspace`): the Write and NodeManagement audit events over the wire.
- No interop ledger rows for Annotations, AnnotationCount or the change audit events: no peer of the pinned opcua-interop release is tested for them.
- `TestRoleSet_AddRoleAndReevaluation`, `TestRoleSet_MethodErrors`, `TestRoleSet_Authorization`, `TestRoleSet_ApplicationsAndEndpoints`, `TestRoleSet_AuditEvents` and `TestRoleSet_Disabled` (`conformance/security`, over SignAndEncrypt with the `rolemgmt` client and the `RBACAccessController`): a role added, granted to the active session of another user without a new ActivateSession and to a new session, taken away and removed with its DefaultRolePermissions; the result codes of §4.2.2, §4.2.3 and §4.4.5 to §4.4.10; a user without SecurityAdmin and a Sign channel refused; Applications and Endpoints as include and exclude lists; the audit events; no RoleSet Methods without the option.
- `TestRoleSetDefaults`, `TestRoleSetIdentities`, `TestRoleSetCheckRule`, `TestRoleSetApplicationsAndEndpoints`, `TestRoleSetValidators`, `TestRoleSetSubjectCriteria`, `TestRoleSetJWTClaims`, `TestRoleSetFacts`, `TestRoleSetRuleMatches`, `TestRoleSetGrants`, `TestRoleSetGrantAndReevaluate`, `TestRoleSetAddRemoveRole`, `TestRoleSetAuthorize`, `TestRoleSetHandlers`, `TestRoleSetPropertyWriter` and `TestRoleSetDisabled` (`server`), `FuzzRoleSetSubjectCriteria` and `FuzzRoleSetJWTClaims` (the X509Subject criteria and the JWT claims a client sends).
- `rolemgmt`: the client against a server (`TestRoleSet`, `TestRoleErrors`, `TestRoleReadWriteRefused`), `TestConfigOf`; `uamethod`: the RoleSet and Role contracts in the round-trip, count and type tests, `TestRoleContracts`.
- No interop ledger rows for the RoleSet: no peer of the pinned opcua-interop release manages roles; it is tested against go-opcua only.

- `TestServerMethodsRegistered`, `TestServerMethodsOwnership`, `TestGetMonitoredItemsMethod`, `TestResendDataMethod`, `TestDrainRecordsLastSent`, `TestSetSubscriptionDurableMethod`, `TestDurableLifetimeArithmetic`, `TestRequestServerStateChangeMethod`, `TestSetServerState` and `TestEstimatedReturnTimeNode` (`server`): the handlers, their argument and ownership errors, the LifetimeCount of the revised hours (72000 for 2 hours at 100 ms) and its ModifySubscription bounds, the queue revisions, the authorization by role, the countdown of SecondsTillShutdown and the Property with the null DateTime.
- `TestServerMethods_GetMonitoredItems`, `_ResendData` (the last values sent, the queued value instead, nothing for items in Sampling mode and event items), `_SetSubscriptionDurable` (a queue of 500 against 100, a ModifySubscription lifetime of 500000, 150 queued values taken over by another session with TransferSubscriptions), `_DurableLimits` and `_Subscription` (`conformance/subscription`) over the wire.
- `TestSecurity_RequestServerStateChange` (`conformance/security`): an anonymous user is refused with `Bad_UserAccessDenied`, a channel without security with `Bad_SecurityModeInsufficient`, a ConfigureAdmin over Basic256Sha256 Sign is accepted, and ServerStatus, SecondsTillShutdown and EstimatedReturnTime follow the change and the change back to Running.
- `TestClientServerMethods` (root): the client calls of `*opcua.Client` and `*opcua.Subscription`. `TestContracts` and `TestCallAll` (`uamethod`) cover the ServerType contracts.
- `TestImportedAddressSpaceGolden`: `testdata/nodeset_golden.txt` is rewritten for the values of SecondsTillShutdown, ShutdownReason and EstimatedReturnTime; the dumps differ from those before in these three nodes of namespace 0 only.
- `TestServerCapabilitiesMandatory`, `TestServerCapabilitiesOptions`, `TestBindServerCapabilitiesWithoutNode`, `TestContinuationPointCapabilityUInt16` (`server`) and `TestServerCapabilities_Mandatory` (`conformance/addrspace`, through a client): every Mandatory ServerCapabilities Property with its DataType, the options copied, the UInt16 bound. `TestImportedAddressSpaceGolden`: the dumps differ from those before by the values of these seven Properties only (`i=2269`, `2271`, `2272`, `2735`, `2736`, `2737`, `3704`).
- `TestSessionKeepAliveKeepsIdleSessionOpen` (root) failed once in Race (Go 1.27): the idle client came back with a new session, which only a stall of more than the 2 s session timeout explains. The client did not reconnect, and it keeps the session alive every 200 ms. The timeout is now 4 s, and the test checks the same thing.

- `TestRoundTrip`, `TestSingleMethods`, `TestGroupName`, `TestFailedCommit` (a backend that fails on the n-th key of an ApplyChanges, for every key and each of not committed, lost and landed with an unknown outcome: the records before it, at once or after `Settle`), `TestUnknownOutcome` (a fenced store, a failed Settle, a write back with an unknown outcome), `TestOpenErrors`, `TestConcurrent` (a load during a write, writers and readers under `-race`), `TestRecordErrors`, `TestEncodeError` and the fuzz target `FuzzRecords` (`server/pushstore`, 100 % statement coverage).
- `TestPushBatchStore`, `TestPushBatchStoreFailure`, `TestPushRestore` and `TestPushRestoreErrors` (`server`): one StoreChanges per ApplyChanges over several groups with a deletion, a group of the application and ResetToServerDefaults; a failure leaves the trust lists, certificates and LastUpdateTime as they were, discards the transaction and records an error per trust list and group; the restore replaces, adds and deletes certificates of every group, ignores groups and types the server does not have, and fails `New` on invalid records. `TestPushDeleteCertificate` and `TestPushStore` expect the discarded transaction.
- `TestGDSPush_FileStoreRestart`, `TestGDSPush_FileStoreFailedCommit` and `TestGDSPush_FileStoreConcurrent` (`conformance/certmgmt`, over the wire with package `gds`): CloseAndUpdate, AddCertificate, RemoveCertificate, UpdateCertificate after CreateSigningRequest and CreateSelfSignedCertificate, each with ApplyChanges, survive a restart (an issued client is admitted, the endpoints present the new certificate, the LastUpdateTime is kept) and ResetToServerDefaults empties the store; injected failures and unknown outcomes are `Bad_InternalError` with nothing applied and the store settled by the next ApplyChanges; a second session gets `Bad_TransactionPending`, and during a blocked store write the trust list in effect, its validation and a load of the store are those before it.
- `TestPushApplyChangesOpenForWriting`, `TestPushApplyChangesOtherSession`, `TestPushApplyChangesGoneSession` and `TestFileOpenForWriting` (`server`): `Bad_InvalidState` with a writer open and Good once it is closed, a reader that does not block, `Bad_SessionIdInvalid` from another session with the transaction left pending, `Bad_NothingToDo` without a transaction and for one whose session is gone. The push tests of `server`, `gds`, `conformance/certmgmt` and `chaos/certmgmt` that called ApplyChanges or CancelChanges without a transaction, or from another session, expect these codes.

---
## v1.42.1

**Date:** 2026-11-28
**Previous release:** v1.42.0

Two fixes of the UAFX ConnectionManager (`uafx/fxcm`): `Recovery.Unreachable` could lose the error of a server that cannot be reached while a run of the set was in progress (design §6.4), and a CreationTime past the year 9999 did not compare equal to its own record after a restart (design §6.5).

### Fixed

- `fxcm`: a background verification pass that skipped a set because a run held it (the run verifies that set as its first step) recorded the skip as a successful attempt and cleared the error the run had just recorded, so `Status(k).Recovery.Unreachable` was empty while the records stayed Unverified and the server was down, until the next background retry (up to `VerifyOptions.RetryMax`, 1 min by default). A pass that contacts no server now keeps the last error; an attempt of a run on its own set is recorded, and the error is forgotten once no set has an Unverified record on the server. This was the intermittent failure of `TestCrash` "establish with an intent written".
- `fxcm`: a Diagnostics CreationTime at or after 9999-12-31 23:59:59 UTC, which the binary encoding stores as the maximum Int64 (OPC 10000-6 §5.2.2.5), was compared as read against the clamped value its record loads after a restart, so the incarnation check left such an endpoint Unresolved instead of re-proving it. The CreationTime read from an endpoint and the one loaded from a record are now both held as they are after their encoding; the same mismatch made the record codec fail its round trip (found by `FuzzDecodeRecord` in CI).

### Tests

- `TestVerifySkipKeepsUnreachable` (`uafx/fxcm`): a failed attempt is reported, a pass that skips the held set and the run of another set keep the report, the run's attempt on its set is recorded, and the report goes when nothing on the server is Unverified.
- `TestCanonicalTime` (`uafx/fxcm`): CreationTimes in range, at and after the 9999 limit, before 1601 and null, and a record with a CreationTime after the limit, which loads canonical; the input `FuzzDecodeRecord` found is in its corpus.

---
## v1.42.0

**Date:** 2026-11-28
**Previous release:** v1.41.0

Correctness fixes of phase 0 of docs/roadmap.md, each against the clause of the specification it follows, and phase 1: pinned code generator inputs and one NodeSet2 reader.

The code generators read only pinned inputs: every file `schema/update-schema.sh` downloads comes from one commit of the OPC Foundation UA-Nodeset repository (`ed0b821f6a6f`, the head of `latest` on 2026-11-18; every vendored file is byte-identical to it), recorded with its SHA-256 and, for a NodeSet, its Models and RequiredModels in `schema/manifest.json`. The pinning changes no vendored input and no generated file. The module is about 7 MB smaller.

### Added

- server: `WithIssuedTokenPolicy(issuedTokenType, issuerEndpointURL)` sets the IssuedTokenType and IssuerEndpointUrl the IssuedToken UserTokenPolicy of every endpoint advertises (Part 4 §7.41: the IssuedTokenType is a URI, "This field may only be specified if TokenType is ISSUEDTOKEN"), and `IssuedTokenTypeJWT` is the URI of a JSON Web Token, `http://opcfoundation.org/UA/UserToken#JWT` (Part 6 §6.5.2.2, Table 54).

### Changed

- `schema/update-schema.sh [REF]` downloads every input at REF (a commit, branch or tag; default: the pinned commit, which must give no diff) through `internal/cmd/schemamanifest update` and rewrites `schema/manifest.json`; nothing is written unless every download succeeds.
- `make gen` first runs `schemamanifest verify`: the SHA-256 and Models of every input must match the manifest, and every RequiredModel must be satisfied by a vendored model with the same ModelUri, by the ModelVersion and PublicationDate comparison of OPC 10000-6 §F.2, Table F.1 (UAFX requires UA 1.05.06, DI requires UA 1.05.04 and GDS UA 1.05.07 of 2026-05-01; the vendored UA is 1.05.07 of 2026-07-30).
- `make check-gen` also fails on a new untracked generated file (`*_gen.go`, `*_gen_test.go`, `interop/COVERAGE.md`, `interop/GAPS.md`), not only on a changed one.
- The weekly `schema-check.yml` workflow compares the head of `latest` with the pinned inputs and reports the commits, the inputs whose content changed and the Version, ModelVersion, PublicationDate and RequiredModels of each changed model.
- `internal/nodeset.Parse` is the one NodeSet2 reader: of `server.ImportNodeSetXML`, of the namespace 0 the server builds itself and of the `cmd/uafx` generator. It reads every attribute of each node class with the defaults of UANodeSet.xsd, references, role permissions, DataType definitions and values (OPC 10000-6 Annex F), and has the queries the generators need (Related, Children, ModellingRule, TypeDefinition, SuperType, MethodArguments). It replaces `internal/schema/uaNodeSet.go`, xgen output edited by hand, and the XML types of `cmd/uafx`. The imported address space of namespace 0 and of the GDS, DI and UAFX models is unchanged (`TestImportedAddressSpaceGolden`, recorded with the old reader); the generated UAFX code is unchanged.

### Removed

- `schema/Opc.Ua.PredefinedNodes.xml` (7 MB, the .NET stack's form of the namespace 0 model): nothing in the module read it.
- `schema/UANodeSet.xsd`: nothing read it, it was not downloaded and it was an older revision (1.05.02) than upstream's (1.05.04). Go has no XML Schema validator; the NodeSets are checked by the manifest instead.

### Fixed

- server: the UserRolePermissions Attribute lists the RolePermissions of the roles granted to the session that reads it, with Read and with a monitored item (Part 3 §5.2.10: "the Permissions that apply to a Node for all Roles granted to current Session"). Before, it returned every entry of RolePermissions. A request without a session, or a session that the `RoleMapper` gave no role, has the Anonymous role, as for the `RBACAccessController`.
- server: Cancel answers each Publish request it cancels with a ServiceFault `Bad_RequestCancelledByClient` (Part 4 §5.7.5: "Successfully cancelled service requests shall respond with Bad_RequestCancelledByClient") and still returns their number in cancelCount. Before, the cancelled requests were dropped without a response and the client waited for its request timeout. The Publish requests with another handle stay queued in their order: no Publish request is queued while Cancel takes the queue apart.
- server: a Publish request that finds the queue of its session full is queued, and the oldest queued request is answered with `Bad_TooManyPublishRequests` and its own RequestHandle: "When a Server receives a new Publish request that exceeds its limit it shall de-queue the oldest Publish request and return a response with the result set to Bad_TooManyPublishRequests" (Part 4 §5.14.5.1). Before, the new request was refused and the oldest stayed queued. A subscription that puts a Publish request back does the same instead of dropping it when the queue filled meanwhile. A session queues max(100, MaxSubscriptionsPerSession + 1) Publish requests, as "a Server shall accept more queued Publish requests than created Subscriptions" (§5.14.5.1); before, it was 100 whatever `WithMaxSubscriptionsPerSession` allowed. The client was checked against the same clause: it has one Publish request outstanding and waits a second after `Bad_TooManyPublishRequests` before it sends the next, so it does not spin.
- client: a subscription recreated after a reconnect (or after the server dropped it) keeps the publishing mode last set with `Subscription.SetPublishingMode` or `Client.SetPublishingMode`: CreateSubscription is sent with that publishingEnabled (Part 4 §5.14.2.2) instead of TRUE, so a disabled subscription no longer comes back publishing. Its triggering links are created again: `SetTriggering` records the links the server confirms (linksToRemove before linksToAdd, §5.13.5.2), `Unmonitor` drops the links of the items it deletes (§5.13.6.1, §5.13.1.6), and the recreation sends one SetTriggering per triggering item with the new server ids of the items. Before, the links were lost and an item to report in sampling mode never reported again. Removes the entry from LIMITATIONS.md and docs/interop-gaps.md.
- server: `ImportNodeSetXML` maps the namespace indexes of a NodeSet to those of the server. "The NamespaceIndexes used in NodeId, ExpandedNodeIds and QualifiedNames identify an element in this list. The first index is always 1 (0 is always the OPC UA namespace)" (Part 6 §F.2, NamespaceUris). A URI the server already has keeps its namespace instead of being added again, the others become new namespaces, and the document's NodeIds, aliases, reference targets, BrowseNames and QualifiedName values are rewritten to the server's indexes with the remapper `uafx/fxserver` already used. Before, every URI was added as a new namespace and the nodes landed in whatever namespace had the document's index on the server. A document whose indexes already are those of the server, or that has no NamespaceUris, is imported exactly as before.
- server: `ImportNodeSetXML` reads a BrowseName without a namespace prefix as a name in namespace 0: "The form without a prefix (the first row in Table 7) shall only be used for QualifiedNames in the OPC UA Namespace" (Part 6 §5.1.12). The official companion models rely on it, the InputArguments Property of a DI Method (`ns=1;i=6167`, `BrowseName="InputArguments"`) is `0:InputArguments`, as are the `Default Binary` and `Default XML` encodings of their DataTypes (Part 6 §F.15). Before, the importer put such a name in the namespace of its node, so a client browsing a companion Method for `0:InputArguments` did not find it. A prefix that names no namespace of the document, or of the server for a document without NamespaceUris, or that is not a UInt16, fails the import instead of being read as part of the name. `gdsserver` passes the GDS NodeSet to the importer as it is instead of rewriting it itself, and `internal/nodeset` and the importer read BrowseNames with the one parser.
- server: the raw delete of the built-in `Historian` (`DeleteRawModified`, HistoryUpdate with DeleteRawModifiedDetails) excludes the end time, as a raw read does: "values up to but not including the endTime are deleted", and with startTime = endTime "the value at the startTime is deleted" (Part 11 §6.9.5.1). A range without a sample is `Bad_NoData` (§6.9.5.2). Before, the sample at the end time was deleted too, although a raw read of the same range does not return it, and an empty range was `Good`. Removes the entry from LIMITATIONS.md and docs/interop-gaps.md.
- server: HistoryUpdate refuses a DeleteRawModifiedDetails, raw or modified, without a defined startTime or endTime, or with startTime after endTime: "Both startTime and endTime shall be defined. The startTime shall be less than the endTime" (Part 11 §6.9.5.1). The operation gets `Bad_HistoryOperationInvalid` ("The history details parameter is not valid", Part 4 §7.38.2 Table 179, one of the HistoryUpdate operation results of §5.11.5.4 Table 58) and nothing is deleted; the other operations of the request are carried out. Part 11 names no code for this, so the code is the choice of this implementation. A time at or before 1601-01-01, the zero `time.Time` the decoders return for the encoded 0, is not defined: "the earliest and latest times that can be represented on a given platform are invalid date/time values" (Part 6 §5.2.2.5). The check runs in HistoryUpdate before any `RawHistoryDeleter` is called, and in `Historian.DeleteRawModified`. Before, the built-in historian read a zero time as an open side of the range and a reversed range as a reverse delete, and other backends got whatever the client sent. Reads keep their open and reverse ranges.
- server: SetTriggering removes the links of linksToRemove before it adds those of linksToAdd: "The list of linksToRemove is processed before the linksToAdd" (Part 4 §5.13.5.2, Table 72). Before, it added first, so a request that removed and added the same link left the item without it. The removeResults and addResults keep the size and order of their own lists in the request.
- server: the IssuedToken UserTokenPolicy advertised an empty IssuedTokenType, from which a client cannot tell which token the server takes; with `WithIssuedTokenPolicy` it names the token type and the issuer. Without the option both fields stay empty, as before, since the library does not know which tokens the `IssuedTokenValidator` accepts; the other token policies never carry them.

### Behaviour changes

- server: with the Publish queue of a session full, the oldest queued Publish request gets `Bad_TooManyPublishRequests` instead of the new one; a client that sends more Publish requests than the server queues sees the error on its oldest request. A server configured with `WithMaxSubscriptionsPerSession` above 99 queues one Publish request more per session than that. There is no option to restore the refusal of the new request.
- client: when the server refuses a triggering link the recreation sends, or the request fails, the subscription is recreated without that link and the recovery event has the outcome `SubscriptionRecoveryPartial` instead of `SubscriptionRecoveryRecreated`; its Detail names the links, which stay recorded and are sent again with the next recreation. A recreation of a subscription with links sends one SetTriggering request per triggering item more.
- server: `ImportNodeSetXML` of a document whose NamespaceUris names a namespace the server already has no longer adds a second namespace with the same URI; importing a model twice keeps one namespace. A document whose table differs from the server's has its nodes in the namespaces of their URIs, not at the document's indexes. To import with the document's indexes as server indexes, remove its NamespaceUris.
- server: `ImportNodeSetXML` puts a BrowseName without a prefix on a node of another namespace in namespace 0, where it was in the namespace of the node. A model that meant the namespace of its node has to say so with the prefix, `BrowseName="2:Name"`, as Part 6 §5.1.12 requires. A BrowseName prefix outside the namespace table fails the import.
- server: a raw history delete of the built-in `Historian` keeps the sample at the end time; to delete it as before, pass an end time just after it. A delete that finds no sample returns `Bad_NoData` instead of `Good`. A delete with startTime after endTime, or without a start or end time, deletes nothing and returns `Bad_HistoryOperationInvalid`, from every history backend, where the built-in historian deleted the closed range between the two times or left the range open on the side without a time. To delete everything up to or from a time, pass a start time just after 1601-01-01 or an end time far in the future; to delete a reversed range, swap the times.

### Tests

- `TestRead_UserRolePermissions`, `TestForSessionRoles_Edges` and `TestReadSample_UserRolePermissions` (`server`): sessions with one, two, an unlisted and no role, a node without RolePermissions, malformed entries and a monitored item.
- `TestCancel_AnswersCancelledPublishRequest` (`server`, over the wire): the client's cancelled Publish returns `Bad_RequestCancelledByClient` and Cancel returns cancelCount 1. `TestCancel_KeepsOtherPublishRequests`: several requests with the handle, the order of the others, a request without a header and Cancel without a session.
- `TestQueuePublishRequest_EvictsOldest` and `TestPublish_FullQueueAnswersOldest` (`server`, the second over the wire): one request more than the queue holds answers the oldest with `Bad_TooManyPublishRequests` and its RequestHandle, the new one is queued, the order is kept and another session is not touched (the wire test fails without the fix). `TestPublishQueue_Concurrent` (with `-race`): queuing, taking, Cancel and the release of a closing session at the same time answer every request exactly once. `TestPublishQueueSize`: the queue of a session holds more requests than its subscriptions.
- `TestRecreateSubscription_KeepsPublishingMode` and `TestRecreateSubscription_RestoresTriggeringLinks` (over the wire against the go-opcua server): a disabled subscription stays disabled after the recreation and is enabled again through `Client.SetPublishingMode`; an item to report in sampling mode is reported with its triggering item after the recreation (the test fails without the fix). `TestRestoreTriggering_ServerRefuses`, `TestRestoreTriggering_SendFails`, `TestRememberTriggering`, `TestRecreatedEvent` and `TestSetPublishingMode_NotConnected`: refused links and triggering items, failed requests, removal order, deleted items and the partial recovery event.
- `TestImportNodeSetXML_RemapsNamespaces`, `TestImportNodeSetXML_RemapsReorderedNamespaces`, `TestImportNodeSetXML_MatchingNamespaces`, `TestImportNodeSetXML_RemapErrors` and `TestNamespaceIndex_Full` (`server`): a namespace the server has at another index, two namespaces in the other order with a reference between them, a second import, a matching document, a document without NamespaceUris, an index outside the table and a full namespace table. `TestImportNodeSetXML_UnprefixedBrowseNameIsNamespace0` (`server`): a companion model with InputArguments and OutputArguments Properties, Default Binary and Default XML encodings and the prefixes 1: and 2:, with and without rewritten indexes. `TestImportNodeSetXML_BrowseNamePrefixErrors`: a prefix outside the NamespaceUris, a namespace the server does not have and a prefix that is not a UInt16, for every kind of node. `TestParseQualifiedName` (`internal/nodeset`).
- `TestHistorian_DeleteRawModifiedRange` (`server`): end time excluded, startTime = endTime with and without a sample, reverse and open ranges, a range ending at the first sample and an empty range, each checked against what ReadRaw returns for the range. `TestHistory_Delete` (`conformance/history`) checks the same over the wire; its expectations followed the closed range and are now those of Part 11. Reversed, open and missing ranges are `Bad_HistoryOperationInvalid` and delete nothing, in `TestHistorian_DeleteRawModifiedRange`, `TestHistory_Delete/RawRangeInvalid` (with a valid operation in the same request), `TestHistoryUpdate_DeleteRawModifiedRangeChecked` (a custom backend that is not called) and `TestCheckDeleteRawRange` (the null DateTime of each encoding).
- `TestSetTriggering_RemoveBeforeAdd` (`server`): removing and adding the same link, removing a missing link and adding it, replacing one link or one of two, adding only, removing only, and the order of the results (fails without the fix). `TestSetTriggering_RemoveAndAddKeepsLink` (over the wire): the item to report is reported with its triggering item after such a request.
- `TestWithIssuedTokenPolicy` (`server`): the configured IssuedTokenType and IssuerEndpointUrl on every IssuedToken policy and on no other, and empty fields by default.
- `TestVendoredInputs`, `TestCompareModels`, `TestRequiredModels`, `TestUpdateAndVerify`, `TestUpdateFails`, `TestDiff` (`internal/cmd/schemamanifest`). `TestGeneratedFileList` (`internal/cmd/gen`) checks the list of generated files against the `*_gen.go` and `*_gen_test.go` files of the module.
- `TestImportedAddressSpaceGolden` (`server`): per namespace the number of nodes and references and a SHA-256 over every node of namespace 0 and of the GDS, DI and UAFX models. The tests of `internal/nodeset` walk the vendored NodeSets and fail on an attribute or element the reader drops; `FuzzParse` covers Parse and its queries.

---
## v1.41.0

**Date:** 2026-11-27
**Previous release:** v1.40.0

`uafx.Inspect` reports the persistence of an AutomationComponent and its ConnectionEndpoints (OPC 10000-81 §6.2.6, §6.6.2), so that a client can see what v1.40.0 servers announce: SupportsPersistence and the other ComponentCapabilities, the CleanupTimeout of an endpoint as the server holds it, and the CreationTime and ModificationTime of its Diagnostics, which a restored endpoint keeps across a restart. None of the pinned references of opcua-interop implements UAFX, so this is tested against go-opcua only. Two new findings can appear in a Report; see Behaviour changes.

### Added

- `uafx.AutomationComponent.Capabilities` (`*uafx.ComponentCapabilities`): SupportsPersistence, MaxConnections, MaxConnectionsPerCall, MaxFunctionalEntities, MinConnections and CommandBundleRequired of the ComponentCapabilities (Part 81 §6.2.6 Table 26), each nil when the component does not have the member or it cannot be read; nil when the component has no ComponentCapabilities. `ComponentCapabilities.Persistence` reports SupportsPersistence TRUE.
- `uafx.ConnectionEndpoint.CleanupTimeoutMs`: the CleanupTimeout as the server holds it, in milliseconds, nil when it cannot be read. `CleanupTimeout` stays 0 for a negative value, which means the endpoint is never cleaned up and which a persistent endpoint requires (§6.6.2), so the two could not be told apart before.
- `uafx.ConnectionEndpoint.CreationTime` and `ModificationTime`, from the Diagnostics of the endpoint (§6.6.2 Table 74), zero when it has none.
- The example `uafx/inspect` prints whether each AutomationComponent supports persistence, "never" for a negative CleanupTimeout and the CreationTime and ModificationTime of an endpoint.

### Behaviour changes

- `Inspect` adds a Finding (clause 6.6.2) for a persistent ConnectionEndpoint whose CleanupTimeout is not negative, 0 and NaN included ("For a persistent ConnectionEndpoint, the CleanupTimeout shall be set to a negative number"), and a Finding (clause 6.2.6) for a persistent ConnectionEndpoint on an AutomationComponent that does not announce SupportsPersistence TRUE (Table 26: absent or FALSE means it does not support persistent endpoints). A server that shows such endpoints now has these Findings; a go-opcua AutomationComponent has neither.
- `Inspect` reads the ComponentCapabilities of each AutomationComponent and the Diagnostics of each ConnectionEndpoint: one Browse and one Read more for each, within the existing Limits.

### Tests

- `TestInspectCapabilities` (`uafx`): every ComponentCapabilities member, a negative CleanupTimeout with the Diagnostics times, the findings for a CleanupTimeout of 0 and NaN and for SupportsPersistence FALSE. `TestInspectFaultsCapabilities` fails each call of such an inspection in turn. `TestInspectPersistence` (`uafx/fxserver`): a go-opcua AutomationComponent with a store announces SupportsPersistence TRUE, its persistent endpoint a negative CleanupTimeout and its Diagnostics, with the same CreationTime after a restart and no persistence finding; without a store SupportsPersistence is absent.

---
## v1.40.0

**Date:** 2026-11-27
**Previous release:** v1.39.1

Persistent UAFX ConnectionEndpoints on the AutomationComponent (OPC 10000-81 §5.5.5, §6.6.2; stage C3.1 of docs/design/uafx-persistent-connections.md). With a store, an AutomationComponent supports IsPersistent TRUE: EstablishConnections stores the endpoint, its control and the PubSub components it references before it enables communication, CloseConnections writes a disable or removal before it acts, and EnableConnections restores the endpoints after a restart at their NodeIds, with their control and communication, or quarantines the records it cannot restore. Package `uafx/fxstore` is the storage contract with a memory and a file backend. The server gets a hook that keeps such records in line with every other change of the PubSub configuration, and the PubSub runtime a gate that keeps a restored secured group off keys that may predate the restart. With a store, the ConnectionManager keeps its sets, the records of its endpoints and the journal of its runs (stage C3.2), and recovers after a restart (stage C3.3): it re-proves its records against the AutomationComponents, completes the work it owes through Process and Reconcile, and keeps proven endpoints in place instead of closing and creating them again, so that the ConnectionManager and the AutomationComponents restart independently without an unsafe removal or a needless interruption. None of the pinned references of opcua-interop implements UAFX, so this is tested against go-opcua only. Without a store the AutomationComponent behaves as before; the ConnectionManager changes in three ways listed under Behaviour changes, which follow Part 81 §6.2.4.3.9.2 and §6.6.2.

### Added

- Package `uafx/fxstore`: `Store`, a key-value map with an atomic `Apply` whose error tells three outcomes: committed, definitely not committed (`ErrNotCommitted`, `AsNotCommitted`) and unknown (`OutcomeOf`, `Outcome`). `MemoryStore` (no restart survives it) and `FileStore` (`OpenFile`, `Limits`: one locked directory, every Apply a fsynced rewrite and rename; `Durability` is `DurabilityPowerLoss` on Unix and `DurabilityProcessCrash` on Windows, where a directory cannot be fsynced; network file systems are not supported). `Domain` (`OpenDomain`, `DomainOptions`, `DomainStatus`, `UnresolvedWrite`): one namespace of keys with an owner, a schema and a revision; a write with an unknown outcome fences it until a confirming Apply settles it, and the confirmation keeps the identity of the ambiguous batch (`ErrFenced`, `ErrForeignOwner`, `ErrSchema`); the evidence of at most 64 confirmations with an unknown outcome is kept, after which the domain stays fenced until it is opened again. Package `uafx/fxstore/storetest`: `Run`, the contract tests for any backend, and `Faulty`, a fault injector (design §3).
- `fxserver.ConnectionOptions.Store`, `StoreTimeout` and `StrictNotPersisted`. With a Store, SupportsPersistence is TRUE in the ComponentCapabilities of each AutomationComponent (§6.2.6 Table 26), set after the restore; a store that cannot be opened, has another owner or a newer schema fails EnableConnections. An establish with IsPersistent TRUE needs a negative CleanupTimeout (§6.6.2; anything else is `Bad_InvalidArgument`, library interpretation C3-D4) and passes the persisted check of §6.2.4.3.9.2 (no 0:NotPersisted TRUE on its reader or writer or their parents, Part 14 §6.2.2; else `Bad_InvalidState`); with StrictNotPersisted a non-persistent endpoint's reader or writer needs 0:NotPersisted TRUE. A write that did not commit fails the call with `Bad_ResourceUnavailable` in the first persistent ConnectionEndpointResult and `Bad_NothingToDo` in the others, an unknown outcome with `Bad_InternalError` (library interpretation C3-D13); the call rolls back either way (Table 21). CloseConnections writes Enabled FALSE or RemovePending before it acts, so no restart undoes a durable disable or removal (design §4.4); an endpoint whose runtime removal failed stays RemovePending: commands naming it are `Bad_InvalidState` (library interpretation), a close with Remove FALSE leaves its record RemovePending, and the next removal or start completes it. A reader or writer endpoints share is disabled once none of them demands it (enabled by EnableCommunicationCmd and not disabled since), and removed with the last endpoint that references it, also when the endpoint whose call created it goes first (§6.2.5.2); whether a call created it is stored with the component, which the endpoints share, so the hand-over survives a restart.
- The restore (design §4.6): RemovePending records are completed, every other record is restored whole or not at all, its components adopted when equal, added when missing; NodeIds are stored with the NamespaceArray of their record and mapped at load, also inside the PubSub structures. `Connections.Quarantined` (`QuarantinedEndpoint`, `ErrQuarantine`), `RetryRestore` and `Discard`: a record that fails is kept and reserves its Name, NodeIds and PubSub ids; a record with a NodeId in a namespace the server does not have is quarantined as retryable (`QuarantinedEndpoint.MissingNamespaces`), reserves its NodeIds by namespace URI and is restored once the namespace is there; the quarantine follows the store after a move or Discard with an unknown outcome; one whose identity does not read fences establishes of its AutomationComponent and the PubSub id allocation of the server, and a key outside the record layout fences every AutomationComponent (design §4.7). `Connections.Persistence` (`PersistenceStatus`) reports the store, the restored endpoints and the quarantine.
- `fxcm.Options.Store` and `StoreTimeout` (design §6, stage C3.2): the Manager keeps its sets, their Versions, the records of its endpoints, the journal of its runs and the intents of its calls in the namespace `cm` of the store, owned by its ApplicationURI. `Add`, `Replace`, `Remove`, `Update` and a commit are durable before they are visible; a write that did not commit fails with `Bad_ResourceUnavailable`, one with an unknown outcome with `Bad_InternalError` (library interpretation C3-D13) and fences the store, also for runs already in flight, until it is settled in the background. A run writes its run record before its first call and an intent before each call; a call whose intent was not written is not sent (FxErrorRuntimeError, library interpretation), and a completion that was not written leaves its endpoints Unresolved and its evidence in the store. After a restart every endpoint record is `Unverified` (new `Ownership`, decision C3-D9) until it is verified: reported, never closed, adopted or changed, decided by the verification or by `Settle`; the journal of runs that did not end is `Status.Recovery` (`Recovery`, `OwedWork`, `OwedKind`). `Manager.StoreStatus` (`StoreStatus`) reports the store and the records that do not decode, which keep their keys. A store of another ApplicationURI or a newer schema fails `New`. Endpoint records carry the evidence of design §6.5 (server ApplicationUri and certificate thumbprint, NamespaceArray, NodeIds qualified by namespace URI, ConnectionManagerApplicationUri, Diagnostics CreationTime, the fingerprint of what was sent, the generation and fingerprint of the run's configuration); `fxcm.ServerIdentity` and `fxcm.IdentifiedSession` let a `Session` report the identity. A write with an unknown outcome fences the Manager until memory has followed the store (`StoreStatus.Reconciling`); its generations are never reused. Replace, Remove and a complete Update journal their whole set change, with reserved generations, before their first close (`OwedWork.Changes`, `PlannedChange`; the keys an owed change adds are held, `StoreStatus.Orphaned`). Owed work blocks Replace, Remove and Update of its set (`Bad_InvalidState`), and every operation of a set it fences, whose CommitEdit is refused too (`Recovery.Fenced`); the Names of an unended intent are held. A Replace or Remove whose closes failed after one had an effect keeps its whole transaction as owed work. A commit with an unknown outcome keeps its edit until settled and, when it landed, ends it exactly once. The identity evidence says whether it is authenticated (the secure-channel peer, `ServerIdentity.Authenticated`), reported or unavailable; `ClientDialer` reads it from the active channel of its client for every record and intent (new `opcua.Client.PeerCertificate` and `opcua.PeerCertificate`: the certificate of the active channel as the client validated it), so Options that change the endpoint's security and reconnects are followed. A definite failure of one operation is no proof the call did nothing else: the Names without a record are browsed again and the intent stays unless all are proven; only calls of reservations and verifications owe nothing. Ambiguous call results (decision C3-D13: Bad_InternalError and the other statuses of docs/uafx.md, results that do not decode or do not answer the call) keep their intent and leave their Names Unresolved. Records are validated against their keys, the counters and each other; an invalid one blocks its set (`Recovery.Blocked`) or every set (`StoreStatus.BlockedAll`), invalid counters make the store read-only (`StoreStatus.ReadOnly`).
- `uafx/fxcm` recovery (design §6.4–§6.6, stage C3.3). `Options.Verify` (`VerifyOptions`: `Timeout`, `Parallelism`, `RetryInitial`, `RetryMax`, `Manual`; `DefaultVerifyTimeout`, `DefaultVerifyRetryInitial`, `DefaultVerifyRetryMax`): after `New` the Unverified records are verified in the background per server address, with a deadline, bounded concurrency and a backoff; `Close` cancels it; every run verifies the records of its set as its first step. A server that cannot be reached is reported in `Recovery.Unreachable`; `EventVerified` reports each verdict and each failed attempt. The re-proof (design §6.5) checks the server identity like for like, the endpoint of the record's Name at its NodeId (mapped by namespace URI), the ConnectionManagerApplicationUri, the CreationTime (or ExclusiveApplicationURI without one) and the endpoint parameter (Mode, Variables, IsPersistent, CleanupTimeout, RelatedEndpoint; stored with the record): proven records are KnownOwned or TakenPreconfigured again, absent or foreign ones are dropped and never closed, the rest is Unresolved; a record made over a secured channel without an authenticated identity is never re-proved by its ApplicationUri. The Names of an unended establish intent are re-proved as a lost response against the server identity, the preconfigured NodeId and the parameter the intent recorded, never resent; an intent of CloseConnections or EnableCommunicationCmd records its targets, their prior class and Remove, and is proven by the postcondition of its operation (Remove TRUE: gone, or released for a TakenPreconfigured endpoint; Remove FALSE: every DataSetReader and DataSetWriter Disabled; enable: every one not Disabled; Part 14 §9.1.10; a mix or a State that cannot be read proves neither), never by ownership: otherwise the endpoint is Unresolved, the intent stays and neither a run, a rollback nor Reconcile resends it; such an intent completes only when every target it records has its outcome proven, whatever the class of its record, or has no node left. Before a close-first, an adoption, a close or an enable of a recorded endpoint, its CreationTime and ConnectionManagerApplicationUri are read again: another incarnation is Unresolved (unreadable: Unverified) and never closed, adopted, enabled or rolled back. An intent ends once its Names are decided, also by `Settle`. Owed work is done by the first step of the next `Process` or `Reconcile` of its set: the verification, the owed rollback (Remove TRUE of every closable endpoint, §6.7.3.2) and the end of finished run records; an owed set change is completed by `Reconcile` only, with its reserved generations (`Process` is `Bad_InvalidState`); the recovery gates the run: when the owed rollback or the end of an owed run fails, the action is not executed and the run fails with FxErrorRuntimeError and `Bad_InvalidState`; a server with a call of an earlier run of the set whose outcome is unknown is blocked for the run, nothing is sent there. The fence is narrowed: an owed call fences the sets sharing its server until it is resolved, other owed work the sets sharing a server only while a record on it is Unverified, the participants of an owed set change until it is made; the fence is checked again before each state-changing intent is written, atomically with its write, and the retained intents of active runs fence too; ServerAddresses whose records show one ApplicationUri are fenced as one, and the background verification holds the FunctionalEntity locks of the runs. Adoption (design §6.6, decision C3-D6): an establish run keeps in place the endpoints it finds when every endpoint of the run has a KnownOwned record of the configuration's generation and fingerprint, the recorded CreationTime, and the actual configuration it would create (parameter, DataSetReader and DataSetWriter, ControlGroups, and the PubSub properties of its writer, reader, groups (UADP MessageSettings and MaxNetworkMessageSize included) and connections, PublishedDataSet, DataSetMetaData and TargetVariables, with the ids the Manager allocated; a configuration with settings it cannot compare is not adopted), all or nothing (else C2 close-first; when step 0 failed a Connection, they are left as they are); then EnableCommunicationCmd for ActionEstablishConnectionsEnabled, CloseConnections Remove FALSE for ActionEstablishConnectionsDisabled, the configured enablement for ActionEstablishConnections; `RunResult.Adopted` lists them, and RollbackOnError TRUE closes them on an abort (CR-4). A run, or a close or enable step, whose pooled session to a server was dialed by an earlier run and fails its first read reads once more on a new session, before anything is sent. Library interpretations in docs/uafx.md#persistence-of-the-connectionmanager.
- `uafx/fxcm`: the Manager fills 0:NotPersisted of the DataSetReader or DataSetWriter of an endpoint from IsPersistent where the set leaves it out, and FALSE on the parents of a persistent endpoint's, so that the persisted check of §6.2.4.3.9.2 holds (design §6.7, decision C3-D2); a contradicting value or a reader or writer shared by a persistent and a non-persistent endpoint fails with ConnectionConfigurationSetInvalid and `Bad_ConfigurationError`. Validation refuses IsPersistent TRUE with a CleanupTimeout that is not negative (§6.6.2, §6.12; library interpretation C3-D4).
- ConnectionEndpoint Diagnostics with CreationTime and ModificationTime (§6.6.2 Table 74), kept across a restore.
- server: `PubSubConfigurationHook`, `PubSubChange` and `Server.SetPubSubConfigurationHook`: a hook that sees every change of the PubSub configuration (CloseAndUpdate and the other Methods of Part 14 §9.1.3, `UpdatePubSubConfiguration`, `PubSubConfigurationUpdate.Revert`, `ChangePubSubConfiguration`) in its transaction, can refuse it (the change is undone and fails with the hook's StatusCode, or `Bad_InternalError`), and holds WriterGroupIds and DataSetWriterIds that ReserveIds and CloseAndUpdate do not hand out. A refused change is undone by name: what it removed or changed comes back under a new ComponentID and node; `fxserver` moves its References and its bookkeeping to them in the same transaction, and a refused CloseConnections fails and can be repeated. `fxserver` uses it to write the records of persistent components, to refuse 0:NotPersisted TRUE on them (`Bad_InvalidState`), to refuse a quarantined WriterGroupId or DataSetWriterId on a new or a modified component, and to mark components another mechanism removed (Part 14 §9.1.2, design §4.5); a change of `fxserver`'s own that only removes or disables components (after its durable intent) is not refused when its record does not commit, the record is owed; the same change by another mechanism is refused.
- server: `Server.ChangePubSubConfigurationThen` is `ChangePubSubConfiguration` with a function it calls in the same transaction once the change is complete, after the hook and after the restore of a refused change.
- server: `PubSubConfigurationUpdate.Moved`, `PubSubChange.Moved` and `PubSubConfigurationUpdate.RevertMoves`: the components an update (CloseAndUpdate, `UpdatePubSubConfiguration`) or its revert replaced in place under the same Name, with their old and new ComponentID and node, computed in the PubSub transaction; a component added under the path of an element the same update removed (ElementRemove) is a new one and not listed.
- server: `PubSubConfigurationRestorer` and `PubSubComponentMove`: a hook that is a restorer is told, in the transaction, which components a refused change of any mechanism brought back under a new ComponentID and node; `fxserver` moves the References and bookkeeping of its endpoints to them.
- server: `Server.BuildPubSubModel` builds the PubSub information model before Start, so that the Objects of components have NodeIds a companion specification can reference; Start does not build it again.
- pubsub: `PubSub.GateSecurityGroup` and `PubSub.SecurityGroupGate`, the restart gate of a SecurityGroup (design §4.10, Part 14 §7.2.3, §7.2.4.4.3): a gated group secures and accepts messages only under a key it saw as a future key before it became current, for every key: a current key it did not see coming taints it and closes the gate until a key seen coming after that becomes current, and `SetKeySource` forgets the future keys of the old source and starts a new generation of the gate (an observation of the old source still running records nothing, a KeySource handed out before gives no keys); `CurrentKeys` returns the key the gate observed. Keys are told apart by a fingerprint of their material, not by SecurityTokenId, and new material alone is not proof; a static or unavailable key source never opens the gate; the gate outlives a new KeySource and a recreated group. It is not protection against a key source rolled back to keys used before the restart that the process never saw current (library interpretation). `fxserver` sets it for every restored secured group.

### Behaviour changes

These apply to every `uafx/fxcm` Manager, with or without `Options.Store`:

- An establish run now sends 0:NotPersisted on the DataSetReader and DataSetWriter of each endpoint whose set leaves it out: TRUE for a non-persistent endpoint, FALSE for a persistent one, and FALSE on the group and PubSubConnection above a persistent endpoint's, so that the persisted check of SetCommunicationConfigurationCmd (Part 81 §6.2.4.3.9.2) holds on AutomationComponents that enforce it.
- A set whose explicit 0:NotPersisted contradicts IsPersistent, or that shares a DataSetReader or DataSetWriter between a persistent and a non-persistent endpoint, now fails those endpoints with ConnectionConfigurationSetInvalid and `Bad_ConfigurationError` instead of sending them.
- Validation now refuses IsPersistent TRUE with a CleanupTimeout that is not negative (§6.6.2: "For a persistent ConnectionEndpoint, the CleanupTimeout shall be set to a negative number"; library interpretation C3-D4); such sets were accepted before and failed on the AutomationComponent.

For `uafx/fxserver` AutomationComponents with `ConnectionOptions.Store` (new in this release, changed after its review):

- EstablishConnections on an AutomationComponent fenced by an unresolved store write or by a quarantined record whose identities do not read returns the Method status `Bad_InvalidState` (Part 81 Table 9), not `Bad_ResourceUnavailable`.
- After `Connections.Close`, EstablishConnections and CloseConnections return `Bad_InvalidState` (for CloseConnections a library interpretation: Table 23 lists only Uncertain), and `RetryRestore` and `Discard` return an `ErrQuarantine` error; nothing writes the Store after Close returns. A call running when Close starts finishes first.
- When the commit point of an EstablishConnections call without CreateConnectionEndpointCmd fails, the status is in EnableCommunicationResult (Table 17), or in CommunicationLinksResult (Table 16) for a SetCommunicationConfigurationCmd with links and without enable, instead of ConnectionEndpointResult (other calls keep ConnectionEndpointResult; the `Bad_InvalidState` of a RemovePending endpoint follows the same rule); a `uafx/fxcm` Manager then reports EnableCommunicationError for an enable-only call.
- A required store write the store can never commit (`fxstore.ErrLimit`, `fxstore.ErrInvalidKey`) no longer fences the store: it is logged at Error and counted in the new `PersistenceStatus.Diverged`, and the records do not follow that runtime change until a later write or a restart replaces them.

### Tests

- Crash tests: the server runs as a subprocess on a FileStore and is killed at seven points of establish, close and disable, then restarted: the endpoint comes back as committed, with its control and communication, and no durable disable or removal is undone (`TestCrash`).
- Every store outcome at the commit point and at close (not committed, unknown, fenced, owed writes settled with backoff), validation (C3-D4, PC-1, PC-2), the hook (Methods, updates, Revert, refusals, held ids), quarantine of a corrupt body, a corrupt identity, a component conflict and an unknown key, Discard and RetryRestore, a secured restore with a static key and after a rotation, the key gate cases of design §4.10, the record codecs and the namespace walker over the NodeIds of a PubSub configuration. Fuzz targets: `FuzzDecodeEndpoint`, `FuzzDecodeComponent` (`uafx/fxserver`), `FuzzDecodeState`, `FuzzDecodeMeta` (`uafx/fxstore`).
- ConnectionManager crash tests: the Manager runs as a subprocess on a FileStore and is killed at seven points of Add, establish, rollback and Replace, then started on the same store: the set as committed, the owed work reported, no record trusted and no call made (`uafx/fxcm` `TestCrash`). Every outcome of a set change, an intent, a run record and a completion not written, a run in flight fenced by another operation's ambiguous write (`TestStoreFenceInFlightE2E`), Unverified records and Settle across a restart, NotPersisted against strict AutomationComponents. Fuzz target `FuzzDecodeRecord` (`uafx/fxcm`). C3.2 review fixes: the stored evidence after the public API with a Version committed while the run ran (`TestStoreEvidenceE2E`), concurrent completions with one not committed (`TestStoreCompletionConcurrentE2E`), Add, CommitEdit, Replace and Remove with landed and lost unknown outcomes and no generation reused (`TestStoreFenceFollowE2E`), an owed call re-proved live and after a restart, never resent (`TestStoreOwedEnforcedE2E`), a rollback-required phase not written and a rollback close that fails (`TestStoreRollbackObligationE2E`), the transaction of a complete Update switched and lost (`TestStoreUpdateTransactionE2E`), ambiguous and definite method, operation and malformed results of establish and close (`TestStoreAmbiguousE2E`), real persistent AutomationComponents whose store has an unknown or a not-committed outcome (`TestStorePersistentACE2E`), the semantic validation of every record kind (`TestRecordsSemantic`), keys independent of namespace indexes (`TestEndpointKeyNamespaces`), and two more crash points (an intent of a creating call, an Update between its closes and its switch). Second review: a commit whose acknowledgement was lost followed by a repeated CommitUpdates, and the edit kept while settling (`TestStoreCommitPending`); the identity sources (`TestIdentitySources`); a definite per-operation failure that hid a created endpoint (`TestStorePartialOutcomeE2E`); session-scoped calls (`TestSessionScoped`); every unresolved outcome keeps its intent. Final review: sets sharing an AutomationComponent and existing sets of a pending Update fenced live and after a restart (`TestStoreCrossSetFenceE2E`, `TestStoreUpdateParticipantFenceE2E`), a Replace and a Remove with one close succeeded and one definitely failed, and one with no close succeeded (`TestStorePartialSetChangeE2E`), the identity of the active channel across Options and reconnects (`TestIdentityOfChannel`, `TestClientPeerCertificate`), a reentrant Observer of a landed commit (`TestStoreFollowObserverReentrant`) and the one-step Replace (`TestReplaceSetOneStep`).
- C3.3: the verification after a restart with the AutomationComponents up (proven, the endpoints kept in place: no CloseConnections, the same NodeIds; `TestStoreRestartE2E`), unreachable with a backoff and reported, then proven (`TestVerifyUnreachableE2E`), cancelled by Close (`TestVerifyCloseE2E`), absent and foreign records dropped and nothing closed (`TestVerifyAbsentE2E`, `TestVerifyForeignE2E`); adoption enabled, disabled and as configured, a changed parameter Unresolved, the fallback to close-first, RollbackOnError closing the adopted endpoints (`TestAdoptionE2E`); owed rollbacks completed by Process after a phase not written and after a close that failed (`TestStoreRollbackObligationE2E`), an owed Replace and an owed Update with an Add completed by Reconcile (`TestStoreFenceFollowE2E`, `TestStoreUpdateTransactionE2E`), an owed intent completed by Settle (`TestStoreOwedEnforcedE2E`), the fence narrowing (`TestFencedOf`), the comparisons of the re-proof (`TestSameServer`, `TestSameParam`), the CM projection of a restarted Manager (`fxserver` `TestConnectionManagerRestart`). Five more crash points: the verification before and after its write, the adoption before the enablement, the owed rollback before its closes and the owed set change before its switch (`uafx/fxcm` `TestCrash`). `FuzzDecodeRecord` seeds an endpoint record with its parameter.
- C3.3 review: lost EnableCommunicationCmd done and not done, live and across a restart, and lost Remove FALSE done and not done (`TestLostEnableE2E`, `TestLostDisableE2E`: proven by the postcondition, else Unresolved and never resent); a lost establish re-proved, on another server and with a changed configuration (`TestLostEstablishReproofE2E`); a rollback close that failed waits for `Settle`, no implicit resend (`TestStoreRollbackObligationE2E`); a writer, a writer group, a reader changed and a writer replaced under the same Name not adopted (`TestAdoptionE2E`); an AutomationComponent restarted under a live Manager from its own store, the endpoints proven and kept with their NodeIds and no CloseConnections, and with an empty store (`TestACRestartE2E`); the Manager and an AutomationComponent restarted with its namespaces moved, the records following the NamespaceArray and the node now at an endpoint's old NodeId untouched (`TestNamespaceReorderE2E`); secured records without authenticated evidence (`TestSameServer`), the enable and close intent checks (`TestRecordChecks`), aliases in the fence (`TestFencedOfAliases`), every PubSub property adoption compares, absent optional Properties included, and every setting it declines (`TestSameComm`). Second review: a bidirectional endpoint with its reader disabled and its writer enabled after a lost Remove FALSE stays Unresolved (`TestLostDisableE2E/partly_done`, `TestCommOf`); an AutomationComponent restarted with another incarnation at the NodeId, Name and CM URI of a recorded endpoint, neither closed by an establish with RollbackOnError TRUE nor by a remove (`TestReplacedIncarnationE2E`); a disable and an enable whose completion was not written, the records still KnownOwned, decided by the outcome live and after a restart, not resent (`TestOutcomeCompletionLostE2E`); a lost release (Remove TRUE) of a taken preconfigured endpoint, done and not done (`TestLostReleaseE2E`); the atomic fence (`TestFencedBy`); a reader group and a writer group's message settings changed, not adopted (`TestAdoptionE2E`). CI: the race run of the `server` job and the `coverage-merged` job run with `-timeout=10m`, as `uafx/fxcm` took 238 s and `uafx/fxserver` 186 s of the earlier 5 minutes under the race detector on a 2-CPU runner; no deadline of a test changed.
- Pre-release review: the fuzz targets of the store records (`FuzzDecodeEndpoint`, `FuzzDecodeComponent`, `FuzzDecodeState`) frame their input with its CRC-32C so mutations reach the decoders; `FuzzDecodeRecord` checks the semantic validation and that a record re-encodes to the same value, and the new `FuzzLoadState` fuzzes a stored state with one record replaced; a crash child that misses its point fails at once instead of after the one-minute kill. `TestClosedRefusesMethods`, `TestCommitFailureResult`, `TestRequireRefusedForGood` (a store at its Limits), `TestEnableResultMapping`, `TestWithNamespace`.
- `storetest`: its checks against backends that each break one rule of the contract (a correct backend passes all, each flaw fails one).
- Review fixes: the key gate with a key that predates the restart offered after the gate opened, a missed rotation, a replaced KeySource and future keys of before a lost continuity; CloseConnections whose transactions a hook refuses at each point of a disable and a removal; a record with a missing namespace kept across a restart and restored by RetryRestore and at a start that has it; quarantine moves and Discards with committed and not committed unknown outcomes; a modify onto a reserved WriterGroupId or DataSetWriterId; a shared writer disabled and removed in both orders, persistent, mixed and after a restart; Enable and Disable with the Status Methods across a restart; the bound on confirmations. Second review: enable and disable of a RemovePending endpoint and a restart; the ownership of a shared writer after the owner was removed or not restored and a restart; a KeySource replaced while the gate observes the old one (a blocking source) and a rotation between the observation and the lookup; a change of another mechanism right after a refused close; a removal by another mechanism whose record does not commit, with the endpoint's References following the restored writer; the moves a restorer is told; a monitor read that races a run. Shared components across calls: separate EstablishConnections calls sharing a writer through ElementModify, the References of both endpoints, both removal orders, persistent and mixed endpoints with a restart between the removals, the demand of the first endpoint when the later call enables nothing, a rollback after the update, and no adoption of a component another mechanism removed and added again under the same Name (`TestSharedAcrossCalls`, `TestSharedAcrossCallsDemand`, `TestSharedNotAdoptedByName`, `TestPubSubUpdateMoved`).

### Fixed

- `uafx/fxserver`: an endpoint that a later EstablishConnections linked to an existing DataSetReader or DataSetWriter (with the ElementModify a reference to an existing element needs) shares it, but the runtime replaces a modified component under the same Name: the endpoints of the earlier calls kept References to the removed node, lost the component's provenance and pending removals, and the replaced writer stayed disabled while they demanded it. The endpoints now follow the moves the server reports for the update and for its revert at a rollback, by ComponentID, and a replaced reader or writer an endpoint demands is enabled again (library interpretation). A native CloseAndUpdate is followed by the hook of a persistent AutomationComponent. Found in the C3.1 review.
- `pubsub`: the test of a secured WriterGroup counted the DataSets a subscriber received while it could still be handling the last secured message; it now waits for the subscribers to have handled every message (no timeout or count relaxed).

- `uafx/fxcm`: the monitor copied an endpoint record after it released the lock of its set while a run changed the record's ClosePending (a data race the race detector reported in CI). It copies under the lock now, after checking the record is still the set's, and drops an observation when a run started (also one that ended again) or the set went while it read the Status.

- `uafx/fxserver`: a PubSub change the configuration hook refuses, after a CloseAndUpdate or an EstablishConnections replaced components in place, left persistent endpoints with References to removed components (Status no longer Operational), and CloseConnections with Remove TRUE then returned Good but left the writer enabled and publishing. The endpoints follow the moves only of an accepted change and are moved to the restored components on a refusal (`TestRefusedModifyKeepsLinks`).
- `uafx/fxserver`: a replaced shared DataSetReader or DataSetWriter that another endpoint demands is enabled again only after the commit point of the EstablishConnections call, so nothing is sent under the configuration of a call whose records do not commit (design §4.3; `TestSharedReenableAfterCommit`).
- `uafx/fxserver`: the ModificationTime of a ConnectionEndpoint (Part 81 §6.6.2 Table 74) changes only once its record commits, is restored with the record when a call is rolled back after its commit, and now also follows the modifications of non-persistent endpoints (links, enable, disable) and the use of a preconfigured endpoint (`TestModificationTime`, `TestModificationTimeUncommitted`).
- `uafx/fxserver`: when EnableConnections fails after the restore (SupportsPersistence cannot be set), the restored endpoints are removed, and a restored preconfigured endpoint is put back as it was, instead of left without an owner; their records stay for the next start (`TestRestoreUndoneOnStartFailure`).
- `uafx/fxserver`: SupportsPersistence has the TypeDefinition 0:BaseDataVariableType (Part 81 §6.2.6 Table 26), not PropertyType.
- `uafx/fxserver`: the persisted check of SetCommunicationConfigurationCmd (§6.2.4.3.9.2) failed open when a configuration could not be read; it now fails with `Bad_InvalidState` (`TestCheckPersistedReadError`).
- `uafx/fxserver`: the NodeId of a ByteString identifier stored with a record was mapped from its base64 text, not its bytes.
- `uafx/fxcm`: after a store write with an unknown outcome was settled, memory kept its own endpoint records: a completion write that landed left its endpoints Unresolved, the next Process failed and wrote them back as Unresolved, and the set stayed in Error, also across restarts. The Manager now rebuilds its records from the committed state (design §3.3): a record whose stored value differs takes it, Unverified, and one only memory has is dropped unless an unended intent holds it (`TestSettleRebuildsMemory`).
- `uafx/fxcm`: the background verification starts again after a settle and covers the servers of the unended intents of runs that ended (design §6.4), so `Recovery.Pending` and the owed calls clear without a Process (`TestSettleStartsVerification`).
- `uafx/fxcm`: `Close` waited up to StoreTimeout for a settle attempt blocked on the store; the attempt is now cancelled and the store stays fenced until the next `New` (`TestCloseDuringSettle`). A failed journal write no longer takes the lock of the owed work while holding a run's lock, against the documented order.
- `uafx/fxstore`: `Domain.Require` owed writes that can never commit (an empty or `meta` key, new `ErrInvalidKey`, or a batch over the Limits, `ErrLimit`), so Settle retried them for ever and the domain stayed fenced until it was opened again. Require now returns them with that error and does not fence; a required write found not to fit only when Settle writes it is dropped and reported by that Settle (`TestDomainRequirePermanent`, `TestDomainSettleDropsPermanent`). Require copies its batch, and `Store.Apply` documents that it borrows the batch for the call (`TestDomainRequireCopiesBatch`).
- `uafx/fxstore`: `Domain.State`, `Status` and `Schema` waited for a store Load or Apply in progress; they now return the state before it without waiting (design §3.5; `TestDomainReadsDuringSlowWrite`).
- `ua`: a DateTime at or after 9999-12-31 23:59:59 UTC encoded as the exact tick count, and one past the range of an int64 tick count (the decoded MaxInt64) as the null DateTime, so the latest DateTime came back as null; the binary encoding now writes MaxInt64 for all of them (Part 6 §5.2.2.5). Found by `FuzzDecodeRecord`, whose input is kept in its corpus.
- Citations: CloseAndUpdate is Part 14 §9.1.3.7.6 and the coordination of configuration mechanisms §9.1.2 (they were cited as §9.1.3.7.4, which is PubSubConfigurationValueDataType in 1.05.06); ElementModify is §9.1.3.7.2 Table 239.

### Not implemented

- Not persisted: ConfigurationData of a persistent endpoint, a known deviation of §6.2.4.3.7, which requires SetStoredVariables (§6.4.6.3) for it, and the VariableStorage Methods (§6.4.6), the server's PubSub configuration beyond the components persistent endpoints reference (Part 14 §9.1.2 is not met), Enable or Disable of a component with the Methods of its Status Object (after a restart its enablement follows its endpoints). A restarted ConnectionManager does not adopt an endpoint whose record was lost (Unresolved) and adopts all endpoints of a run or none. StrictNotPersisted is off by default, a documented deviation; 0:NotPersisted on PublishSubscribe is not checked. The gate holds the whole SecurityGroup of a restored secured group. See LIMITATIONS.md and docs/uafx.md#persistence.

---

## v1.39.1

**Date:** 2026-11-25
**Previous release:** v1.39.0

Four fixes to the ConnectionManager server of `uafx/fxserver`, found while driving it from opcuactl: a client that read the state of a set right after ProcessConnectionConfigurationSets could see the state before the run, a late event of an edit that had ended could end the edit of the next owner of the Lock, CloseAndUpdate refused its Operations in the encoding Table F.39 gives, and a set that never took a transition showed LastTransition `Transition(0)`. No API changes; no changes need attention when upgrading.

### Fixed

- `uafx/fxserver`: ProcessConnectionConfigurationSets returned before the nodes of a set showed the run it started: they followed the Manager in a goroutine, so a client that read CurrentState right after a Good result could read Ready, the state before the run, and take a run that had not started for one that had ended. The Method now applies the events of the run to the nodes before it returns, so a client then reads Processing or a later state of that run (a run that ends fast may be Ready or Error already), never the state before it (§6.7.5, §6.9.2); EditConnectionConfigurationSets does the same for the Lock and Edit of the set. The events of the Manager are applied in the order they came also when a Method, `ConnectionManager.Flush` and the server's own loop apply them at once: before, two of them could apply two batches of events in the other order. A Method applies the events queued before it only, not the ones that keep coming while it does.
- `uafx/fxserver`: the end of an edit whose Lock went (ExitLock, BreakLock, expiry, the end of the session; §6.7.4, OPC 10000-100 §7.2) reached the nodes as an event that names no edit. When another session took the Lock with StartEditing before that event was applied, it ended the new edit in the nodes: Edit FALSE, the Lock back with the ConnectionManager, and the writes and CommitUpdates of the new owner refused while the Manager still held its edit. The nodes now end an edit only when the Manager has none.
- `uafx/fxserver`: CloseAndUpdate of ConnectionManagerConfiguration answered `Bad_TypeMismatch` to Operations sent as an array of Byte, the DataType Table F.39 gives it (an array of ConnectionConfigurationSetOperation, an OptionSet of Byte), and took only a ByteString. It now takes both (OPC 10000-4 §5.12.2.4).
- `uafx/fxserver`: LastTransition of a set that never took a transition read `Transition(0)`; it is now an empty LocalizedText, as its Id is the null NodeId.
- Tests: twenty runs, each with its state read right after the Method returned (it was Ready in some before the fix); twenty runs that end before the Method returns; twenty StartEditing and DiscardUpdates with the Lock read right after; the late event of a lost edit (ExitLock, expiry) replayed after the StartEditing of another session, and twenty handovers of the Lock between two sessions (both ended the new edit before the fix); Methods on one set while eight other sets run and drain without pause; LastTransition before the first run; and CloseAndUpdate with Operations as an array of Byte.

---

## v1.39.0

**Date:** 2026-11-25
**Previous release:** v1.38.0

The UAFX ConnectionManager as a Go library (OPC 10000-81 §6.7 to §6.16, §13, Annex F): package `uafx/fxcm` validates ConnectionConfigurationSets, reads and writes their files, holds the state machine, the edit, and the ownership and diagnostics rules a ConnectionManager works by, and its `Manager` establishes, enables, disables and removes the Connections of the sets on AutomationComponents, over unicast and multicast flows. `fxserver.EnableConnectionManager` serves a `Manager` as the ConnectionManager of a server: its sets as nodes, EditConnectionConfigurationSets, ProcessConnectionConfigurationSets, their events and the configuration file of F.3; `uafx` calls the Methods. A go-opcua AutomationComponent now finds the readers and writers of an endpoint inside groups and PubSubConnections it named itself (see Fixed), and CloseAndUpdate of the PubSub configuration no longer loses a change another client makes while it runs. None of the pinned references of opcua-interop implements UAFX, so this is tested against go-opcua only. No changes need attention when upgrading.

### Added

- Package `uafx/fxcm`, the configuration model of a ConnectionManager. `NewConfig` validates a `uafx.ConnectionConfigurationSetConf` and returns an immutable `Config` with Version 1 (§6.8.2); an invalid set is a `*ConfigError` with one `Finding` per defect, its path and its clause (`ErrConfig`, `ua.StatusBadConfigurationError`, FxError ConnectionConfigurationSetInvalid). It checks the indexes between the arrays (F.1.2.1), the namespace indexes against the Namespaces of each ServerAddress (F.1.2.2), the members a Connection, an endpoint, a flow, an AutomationComponent, a ServerAddress and a SecurityKeyServer need (§6.8.2, §6.10 to §6.15, §9.2, §9.3), the names of the Connections and of the endpoints in a FunctionalEntity (§6.8.2, §6.12), and unicast and multicast flows (§6.13.3); SelectionLists with RestrictToList TRUE, unique BrowseNames and one publisher per flow are library interpretations, named in the findings. See docs/uafx.md#connectionmanager-configuration.
- `fxcm.DecodeFile` and `fxcm.EncodeFile`: the ConnectionConfigurationSet file of F.2, a UABinaryFileDataType; a defect is `ua.StatusBadTypeMismatch` (Table F.40), `DecodeFile` reads and `EncodeFile` writes at most 16 MiB (`ua.StatusBadEncodingLimitsExceeded`), and, as a compatibility tolerance, a file written with the namespace indexes of a NamespaceArray or without the OPC UA namespace is read too; hand-written files are the fixtures.
- `fxcm.EditSlot`: StartEditing, CommitUpdates and DiscardUpdates of §6.7.4 on a working copy, with the Lock of a `LockOwner`; Version is incremented on every commit, and a lost Lock is DiscardUpdates. `fxcm.State`, `fxcm.Transition`, `fxcm.Start` and `fxcm.Finish`: the ConnectionConfigurationSetStateMachine of §6.9.2 with its NodeIds and event types.
- The ownership rules of a ConnectionManager as pure functions: `fxcm.Ownership` (KnownOwned, TakenPreconfigured, Unresolved, Foreign; only the first two may be closed), `Classify` and `Scan` for an endpoint found under a Name (a preconfigured endpoint another ConnectionManager uses since is Unresolved, never closed), `ResolveLostResponse` for an endpoint after a lost response (KnownOwned only with the ConnectionManagerApplicationUri of this ConnectionManager, the Name absent before, the FunctionalEntity serialized and an exclusive ApplicationUri asserted), and `RetryAllowed` (only transient failures and no Unresolved endpoint). `fxcm.Diagnose` and `fxcm.ConnectionStateOf`: the ConnectionDiagnostics of §10.19 (the StatusCode of a failure as reported) and the ConnectionState of §10.20.
- `fxcm.Manager` (`fxcm.New`): holds sets (`Add`, `Replace`, `Remove`, `Update` as CloseAndUpdate of F.3.3, the edit of §6.7.4) and processes them (`Process` with an action of FxProcessEnum, §6.7.5; `Reconcile`), one `Run` per set that runs in the background (`Run.Wait`, `RunResult`, `Status`, `Counters` of §6.7.2). An establish run dials each server through a `Dialer` (`ClientDialer`: GetEndpoints, `opcua.SelectEndpoint`, the ServerUri checked, §9.2, §13.2), resolves the identifiers of the set (NodeIds by the Namespaces of their ServerAddress, RelativePaths, the placeholders of the TranslationTable, §6.16.3, §13.3; cached per server with its NamespaceArray and NamespacePublicationDates), finds what is under the endpoints' Names, reserves the communication ids, gives the subscribers of each flow the ids of its publisher (E.2.2), and calls EstablishConnections, in parallel over the AutomationComponents and split at their MaxConnectionsPerCall (§6.2.6); with RollbackOnError a failure closes what the set may close. Enable, Disable and Remove runs call EstablishConnections with EnableCommunicationCmd and CloseConnections. Every call carries the AuditEntryId of its run (§6.7.3.2). The ConnectionsDiagnostics follow every run (§10.19).
- Ownership safeguards (design §5.3, §5.4): a run closes only the endpoints it made or took preconfigured. After a lost response an endpoint is ours only with `Options.ExclusiveApplicationURI`, else Unresolved: never closed, keeping a remove in Error until `Manager.Settle` (`SettleOwned`, `SettleForeign`) decides it. Two Managers with the same ApplicationUri do not close each other's endpoints.
- `Options.Retry` (`RetryPolicy`): a set in Error is processed again with jittered exponential backoff when `RetryAllowed` says so. `Options.Monitor` (`MonitorOptions`): the Status of the established endpoints is read every Interval and gives the ConnectionState (§10.20), and with `Reestablish` a vanished endpoint starts the last establish again. `Options.Observer` (`Event`, `ObserverFunc`) and `Options.Logger` report transitions, calls, endpoints, settles, retries and monitor findings.
- Library interpretations, in docs/uafx.md#running-a-connectionmanager: a PubSub configuration is not generated from the flows; a PublishedDataSet of the same Name is reused only when its PublishedData (SubstituteValues and MetaDataProperties included), its DataSetMetaData Fields (every member but the Description; a null DataSetFieldId is the publisher's) and its DataSetClassId equal the set's, and is then shared, never changed or removed (otherwise SetCommunicationConfigurationError and `Bad_BrowseNameDuplicated`); when a PubSubConnection matched one with another PublisherId the subscribers (DataSetReaders with a null PublisherId or their publisher's) are adapted with one more EstablishConnections call (SetCommunicationConfigurationCmd, ElementModify of the DataSetReaders, §6.16.3); an AutomationComponent with CommandBundleRequired, which cannot take that call (§6.2.6), is configured after its publishers with their PublisherIds, and only bundled ACs subscribing to each other in a cycle fail on a mismatch (those waiting on a cycle go after it); `Bad_NodeIdUnknown` from CloseConnections counts as closed; readers and writers no endpoint links stay on the AutomationComponent after a close.
- `fxserver.EnableConnectionManager` (`ConnectionManager`, `ConnectionManagerOptions`, `ErrConnectionManager`): a `Manager` as FxRoot.ConnectionManager of a server with the CM model (§6.7, §12.3). Its sets are ConnectionConfigurationSetType Objects with the members of §6.8.2 and the References of Table 90, in Folders, following the Manager (`SetNode`, `Flush`); the fields a client may configure are SelectionList Variables (OPC 10000-5 §7.18, §6.8.1, F.1.2.3), NodeIdentifiers shown as PortableNodeIdentifiers with the NamespaceUris of their ServerAddress (F.1.2.2), MessageSecurityModes as Int32; Version, Edit, RollbackOnError, ConnectionsDiagnostics, the state machine (§6.9.2) and a ProcessingResult per Connection (library interpretation). EditConnectionConfigurationSets (§6.7.4, Tables 80 to 82, `Editable`) gives the Lock of a set (OPC 10000-100 §7; locked to the ConnectionManager, LockingUser `CM`, outside edit) to the calling session, with RenewLock, ExitLock, BreakLock, expiry after MaxInactiveLockTime and release at the end of the session; writes outside the owner's edit are `Bad_Locked`. CommitUpdates reflects the changed flow Variables onto the PubSubConfigurations of the AutomationComponents (§6.13.1, §6.16.3; the mapping is a library interpretation, CS-19, in docs/uafx.md#editing); a working copy that is invalid or conflicts is `Bad_InvalidState` and stays in edit (library interpretation). ProcessConnectionConfigurationSets (§6.7.5, Tables 84 to 86) starts the runs and returns; the ProcessingStarted, ProcessingSucceeded and ProcessingFailed events (§8.6 to §8.9) and the state of the set tell the outcome. AggregatedCurrentState, the Diagnostics counters and Capabilities (§6.7.2, §6.7.6); with auditing, AuditUpdateMethodResultEventType for every call and AuditUpdateConnectionConfigurationSetEventType for every write (§8.5). With `File`, ConnectionManagerConfiguration (F.3): Open for Read or Write+EraseExisting, handles that end with their session (OPC 10000-20 §4.2.1), CloseAndUpdate with one operation per set that asks the authorizer again (F.3.3), ChangesApplied (Table F.39), results and the set Objects; with RequireCompleteUpdate a batch is applied whole or not at all, and one that would close the Connections of more than one set is `Bad_InvalidState` (library interpretation); the atomicity covers the sets of the Manager, not endpoints a failed close already closed on an AutomationComponent; `Manager.Close` waits for a complete update, also an add-only one, and one it overtakes before anything was closed applies nothing (`Bad_Shutdown`). A claim holds a set without processing it: only the remove run that closes its Connections (or the commit of a batch, for a set without Connections) takes the transitions and emits the processing events, so a refused batch emits none; an empty `Manager.Update` applies nothing with or without requireComplete. The removals, disables and enables of `uafx/fxserver` run in the PubSub transaction of the server (`Server.ChangePubSubConfiguration`). The Lock deadline is checked on every write, RenewLock and edit call; LastTransition follows the transition the set took (`fxcm.Status.Transition`); calls refused before they reach a set are audited too; the names in the String NodeIds are escaped; the References of a set follow a Replace that changes a flow index. Edit, Process, writes, file writes and BreakLock need the Role ConfigureAdmin (Part 3 §4.9.2, `fxserver.ConfigureAdmin`) unless `Authorizer` (`CMAuthorizer`, `CMRequest`, `CMOperation`) decides. See docs/uafx.md#serving-a-connectionmanager.
- `uafx.EditConnectionConfigurationSets`, `uafx.ProcessConnectionConfigurationSets` and `uafx.ConnectionManagerNode`: call the Methods of the ConnectionManager of a server; they return the status of the call and one result per set.
- `fxcm.Manager.AddObserver` and `Manager.Options`; the Events `EventSetAdded`, `EventSetReplaced`, `EventSetRemoved`, `EventEditStarted`, `EventCommitted` and `EventEditEnded`, and `Event.Version` and `Event.Action`.
- server: `PubSubConfigurationUpdate.Created` reports whether an update created a PubSubConnection, group or PublishedDataSet in the runtime, from the ids the runtime returned as the update applied the configuration.
- `fxcm.Manager`: a Replace, Remove or Update claims its sets until it is done, so that no run, retry or edit starts on them meanwhile (`Bad_InvalidState`); a claim takes no transition: the remove run does.
- server: `Server.ChangePubSubConfiguration` runs Go code that changes the PubSub runtime in the transaction of CloseAndUpdate, `UpdatePubSubConfiguration`, `Revert` and the PubSub Methods (see Fixed).
- An example, `examples/uafx/cm`: a ConnectionManager server whose sets a client writes through the file or `-set` loads.
- Tests: every validation rule with the valid set it changes, the file in both namespace layouts and its errors, the edit, the state machine, the ownership and retry rules, the diagnostics, and the fuzz target `FuzzDecodeFile`. The Manager end to end against `fxserver` AutomationComponents with UDP PubSub: establish, enable, disable, remove and establish again with data flowing; BrowsePaths and placeholders, asset and FunctionalEntity verification, MaxConnectionsPerCall and CommandBundleRequired; preconfigured endpoints; the rollback; a PublishedDataSet name collision with other content and the comparison of every item and field member; a DataSetReader that names its publisher's PublisherId adapted; a SecurityKeyServer refused; the PublisherId adaptation, with CommandBundleRequired after the publisher, its nested results and a failing call; Close waiting for a Remove; every use of every service failed in turn and every call's response lost, leaving nothing behind; two Managers with the same ApplicationUri; the monitor; the retry policy; the ClientDialer. The ConnectionManager server: nodes and References, SelectionList writes, the PortableNodeIdentifier view, the Lock, commit with reflection and its conflicts, Process and its events, the audit events, the file, the authorizer, and a SignAndEncrypt server with an authorized user, a viewer and a right revoked between Open and CloseAndUpdate. Five establish and remove cycles on an `fxserver` AutomationComponent leave its PubSub runtime as it was. Headline (design §7.1): two AutomationComponents and a ConnectionManager, each its own server, driven only through the Methods, the SelectionList Variables and the file, over SignAndEncrypt sessions with a ConnectionAdmin user: add, establish, disable, enable, edit the PublishingInterval and see it on the AutomationComponent, remove. Multicast with four servers: one publisher, two subscribers on a UDP multicast group, one DataSetWriter serving both; it needs an interface that carries multicast, skips without one, and fails instead with `GO_OPCUA_MULTICAST_REQUIRE=1`, which the CI `server` job sets; run on macOS on en0 and lo0.

### Fixed

- server: CloseAndUpdate and `Server.UpdatePubSubConfiguration` read the PubSub configuration and then applied the update as the difference to it, while the PubSub Methods that change the configuration (AddConnection, AddWriterGroup, RemoveGroup, Enable, Disable and the others of Part 14 §9.1.3) did not wait for them: a connection another client added in between was removed again, one it removed came back. They now run in one transaction, so such a change is applied after the update and kept (§9.1.3.7.6: elements the update does not reference are left alone). Go code joins the transaction with the new `Server.ChangePubSubConfiguration`; calls on `Server.PubSub()` itself stay outside it. ReserveIds and `Server.ReservePubSubIDs` run in it as well: they read the configuration while an update had assigned ids it had not applied yet, and could reserve one of them (§9.1.3.7.5: the ids are neither used nor reserved). Concurrent calls of `PubSubConfigurationUpdate.Revert` raced on its state, and all but the first could return `ErrPubSubChanged`: the first restores the configuration and the others now do nothing.
- `uafx/fxserver`: CloseConnections with Remove left the groups, PubSubConnections and PublishedDataSets an EstablishConnections call created, so each establish of a set added another WriterGroup and repeated cycles left empty ones behind. They now go once nothing uses them: a group without readers and writers, then a PubSubConnection without groups, a PublishedDataSet no DataSetWriter publishes (Part 81 §6.2.5.2, "all related communication model Objects if not referenced from other ConnectionEndpoints"). A group another writer or reader still uses stays, with its connection, but the departing writer's PublishedDataSet goes when no other writer publishes it. A component is the call's when the call adds it with ElementAdd and the call's update created it (`PubSubConfigurationUpdate.Created`); preconfigured, matched and concurrently added components stay. A removal that fails is the endpoint's result, and the endpoint stays until a later close removes what is left.
- `uafx/fxserver`: an endpoint lost the ownership of a DataSetReader or DataSetWriter that a later EstablishConnections call replaced with ElementModify (the runtime gives it a new NodeId), so CloseConnections with Remove left it behind (§6.2.5.2).
- `uafx/fxserver`: EstablishConnections did not find the DataSetReader or DataSetWriter of an endpoint whose PubSubConnection, group or element the call added with a null Name, which the server names (Part 81 §6.16.3): the link failed with `Bad_NotFound` and the call was aborted. The links now use the Names the call assigned, as returned in its ConfigurationValues.

---

## v1.38.0

**Date:** 2026-11-24
**Previous release:** v1.37.0

The DataTypes of OPC UA FX (UAFX, OPC 10000-81 version 1.00.04) are generated from the NodeSets of the OPC Foundation, with their binary encoding: all 18 enumerations and OptionSets and 56 structures of the Data, AC and CM namespaces, of which v1.37.0 had the arguments of EstablishConnections, written by hand. The generated code encodes the arguments of v1.37.0 to the same bytes and is checked against the Binary Schemas of the NodeSets and byte fixtures written from Part 6. Two decoders of package `ua` refuse or normalize input they accepted inconsistently (see Fixed). A go-opcua server also serves the ControlGroups of UAFX (Part 81 §6.5): their Methods, the LockingServices of their Locks (OPC 10000-100 §7), and EstablishControlCmd and ReassignControlCmd of EstablishConnections, which were `Bad_NotSupported`; by default only sessions with the Role ConnectionAdmin establish, release and reassign control and break Locks. None of the pinned references of opcua-interop implements UAFX, so this is tested against go-opcua only. No changes need attention when upgrading.

### Added

- ControlGroups in `uafx/fxserver` (Part 81 §6.5): `EnableConnections` serves EstablishControl, ReleaseControl and ReassignControl of every ControlGroup in the ControlGroups folders of the FunctionalEntities, and InitLock, RenewLock, ExitLock and BreakLock of the Locks of their ListToBlock and ListToRestrict (OPC 10000-100 §7.5 to §7.8), with Locked, LockingClient, LockingUser, RemainingLockTime and IsControlled. While a Lock is held, writes and calls of the items of ListToBlock fail for everyone, those of ListToRestrict for everyone but the owner, with `Bad_Locked`. A Lock goes after the MaxInactiveLockTime of its folder or of the server (`ConnectionOptions.MaxInactiveLockTime`, written to the ServerCapabilities, one minute by default) and when the session that took it ends. EstablishControlCmd controls the ControlGroups of an element for the caller (`Bad_Locked` when another owner holds them), SetConfigurationDataCmd writes as the ConnectionEndpoint, and ReassignControlCmd gives them to the endpoint, which holds them with the LockingUser `UAFX` and a Controls Reference while its Status is not Error, until CloseConnections with Remove releases them (§6.2.4.3.6 to §6.2.4.3.8, §6.2.5.2). An aborted call releases what its EstablishControlCmd took (Table 21). An Object in a list covers its hierarchy (HierarchicalReferences) and the Methods called on it. An item that stands for more than 4096 nodes makes `EnableConnections` fail rather than protect a part of it. EstablishControl, ReleaseControl, ReassignControl, their commands, BreakLock, CloseConnections with Remove of an endpoint that controls ControlGroups and SetConfigurationDataCmd writing through an endpoint's Lock need the well-known Role ConnectionAdmin (Part 81 §5.9, recommended by §6.5.3 to §6.5.5; `Namespaces.ConnectionAdmin` for a `server.RoleMapper`), else `Bad_UserAccessDenied`; `ConnectionOptions.ControlAuthorizer` (`ControlRequest`, `ControlOperation`) replaces that policy. InitLock and EstablishControl return -1 while a write or call runs that the Lock would prevent (OPC 10000-100 §7.2), such as a Write a `ValueWriter` still holds. A ControlGroup a client controls has no Controls Reference: §6.5.2 wants it from the Object of the client connection, which the server does not have. See docs/uafx.md#controlgroups.
- server: `Guard`, `SessionEndGuard` and `Server.AddGuard`: checks the server makes after the `AccessController` for every Variable value a client writes and every Method it calls, for state such as locks; `OperationGuard`, told when a write or call it allowed is over (after the `ValueWriter` of a Write that is answered later), so that it knows which operations are active; `Session.ClientApplicationURI`.
- The enumerations, OptionSets and structures of the UAFX Data, AC and CM namespaces in package `uafx`, generated by `cmd/uafx` from the NodeSets in `uafx/internal/model` (`make gen`): the structures of the ConnectionManager (`ConnectionConfigurationSetConf`, `ConnectionConfigurationConf`, `CommunicationFlowConfigurationConf`, `ServerAddressConf`, `NodeIDTranslationConf` and the others of the CM namespace), of the AC namespace (`ApplicationIdentifier`, `ApplicationID`, `ConnectionDiagnostics`, `PortableNodeIdentifier` and others) and the enumerations `ConnectionState`, `FxError`, `CommHealth`, `LastActivityMask`, `FxTimeUnits`, `ClampKind`, `SocketKind`, `FxEdit`, `FxProcess`, `ConnectionConfigurationSetOperation`. Optional fields are nil when absent (Part 6 §5.2.7), and a present optional array keeps its presence when it is null on the wire: it decodes as an empty slice (§5.1.11: null and empty arrays are semantically the same); a union sets at most one field (§5.2.8); an abstract structure (`ConnectionEndpointParameter`, `CommunicationConfiguration`, `CommunicationConfigurationResult`, `CommunicationLinkConfiguration`, `CommunicationModelConfiguration`, `CommunicationFlowConfigurationConf`, `ReserveCommunicationIDs`, `ReserveCommunicationIDsResult`) is an interface of its concrete structures.
- `uafx.EncodeStructure(v, ns)` and `uafx.DecodeStructure(eo, ns)` with `uafx.NamespaceIndexes`: encode and decode any UAFX structure in an ExtensionObject with the namespace indexes of a server (`ErrCodec`). The decoder takes hostile input: array lengths are checked against the bytes that are left, undefined EncodingMask bits, SwitchFields and nested structures of another DataType than the field's are errors before anything is decoded, and the body must be consumed.
- `PubSubReserveCommunicationIDs1` and `PubSubReserveCommunicationIDsResult1`, the version 1 structures of ReserveCommunicationIdsCmd, which the decoder of EstablishConnections already accepted.
- Tests: `TestSchemaMatchesBinarySchema` (every DataType, field order, EncodingMask bits, SwitchValues, ExtensionObject fields, enumeration names and values, OptionSet bits and widths against `schema/opc.ua.fx.*.nodeset2.bsd`, vendored by `schema/update-schema.sh`), `TestStructureFixtures` (hand-computed bytes of unions, optional fields and subtypes at two sets of namespace indexes), `TestOptionalNullArray` (a present null optional array keeps its EncodingMask bit), `TestGoldenReleaseB` (the bytes of the EstablishConnections arguments of v1.37.0), a round trip of every structure with optional fields absent, present and empty, and filled, the decoder errors, and the fuzz target `FuzzDecodeStructure`. ControlGroups end to end with two clients and through EstablishConnections, CloseConnections and the rollback in `uafx/fxserver`: the Locks on the clock of the test, an Object in ListToRestrict, clients without ConnectionAdmin, a ControlAuthorizer that denies, a client without ConnectionAdmin closing and writing through an endpoint that controls a group, the node limit of a list item, a lock request during a Write a ValueWriter holds, and a session that ends between EstablishControlCmd and ReassignControlCmd; the Guards in `server`.

### Changed

- The argument structures of EstablishConnections and their codecs (`EncodeEstablishConnectionsRequest` and the others) are generated; their names, fields and encoding are those of v1.37.0. An optional array of them that is present with the length -1 now decodes as an empty slice instead of nil, so encoding it again keeps the field.
- EstablishConnections with EstablishControlCmd or ReassignControlCmd on a ControlGroup the FunctionalEntity has no longer aborts with `Bad_NotSupported`; a ControlGroup without its Locks is `Bad_InvalidState`.
- `make gen` runs with Go 1.26 and 1.27: `stringer` of golang.org/x/tools v0.43.0 failed under Go 1.27. golang.org/x/tools is v0.53.0, and with it golang.org/x/sys v0.50.0, golang.org/x/mod v0.43.0 and golang.org/x/sync v0.25.0.

### Fixed

- `ua.Variant`: a scalar with the ArrayDimensions bit of its encoding mask set decoded without dimensions but kept the bit, so `Encode` wrote a dimension count that was not in the input and the following fields of a structure moved by four bytes. ArrayDimensions belong to arrays (Part 6 §5.2.2.16); the bit is now dropped for a scalar. Found by `FuzzDecodeStructure`.
- `ua.ExtensionObject`: an encoding byte other than 0x00, 0x01 and 0x02 (Part 6 §5.2.2.15) was read as a binary body and encoded again as an object without one; it is now `StatusBadDecodingError`. Found by `FuzzDecodeStructure`.

---

## v1.37.0

**Date:** 2026-11-23
**Previous release:** v1.36.0

A second part of OPC UA FX (UAFX, OPC 10000-81 version 1.00.04): non-persistent connections with PubSub. A go-opcua server serves EstablishConnections and CloseConnections on its AutomationComponents (§6.2.4, §6.2.5), with the Status, health and CleanupTimeout of the ConnectionEndpoints, and a client calls them. ControlGroups, persistent connections and the ConnectionManager are not implemented. None of the pinned references of opcua-interop implements UAFX, so this is tested against go-opcua only. No changes need attention when upgrading.

### Added

- `uafx/fxserver.EnableConnections(srv, ns, opts)`: serves EstablishConnections and CloseConnections on every AutomationComponent below FxRoot, with the PubSub runtime of the server (`server.WithPubSub`). EstablishConnections runs its commands in the order of §6.2.4.3.1: VerifyAssetCmd (with `ConnectionOptions.AssetVerifier`, else `Bad_NotSupported`), VerifyFunctionalEntityCmd (Table 45: values read with the caller's rights, Strings without leading and trailing whitespace, an ApplicationIdentifier by its UniqueIdentifier, other structures by their TypeID and binary body), ReserveCommunicationIdsCmd, CreateConnectionEndpointCmd (a new PubSubConnectionEndpoint, or the preconfigured one of that name when it is not in use), SetConfigurationDataCmd, SetCommunicationConfigurationCmd (the PubSub configuration as CloseAndUpdate applies it, with checks that the DataSetReader and DataSetWriter of each endpoint exist and carry its Variables) and EnableCommunicationCmd. A failed command aborts the call with Uncertain and `Bad_NothingToDo` for the commands that did not run (§6.2.4.3.11), and the call's changes are undone as Table 21 asks; ConfigurationData written and ids reserved stay. CloseConnections disables the unshared readers and writers of the endpoints and, with Remove, removes those the connection's calls created and the endpoints that are not preconfigured (§6.2.5); a PubSub operation that fails makes the result of its endpoint Bad and the call Uncertain, and the endpoint stays until a later close succeeds. The commands run with the session of the caller: the AccessController, the AccessRestrictions, the PubSubAuthorizer and the access levels apply as for that session's own calls and writes. `ConnectionOptions` sets `MaxConnections`, `MaxConnectionsPerCall`, `CommandBundleRequired`, `UDPPort`, `Interval` and `Logger`.
- The Status of the PubSubConnectionEndpoints follows their DataSetReaders and DataSetWriters (§6.6.3), and the CommHealth of the ConnectionEndpoints folders, bits 0 to 15 of the OperationalHealth of the FunctionalEntities and the AggregatedOperationalHealth of the AutomationComponents follow (§6.4.8, §10.9, §10.34, §9.1.2); `Connections.RefreshHealth` after an application changes bits 16 to 31. The CleanupTimeout starts when an endpoint leaves Operational and closes it with Remove when it expires (§6.6.2), with an AuditConnectionCleanupEventType event (Status false and a retry when the close fails); the expiry is decided between calls, so an endpoint a CloseConnections closed meanwhile stays; each call reports an AuditUpdateMethodResultEventType event when the server audits. `Connections.Status`, `Connections.Endpoints` and `Connections.Close`.
- ControlGroups: a call with EstablishControlCmd or ReassignControlCmd and no element with ControlGroups is `Bad_InvalidArgument` (Table 8); an empty ControlGroups list is a no-op; a ControlGroup the FunctionalEntity does not have is `Bad_NodeIdUnknown`, one it has `Bad_NotSupported`, and either aborts the call. A persistent ConnectionEndpoint is `Bad_NotSupported`.
- `uafx.EstablishConnections(ctx, client, ac, req)` and `uafx.CloseConnections(ctx, client, ac, endpoints, remove)`: call the Methods of an AutomationComponent; `ErrCall`. The argument structures of EstablishConnections (`EstablishConnectionsRequest`, `EstablishConnectionsResult`, `ConnectionEndpointConfiguration`, `PubSubConnectionEndpointParameter`, `PubSubCommunicationConfiguration` and the others of §10) with `FxCommandMask` and the verification enumerations, and their codecs `EncodeEstablishConnectionsRequest`, `DecodeEstablishConnectionsRequest`, `EncodeEstablishConnectionsResult`, `DecodeEstablishConnectionsResult` (`ErrCodec`), which take the namespace index of the UAFX Data namespace on the server.
- server: `Server.ReservePubSubIDs` and `Server.UpdatePubSubConfiguration` (with `PubSubConfigurationUpdate.Revert` and `ErrPubSubChanged`) let a Method of a companion specification reserve ids and apply a PubSub configuration as ReserveIds and CloseAndUpdate do (Part 14 §9.1.3.7), with the checks those Methods make for the session of the call. `Server.WriteValue` and `Server.ReadValue` write and read a Value with the checks of the Write and Read services for the session of the Method call. `MethodCaller.ClientApplicationURI`. `Node.AddReference` adds a reference of a ReferenceType of any namespace.
- `examples/uafx/server` serves the connection Methods; its endpoint is preconfigured with input, output and configuration Variables.
- Tests: end-to-end connections with UDP PubSub in `uafx/fxserver` (data flowing, a failure at every command and the state after the abort, preconfigured and shared readers and writers, CleanupTimeout, access control, audit events; failures injected into CloseConnections and the cleanup, a CloseConnections and a call run exactly between a found expiry and its close), `chaos/uafx` (parallel calls and calls under connection faults), fuzz targets `FuzzDecodeEstablishConnections` and `FuzzScanners`.

### Changed

- `fxserver.AddModel` and `fxserver.ImportNodeSet` map namespace indexes with hand-written scanners instead of regular expressions, with the same result (checked against the expressions by a fuzz target): an import of the UAFX and DI models takes about a third less time and allocates a quarter less, and under the race detector half the time and under a fortieth of the memory.

---

## v1.36.0

**Date:** 2026-11-23
**Previous release:** v1.35.0

A first part of OPC UA FX (UAFX, OPC 10000-81 version 1.00.04): the information model. A client reads the UAFX model of a server, its AutomationComponents with their Assets, FunctionalEntities, ConnectionEndpoints and health, and the ConnectionManager, and sees where the address space deviates from Part 81; a server serves the model. The Methods of Part 81 that establish, verify and close connections are not implemented, and none of the pinned references of opcua-interop implements UAFX, so it is tested against go-opcua only. No changes need attention when upgrading.

### Added

- `uafx.Inspect(ctx, client, limits)`: the UAFX namespaces of a server with their NamespaceMetadata versions, its ServerCapabilities, FxRoot (§12.2), the AutomationComponents FxRoot organizes (§6.2.2: ConformanceName, AggregatedHealth, Descriptors) with their Assets (§6.3.2, the nameplate), FunctionalEntities and SubFunctionalEntities (§6.4.2) and ConnectionEndpoints (§6.6.2: Status, IsPersistent, CleanupTimeout), and the ConnectionManager (§12.3). Subtypes of the UAFX types are recognised by the HasSubtype chain of the server; a supertype the server cannot tell is an `ErrInspect`, never a node left out. Members are matched by BrowseName in the namespace of the standard that defines them (§14.2), so a vendor child of the same name is not taken for a standard member. AggregatedHealthDataType and FxVersion are decoded with the namespace index the server has for AC. `Report.HasFXNamespaces()` tells whether the server has the namespaces §14.2 requires (DI, Data, and AC or CM), `Report.IsFXServer()` whether it also has FxRoot (§12.2); neither is a conformance statement. `Report.Findings` lists deviations from Part 81 the address space shows: a missing namespace, DI included (§14.2), a missing FxRoot, more than one ConnectionManager, missing mandatory members of AutomationComponents, ConnectionEndpoints and the ConnectionManager, undecodable health and version values. `Limits` (`MaxComponents`, `MaxChildren`, `MaxDepth`, `MaxNodes`) bounds what a large or hostile server makes it read; a node shown twice or in a cycle is reported once, every Browse page counts against the limits, continuation points are always released (with a bounded context of their own when the caller's is done), and no Read asks for more nodes than the server's MaxNodesPerRead.
- `uafx/fxserver.AddModel(srv, models...)`: imports the UAFX Data, AC and CM models (`ModelAC`, `ModelCM`) with the DI model of OPC 10000-100 into a server. Namespace 1 is the namespace of the local server (§14.2): its URI is the server's ApplicationUri (Part 5 §6.3.1). On a server without one, `AddModel` adds it; a server without an ApplicationUri, or whose namespace 1 has another URI, is `ErrModel`. A DI namespace the server has is used if it holds the DI nodes the model refers to, with their NodeClass; otherwise `ErrModel`. `fxserver.ImportNodeSet(srv, doc)` imports a NodeSet that builds on the model, such as the instances of an AutomationComponent, with the namespace indexes of the server (Part 6 §F.2); it rewrites only the places where Annex F puts a NodeId or a QualifiedName (in values: NodeId and ExpandedNodeId values, ExtensionObject TypeIds and the NodeId fields of the standard structures Argument, StructureField, StructureDefinition and RolePermissionType) and copies descriptions, strings, comments, Extensions and the bodies of other structures as they are. The Methods of the model answer `Bad_MethodInvalid`.
- `server.(*Server).ApplicationURI()`: the ApplicationUri of the server, from the `ApplicationURI` option or its certificate.
- NodeId packages generated from the NodeSets of the OPC Foundation: `uafx/fxdataid`, `uafx/fxacid`, `uafx/fxcmid` and `di/diid`, each with its `NamespaceURI`.
- `examples/uafx/server` (a server with one AutomationComponent) and `examples/uafx/inspect` (prints the report, `-json`).
- Tests: `conformance/uafx` (every RSA and ECC policy, username identity, multi-chunk responses, concurrent clients, OperationLimits), `chaos/uafx` (connection faults, value and model changes, server close), fuzz targets `FuzzInspectHostileServer`, `FuzzDecodeStructures` and `FuzzRemap`.
- [docs/uafx.md](docs/uafx.md).

---

## v1.35.0

**Date:** 2026-11-20
**Previous release:** v1.34.0

SecureChannels in the SecurityMode Sign with the ECC policies without authenticated encryption derive their keys as Part 6 §6.8.1 asks and as open62541 does since v1.5.10, and the interop suite is pinned to opcua-interop v0.20.0 (open62541 v1.5.10, node-opcua 2.187.32). Changes that need attention when upgrading: such a channel to a peer that derives the keys the old way, open62541 v1.5.9 or earlier or go-opcua v1.34.0 or earlier, fails (see Breaking).

### Breaking

- **`Sign` mode key derivation of `ECC_nistP256`, `ECC_nistP384`, `ECC_brainpoolP256r1` and `ECC_brainpoolP384r1`** (client and server). Part 6 §6.8.1 Step 1: "When not using AuthenticatedEncryption with Sign only, the EncryptionKeyLength and InitializationVectorLength are set to 0" in the calculation of L, which is part of the HKDF salt and the length of the derived key material. The signing keys of a Sign-only channel are now derived with L = the signing key length; they were derived with L covering the signing key, the encrypting key and the IV, as open62541 v1.5.9 and earlier do. open62541 v1.5.10 follows the specification (open62541 commit 1e4eff47c8), and its client and server no longer open such a channel with go-opcua v1.34.0. A peer that derives the keys the old way cannot use a Sign channel with this version: its first symmetric message fails the signature check. `opcua.ECCSignLegacyKeyLength()` and `server.ECCSignLegacyKeyLength()` restore the old derivation. `SignAndEncrypt`, the RSA policies and the policies with authenticated encryption (`ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly`, `ECC_curve25519`, `ECC_curve448`) are not affected.

### Added

- `opcua.ECCSignLegacyKeyLength()`, `server.ECCSignLegacyKeyLength()` and `uasc.Config.ECCSignLegacyKeyLength`: derive the keys of Sign-only channels of the four policies above as open62541 v1.5.9 and earlier. On the server it applies to the channels it accepts and to its registration with a discovery server.
- `uapolicy.KeyExchange.SetSecurityMode(mode)`: the MessageSecurityMode of the channel the keys are for. With `MessageSecurityModeSign` the four policies above derive the signing keys alone. Without a call the keys are derived as before, so direct users of `uapolicy` see no change.

### Changed

- Interop: opcua-interop v0.20.0 (open62541 v1.5.10, node-opcua 2.187.32). open62541 v1.5.10 serves RegisterServer and RegisterServer2 only on a channel with a client certificate whose application URI is the registered serverUri (advisory open62541-SA-2026-0051). `TestOpen62541LDS_GoServerRegisters` registers the go-opcua server with its certificate, over the most secure endpoint the certificate fits, which `WithDiscoveryRegistration` picks without `RegisterInsecure`. The `Sign` rows of `ECC_nistP256` and `ECC_nistP384` against open62541 pass in both directions, directly and over reverse connect.

---

## v1.34.0

**Date:** 2026-11-19
**Previous release:** v1.33.0

Server applications can take clients' writes of a Variable's Value themselves (a device write with read-back, off the request dispatcher), close a session on the application's behalf and validate client certificates with their own validator. SetTriggering keeps its links and reports the triggered items, and a Write to a Variable the client may not write is refused for its access level whatever the DataValue carries. Contributed by MatthewReed303 (#34, #35, #36). Changes that need attention when upgrading: the status codes of SetTriggering and of a Write to a non-writable Variable follow Part 4 now (see Fixed); there is no option to restore the old codes, which were wrong.

### Added

- server: `Node.SetValueWriter(ValueWriter)` hands clients' Writes of a Variable's Value to the application (`ValueWrite`: the session, the node, the DataValue as the client wrote it, an IndexRange merged). The writer's status is the operation's result and the server does not store the value; a written StatusCode or timestamps, which the server refuses for a stored value, are the writer's to take or refuse. AccessLevel, UserAccessLevel, AccessRestrictions and the `AccessController` apply first. Writers run off the request dispatcher: a slow writer (a device write with read-back) holds up only its own Write request, which keeps its in-flight slot until it is answered; one session's writes reach the writers in order; `ctx` ends at `Close` (which waits for them) or when the TimeoutHint elapses; a panic fails the operation with `Bad_InternalError`.
- server: `Server.CloseSession(sessionID)` ends a session on the application's behalf (a user disabled or given another role): subscriptions deleted, queued Publish requests answered with `Bad_SessionClosed`, continuation points released, the `SessionObserver` told `SessionClosedByServer`; the client's next request fails with `Bad_SessionIdInvalid`.
- server: `WithClientCertificateValidator(ClientCertificateValidator)` sets the application's own validator of client application certificates (a trust list changed while the server runs, a rejected list kept for an administrator). It replaces the validator of `WithClientCertificateTrustList` and is refused with `WithPushManagement`.

### Fixed

- server: SetTriggering (Part 4 §5.12.1.6, §5.12.5) keeps the links it is given: when a triggering item's notifications are published, the samples its linked items in Sampling mode queued are published with them (a linked item in Reporting mode reports by itself, a Disabled one has nothing). Links are added before they are removed; a linked item must be one of the triggering item's subscription; deleting either item deletes the link. A request with nothing to add or remove answers `Bad_NothingToDo`, and one whose triggering item is not in the subscription it names `Bad_MonitoredItemIdInvalid`. The links used to be validated and not kept, so a triggered item in Sampling mode was never reported.
- server: a Write of the Value of a Variable whose AccessLevel has no CurrentWrite is `Bad_NotWritable`, and of one whose UserAccessLevel has none `Bad_UserAccessDenied` (Part 3 §5.6.2, Part 4 §5.10.4), also when the client sends a StatusCode or timestamps with the value; it was `Bad_WriteNotSupported`, which tells the client to write the value alone. asyncua sends a Good StatusCode with every write. AccessRestrictions are checked before the DataValue's content too.

---

## v1.33.0

**Date:** 2026-11-15
**Previous release:** v1.32.1

The client verifies the endpoint list it selected its endpoint from with the ServerEndpoints of CreateSession (Part 4 §5.6.2), the server answers GetEndpoints and CreateSession with the same endpoints for the same URL, the batch helpers take a response only with one result per operation, and the PubSub JSON mapping bounds a String PublisherId as UADP does. Changes that need attention when upgrading: a client whose endpoint came from `GetEndpoints` refuses a server whose CreateSession endpoints differ from that answer (see Breaking).

### Breaking

- **A client compares the `GetEndpoints` answer it selected its endpoint from with the ServerEndpoints of the CreateSession response** (Part 4 §5.6.2), when the endpoint given to `SecurityFromEndpoint` is one of the endpoints `opcua.GetEndpoints` or `Client.GetEndpoints` returned. The lists differ when an endpoint of one has no endpoint in the other with the same security policy, mode and level, transport profile, user token policies, application URI (when both name it) and certificate (as bytes, when both carry one); their order and the endpoint URLs are not compared. On a difference, Connect closes the session before ActivateSession and fails with an error matching `ua.StatusBadSecurityChecksFailed`. A server that returns other endpoints in CreateSession than in GetEndpoints is refused, and so is, on a reconnect, a server whose endpoints changed since the client discovered them. `opcua.InsecureSkipDiscoveredEndpointsCheck()` restores the behaviour of v1.32.1.

### Added

- `opcua.DiscoveredEndpoints(endpoints)`: the endpoint list the client selected its endpoint from, compared with the ServerEndpoints of every CreateSession as above. It takes precedence over the `GetEndpoints` answer and serves endpoints that are copies or come from elsewhere. After a server certificate change the client compares with the endpoints it fetches again.
- `opcua.InsecureSkipDiscoveredEndpointsCheck()`: turns the comparison of the list off, wherever the list comes from. The comparison of the endpoint given to `SecurityFromEndpoint` stays.
- `jsonmsg.MaxCorrelationData` (4096): the longest CorrelationData, String PublisherId and String RequestorId the JSON decoder accepts. The UADP decoder uses the same bound.

### Fixed

- client: `ReadMulti`, `ReadValues`, `WriteValues` and `Node.Attributes` (and so `Node.Summary`) take a response only when it holds one result per operation of the request, in every chunk of a `ReadMulti`; a response with another number of results fails with an error matching `ua.StatusBadUnknownResponse`.
- server: GetEndpoints (Part 4 §5.4.4) and CreateSession (§5.6.2) select the endpoints of the URL the client named in the same way: the scheme and the host compared without regard to letter case, one trailing slash ignored, the path compared as it is; when no endpoint has that URL, both return all endpoints. A client that names a server with opc.wss or opc.https endpoints next to opc.tcp with another letter case for the host or with a trailing slash gets the same endpoints from both services, and so connects with the comparison above.
- pubsub JSON: a String PublisherId (of a NetworkMessage, a DataSetMessage, a metadata, status or action message) or a String RequestorId of more than 4096 bytes is a decode error, as in UADP.

---

## v1.32.1

**Date:** 2026-11-14
**Previous release:** v1.32.0

Bounds on the work and memory of decoding: Variant arrays, AMQP 1.0 messages, PubSub metadata, chunk reassembly and PKCS #12 files; limits on GDS query patterns and SecurityGroup key counts; and 32-bit builds that handle lengths, enumeration names and NodeSet2 integer attributes as 64-bit builds do. No API changes.

### Fixed

- UA Binary: a Variant array is never longer than the bytes that follow its length (every element takes at least one byte); a longer one is refused before it is allocated. The decoding of an array and of its ArrayDimensions stops at the first element that does not decode.
- UA Binary: the length of a String, ByteString or ExtensionObject body is compared with the remaining input as an unsigned number, so 32-bit builds take the same lengths as 64-bit builds. `ua.Buffer.ReadN` with a negative count fails with `io.ErrUnexpectedEOF`, as with more bytes than are left.
- server: the length at the start of a legacy encrypted user password is compared with the decrypted bytes as an unsigned number (`Bad_IdentityTokenInvalid` when they cannot hold it), and a MaxNotificationsPerPublish above the largest `int` of a 32-bit build is taken as that largest value, as on 64-bit builds.
- ua: the String method of an enumeration with an unsigned type gives `Type(n)` for every value that has no name on 32-bit builds too. `make gen` keeps this when it regenerates the methods.
- server: the NodeSet2 import reads the integer attributes ValueRank and the `Value` of a DataType field as 64-bit numbers, so 32-bit and 64-bit builds accept and refuse the same files.
- pubsub AMQP: the element counts of the nested lists, maps and arrays of an AMQP 1.0 message share one budget, the bytes of the message, so decoding allocates in proportion to the message size.
- GDS: the 4096-byte limit of a QueryApplications or QueryServers pattern is checked before the pattern is compiled, and consecutive `%` compile as one.
- pubsub JSON: a reader looks the field names of a DataSetMessage up in an index of its DataSetMetaData, built once for each DataSetMetaData, and the JSON decoder builds one index per DataSetMetaData of a NetworkMessage. A DataSetMetaData from the network (`ua-metadata`, or a UADP discovery announcement) with more than 65535 fields is a decode error.
- pubsub JSON: an unsigned integer of 2^64 or more in exponent or fraction notation is refused, as it is in plain notation.
- pubsub security: `KeyService.AddSecurityGroup` refuses a `MaxPastKeyCount` + `MaxFutureKeyCount` above 65534 with `Bad_InvalidArgument` before it generates keys, so the keys of a SecurityGroup fit the Keys array of one GetSecurityKeys result.
- pubsub UADP: the structure type cache of RawData fields keeps only the NodeIds that have a registered Go type.
- pubsub UADP: the decoder refuses a String PublisherId and a CorrelationData of more than 4096 bytes, and a `Reassembler` charges the first chunk of a message with its String PublisherId, String RequestorId and CorrelationData, which the message keeps while chunks are missing.
- uapolicy: `ParsePFX` charges a key derivation its iterations times the blocks of hash output it derives against the work limit, and refuses a PBMAC1 key length above the block size of its HMAC.

### Tests

- conformance/addrspace: `TestView_MapNamespace` serves `math.MaxInt` as its Go `int` value, where it served a constant that did not fit the `int` of a 32-bit build, so the package builds and its tests run on 32-bit builds.

### Notes

- v1.32.0 added `DomainNames []string` to `gdsserver.PendingRequest`, so values of the type can no longer be compared with `==` (the API check against v1.31.0 reports it). Code that compared them compares the fields it needs. Nothing in the code changes.

---

## v1.32.0

**Date:** 2026-11-13
**Previous release:** v1.31.0

Stricter server defaults and more limits, checks of session and certificate state, and the MessageNonce sequence of secured PubSub. Changes that need attention when upgrading: the server limits the operations per request to 32 by default, serves Node Management and Query only when enabled, serves a session only on its own SecureChannel, and a client checks the CreateSession ServerEndpoints against the endpoint it chose. This release also contains the fixes prepared as v1.31.1, which was not released.

### Added

- server: `WithOperationLimits(OperationalLimits)`. The server enforces the OperationLimits it publishes (Part 5 §6.3.11): a request with more operations than its limit fails with `Bad_TooManyOperations` (Part 4 §7.38). The default is 32 for every limit; a field set to 0 has no limit.
- server: `EnableNodeManagement()` to serve AddNodes, AddReferences, DeleteNodes and DeleteReferences, and the `NodeManagementAccessController` interface to authorize each operation; `RBACAccessController` implements it. Without the option they return `Bad_ServiceUnsupported`.
- server: `WithQuery(bool)` to serve QueryFirst and QueryNext. When enabled, Query applies the Browse, Read and AccessRestrictions checks of the nodes it returns.
- server: `WithMaxMonitoredItems` (default 100000), `WithMaxMonitoredItemsPerSubscription` (10000) and `WithMaxMonitoredItemsPerSession` (20000); CreateMonitoredItems beyond them fails with `Bad_TooManyMonitoredItems`.
- server: `WithMaxBrowseContinuationPoints` (default 10) and `WithMaxQueryContinuationPoints` (default 5) per session.
- `ua.MaxBinaryNestingDepth` (100): the nesting depth of UA Binary values.
- `uapolicy.VerifyCertificateChains`: the verified chains of a certificate.
- `gdsserver.PendingRequest.DomainNames`: the host names a pending certificate request will be issued for.
- pubsub: `WithNonceSequencePerToken`, `Counters.NonceSequenceDiscards` and `uadp.EncodeOptions.NextNonceSequenceForToken`.

### Changed

- server: Node Management and Query are off by default (see Added). Servers that offer them call `EnableNodeManagement()` or `WithQuery(true)`. With Node Management on and no `NodeManagementAccessController`, clients cannot change namespace 0.
- server: a request carrying the AuthenticationToken of a session on another SecureChannel fails with `Bad_SecureChannelIdInvalid` (Part 4 §5.7.3), CloseSession included. The first ActivateSession has to come over the channel of CreateSession; a later one moves the session to a new channel when that channel has the same security policy, mode and client certificate and the user is the same (`Bad_IdentityChangeNotSupported` otherwise, §5.7.3.1). A client that reconnects keeps its session as before. On opc.https and UA JSON over opc.wss a session is tied to its security policy.
- server: an X.509 user token policy on an endpoint with security None names a SecurityPolicy (Part 4 §7.40.5): the enabled RSA policy with the highest SecurityLevel, else the highest ECC one. When only None is enabled, no X.509 user token is offered. An X.509 token whose policy is None is rejected with `Bad_IdentityTokenRejected`.
- server: an LDS registration over a channel without a client certificate (opc.https, UA JSON over opc.wss) needs `LDSAllowInsecureRegistration`, also with `LDSSkipServerURICheck`.
- server: HistoryRead and HistoryUpdate of data are authorized per node, as Read and Write are: the AccessController, AccessRestrictions and the HistoryRead/HistoryWrite bits of AccessLevel. CreateMonitoredItems on a data item applies the checks of Read.
- server: NodeSet2 variables without AccessLevel are CurrentRead, the schema default, and the Server object's own variables are CurrentRead; before, clients could write them.
- server: `Node.SetAttribute` no longer refuses a Value on AccessLevel, so server code can update read-only values. Client writes and `NodeNameSpace.SetAttribute` are checked as before.
- server: the PubSub configuration methods check their TargetVariables and PublishedVariables against the calling session, target attributes other than Value obey WriteMask and DataType, and under `RBACAccessController` the methods need ConfigureAdmin. Password and secret ConnectionProperties read as null in the address space.
- server: Republish and the acknowledgements of a Publish name subscriptions of the calling session only; others fail with `Bad_SubscriptionIdInvalid`.
- server: Browse and Query continuation points belong to their session, are limited per session (`Bad_NoContinuationPoints`), expire after 10 minutes without use and are released with the session.
- server: event monitored items with QueueSize 0 get a queue of 1000 (was 1), at most 10000. A full queue discards an event as its DiscardOldest says and marks the place with an EventQueueOverflowEventType event (Part 4 §5.12.1.5). Events count against MaxNotificationsPerPublish. `EmitEvent` and `EmitBaseEvent` never block; their wait argument has no effect.
- server: a ContentFilter or EventFilter with more than 256 elements is refused.
- client: CreateSession compares the ServerEndpoints of the response with the endpoint given to `SecurityFromEndpoint` (Part 4 §5.6.2): application URI, security policy and mode, SecurityLevel, transport profile and user token policies. A mismatch fails the connection with `Bad_SecurityChecksFailed` and closes the session. An EndpointDescription built by hand has to match the server's.
- UA Binary values nested deeper than 100 Variant, DataValue, DiagnosticInfo and ExtensionObject levels fail to decode and encode with `Bad_EncodingLimitsExceeded`, as in the JSON and XML codecs.
- uasc: a SecureChannel holds the chunks of at most 16 incomplete messages, and at most twice the largest message it accepts; beyond that the connection is closed with `Bad_TcpMessageTooLarge`.
- uacp: a connection accepted by `uacp.Listener` that does not send OpenSecureChannel within 10 s of the HEL/ACK is closed.
- GDS: the host names of a certificate are fixed when the request is made, from the request or the DiscoveryUrls of the application at that time. DiscoveryUrls with wildcard hosts are refused with `Bad_InvalidArgument`. Requests stored by an earlier version keep the DomainNames they stored.
- Push management: the revocation of issuers is checked along the verified certificate chains.
- Certificate chains with Ed448 signatures: the search for a path verifies at most 100 signatures and looks at at most 10000 candidates; duplicate intermediates are ignored.
- pubsub: secured UADP messages (PubSub-Aes128-CTR, PubSub-Aes256-CTR) whose MessageNonce sequence number is not newer than the last one of their sender and SecurityTokenId are ignored (Part 14 §7.2.3, Table 156): DataSetMessages, chunks, and Action requests and responses. They count as `NonceSequenceDiscards`. A publisher restarted on the same token is taken again after twice the MessageReceiveTimeout, or with `WithNonceSequencePerToken` at the next token.
- pubsub: senders start the MessageNonce sequence at 1 for every SecurityTokenId (Table 156); before it never started over.
- pubsub: a DataSetMessage sequence number a quarter of the number space or more ahead is ignored (`SequenceDiscards`) instead of resynchronising; `SequenceResyncs` counts resynchronisations after a sender's record expired. Reader sequence records expire after twice (was once) the MessageReceiveTimeout.
- pubsub: reassembly discards a message whose chunks conflict, or whose GroupHeader numbers differ between chunks, and keys chunks by SecurityTokenId.

### Fixed

- server: an OpenSecureChannel refused for an untrusted client certificate is reported to the `SessionObserver` and audited before the client receives the Error message. Before, the client could see the refusal first.
- A decrypted chunk whose padding size exceeds its length fails with `Bad_SecurityChecksFailed` instead of panicking. A panic on the client's receive goroutine ends the channel, and its pending requests fail with `Bad_InternalError`, instead of ending the process.
- server: the session limit of v1.31.0 (`WithMaxSessions`, 100 by default) filled up with sessions their clients had left behind. A client that loses its connection cannot close its session, which then stays until its session timeout (up to 30 minutes), so on an unreliable network the server soon refused every new client with `Bad_TooManySessions`. A full server now closes the session whose secure channel has been gone longest to make room, as `SessionClosedByServer` for the `SessionObserver` and an audit event of a terminated session. A session on an open channel is never closed for it, so a client that can create sessions cannot push others out. opc.https and UA JSON over opc.wss have no connection that closes, so there an abandoned session cannot be told from an idle one: a full server closes the one unused longest once it has been unused for 30 s, after the sessions of closed channels. A client that keeps such a session sends Publish requests, or reads to keep a session without subscriptions alive, more often than that. A client that comes back to a closed session gets `Bad_SessionIdInvalid` and creates a new one.
- client: a client that gave up on its session after a fault created a new one without closing the old one, which the server kept until its timeout. It now closes it first (best effort, keeping the subscriptions for the transfer to the new session, Part 4 §5.6.4). A server that refuses the new session with `Bad_TooManySessions` is asked again after a wait that starts at `ReconnectInterval` and doubles up to 30 s, instead of every `ReconnectInterval`.
- server: closing a session took time quadratic in the number of sessions with diagnostics, because removing a reference compared NodeIds through their strings, and the type and summary nodes reference every session's diagnostics. With many clients coming and going, the one goroutine that handles all requests fell behind and the requests of other clients waited. `ua.NodeID.Equal` now compares the fields without allocating and gives the same answer as before. The alarm chaos test, whose clients connect again every round, ran 260 to 300 s on v1.30.0 and runs about 50 s now (race detector, 30 s of faults).
- The client's MQTT transport kept a long reconnect backoff after it had connected again. The backoff only started over after a connection that lasted `MaxReconnectDelay` (30 s, which the PubSub transport does not change), so under repeated faults it grew to its maximum, and one DISCONNECT from the broker (Server busy, Keep Alive timeout, ...) or a broker outage of a fraction of a second then kept the client away for 24 to 36 s. A PubSub subscriber with a persistent session missed its data for that long while the broker queued it. The backoff of failed connection attempts now starts over once the client is connected, as it did before v1.9.1. The wait after a DISCONNECT has a backoff of its own: it grows while the connections last shorter than it and starts over after one that lasted longer, so two clients with one client identifier still back off instead of taking the session from each other in a tight loop (the reason for the v1.9.1 change), and so does a client a broker disconnects right after every CONNACK.

---

## v1.31.0

**Date:** 2026-11-03
**Previous release:** v1.30.0

Findings of a static analysis review: defects, limits that were only kept by a check elsewhere and are now checked where the value is converted, and server limits that were missing. Three changes need attention when upgrading: the server limits sessions and subscriptions, clients can write attributes other than Value only where the node's WriteMask allows it, and both sides keep to the message size and chunk count the peer announced.

### Added

- server: `WithMaxSessions` (default 100), `WithMaxSubscriptions` (default 1024, all sessions) and `WithMaxSubscriptionsPerSession` (default 64), the defaults of open62541. They are published as ServerCapabilities `MaxSessions`, `MaxSubscriptions` and `MaxSubscriptionsPerSession` (Part 5 §6.3.2). Before, the number of sessions and subscriptions was unbounded, and a client that never activated its sessions could fill memory.
- `uacp.Conn.PeerMaxMessageSize` and `PeerMaxChunkCount`: the limits the peer announced for what it receives.
- `message.PublisherID.Validate`: checks the type and that a numeric PublisherId fits it. `uadp.Encode` and the PubSub configuration use it; `PublisherID.Variant` still truncates, so call `Validate` first.

### Changed

- server: CreateSession fails with `Bad_TooManySessions` (Part 4 §5.6.2) once the server keeps `WithMaxSessions` sessions, activated or not; a closed or timed-out session frees its place. CreateSubscription fails with `Bad_TooManySubscriptions` (§5.13.2) at the server-wide or the per-session limit. TransferSubscriptions answers `Bad_TooManySubscriptions` for a subscription that would take the session past its limit and leaves it where it was.
- server: the Write service enforces the WriteMask of a node for every attribute other than Value (Part 3 §5.2.7, §8.60). Without its bit, a write is `Bad_NotWritable`; a UserWriteMask on the node narrows it further (`Bad_UserAccessDenied`, §5.2.8). Nodes built with the Go API have no WriteMask, so clients can write only their Value, as in UA-.NETStandard and open62541. Before, a client could overwrite NodeClass, BrowseName, EventNotifier, DataType and the others with any value. To open DisplayName, Description and the others, set `ua.AttributeIDWriteMask` (UInt32) on the node; a custom `NameSpace` returns it from `Attribute`. NodeSet2 imports keep their WriteMask, and AddNodes now keeps the WriteMask and UserWriteMask the client sends. NodeId and NodeClass are never writable; UserRolePermissions is `Bad_NotWritable`, and an unknown AttributeId is `Bad_AttributeIdInvalid`.
- uasc: the client sends no request above the MaxMessageSize or MaxChunkCount of the server's Acknowledge (Part 6 §7.1.2.4) and fails it with `ErrMessageTooLarge` and `Bad_RequestTooLarge`. The server aborts a response above the limits of the client's Hello (§7.1.2.3) with an abort chunk carrying `Bad_ResponseTooLarge`, so the client gets that status at once and the channel stays open. Before, the server sent the response and the client discarded it with `ErrTooManyChunks` or `ErrMessageTooLarge`.
- The client's `MaxMessageSize` and `MaxChunkCount` options cap what it accepts even if the server announces more. Left at 0, the client takes the server's limits, or 512 chunks and 2 MiB when the server has none, as before; a server that announces MaxUint32 no longer raises them. With default settings nothing changes on the wire.
- server: `NodeNameSpace.SetAttribute` applies AccessLevel only to the Value attribute (Part 3 §5.6.2). Before, a read-only Value also made the node's other attributes read-only.
- `server.DataValueFromValue` and the server's own values encode a Go `int` outside the Int32 range as an Int64. Before, it was truncated to an Int32.
- `server.Server.AddNamespace` refuses a namespace beyond the 65536 that a UInt16 NamespaceIndex can address (Part 3 §8.2.2): it logs an error and returns -1. A NodeSet2 import that would pass that limit fails before it adds a namespace.
- The PubSub configuration refuses a PublishedDataSet with more than 65535 fields (Part 14 §7.2.4.5: FieldCount and the field index are UInt16). Before, the key frame failed to encode, but the delta frames after it went out with wrapped field indexes. `jsonmsg.DecodeOptions.MaxFields` is capped at 65535 for the same reason.
- `uadp.Encode` refuses a chunk with no ChunkData or ChunkData beyond TotalSize, as the decoder does, and a PublisherId wider than its type.
- `opc.https` responses carry `X-Content-Type-Options: nosniff`.

### Fixed

- server: a write of an attribute other than Value with a value of the wrong DataType (a String for EventNotifier, an Int32 for NodeClass) is refused with `Bad_TypeMismatch` instead of being stored. A write of the Value of a `MapNamespace` key with no value returns `Bad_TypeMismatch` instead of dereferencing a nil Variant.
- The client's AMQP transport read a broker's incoming window or link credit of 2^31 or more, MaxUint32 for "unlimited" among them, as negative and stopped sending (AMQP 1.0 §2.5.6, §2.6.7: they are counts, not serial numbers). PubSub publishing over such a broker stalled.
- The client's MQTT transport wrote a client identifier, user name, password or will payload over 65535 bytes with a wrapped two-byte length (MQTT §1.5.4, §1.5.6), and the broker read its tail as the following fields. `Dial` and the encoder now refuse it.
- `Client.NodeFromQualifiedPath` accepted a namespace index above 65535 ("70000:Name"), which its documentation excludes, and addressed namespace 4464. It now refuses it.
- server: a DataType whose numeric id ends in the byte of a built-in number (DiagnosticsLevel i=19723, ContinuationPoint i=521, ...) counted as numeric, so an absolute or percent deadband on such a Variable was accepted instead of `Bad_FilterNotAllowed` (Part 4 §7.22.2).
- server: an event filter's BitwiseAnd and BitwiseOr with a UInt64 operand returned an Int64, so results of 2^63 and above compared as negative (Part 4 §7.4.3: the result has the size of the larger operand). They now return a UInt64.
- server: a NodeSet2 file with an AccessLevel or UserAccessLevel above 255 or a ValueRank outside Int32 had the value truncated; an AccessLevel of 259 became CurrentRead|CurrentWrite. Such values are now skipped with a warning. An EventNotifier stored as an Int32 or UInt32 outside 0..255 reads as 0.
- uasc: a server or `uacp.Listener` configured with MaxChunkCount or MaxMessageSize 0, which Part 6 §7.1.2 defines as no limit, refused every message of more than one chunk, or every message. Zero now means no limit.
- uasc: after a message was refused for too many chunks or bytes, its remaining chunks were collected again and merged with its final chunk into a message of their own. They are now dropped up to the final chunk.
- uasc: a message of many chunks is refused with `ErrMessageTooLarge` as soon as its chunks pass MaxMessageSize, not after all of them are collected. Message sizes are compared without truncation, a chunk that cannot fit the UInt32 MessageSize is refused on send, and uacp compares the send size before converting it.
- ua: a multi-dimensional array whose element count passes Int32, an ExtensionObject body over 2 GiB, and an unsigned enumeration or option set value above MaxInt64 in JSON and XML were encoded with wrapped or negative lengths or values. The first two now fail with an encoding error; the third is written and read as an unsigned number.
- `Node.NodeClass` refuses a NodeClass outside UInt32 from a server instead of truncating it. Session `Lifetime` and the request TimeoutHint are clamped to the UInt32 milliseconds they are sent in.
- PubSub: received RawData with a zero dimension in a multi-dimensional array or a dimension above Int32 is refused in the UADP decoder. The MQTT transport compares a MaximumPacketSize property above 2^31 correctly on 32-bit platforms.
- Examples: `examples/crypto` wrote the generated private key world-readable (0644), now 0600; three example servers wrote their certificate and key with mode 0, so they could not read them back. The PubSub and translate examples refuse a PublisherId or namespace flag outside UInt16 instead of truncating it.

---

## v1.30.0

**Date:** 2026-11-02
**Previous release:** v1.29.5

### Added

- `server.WithSessionObserver` and `server.SessionObserver`: the application is told about client connections (`OnConnectionOpened`, `OnConnectionClosed` with the duration) and sessions (`OnSessionActivated`, `OnSessionClosed` with the reason `SessionClosedByClient`, `SessionTimedOut` or `SessionClosedByServer`) where they happen, with the session name, the client's ApplicationDescription, the endpoint, the client's address, the security and the user (`SessionInfo`). Before, a server could only find out about its clients by polling the session diagnostics or parsing its log. `server.BaseSessionObserver` implements the interface with no-op methods for embedding.
- `SessionObserver.OnRejected` and `server.Rejection`: the observer is also told about the requests the server refused: an OpenSecureChannel (an untrusted client certificate), a CreateSession, an ActivateSession (a wrong password, a token type no endpoint offers), with the status, the client's address, the security, the client certificate and, for the sessions, the session name and the identity the client tried.
- Security audit events (Part 4 §6.5.5, §6.5.6; Part 5 §6.4): with `WithAuditing(true)` the server reports AuditOpenSecureChannelEventType (opened channels and every failed OpenSecureChannel), AuditChannelEventType (CloseSecureChannel), AuditCreateSessionEventType and AuditActivateSessionEventType (every call, refused ones too), AuditSessionEventType (`Session/CloseSession`, `Session/Timeout`, `Session/Terminated`) and the AuditCertificateEventType subtypes of a refused certificate, which the failed AuditOpenSecureChannelEventType names in CertificateErrorEventId. The user identity token of AuditActivateSessionEventType carries no password or issued token data. Before, only the condition methods, the GDS and `ReportAuditEvent` raised audit events.
- `uasc.Config.OpenSecureChannelHook`: a server channel reports every OpenSecureChannel request it handled and the status it answered with.

### Changed

- `Session.Identity()` (and `MethodCaller.Identity`) no longer carry the password of a UserNameIdentityToken: the session does not keep it. The doc comment said the password was still encrypted; it was the clear text. The `RoleMapper` still gets the token with the password.

### Fixed

- server: a rejected ActivateSession changed the user identity of the session to the one it rejected (Part 4 §5.6.3 leaves the session as it was). A client of an activated session that sent ActivateSession with another user's name and a wrong password got `Bad_UserAccessDenied`, but the session then reported that user in `Session.Identity()`, which an `AccessController` may decide on, and counted as that user's session for TransferSubscriptions. The roles were not affected. The session now takes an identity only once it has been accepted.
- server: ActivateSession accepted every user token type, also those no endpoint offers (Part 4 §5.6.3: the EndpointDescription says which UserIdentityTokens the server accepts). A server that offers only user names let in anonymous clients, and one that offers user names only on secured endpoints accepted a clear text password over a None channel. A token type is now accepted only if an endpoint of the client's channel (same security policy and mode; opc.https and opcua+uajson for their virtual channels) offers it, else `Bad_IdentityTokenRejected`. A null or empty token counts as anonymous, as Part 4 says; before, it kept the identity of the previous activation. A token that is no user identity token is `Bad_IdentityTokenInvalid`.

---

## v1.29.5

**Date:** 2026-11-02
**Previous release:** v1.29.4

### Fixed

- HistoryUpdate DeleteEventDetails answers an EventId without an event with `Bad_NoEntryExists` (Part 11 §6.2.2), as UA-.NETStandard does, not `Bad_NoData`. When no event matches any of the EventIds, the node status is `Bad_NoData` (§6.9.7.2). A client that tests for `Bad_NoData` per operation has to test for `Bad_NoEntryExists`.
- With a client certificate trust list, CreateSession on a channel with SecurityPolicy None refused a client that sent a certificate the list does not trust (`Bad_SecurityChecksFailed`). The server now ignores that certificate, as Part 4 §5.7.2.2 says; `Session.ClientCertificate` is nil on such a session. The node-opcua client sends its certificate there.
- The UserName token policies of opc.https endpoints, and of opc.wss None endpoints, name the security policy that encrypts the password (Part 6 §7.4.1): a secured opc.https endpoint its own, a None endpoint the strongest enabled RSA policy whose certificate it carries (Part 4 §7.41). The password no longer goes in clear text inside TLS when such a policy is enabled, and the UA-.NETStandard client, which refused to send it (`Bad_SecurityChecksFailed`), can log in. Without an enabled RSA policy, and on opc.tcp, nothing changes.
- A value a client writes gets the time the server received it as its SourceTimestamp (Part 4 §7.11.3), and the PubSub publisher stamps the ServerTimestamp of a value it samples, as a Read does (§7.11.4). Before, a written value had neither: a Read with TimestampsToReturn Source returned no timestamp, and a PubSub DataSetMessage left out the timestamps its DataSetFieldContentMask selects. With the trigger StatusValueTimestamp and no deadband, a write of the same value is now a data change: its SourceTimestamp changes.

---

## v1.29.4

**Date:** 2026-11-02
**Previous release:** v1.29.3

### Fixed

- A server no longer refuses a Hello whose EndpointUrl names another port than the one it listens on with `BadTcpEndpointUrlInvalid`. A server behind a published port or a proxy could not be reached (`docker run -p 5000:4840`). The scheme, host and path are still compared.
- A Read or Write that the AccessLevel of a node rules out now answers `BadNotReadable` or `BadNotWritable` (Part 4). `BadUserAccessDenied` remains for what only the UserAccessLevel or the access controller rules out. A client that tests for `BadUserAccessDenied` on such a node has to test for the new status.

### Added

- `server.Node.AccessStatus`, the status of a read or write of the node.

---

## v1.29.3

**Date:** 2026-11-01
**Previous release:** v1.29.2

### Security

- A TLS client certificate removed from the DefaultHttpsGroup trust list could still connect to `opc.https` and `opc.wss` endpoints by resuming a TLS session saved while it was trusted, with `HTTPSClientCertificates` set to verify or require. The trust list is now checked on every connection. Affects v1.18.0 to v1.29.2. See advisory GHSA-5mpv-gmwr-mmh5.

### Changed

- With `HTTPSClientCertificates` set to verify or require, the check runs in `tls.Config.VerifyConnection`. A `VerifyConnection` in the given TLS configuration still runs, after the trust list.

---

## v1.29.2

**Date:** 2026-10-31
**Previous release:** v1.29.1

### Changed

- Tests, CI and documents only. `make coverage-gate` is now `make coverage-pkg-check`, and `make examples` writes to `bin/`.

---

## v1.29.1

**Date:** 2026-10-31
**Previous release:** v1.29.0

### Changed

- Compiled binaries are removed from the repository and its history. Library code is unchanged from v1.29.0. Tags from before this release were rewritten, so GitHub now serves different module contents for 13 of them, and `GOPRIVATE` builds that pin one of those versions fail their `go.sum` check; move to this release.

---

## v1.29.0

**Date:** 2026-10-30
**Previous release:** v1.28.0

### Summary

Secure defaults. A client and a server run without message security only when asked to by name, and a client trusts only the certificates it is given. **This release breaks callers that relied on the old defaults.** Go libraries in this organisation stay on v0 or v1, so it ships as a minor version (otfabric/engineering ADR-0010).

### Breaking

- **`NewClient` refuses a client without message security** over opc.tcp (`errors.ErrInsecureNotAllowed`), however policy None was reached: no options, `SecurityPolicy("None")`, or a None endpoint given to `SecurityFromEndpoint`. Add `opcua.InsecureNoSecurity()` to opt in.
- **A server that presents no certificate is refused** under Sign and SignAndEncrypt (`errors.ErrNoCertificate`), also on reverse connect. It was accepted.
- **Server certificates are validated against `TrustedCertificates` only.** The system CA pool is no longer used (Part 4 §6.1.3). A client using message security needs `TrustedCertificates`, or `InsecureSkipVerify` for development.

- **`Server.Start` refuses to offer no message security** (`errors.ErrInsecureNotAllowed`): a server with no security configured, or with `EnableSecurity("None", …)`, needs `server.InsecureNoSecurity()`. A secure-only server still answers the discovery services.

### Unchanged

Policy None stays supported. `GetEndpoints`, `FindServers`, `FindServersOnNetwork` and `DiscoverServers` need no opt-in, and neither do `opc.https` and `opc.wss`, which TLS secures.

### Added

- `opcua.InsecureNoSecurity()`, `server.InsecureNoSecurity()`, `errors.ErrInsecureNotAllowed`.

---

## v1.28.0

**Date:** 2026-10-26
**Previous release:** v1.27.0

### Summary

References are removed as they are added, on both ends, and the NodeSet importer and the node management services keep both ends, ReferenceTypes of every namespace and Part 4 §5.7 to the letter.

### Fixed

- **server: `Node.RemoveRef` removes both ends of a reference (behaviour change).** v1.26.1 made `AddRef` record a reference on both ends, but `RemoveRef` removed the end it was called on only, so the target kept an inverse reference to a node that no longer had the forward one. It now removes both, whichever end it is called on, and reports whether either end held it; a reference of a node to itself loses both directions. The other end is found through the server of the node's namespace: a node that was not added to a namespace, or a target on another server (ServerIndex != 0), loses the called end only. Code that removed the inverse by hand keeps working (the second call reports false). The matching now compares the ReferenceType NodeId with its namespace, and the ServerIndex of the target.
- **server: the NodeSet importer records references like `AddRef`.** A reference already in the address space (from an earlier import of the same or another nodeset, or from `AddRef`) is no longer added a second time. A symmetric ReferenceType (Part 3 §5.3.3.2) now has its other end too: the target of a symmetric reference declared on one node did not see it in any browse direction; one declared forward on both nodes is one reference. A ReferenceType of a namespace other than 0 keeps its namespace: `ns=2;i=5001` was stored as `i=5001`.
- **server: AddReferences (Part 4 §5.7.3)** keeps the namespace of the ReferenceType (it was truncated to namespace 0 as in the importer), answers `Bad_ReferenceTypeIdInvalid` for a ReferenceTypeId that is not a ReferenceType node and `Bad_DuplicateReferenceNotAllowed` for a reference that exists, also when the request names it from its other end (it answered Good and added nothing).
- **server: DeleteNodes honours `DeleteTargetReferences` (Part 4 §5.7.4)**: the references of which the deleted node is the target are removed from their source nodes too; without it they stay, as before. DeleteReferences removes the target's end only with `DeleteBidirectional`, as before.

---

## v1.27.0

**Date:** 2026-10-26
**Previous release:** v1.26.1

### Summary

`PubSub.Ready` waits until the transports of a started PubSub runtime are open and subscribed, so that an application knows when a message sent to it is received.

### Added

- **pubsub: `PubSub.Ready(ctx)`.** `Start` opens the transports of the connections in the background, so a reader could miss a message sent right after `Start` returned: a one-shot publish, a chunked message, a discovery probe or answer (as `opcuactl` tests on Linux showed, 1 in about 30 runs). `Ready` waits until every running connection has opened its transport and made its first subscriptions (its readers, its discovery listener, its Action requests and responses). A subscription that failed is retried in the background and shows in the connection's Status; an unreachable broker keeps `Ready` waiting until its context ends. It returns `ErrClosed` on a closed runtime and the new `ErrNotRunning` on one that is not started or stops while waiting.

### Fixed

- **interop: a one-shot adapter client that stalls without output is retried once**, as the stdin adapter commands already were; the run error is reported with the output (test harness only).

---

## v1.26.1

**Date:** 2026-10-26
**Previous release:** v1.26.0

### Summary

Fixes found by the opcuactl test coverage pass: the client browse helpers report a Bad browse status instead of an empty result, and two address space fixes in the server.

### Fixed

- **client: the browse helpers return a Bad BrowseResult StatusCode as the error (behaviour change).** `Node.References`, `Node.Children`, `Node.ReferencedNodes`, `Node.BrowseAll`, `Client.BrowseAll`, `Node.TypeDefinition`, `Node.Walk` / `WalkLimit` / `WalkLimitDedup`, `Node.BrowseWithDepth` and `Client.MethodArguments` ignored the StatusCode of the Browse and BrowseNext results, so browsing an unknown node returned an empty list and a nil error. A Bad result status (Part 4 §5.8.2.2, §5.8.3.2: `Bad_NodeIdUnknown`, `Bad_ViewIdUnknown`, `Bad_ReferenceTypeIdInvalid`, `Bad_BrowseDirectionInvalid`, `Bad_ContinuationPointInvalid`, ...) is now the error, a `ua.StatusCode` as the other helpers return it: **callers that browsed an unknown node and got `(nil, nil)` now get `ua.StatusBadNodeIDUnknown`**, `TypeDefinition` of an unknown node included (a known node without a type definition is still `(nil, nil)`). Good and Uncertain results return their references as before. The recursive helpers yield references to nodes of other servers (ServerIndex != 0) without descending into them. The GDS client still falls back to the standard method NodeId when the object cannot be browsed.
- **server: the HistoricalEventFilter Property gets a proper NodeId.** `Server.EnableEventHistory` built its NodeId from the whole NodeId of the notifier, so the Property of `ns=1;s=Demo` was `ns=1;s=ns=1;s=Demo/HistoricalEventFilter`. It is now `<id>.HistoricalEventFilter` in the namespace of the notifier, as the argument Properties of `SetMethodArguments`: `ns=1;s=Demo.HistoricalEventFilter`, `ns=2;s=i=7001.HistoricalEventFilter` for a numeric notifier (Part 11 §5.4.2). Clients that found the Property by browsing (BrowseName `HistoricalEventFilter`) are unaffected; a hard-coded old NodeId must be updated.
- **server: `Node.AddRef` records both ends of a reference (behaviour change).** `parent.AddRef(child, rt, true)` stored the reference on `parent` only, so a node linked with one `AddRef` — as the documentation and examples show, e.g. an Object under the Objects folder with Organizes — had no inverse reference: Browse with BrowseDirection Inverse or Both did not return its parent (Part 3 §7.1, Part 4 §5.8.2). The AddNodes and AddReferences services had the same gap. `AddRef` now also gives `o` the opposite direction to `n`; adding a reference both ends hold already (also from the other end, as code that added the inverse by hand does) does not duplicate it. Browsing a node Inverse or Both, and the inverse of type nodes (HasTypeDefinition), may now return references it did not before. `NodeNameSpace.DeleteNode` removes the inverse ends of the deleted node's forward references from their targets; `RemoveRef` still removes one end. The NodeSet importer is unchanged (it derives the directions itself). `Node.DataType` no longer panics on a DataType attribute set as a `*ua.NodeID`.
- **server: Browse of a node in an unknown namespace is `Bad_NodeIdUnknown`** (Part 4 §5.8.2.2), not the bare `Bad` status.

---

## v1.26.0

**Date:** 2026-10-25
**Previous release:** v1.25.0

### Summary

Historical events in the server (Part 11 §5.4, §6.5.2, §6.9.4, §6.9.7): a notifier made a HistoricalEventNode with `Server.EnableEventHistory` keeps the events reported on it in the history provider, the default `*Historian` included, and serves HistoryRead `ReadEventDetails` and HistoryUpdate `UpdateEventDetails` / `DeleteEventDetails`. The client's `HistoryReadEvent`, `HistoryUpdateEvents` and `HistoryDeleteEvents` work against it unchanged. New client helpers page through event history (`ReadEventHistory`, `ReadEventHistoryAll`) and release continuation points (`HistoryReleaseContinuationPoints`); the value helpers `ReadHistory` / `ReadHistoryAll` now page and release the same way.

### Added

- **Event history.** An Object or View whose EventNotifier has the HistoryRead bit (Part 3 §5.4, Part 11 §5.4.4) is a HistoricalEventNode: the events reported on it go to the `EventHistoryProvider` of the server — `EmitBaseEvent`, conditions and audit events, also those reported on the Server object and on the other notifiers of an event, as its event items receive them.
  - `Server.EnableEventHistory(notifier, EventHistoryOptions{Writable, Filter})` sets SubscribeToEvents | HistoryRead (| HistoryWrite) and the HistoricalEventFilter Property (Part 11 §5.4.2): its WhereClause selects the events stored, its SelectClauses the fields. Without a filter whole events are stored.
  - `*Historian.EnableEvents(notifier, maxEvents)` keeps up to `maxEvents` events per notifier (default 1000), ordered by Time; a full history drops its oldest event. `RecordEvent` with `NewHistoricalEvent` seeds it.
- **HistoryRead `ReadEventDetails`** (and `ReadEventDetails2` without ReadModified): the time range and its direction (Part 11 §6.5.2.2), `NumValuesPerNode` counting the events the WhereClause passes, the SelectClauses as the fields (`Bad_NoData` for a field the history does not store, null for one the event does not have), `Good_NoData`, session-bound continuation points that resume after the last event returned, so pages stay consistent while events are added or deleted. Fewer than two of NumValuesPerNode / StartTime / EndTime is the service result `Bad_HistoryOperationInvalid`, a filter without SelectClauses `Bad_EventFilterInvalid`. Audit events go to the sessions an `EventAccessController` allows.
- **HistoryUpdate `UpdateEventDetails`** (insert, replace, update; events matched by EventId) **and `DeleteEventDetails`**, with a result per event: `Good_EntryInserted`, `Good_EntryReplaced`, `Bad_EntryExists`, `Bad_NoEntryExists`, `Good_DataIgnored`, `Bad_TypeDefinitionInvalid`, `Bad_SourceNodeIdInvalid`, `Bad_OutOfRange`; `Bad_NoData` for an unknown EventId to delete; `Bad_NotWritable` without the HistoryWrite bit.
- **HistoryServerCapabilities** report what the provider of `SetHistorian` implements: AccessHistoryEventsCapability, Insert/Replace/Update/DeleteEventCapability, and the data capabilities, which were all false before.
- `MaxNodesPerHistoryReadEvents` and `MaxNodesPerHistoryUpdateEvents` are enforced (`Bad_TooManyOperations`).
- **`Node.SetMethodArguments(in, out []*ua.Argument)`** gives a Method node its InputArguments and OutputArguments Properties (Part 3 §5.7: PropertyType, DataType Argument, ValueRank 1, HasProperty) in the namespace of the method, which callers built by hand with `NewNode`. `Client.MethodArguments` reads them and the Call service checks the input arguments against them. The method_server example uses it.
- **client: event history helpers.** `Client.ReadEventHistory(ctx, nodeID, start, end, filter, maxEvents)` returns the field lists of the events of a HistoricalEventNode, following continuation points up to `maxEvents` (0: the whole range); `Client.ReadEventHistoryAll(ctx, nodeID, start, end, filter, pageSize)` is its `iter.Seq2`, with `pageSize` as the NumValuesPerNode of each call. A start after the end reads newest first (Part 11 §6.5.2); `Good_NoData` is an empty result, a Bad status of the node the error (a `ua.StatusCode`). A continuation point the server still holds when a read is truncated, the consumer stops early or `ctx` is done is released (the iteration then ends with `ctx.Err()`).
- **client: `Client.HistoryReleaseContinuationPoints(ctx, details, nodes...)`** releases the continuation points of HistoryRead calls the caller does not continue (`releaseContinuationPoints`, Part 4 §5.10.3) and returns the status of each node, `Bad_ContinuationPointInvalid` for one that is unknown, used, released or of another session. Callers no longer build the `HistoryReadRequest` by hand.
- **ua: `EventFilterBuilder.SelectPaths` and `FieldPath` take `ns:Name` segments**, e.g. `2:Temperature` or `AckedState/2:Note`, as BrowseNames of that namespace, as QualifiedNames are written elsewhere; plain segments stay namespace 0 (`0:Name` for a namespace 0 name that itself starts with digits and a colon).
- API: `server.EventHistoryProvider`, `EventHistoryUpdater`, `EventHistoryDeleter`, `HistoricalEvent`, `NewHistoricalEvent`, `EventHistoryOptions`, `Server.EnableEventHistory`, `Historian.EnableEvents` / `EventsEnabled` / `RecordEvent` / `ReadEvents` / `UpdateEvents` / `DeleteEvents`.

### Changed

- **server: the normal close of a secure channel is logged at Info, not Warn.** A client's CloseSecureChannel, the peer closing its connection and the server shutting down are the expected end of a channel, logged at the level its opening is ("secure channel closed", "context done, closing secure channel"). Protocol, decode and send errors stay Warn / Error.
- **server: `NewVariableNode` gives the DataType of its value and a BrowseName in its own namespace.** The DataType attribute was the VariableNode ObjectType (i=267, read back as the type of the current value) and the BrowseName was in namespace 0. The DataType is now that of the initial value (Part 3 §5.6.2): the built-in type of its Variant (`float64` → Double, `int` → Int32, `[]string` → String), the DataType of a namespace 0 structure, Structure for other structures, BaseDataType for nil; the new ValueRank attribute is Scalar (-1), the number of array dimensions (with ArrayDimensions 0) or Any (-2) for nil. A `ValueFunc` keeps a DataType derived from the value on each read, with ValueRank Any. `NewFolderNode` also puts the BrowseName in the namespace of the node, and AddNodes keeps the namespace of the requested BrowseName. Attributes set with `SetAttribute` override these as before; code that compared a BrowseName of such a node with namespace 0, or formatted it with `Variant.String()` (now `2:Name`), needs the namespace.

### Fixed

- **client: `ReadHistory` and `ReadHistoryAll` handle paging and `Good_NoData` as documented.** `ReadHistory` returned only the first page of a server that pages (its documentation promises up to `maxValues` values, all of them for 0) and left the continuation point open on the server; it now follows continuation points and releases the one of a truncated read. `ReadHistoryAll` left the continuation point open when the loop broke early; it now releases it, also when `ctx` is done between pages. Both returned `Good_NoData` (an empty range on some servers) and a Good result without history as errors; they are now an empty result. Only a Bad status of the node is an error.

- **server: `SetHistorian` while the server runs is race free.** The provider was read by the History services without synchronisation.
- **server: a condition keeps the history bits of its source.** `AddCondition` set the EventNotifier of the source to SubscribeToEvents, dropping HistoryRead and HistoryWrite.
- **server: releasing a history continuation point checks it.** HistoryRead with ReleaseContinuationPoints answered `Good` for any continuation point and released one of another session. A point that is unknown, already used or released, expired, or of another session is now `Bad_ContinuationPointInvalid` (Part 4 §5.10.3) and is left alone.
- **server: `EndPoint` brackets IPv6 literals.** `EndPoint("::1", 4840)` advertised `opc.tcp://::1:4840`, which is not a valid URL (RFC 3986 §3.2.2) for other stacks; with port 0 the bound port was written as `opc.tcp://[::1:0]:<port>`, and a zoned address (`fe80::1%eth0`) did not parse at all. `EndPoint`, `WebSocketEndPoint` and `HTTPSEndPoint` now write `opc.tcp://[::1]:4840`, accept a host given with brackets and escape a zone as `%25` (`fe80::1%eth0` → `[fe80::1%25eth0]`, RFC 6874); the server binds to that zone.

### Tests

- Unit tests of the store (ranges, direction, paging, paging while the history changes, bounds, continuation point expiry, concurrency) and of the services (details checks, per-node results, filters, audit events, capabilities), conformance tests end to end with the go-opcua client, a chaos test paging through the history while events are reported and deleted, reads are abandoned or released, sessions closed and connections dropped, and fuzz tests of the event details and of the store.
- The client event history helpers against a scripted server (paging, truncation, early stop, cancellation before and during a read, malformed results) and end to end against the go-opcua historian, which records the continuation points it hands out and the ones released, so early stop, cancellation and truncation are verified on the server side (a released point no longer continues a read); forward and reverse reads, `Good_NoData`, Bad node statuses, and `SelectPaths` with an `ns:Name` field.

### Interop

- **Pinned opcua-interop v0.17.0** ([release run](https://github.com/otfabric/opcua-interop/actions/runs/40237547159)): every adapter has the client operations `history-read-events` and `history-update-events`, the UA-.NETStandard server the event history fixture `s=History.Events` with HistoryUpdate and `s=History.ResetEvents`, the asyncua server the fixture read only (CLIENT_CONTRACT §17). The full interop suite passes against the new digests.
- **Event history matrix.** The go-opcua interop server serves the same fixture (`EnableEventHistory`, `*Historian`, the five seed events). All six peer clients (open62541, Milo, UA-.NETStandard, node-opcua, asyncua, async-opcua) read it forward and in reverse, page it with continuation points (release and reuse of a consumed point are `Bad_ContinuationPointInvalid`), filter by OfType and Severity, and insert, replace, update and delete events with the expected operation results (`Bad_NoData` for an unknown EventId to delete, Part 11 §6.9.7.2). The go-opcua client reads, pages, filters, updates and deletes the UA-.NETStandard 2.0.1 fixture with `ReadEventHistory`, `ReadEventHistoryAll`, `HistoryReleaseContinuationPoints`, `HistoryUpdateEvents` and `HistoryDeleteEvents`, and reads the asyncua 2.1.0 fixture with its deviations asserted (inclusive range ends, `Good` for an empty range, stateless continuation points, OfType without subtypes); asyncua's refusal of HistoryUpdate (`Bad_UserAccessDenied`) is pinned.
- New capabilities `history.read.events.continuation`, `history.read.events.filter` and `history.delete.events` in every ledger; `history.read.events` and `history.update.events` leave `deferred`: verified in the directions above, `unsupported` towards the open62541, Milo and async-opcua servers (no event history server) and the node-opcua server (variables only). No go-opcua defect was found.

---

## v1.25.0

**Date:** 2026-10-25
**Previous release:** v1.24.0

### Summary

The UA JSON mappings of HTTPS and WebSockets, client and server: https-uajson (Part 6 §7.4.5) and wss-uajson (Part 6 §7.5.2). `server.EnableUAJSON` serves them on the opc.https and opc.wss listeners; the client uses them with `opcua.TransportProfile`, which `SecurityFromEndpoint` sets from a JSON endpoint.

### Added

- **https-uajson.** Each request is an HTTPS POST of a JSON message (Part 6 §5.4.9, the UaTypeId followed by the fields, compact form) with `Content-Type: application/json` (Part 6 §7.4.2 Table 80). The server also takes `application/opcua+uajson`, which UA-.NETStandard sends, answers with the request's content type, and inflates gzip bodies (the size limit applies after inflating). The security policies are those of https-uabinary, named in the `OPCUA-SecurityPolicy` header.
- **wss-uajson.** A WebSocket with the sub-protocol `opcua+uajson` carries one JSON message per WebSocket message (text frames), without HEL/ACK or secure conversation. A message over the limit closes with 1009, invalid UTF-8 with 1007. Only None / None: a WebSocket cannot name a policy.
  - The server serves up to 64 requests of a connection at the same time and answers them as they complete; the RequestHandle correlates them.
  - The client keeps a pool of WebSockets with one request in flight each, so it also works with servers that answer one request per socket at a time (UA-.NETStandard), and checks the RequestHandle of each response.
- **Endpoints.** The JSON endpoints are advertised next to the binary ones, at the same URLs, with the TransportProfileUris `ua.TransportProfileHTTPSJSON` and `ua.TransportProfileWSSJSON`. `SelectEndpointForTransport` selects them; `SelectEndpoint` prefers UA Binary.
- NodeIds of other namespaces than 0 are written with their namespace URI (Part 6 §5.4.2.10). Requests in the verbose and the 1.04 forms are decoded too.
- API: `opcua.TransportProfile`, `opcua.HTTPSJSONContentType` (with `uasc.Config.HTTPSJSONContentType`), `server.EnableUAJSON`, `ua.IsJSONTransportProfile`, `ua.TransportProfileScheme`, `uasc.NewHTTPSJSONChannel`, `uasc.NewWebSocketJSONChannel`, `uasc.EncodeServiceMessageJSON` / `DecodeServiceMessageJSON`, `uacp.MessageConn`, `Dialer.DialWebSocketJSON`, `Listener.ServeWebSocketJSON`.

### Tests

- End-to-end over both JSON transports (GetEndpoints, sessions, read, write, browse, call, subscriptions), conformance tests of the endpoints, policies, user names, content types and sub-protocols, chaos tests (many clients through faulty proxies, hostile WebSocket messages and HTTP bodies) and fuzz tests of the WebSocket message reader, the JSON service messages and the server's JSON bodies.

### Interop

- **UA-.NETStandard 2.0.1 server over wss-uajson and https-uajson** (`TestDotnetServer_Transport_WSSJSON`, `TestDotnetServer_Transport_HTTPSJSON`), on the JSON endpoints it advertises at the security mode None. UA-.NETStandard takes JSON over HTTPS only as `application/opcua+uajson`, which the client sends with `opcua.HTTPSJSONContentType(uasc.HTTPSJSONContentTypeLegacy)` ([client guide](docs/client-guide.md#ua-json-https-uajson-wss-uajson)). No other peer stack implements either mapping.
- New capabilities `transport.wss-uajson` and `transport.https-uajson` in every ledger: verified go-opcua client → UA-.NETStandard server; the UA-.NETStandard adapter client selects UA Binary endpoints only (unverified, `adapter-command-missing`); open62541 1.5.9, Milo 1.1.8, node-opcua 2.187, asyncua 2.1.0 and async-opcua 0.19.0 implement neither mapping (unsupported).
- **Pinned opcua-interop v0.16.0** ([release run](https://github.com/otfabric/opcua-interop/actions/runs/40222483139)): the asyncua client passes the leaf of a server certificate chain and browses with the null ViewDescription, the dotnet and dotnet-gds servers take `--no-certificate-chain`, and the async-opcua trust list check takes the leaf of a chain. No ledger row changes.

---

## v1.24.0

**Date:** 2026-10-25
**Previous release:** v1.23.1

### Summary

opcua-interop v0.15.0 is pinned: every peer client adapter has push management and GDS pull, so the interop ledgers go from 212 unverified rows to 6. Session signatures follow Part 4 §6.1.8 for certificate chains, `Server.Session` returns the exported handle, and QueryFirst checks its type definitions.

### Changed

- **server: `Server.Session(hdr)` returns the exported `*server.Session`.** It returned the unexported `*session`, which no caller outside the package could use. `Session(nil)` is nil instead of a panic.

### Fixed

- **Session signatures cover the leaf of a certificate chain** (Part 4 §6.1.8, legacy signature method). A peer may send its certificate followed by its issuers (UA-.NETStandard does by default).
  - The client signed ClientSignature and the X.509 user token signature over the whole chain, and the server signed ServerSignature over the client's whole chain. Both now sign over the leaf, which every stack accepts.
  - The server verifies ClientSignature and UserTokenSignature over the leaf first, then over the chain as sent, the order §6.1.8 gives.
  - The channel-bound method of the ECC AEAD policies already used the leaf.
- **server: an X509IdentityToken may carry a certificate chain.** ActivateSession refused it with Bad_IdentityTokenInvalid; the alarm audit events and the session diagnostics showed "X509" instead of the subject. `uapolicy.LeafCertificate` returns the leaf of a chain.
- **server: QueryFirst reports a type definition that is no type node.** A NodeTypeDescription whose TypeDefinitionNode is unknown or not an ObjectType or VariableType gets Bad_TypeDefinitionInvalid in its ParsingResult (Part 4 §5.9.3); only the null NodeId did. Found by the async-opcua query client.
- **pubsub: `DiscoverAction` returns with its response counted.** DiscoveryResponsesReceived was counted after the ActionMetaData was handed to the waiter, so counters read right after `DiscoverAction` could miss it.

### Tests

- **The root package tests run in parallel** (`t.Parallel()` in 235 tests), which takes the package well under the CI limit. The tests that swap package-level hooks stay serial.
- Chain tests on both sides with a CA-issued certificate: the signatures cover the leaf, both forms verify, a wrong nonce, data or key is refused.
- **Interop harness:** the codec runs of the peers are named containers, stopped on timeout and retried once when they produced no output.

### Interop

- **Pinned opcua-interop v0.15.0** ([release run](https://github.com/otfabric/opcua-interop/actions/runs/40217588999)): the seven adapters by their new digests, dotnet-gds on UA-.NETStandard 2.0.1 (Opc.Ua.Gds.Server / .Gds.Client).
- **Push management and GDS pull from every peer client.** `client push` with the Part 12 1.05 flags (certificate groups, CreateSelfSignedCertificate, DeleteCertificate, the HTTPS and UserToken groups, PFX, TransactionDiagnostics) and `client gds-pull` against the go server, from open62541, Milo, asyncua, async-opcua and UA-.NETStandard (`TestCertMgmtPushExt_<Peer>Client_GoServer`, `TestGDSPull_<Peer>Client_GoServer`). node-opcua's push client gets the same flags and `client query`.
- **UA-.NETStandard server:** the Part 9 1.05 alarm methods, dialog, branches, alarm groups and audible sound (`TestDotnetServer_Alarms105`), condition audit events with `--auditing` (`TestDotnetServer_AlarmAudit`), CreateSelfSignedCertificate on an empty certificate slot. UA-.NETStandard 2.0.1 has no handler for TimedShelve2 and Respond2.
- **UA-.NETStandard GDS 2.0.1:** the ECC CA's CRL is well formed and CheckRevocationStatus reads it (`Bad_CertificateRevoked`); the test no longer reads a malformed CRL.
- **Push management through each peer's generic `client call`,** condition audit events from node-opcua, UA-.NETStandard PubSub keep-alive and receive timeout, multicast in both directions with UA-.NETStandard (multicast loopback since v0.15.0).
- **Ledgers:** 97 rows settled from the peer sources and 76 promoted with v0.15.0. Unverified: `coverage.json` 0, async-opcua 0, asyncua 0, UA-.NETStandard 2 (PubSub reader state), node-opcua 4 (no GDS pull client).
- [docs/interop-gaps.md](docs/interop-gaps.md): the UA-.NETStandard 2.0.1 GDS, a pushed trust list with the 1.5.378 ECC CRL.

---

## v1.23.1

**Date:** 2026-10-25
**Previous release:** v1.23.0

### Summary

Fixes found by the 25-run hardening batch of v1.23.0: subscription recovery after a reconnect, a data race between two activations of one session, and the error of a PFX whose decryption password is wrong.

### Fixed

- **client: a reconnect that creates a new session no longer recreates the subscriptions it has just transferred.** After the transfer, the Publish request still waiting in the old session is answered with Bad_NoSubscription. The client took that for its current session and marked the subscriptions broken; they were recreated with new ids and lost their notification history. Bad_NoSubscription for a session the client has left is now ignored, like the other errors of such a session.
- **client: no false retransmission gap.** The recovery reported an unrecoverable gap (or a partial recovery) when the server's available sequence numbers were all below the next one the client expects: those are messages the client has received but not yet acknowledged. A gap is now reported only when the server holds later messages but not the next one (serial number comparison, so wrap-around is handled).
- **client: the activations of a session take turns.** The reconnect logic and the application could activate the same session at the same time and both read and wrote its server nonce and ephemeral key (a data race). Each activation uses the nonce the previous one brought.
- **server: Good_SubscriptionTransferred is queued before the subscription leaves the session** (Part 4 §5.13.7). A Publish request of the old session that came in during TransferSubscriptions could get Bad_NoSubscription instead.
- **server: an HTTPS request whose client has already gone away is not served.** The request reached the service handlers when the select between handing it over and the ended context picked the hand-over.
- **uapolicy: decrypted PFX contents that do not parse are `ErrPFXPassword`** ("wrong PFX password or corrupt PFX"), also with a verified MAC. A wrong decryption password gives valid padding about 1 in 256 times; the MAC covers the ciphertext, and a PFX may use another password for encryption than for its MAC (`openssl pkcs12 -twopass`). It used to report a malformed key.

### Tests

- Regression tests for each fix:
  - `TestActivateSessionConcurrent`
  - `TestPublish_NoSubscriptionOfLeftSession`
  - `TestRetransmissionGap`
  - `TestTransferSubscriptions_PublishDuringTheTransfer`
  - the twopass case of `TestParsePFX_Structures`, now deterministic
- **Test servers bind port 0 themselves:** a port chosen first could be taken by a parallel test before the server bound it.
- **`TestRecovery_ServerRestart`:** the restarted server gets its fixture before it starts, so the fixture keeps its namespace index; the diagnostics namespace is created with the first session.
- **`TestReverseConnect_AutoReconnectAfterServerRestart`:** the reverse-connect servers get their fixture before they start (`conformkit.NewServerPrepared`), for the same reason.
- **AMQP test broker streams a delivery within the session window** (AMQP 1.0 §2.5.6). It sent a delivery only when all its frames fitted in the client's incoming window, so a message larger than the window stalled until a test timed out. `TestSessionWindowReopens` now uses a 64-frame window (an internal `SessionWindow` option of the AMQP client and the broker) and runs in milliseconds instead of transferring 17 MB.
- **`TestServerRestartOnSamePort`:** the fixed port comes from `testport` (outside the ephemeral range, free on IPv4 and IPv6), and the server and client use 127.0.0.1: "localhost" may resolve to ::1 first, where a parallel package can listen on the same port.
- **Failure diagnostics:** the recovery tests report the recorded states and events when they fail.

### Interop

- opcua-interop v0.14.0 (unchanged).

---

## v1.23.0

**Date:** 2026-10-25
**Previous release:** v1.22.0

### Summary

Custom access controllers can be written outside package `server`, and the documentation is brought up to date with the stack.

### Changed

- **server: `AccessController` and `EventAccessController` take an exported `*server.Session`.**
  - They took the unexported `*session`, so no package outside `server` could implement them, although the guides described them as pluggable.
  - `server.Session` is a read-only handle of the session: `ID`, `Identity`, `Roles` and `ClientCertificate`. It does not expose the AuthenticationToken or the nonces.
  - A nil `*Session` is a request without a session.
  - An implementation outside the package needs only the new parameter type; `DefaultAccessController` and `RBACAccessController` are unchanged otherwise.

### Documentation

- **API.md:** a table of contents for every section; signatures checked against the code (methods that do not exist removed); PubSub Actions and AMQP; the remaining server options; `ReportAuditEvent`; `Session`.
- **README:** interop evidence counts recomputed from the ledgers; `make interop` runs the six pinned peers; GDS and PubSub examples; the conformance packages.
- **INTEROP.md:** the seven adapters of opcua-interop v0.14.0, an Alarms & Conditions section, push management evidence, current ledger totals.
- **docs:**
  - architecture, client and server guides, security, and interop gaps follow the transports, ECC, GDS and diagnostics;
  - the HTTPS endpoints exclude only the policies with SecureChannelEnhancements.
- **OBSERVABILITY, CONTRIBUTING, ERRORS:** server diagnostics, audit events, adding an interop capability, and the errors of the server and the GDS.

### Tests

- `conformance/addrspace`: a controller of another package that sees the SessionId, identity and roles of the request.
- `server`: unit tests of the handle.

### Interop

- opcua-interop v0.14.0 (unchanged).

---

## v1.22.0

**Date:** 2026-10-25
**Previous release:** v1.21.0

### Summary

The rest of the GDS pull model (Part 12 v1.05 §6, §7.9): signing requests of every key type, PFX keys, the HTTPS and user token certificate groups, the audit events of the Directory, the RolePermissions of the GDS NodeSet and a persistent store. The pull model is verified against the Global Discovery Server and the GDS client of UA-.NETStandard 1.5.378.182.

### Added

- **gdsserver: signing requests of every key type.** StartSigningRequest takes RSA, NIST P-256 / P-384, Brainpool P-256r1 / P-384r1, Ed25519 and Ed448 requests (uapolicy parses and checks them). The Brainpool types have Brainpool CAs, and their CRLs are signed with them.
- **gdsserver: PFX private keys.** StartNewKeyPairRequest delivers the key as PEM or PFX (PKCS #12 with the certificate and its issuer, `uapolicy.EncodePFX`). `gds.EnrollRequest` and `gds.DecodePrivateKey` handle PFX.
- **gdsserver: the HTTPS and user token certificate groups.** The DefaultHttpsGroup issues HttpsCertificateType certificates (RSA, P-256 and P-384 CAs); the DefaultUserTokenGroup serves a trust list of its own. GetCertificateGroups, GetCertificates, GetTrustList and GetCertificateStatus answer per group.
- **gdsserver: audit events.** The Directory methods report the audit events of the GDS NodeSet through the server's auditing, without passwords and private keys.
- **gdsserver: RolePermissions.** The RolePermissions of the GDS NodeSet are honoured besides the checks of the handlers.
- **gdsserver: `NewFileStore`** keeps the GDS state in a directory (atomic writes, 0600 files).
- **server: `ReportAuditEvent`** reports the audit event of an application method to the Server object and the given notifiers, filtered by the EventAccessController like the server's own audit events.

### Fixed

- **server: Call with the MethodId of the InstanceDeclaration.** A Method of the ObjectType of an Object (or of a supertype), called on the Object, is the Method of the Object with that BrowseName (Part 4 §5.11.2.2). It answered Bad_MethodInvalid; UA-.NETStandard's GDS client reads a TrustList that way.
- **server: the NodeSet importer keeps RolePermissions that name the role by NodeId** (`i=15704`, `ns=1;i=1661`). It kept only those that named a well-known role.

### Tests

- Conformance (`conformance/certmgmt`: the three certificate groups, a request lifecycle, the HTTPS group, Brainpool, PFX, a FileStore and the audit events over the wire), chaos (`chaos/gdspull`) and unit tests.
- Interop: the eight `gds.pull.*` rows of UA-.NETStandard are verified in both directions against the new opcua-interop adapter dotnet-gds (`TestDotnetGDSPull_GoClient_DotnetServer`, `TestDotnetGDSPull_DotnetClient_GoServer`). The Interop workflow pulls its image.

### Interop

- Pinned opcua-interop v0.14.0: the six adapters by their new digests, plus the dotnet-gds adapter (`sha256:7c2fc3d6…`, UA-.NETStandard 1.5.378.182 GDS).

---

## v1.21.0

**Date:** 2026-10-25
**Previous release:** v1.20.0

### Summary

The rest of push certificate management (Part 12 v1.05 §7): DeleteCertificate and certificate groups defined by the application. PFX files in BER encoding are accepted.

### Added

- **server: DeleteCertificate** (Part 12 v1.05 §7.10) on the ServerConfiguration. It is part of the transaction and needs SecurityAdmin over SignAndEncrypt.
  - At ApplyChanges, these deletions are refused with Bad_InvalidState and recorded in the TransactionDiagnostics:
    - the certificate the endpoints use;
    - the HTTPS certificate, while there are opc.https or opc.wss endpoints.
  - Deleting and then creating or updating a certificate in the same transaction replaces it.
  - `CertificateDeleteStore` persists deletions. ResetToServerDefaults removes certificates the server did not start with.
- **server: certificate groups of the application** (`PushManagement.CertificateGroups`).
  - Each group has its own TrustList, CertificateTypes and certificates.
  - The groups take part in the transactions, GetCertificates, CreateSigningRequest, UpdateCertificate, CreateSelfSignedCertificate, DeleteCertificate, ResetToServerDefaults and the certificate alarms.
  - New: `Server.CertificateGroupID`, `GroupCertificate` and `VerifyGroupCertificate`.
- **gds:** `Client.DeleteCertificate` and `Client.CertificateGroups`.
- **uapolicy: `ParsePFX` reads PKCS #12 files in BER encoding** (indefinite lengths, constructed OCTET STRINGs), as Java keytool writes them. RC4 and the public-key integrity and privacy modes are refused on purpose.

### Tests

- Unit, e2e, conformance and chaos tests (the certificate-management churn adds deletions and application groups).
- The server and root packages are above 90% coverage with their own tests: discovery registration and SelectEndpoint are now covered there.
- Interop: DeleteCertificate verified against UA-.NETStandard; open62541 and node-opcua do not serve it.
- **The conformance suite is split into packages:** addrspace, alarms, certmgmt, discovery, history, pubsub, security, session, subscription and transport, next to the root package and eccext. CI gives every package 120 s under the race detector, and the single package had reached 114 s. The packages share their helpers through `internal/testutil/conformkit`.

### Interop

- opcua-interop v0.13.0 (unchanged).

---

## v1.20.0

**Date:** 2026-10-25
**Previous release:** v1.19.0

### Summary

The last parts of Alarms & Conditions (Part 9 v1.05): OnDelay / OffDelay, re-alarming, AudibleSound, FirstInGroup and AlarmMetrics, with an injectable clock for the alarm timers.

### Added

- **server: OnDelay / OffDelay.** An activation, or a return to normal, is reported only once it has lasted the delay. A shorter excursion is never reported, and an activation during OffDelay cancels the return to normal. `ConditionState.PendingActive` and `PendingInactive` show a running delay.
- **server: ReAlarmTime / ReAlarmRepeatCount.** An alarm that stays active is annunciated again and counted. It then needs a new acknowledgement, its silence ends, it latches, and it gets a branch when `Branching` is on.
- **server: AudibleEnabled and AudibleSound** (AudioVariableType) with `ConditionConfig.AudibleSound` and `ConditionUpdate.AudibleEnabled`.
- **server: FirstInGroupFlag and the FirstInGroup object** with `ConditionConfig.FirstInGroup`.
- **server: AlarmMetricsType** (`Server.AddAlarmMetrics`, `AlarmMetrics`, `RemoveAlarmMetrics`), for the whole server or one alarm group:
  - alarm count and start time;
  - maximum active time, maximum unacknowledged time and maximum re-alarm count;
  - current, maximum and average alarm rates;
  - a Reset method, audited.
- **server: `WithAlarmClock`.** An injectable clock (`server.Clock`) for the shelving, delay and re-alarm timers.
- **client:**
  - `ReadAlarmMetrics` and `ResetAlarmMetrics`.
  - `ConditionEvent` reports AudibleEnabled, ReAlarmRepeatCount and FirstInGroupFlag. Event lists without these fields still parse.

### Changed

- **server: an alarm annunciated again while it is still unacknowledged or unconfirmed keeps the transition time of its AckedState and ConfirmedState.** The unacknowledged time is therefore counted from the first annunciation. When the occurrence moves to a branch, the new occurrence starts fresh.

### Tests

- Unit, e2e and conformance tests on a manual clock, without sleeps. The chaos test drives concurrent activations, clock advances, acknowledgements, silencing and metrics resets while connections drop.
- Interop: the open62541, Eclipse Milo, UA-.NETStandard, node-opcua, asyncua and async-opcua clients against the Go server. New ledger capabilities: `alarms.alarm-timing`, `alarms.audible-sound`, `alarms.first-in-group` and `alarms.alarm-metrics`.

### Interop

- opcua-interop v0.13.0 (unchanged).

---

## v1.19.0

**Date:** 2026-10-25
**Previous release:** v1.18.0

### Summary

The pull model of certificate management (Part 12 v1.05 §6 and §7.9): a Global Discovery Server that keeps an application directory and issues certificates, and a client that enrolls with it.

### Added

- **gds/gdsserver: a Global Discovery Server.** `Attach(srv, Config)` adds the `Directory` object (CertificateDirectoryType) in the GDS namespace.
  - Directory: FindApplications, RegisterApplication, UpdateApplication, UnregisterApplication (which revokes the application's certificates), GetApplication, QueryApplications and QueryServers.
  - Certificate requests: StartSigningRequest, StartNewKeyPairRequest and FinishRequest. A request waits for `GDS.ApproveRequest` unless `AutoApprove` is set; `MaxRequests` and `RequestLifetime` apply.
  - Revocation and trust: RevokeCertificate, GetCertificateGroups, GetCertificates, GetTrustList, GetCertificateStatus and CheckRevocationStatus.
  - A CA per key type (RSA, NIST P-256 and P-384, Curve25519, Curve448), generated or given. It issues certificates and CRLs, and re-signs the CRL on every revocation and before its NextUpdate.
  - The DefaultApplicationGroup TrustList holds the CA certificates and their CRLs.
  - Access:
    - Directory queries are open.
    - Registration needs DiscoveryAdmin.
    - Certificate requests, revocation and the trust list need CertificateAuthorityAdmin over SignAndEncrypt, or the application itself.
    - Writing the TrustList needs SecurityAdmin.
  - Storage is a pluggable `Store` (`NewMemoryStore`). A GDS attached again to the same Store continues where it stopped, and `GDS.Close` refuses later calls with Bad_Shutdown.
- **gds: `PullClient`** with every Directory and CertificateDirectory method, plus `WaitForCertificate`, `ReadTrustList` and `NewCertificateRequest`.
  - `Enroll` finds or registers the application, requests a certificate, waits for it and reads the trust list.
  - `Enrollment.ClientOptions` and `ServerOptions` configure an `opcua.Client` or a `server.Server` with the result.
- **gds/gdsid:** NodeIds of the GDS information model (Part 12 v1.05.07).
- **server:** `ServeTrustList` serves a TrustList object on any node. Also new: `Node.SetValueFunc` and `MethodCaller.ClientCertificate`.
- **ua:** `ExtensionObject.RawBody` keeps the binary body of an ExtensionObject whose type is not registered.
- **examples/gds-pull:** a GDS that enrolls a server and a client, which then connect.

### Not implemented

- In the GDS: CSRs with Brainpool or Ed448 keys (StartNewKeyPairRequest serves these types), PFX private keys, the DefaultHttpsGroup and DefaultUserTokenGroup of the directory, GDS audit events, the RolePermissions of the GDS NodeSet, and a file-based Store.

### Tests

- Unit, e2e and conformance tests, and chaos tests (a GDS restarted in the middle of a request, churn of registrations, requests and revocations).
- Interop: new ledger capabilities `gds.pull.*`. They are unverified: the peer stacks of opcua-interop have no GDS, and the UA-.NETStandard GDS packages have no release for the adapter's version.

### Interop

- opcua-interop v0.13.0 (unchanged).

---

## v1.18.0

**Date:** 2026-10-25
**Previous release:** v1.17.0

### Summary

The rest of push certificate management (Part 12 v1.05 §7): the HTTPS and UserToken certificate groups, GetCertificates, CreateSelfSignedCertificate, ResetToServerDefaults, TransactionDiagnostics, certificate alarms and PFX private keys. Also signing requests and CRLs for Brainpool and Ed448 keys.

### Added

- **server: DefaultHttpsGroup and DefaultUserTokenGroup** under `WithPushManagement`, each with its own TrustList and CertificateTypes and part of the same transaction.
  - The HTTPS group's certificate is the TLS certificate of opc.https and opc.wss, swapped at ApplyChanges.
  - `HTTPSClientCertificates` (Ignore, VerifyIfGiven, Require) checks TLS client certificates against the HTTPS trust list.
  - The UserToken trust list checks X.509 user tokens before any `WithX509UserValidator`; rejected tokens go to GetRejectedList.
  - New API: `Server.GroupTrustList`, `Server.HTTPSCertificate`, `CertificateGroupStore`.
- **server: GetCertificates, CreateSelfSignedCertificate and ResetToServerDefaults** (Part 12 v1.05 §7.10).
  - A self-signed certificate carries the ApplicationUri and takes effect at ApplyChanges.
  - The reset restores the starting trust lists and certificates. It returns Bad_TransactionPending while another session has a transaction.
- **server: TransactionDiagnostics:** start and end time, result, affected trust lists and groups, and errors. Only SecurityAdmin may read them.
- **server: CertificateExpired and TrustListOutOfDate alarms** of the certificate groups. They are configured with `PushManagement.Alarms` (expiration limit, check interval) and `TrustListUpdateFrequency`.
- **server: UpdateCertificate takes PFX (PKCS #12) private keys.** The password comes from `PushManagement.PFXPassword`; a wrong one is refused with Bad_SecurityChecksFailed.
- **server: CreateSigningRequest for Brainpool, Ed25519 and Ed448 keys.**
- **gds:** `GetCertificates`, `CreateSelfSignedCertificate`, `ResetToServerDefaults`, `TransactionDiagnostics`, `WithTrustList`, and the NodeIds of the HTTPS and UserToken groups and trust lists.
- **uapolicy:** for Brainpool and Ed448 keys:
  - certificate requests: `CreateCertificateRequest`, `ParseCertificateRequest`, `CheckCertificateRequestSignature`;
  - CRLs: `CreateRevocationList`, `ParseRevocationList`, `CheckRevocationListSignature`.

  New PFX encoding and decoding: `ParsePFX` and `EncodePFX` (PBES2 and the PKCS #12 PBEs, HMAC or PBMAC1 integrity).

### Fixed

- **server: trust lists accept CRLs issued by Brainpool and Ed448 CAs.** They used to be rejected because Go's x509 cannot verify their signatures.

### Not implemented

- DeleteCertificate, application-defined certificate groups, and the GDS pull model (Part 12 §6).
- PFX files with BER indefinite lengths.

### Tests

- Unit, e2e, conformance and chaos tests. The chaos churn adds resets, self-signed HTTPS certificates, writes to the HTTPS and UserToken trust lists, and alarm evaluation.
- Interop with the Go client against the peer servers:
  - UA-.NETStandard: GetCertificates, TransactionDiagnostics, the HTTPS and UserToken groups, PFX and the alarms.
  - open62541 and node-opcua: the UserToken trust list.
- New ledger capabilities `certmgmt.push.*`.

### Interop

- opcua-interop v0.13.0 (unchanged).

---

## v1.17.0

**Date:** 2026-10-25
**Previous release:** v1.16.0

### Summary

The rest of Alarms & Conditions (Part 9 v1.05): the OutOfService, Silence and Latched states with their methods, Suppress / Unsuppress, Reset, every `*2` method variant, dialogs, condition branches, alarm groups and condition audit events.

### Added

- **server: alarm states and methods.**
  - `ConditionConfig.Serviceable` adds OutOfServiceState with RemoveFromService / PlaceInService.
  - `ConditionConfig.Silenceable` adds SilenceState with Silence; it is cleared when the alarm becomes active again.
  - `ConditionConfig.Latching` adds LatchedState with Reset. Resetting an active alarm returns Bad_InvalidState.
  - A `Suppressible` alarm gets Suppress / Unsuppress. SuppressedOrShelved is true when the alarm is suppressed, shelved or out of service.
  - Every `*2` variant that takes a Comment is served: Suppress2, Unsuppress2, RemoveFromService2, PlaceInService2, Reset2, TimedShelve2, OneShotShelve2 and Unshelve2.
  - A call for the state the alarm is already in returns Good and sends no event. A method the condition is not configured for returns Bad_MethodInvalid.
  - New hooks: `OnSuppress`, `OnService`, `OnSilence` and `OnReset`.
- **server: DialogConditionType.** `ConditionConfig.Dialog` (DialogConfig), Respond and Respond2, `ShowDialog`, `CloseDialog` and `OnRespond`. Calls are refused with Bad_DialogNotActive or Bad_DialogResponseInvalid.
- **server: condition branches.**
  - With `ConditionConfig.Branching`, an alarm that becomes active again while its previous occurrence is unacknowledged or unconfirmed gets a branch. Branches can also be managed directly: `Condition.CreateBranch`, `Branches`, `Branch`, `DeleteBranch`, and `BranchIDFromContext`.
  - Acknowledge and Confirm accept a branch's EventId. A branch that needs no more action sends a last event with Retain false and is deleted.
  - ConditionRefresh delivers retained branches after their condition.
  - A condition has at most 256 branches (`ErrTooManyBranches`).
- **server: alarm groups.**
  - AlarmGroupType and AlarmSuppressionGroupType (`Server.AddAlarmGroup`, `AlarmGroup.SetSuppressing` / `Evaluate`).
  - `ConditionConfig.SuppressionGroups` and GetGroupMemberships on every alarm.
- **server: condition audit events.** AuditConditionEventType and its Enable, Comment, Respond, Acknowledge, Confirm, Shelving, Suppression, Silence, Reset and OutOfService subtypes, also for refused calls.
  - They are off by default and turned on with `WithAuditing` / `SetAuditing`. Server/Auditing follows the setting.
  - The new `EventAccessController` decides who receives them. `RBACAccessController` implements it with the ReceiveEvents permission.
- **client:**
  - New methods: `Suppress(2)`, `Unsuppress(2)`, `RemoveFromService(2)`, `PlaceInService(2)`, `Silence`, `Reset(2)`, `TimedShelve2`, `OneShotShelve2`, `Unshelve2`, `Respond(2)` and `GetGroupMemberships`.
  - New audit helpers: `NewAuditConditionEventFilter`, `ParseAuditConditionEvent`, and `WithAuditEntryID` (sets ClientAuditEntryId).
  - `NewConditionEventFilter` also selects SuppressedState, OutOfServiceState, SilenceState, LatchedState, DialogState, Prompt and LastResponse. These fields are nil when a server does not report them; event lists in the old layout still parse.
  - New: `ConditionEvent.IsBranch`.

### Fixed

- **server: a session's last activity could move backwards.** A request that read the clock before another one but recorded the time after it took the activity back, so a session in use could time out. The activity time now only moves forward.

### Not implemented

- Part 9 v1.05: AudibleSound, OnDelay / OffDelay, ReAlarmTime, FirstInGroup, AlarmMetrics.

### Tests

- Unit, e2e, conformance and chaos tests (concurrent branch creation, acknowledgement and refresh).
- Interop: the open62541, Eclipse Milo, UA-.NETStandard, node-opcua, asyncua and async-opcua clients against the Go server. New ledger capabilities: `alarms.alarm-state-methods`, `alarms.dialog`, `alarms.branches`, `alarms.alarm-groups` and `alarms.audit-events`.

### Interop

- opcua-interop v0.13.0 (unchanged).

---

## v1.16.0

**Date:** 2026-10-25
**Previous release:** v1.15.0

### Summary

Certificate management by the Part 12 push model (§7), on the server and in a new `gds` client package.

### Added

- **server: `WithPushManagement`.** ServerConfiguration (i=12637) with the DefaultApplicationGroup TrustList (Open, OpenWithMasks, Read, Write, Close, CloseAndUpdate, AddCertificate, RemoveCertificate, LastUpdateTime, UpdateFrequency), CertificateTypes, UpdateCertificate, CreateSigningRequest (RSA and ECC), GetRejectedList, and ApplyChanges / CancelChanges: changes are a transaction of the calling session that ApplyChanges applies. New channels and sessions are validated against the trust list (issuers, CRLs, size limits); after ApplyChanges new channels use the new application instance certificate and open ones keep theirs. Only SecurityAdmin over SignAndEncrypt may call the methods. An optional `CertificateStore` persists the trust list and the certificate.
- **`gds` package:** a push client for the trust list, signing requests, certificate updates, the rejected list and ApplyChanges / CancelChanges.

### Fixed

- **server: the session a subscription is transferred from gets a StatusChangeNotification with Good_SubscriptionTransferred** (Part 4 §5.13.7), with its queued Publish request or its next one; its other queued Publish requests are answered with Bad_NoSubscription when it has no subscription left. It used to get a keep-alive.
- **client: a subscription that another session took over is forgotten** when Good_SubscriptionTransferred arrives from the session the client had put it in; the client used to see Bad_NoSubscription next and recreate it, so the subscription existed twice. The notification from a session the client moved the subscription out of itself (its reconnect, or the application) changes nothing, also when that session is used again later.
- **server: a subscription that is transferred back to a session before that session's next Publish request is not announced to it as transferred.**
- **RELEASE.md v1.13.0** said that `opc.https` supports the non-ECC policies: it supports SecurityPolicy None and every policy without SecureChannelEnhancements, including ECC_nistP256, ECC_nistP384, ECC_curve25519, ECC_curve448 and the two Brainpool policies (`uasc.HTTPSPolicySupported`).

### Not implemented

- The pull model (a GDS that issues certificates), GetCertificates, CreateSelfSignedCertificate, ResetToServerDefaults, the HTTPS and UserToken certificate groups, certificate expiration alarms, TransactionDiagnostics, PFX private keys, signing requests for Brainpool and Ed448 keys, CRLs of Brainpool or Ed448 CAs.

### Tests

- Unit, fuzz, e2e, conformance and chaos tests (invariants of concurrent trust list and certificate changes).
- Interop: the Go client against the open62541, UA-.NETStandard and node-opcua servers, and the node-opcua push client against the Go server (opcua-interop v0.13.0); ledger capabilities `certmgmt.push.*`.

### Interop

- Pinned opcua-interop v0.13.0.

---

## v1.15.0

**Date:** 2026-10-25
**Previous release:** v1.14.0

### Summary

Live server diagnostics (Part 5 §6.3.3): ServerDiagnosticsSummary, the diagnostics arrays and a SessionDiagnosticsObject per session, and DiagnosticInfo in responses when a request asks for it.

### Added

- **server: `Server.ServerDiagnostics` is live.** ServerDiagnosticsSummary counts current and cumulated sessions and subscriptions, rejected and security-rejected sessions and requests, session timeouts and publishing intervals; SamplingIntervalDiagnosticsArray, SubscriptionDiagnosticsArray, SessionDiagnosticsArray and SessionSecurityDiagnosticsArray are filled; every session gets a SessionDiagnosticsObject (namespace `urn:otfabric:go-opcua:diagnostics`) with its SessionDiagnostics (per-service request counters), SessionSecurityDiagnostics, SubscriptionDiagnosticsArray and CurrentRoleIds.
- **server: EnabledFlag** is writable by SecurityAdmin and ConfigureAdmin; enabling resets the counters. `WithServerDiagnostics(false)` starts with diagnostics off; `Server.ServerDiagnosticsSummary`, `ServerDiagnosticsEnabled` and `SetServerDiagnosticsEnabled`. A session's object is readable by the session itself, SecurityAdmin and ConfigureAdmin; SessionSecurityDiagnosticsArray by SecurityAdmin over SignAndEncrypt.
- **server: DiagnosticInfo** for the requests that set `ReturnDiagnostics`: service diagnostics on a fault and per-operation diagnostics, with the string table.
- **client:** the `ReturnDiagnostics` option, `*ServiceError` (the status code with its resolved diagnostic), and typed reads `ServerDiagnosticsSummary`, `ServerDiagnosticsEnabled`, `SetServerDiagnosticsEnabled`, `SessionDiagnostics`, `SessionSecurityDiagnostics`, the `...Of` variants, `SubscriptionDiagnostics` and `SamplingIntervalDiagnostics`; `Subscription.Stats` now returns the server's values. **ua:** `Diagnostic`, `DiagnosticInfo.Resolve`, `ResponseHeader.ServiceDiagnostic` and `Diagnostic`.

### Fixed

- **server: a data race between `AddNamespace` and `Server.Node`.** Node now reads an immutable view of the namespaces that AddNamespace publishes.

### Tests

- Unit, e2e and conformance tests (summary, rejected sessions, session objects, subscriptions, EnabledFlag, disabled diagnostics, ReturnDiagnostics, no secrets in diagnostics).
- Chaos: sessions and subscriptions churn while an observer reads the summary (cumulated counters monotonic, counts exact at quiescence), and while EnabledFlag flips (no deadlock, no leaked session objects).
- Interop: `diagnostics.server-summary` verified with the open62541 and node-opcua servers and with all six peer clients against the Go server; `diagnostics.return-diagnostics` verified with the UA-.NETStandard server; ledger capabilities `diagnostics.*`.

---

## v1.14.0

**Date:** 2026-10-25
**Previous release:** v1.13.0

### Summary

Alarms & Conditions (Part 9) on the server, with client helpers to receive, refresh and act on conditions.

### Added

- **server: conditions.** `Server.AddCondition` creates ConditionType, AcknowledgeableConditionType, AlarmConditionType, LimitAlarm (exclusive and non-exclusive) and OffNormalAlarmType instances with their standard components. `Condition` has the state machines (Enabled, Acked, Confirmed, Active, Suppressed, Shelving, limit states), `Update` and the `Set…` helpers, `EvaluateLimits`, `Report`, and `RemoveCondition`.
- **server: the Part 9 methods** Enable, Disable, AddComment, Acknowledge, Confirm, TimedShelve, OneShotShelve, Unshelve, ConditionRefresh and ConditionRefresh2, through the Call service and the `AccessController`, with the Part 9 status codes; `MaxTimeShelved` and automatic unshelving; the hooks `OnAcknowledge`, `OnConfirm`, `OnAddComment`, `OnEnable` and `OnShelve`, which can refuse a call. `AlarmsConditionsSupported()` is now true.
- **server: event fields resolve by BrowsePath** (`AckedState/Id`), and a select clause with an empty BrowsePath and AttributeId NodeId returns the ConditionId.
- **client:** `NewConditionEventFilter`, `ConditionEventFields`, `ParseConditionEvent` (with `IsRefreshStart` / `IsRefreshEnd`), `Acknowledge`, `Confirm`, `AddComment`, `EnableCondition`, `DisableCondition`, `TimedShelve`, `OneShotShelve`, `Unshelve`, `ConditionRefresh` and `ConditionRefresh2`. **ua:** `EventFilterBuilder.SelectPaths` and `SelectConditionID`, and `FieldPath`.

### Not implemented

- Condition branches (BranchId is null), audit events, dialogs (DialogConditionType), the Latched / Silence / OutOfService states, the AlarmConditionType Suppress / Unsuppress / Silence / Reset / RemoveFromService / PlaceInService methods and the `*2` method variants.

### Tests

- Unit, e2e and conformance tests; a fuzz test of the condition state machine; chaos: sessions acknowledge, confirm, comment, disable / enable and refresh concurrently while the server flips states, removes and re-adds a condition and a proxy drops connections, with the events checked for consistency.
- Interop: the Go client against the UA-.NETStandard, node-opcua and open62541 alarm fixtures, and every adapter client against the Go server (opcua-interop v0.12.0); ledger capabilities `alarms.*`.

### Interop

- Pinned opcua-interop v0.12.0.

---

## v1.13.0

**Date:** 2026-10-25
**Previous release:** v1.12.0

### Summary

The HTTPS (`opc.https`, Part 6 §7.4) and WebSocket (`opc.wss`, Part 6 §7.5) transports for client and server, and fixes to SecureChannel token renewal on a busy server.

### Added

- **HTTPS transport (`opc.https://`, https-uabinary), client and server.** UA Binary messages in HTTP/1.1 POST bodies over TLS 1.2 or later, with the `OPCUA-SecurityPolicy` header and Publish as a long poll. SecurityPolicy None and the non-ECC policies (`uasc.HTTPSPolicySupported`); the ECC policies need SecureChannelEnhancements, which HTTPS has no secure conversation to carry.
- **WebSocket transport (`opc.wss://`, wss-uasc-uabinary, sub-protocol `opcua+uacp`), client and server**, on a small RFC 6455 implementation of its own (`internal/websocket`) with one chunk per binary frame.
- **Client:** options `TLSConfig` and `HTTPClient`, and `SelectEndpointForTransport`. **Server:** the HTTPS and WebSocket listener options, `Server.HTTPSAddr` and `Server.WebSocketAddr`. **ua:** the transport profile URIs.

### Fixed

- **server: a token renewal that a client sent in time no longer waits unread behind that channel's requests** while the server handles others. All channels' requests go to one handler, and a channel stopped reading while one of its requests waited for it, so a renewal could sit in the socket until the token had expired and the server closed the channel. The requests of a channel now wait in a queue of their own, bounded by the in-flight slots as before.
- **uasc: a server no longer closes a channel whose token expires while it processes a renewal it has received in full.** The channel goes on with the new token, or is closed if the renewal fails; part of a multi-chunk OpenSecureChannel does not count.
- **uasc: the client renews at 75 % of the token lifetime counted from when it sent the OpenSecureChannel request**, not from when it had processed the response (Part 4 §5.5.2.1).
- **server: a notification message whose Publish response cannot be sent is resent with the session's next Publish request.** A Publish request read just before its connection dropped could be answered after the drop, and the client, back on a new channel, learned of the lost message only from the sequence number of a later one, possibly a keep-alive many intervals away.
- **uasc: an `opc.https` request that is cancelled, times out or has its channel closed reports that**, also when the server's answer to the cancelled request arrives first; it used to fail decoding the empty answer with "unexpected EOF".

### Tests

- Unit, e2e and conformance tests for both transports; fuzz tests for WebSocket framing, the handshake and HTTPS request bodies.
- Chaos: many clients over opc.wss and opc.https through fault proxies (drops, stalls, latency, fragmentation, refusals), malformed WebSocket frames, slowloris and garbage HTTPS bodies.
- Interop against UA-.NETStandard over opc.wss and opc.https in both directions (opcua-interop v0.11.0); ledger capabilities `transport.wss` and `transport.https` for every peer.
- Deterministic regression tests for the renewal fixes, the Publish resend and the late HTTPS answer; the PubSub key-rotation and publisher-restart chaos tests tell late messages from lost ones.

### Interop

- Pinned opcua-interop v0.11.0.

---

## v1.12.0

**Date:** 2026-10-25
**Previous release:** v1.11.0

### Summary

The ECC security policies ECC_brainpoolP256r1, ECC_brainpoolP384r1 and ECC_curve448 work on client and server, in Sign and SignAndEncrypt, with certificates on those curves that crypto/x509 cannot handle.

### Added

- **Security policies `ECC_brainpoolP256r1`, `ECC_brainpoolP384r1` and `ECC_curve448` (Part 7, Part 6 §6.8).** Client and server, Sign and SignAndEncrypt, including EccEncryptedSecret user tokens, X.509 user certificates on these curves and endpoint selection. Verified against open62541 1.5.9 in both directions.
- **uapolicy: certificates with Brainpool and Ed448 keys.** `ParseCertificate`, `ParseCertificates`, `CreateCertificate`, `VerifyCertificate`, `MarshalPrivateKey` and the type `Ed448`. `ParsePrivateKey` reads Brainpool (PKCS #8, SEC 1) and Ed448 (PKCS #8) keys. Ed448-signed chains are verified against the trusted certificates only. The client, server, reverse connect, LDS and X.509 user tokens use these.
- **ua:** `SecurityPolicyURIECCBrainpoolP256r1`, `SecurityPolicyURIECCBrainpoolP384r1`, `SecurityPolicyURIECCCurve448` and their short names.

### Security

- Brainpool uses `github.com/ProtonMail/go-crypto/brainpool` through Go's generic elliptic code, which is **not constant time**. The Brainpool policies rank below the NIST ones. Prefer the NIST or AEAD policies, or keep the application key in an HSM through `crypto.Signer` (see docs/security.md).
- Ed448 and X448 come from `github.com/cloudflare/circl`; X448 refuses low-order points.
- ECC_curve448 derives keys as open62541 does (HKDF-SHA256, a 32-byte signing key, no SecureChannelEnhancements).

### Fixed

- **server: a Local Discovery Server with the multicast extension announces a registered server as soon as the mDNS instance name it was waiting for becomes free** — when the responder that announced it says goodbye or its records expire, or when another registration holding the name unregisters or expires. Before, the server stayed unannounced and missing from FindServersOnNetwork until a registration changed something; on a real link this also followed a registration that lapsed while the discovery server heard an echo of its own announcement.

### Tests

- **Unit, known-answer and fuzz:** RFC 7027, 7748 and 8032 vectors, key-derivation outputs, OpenSSL-generated certificates and keys (uapolicy/testdata/openssl), and fuzz tests for the certificate parser, the private-key parser and the shared-secret step.
- **e2e and conformance:** every policy and mode, multi-chunk messages, Calls, subscriptions, renewals, EccEncryptedSecret passwords and issued tokens, X.509 users per curve, trust lists and key mismatches.
- **Chaos:** the three policies join chaos/secure (bit flips, replays, incomplete chunks, parallel channels).
- **Interop:** 18 new capabilities verified against open62541 in both directions. `security.ecc.unimplemented-policy` is retired.
- **CI:** the chaos suites run in their own job. The tests of the Brainpool policies scale their token lifetimes and key-exchange counts to the cost of math/big curves under the race detector, a renewal under traffic in the conformance tests has 2 s instead of 1 s before its token expires, and the discovery chaos test waits for a registration that expired on a slow runner to come back.

### Dependencies

- Added `github.com/cloudflare/circl` v1.6.5 and `github.com/ProtonMail/go-crypto` v1.5.2.

---

## v1.11.0

**Date:** 2026-10-25
**Previous release:** v1.10.0

### Summary

PubSub Actions are complete: requests and responses larger than a NetworkMessage go in chunks, PublishedActionMethod targets call Methods of the server, Responders announce their ActionMetaData and Requestors discover it, and a client adds a PublishedAction to a server through the new PubSubConfiguration file object with ReserveIds and CloseAndUpdate (Part 14 §9.1.3.7).

### Added

- **pubsub: chunked Action messages (Part 14 §7.2.4.4.4).** A UADP request larger than `ActionTarget.MaxNetworkMessageSize` (default the limit of the transport) and a response larger than the MaxNetworkMessageSize of the Responder's writer group go as chunks, each with the ActionHeader. The receiver reassembles them within the limits of `WithChunkReassembly` and keeps the chunks of different Requestors and requests apart. JSON Action messages cannot be chunked, so a larger JSON request fails.
- **pubsub: PublishedActionMethod targets call Methods (§6.2.3.10.4).**
  - `PublishedActionMethods(name, request, response, targets, methods)` and `ActionMethodOf(object, method)` build the data set, and `Validate` checks one Method per target.
  - `WithActionMethodCaller` routes the calls. In a server (`server.WithPubSub`) it calls the server's own Methods with the Requestor's inputs.
  - A handler set with `SetActionHandler` takes precedence. Without a handler or a caller, a target answers Bad_NotImplemented.
- **pubsub: Action discovery (ActionMetaData and ActionResponder).**
  - A Responder announces the ActionMetaData of its Action writers (UADP announcement 7, JSON `ua-action-metadata`) when their group becomes Operational. The announcement holds the targets, the request and response DataSetMetaData and the Methods.
  - On a broker it is retained on the writer's MetaDataQueueName (`ActionMetaDataTopic`), together with the connection's ActionResponder (announcement 6, `ua-action-responder`, `ActionResponderTopic`).
  - On a datagram transport it goes to the discovery channel every DiscoveryAnnounceRate. The Responder also answers DataSetMetaData and PubSubConnections probes.
  - `DiscoverAction(ctx, target)` returns the `ActionMetaData`; `md.Apply(target)` completes a target for `CallAction`. The request and response DataSetMetaData share Name and ConfigurationVersion (Table 177). `ActionTarget.MetaDataAddress` is new.
- **server: the PubSubConfiguration file (§9.1.3.7).** `PublishSubscribe.PubSubConfiguration` holds the configuration as a UABinaryFileDataType with a PubSubConfiguration2DataType Body.
  - Open accepts Read, Read + Write and Write + EraseExisting. Readers share the file, a writer has it to itself, and handles belong to their session. Read, Write, GetPosition, SetPosition and Close work as for any FileType, and Size, OpenCount and LastModifiedTime are live.
  - **ReserveIds** hands out WriterGroupIds and DataSetWriterIds from 0x8000–0xFFFF that are unused and not reserved by another session, at most 1024 per session. It also returns the default PublisherId.
  - **CloseAndUpdate** applies the ElementAdd, ElementMatch, ElementModify and ElementRemove operations on PublishedDataSets, connections, writer and reader groups, writers and readers. Removals run first, then parents before children.
  - Missing names and ids are assigned. Each element gets a result: Bad_BrowseNameDuplicated, Bad_NoMatch, Bad_NotFound, Bad_InvalidArgument, Bad_NotSupported, or Bad_ConfigurationError for an element without which the result would not be valid.
  - RequireCompleteUpdate is honoured. The update returns ConfigurationValues and ConfigurationObjects, and the runtime restarts only the components that changed.
  - Not supported: SubscribedDataSets, SecurityGroups and PubSubKeyPushTargets references. The file's DefaultSecurityKeyServices, ConfigurationProperties and ConfigurationVersion are ignored.
- **pubsub/remote: the file from a client.** `ReadConfiguration`, `ReserveIDs`, `UpdateConfiguration` and `Ref`.

### Tests

- **Unit, e2e and fuzz:**
  - chunked requests and responses over UDP and MQTT;
  - Method targets with handler precedence;
  - discovery over datagram and broker, plus the UADP and JSON discovery codecs (fuzz seeds included);
  - the FileType modes, sharing, positions and session handles;
  - ReserveIds, and every CloseAndUpdate operation and result;
  - `FuzzPubSubConfigUpdate`: any file with any references leaves a valid configuration.
- **Chaos:**
  - `TestChaosActionChunks`: chunked calls, unsecured and SignAndEncrypt, over a network that loses, duplicates, reorders, delays and corrupts chunks, while forged chunks come in.
  - `TestChaosActionDiscovery`: discovery under forged ActionMetaData.
  - `TestChaosPubSubConfigurationFile`: sessions read, reserve and update the file concurrently with random and malformed references, abandon handles and drop. Contention gets Bad_NotWritable / Bad_NotReadable, the runtime only ever takes valid configurations, and the handles of closed sessions are freed.
- **Conformance:**
  - server Responders with chunks (`TestPubSub_ActionChunksServerResponder`) and with Method targets (`TestPubSub_ActionMethodServerResponder`);
  - discovery through a broker (`TestPubSub_ActionDiscoveryServerBroker`);
  - a PublishedActionMethod with its connection, group and writer added through ReserveIds and CloseAndUpdate, then called (`TestPubSub_ActionConfigurationFile`).
- **Interop:** `TestPubSubMQTT_Actions` runs go-opcua to go-opcua through Eclipse Mosquitto over UADP (chunked) and JSON. A client configures the Responder on a go-opcua server through the PubSubConfiguration file, and a standalone Requestor discovers the Action from the retained ActionMetaData and calls it. No other stack implements PubSub Actions (ledger capability `pubsub.actions`).
- Two counter checks no longer race: the Responder counts its chunks after its Send returns.

---

## v1.10.0

**Date:** 2026-10-25
**Previous release:** v1.9.1

### Summary

PubSub sends and receives gzip compressed JSON NetworkMessages over MQTT 5.0, the content type `application/json+gzip` of Part 14 §7.3.4.9.1.

### Added

- **pubsub: gzip compressed JSON over MQTT 5.0.** `SetJSONCompression(conn, "gzip")` sets the go-opcua connection property `JsonCompression` (Part 14 defines no property for it; it is not sent to the broker): the connection's JSON data, metadata and Action messages go out gzip compressed (RFC 1952) with the Content Type `application/json+gzip`. `Validate` accepts the property only on MQTT connections with the JSON mapping (values `gzip` and `none`). A connection that runs MQTT 3.1.1 cannot say that a message is compressed and sends it uncompressed, logging a warning once.
- **pubsub: subscribers decompress gzip compressed JSON.** By the content type on MQTT 5.0, and by the gzip header on 3.1.1, where the broker forwards no content type (a UADP NetworkMessage cannot start like a gzip stream). A subscriber decompresses at most 16 MiB of a message (`DefaultJSONDecompressionLimit`, set with `WithJSONDecompressionLimit`); a larger message (a decompression bomb), a truncated or corrupt stream and compressed garbage are decode errors. Before, a subscriber rejected every compressed message.

### Tests

- **Unit and e2e:** compressed data and metadata on the wire with MQTT 5.0 and 3.1.1 subscribers, the uncompressed fallback on 3.1.1, the decompression limit at its boundary and against a 64 MiB bomb, broken streams, validation, and PubSub Actions with and without compression.
- **Chaos:** `TestChaosGzipJSON` runs a compressing publisher to an MQTT 5.0 and an MQTT 3.1.1 subscriber while an attacker floods their queues with decompression bombs, truncated and corrupt gzip streams, compressed garbage and mismatched content types, and the broker restarts and drops connections: no corrupt, duplicate or stale data set is delivered and every forgery is counted as a decode error. `TestChaosMQTT5Broker` gains a compressed JSON QoS 2 case.
- **Conformance:** `TestPubSub_BrokerTransportsServerToServer` configures a compressing connection through the server's AddConnection method; the server-to-server subscriber and the standalone runtime decompress it, and the broker sees `application/json+gzip` and no `JsonCompression` user property.
- **Interop:** `TestPubSubMQTT5_GzipJSON` runs go-opcua to go-opcua through Eclipse Mosquitto with subscribers on MQTT 5.0 and 3.1.1, which learn the DataSetMetaData from compressed metadata messages. No other stack compresses PubSub messages (ledger capability `pubsub.mqtt5.gzip`).

---

## v1.9.1

**Date:** 2026-10-24
**Previous release:** v1.9.0

### Summary

Fixes in the library for the key timing of SKS KeySources, URIs with a `;` in NodeId strings, MQTT clients that take a session from each other, a data race in the server's secure channel, a server that closed channels with a client's CloseSecureChannel request, PubSub writer groups that published before their connection listened, and a client test hook race, and a sweep of the test suites for scheduling-dependent tests: every test that passed or failed depending on timing (on a loaded CI runner, under the race detector, or on Linux) now waits for the event it asserts on. The suites were run in rounds of 25 parallel CI runs until a round came back clean, then 50 more: the release commit passed 75 of 75.

### Fixed

- **pubsub/sks: a KeySource changes keys when the SKS does.** `TimeToNextKey` counts from the SKS's response, but the ring started counting only after the session dialed for the fetch was closed, so every ring changed keys later than the SKS by the time that close took. A publisher whose ring lagged secured messages with a key that a subscriber which fetched just after the key change did not hold. The time since the response is now taken off. A fetch still returns no past keys: where a publisher and a subscriber start together, create the subscriber's KeySource first (documented on `KeySource`).
- **ua: URIs in NodeId, ExpandedNodeId and QualifiedName strings are escaped.** The compact JSON and XML forms wrote a namespace or server URI as is into `nsu=<uri>;` and `svu=<uri>;`, and a URI with a `;` ended early when read back: the value came back as a String NodeId of the whole text and did not survive a second encode. A `;` is now written as `%3B` and a `%` as `%25` (Part 6 §5.1.12), and read back by the codec and by `ua.ParseExpandedNodeID`; other percent-encodings are read as written.
- **mqtt: a client waits its backoff before reconnecting after a broker DISCONNECT.** It reconnected at once, so after another connection took its session over it took the session straight back, the other connection could lose it before its CONNACK, and two clients with one client identifier took the session from each other in a tight loop. The backoff now only starts over after a connection that lasted `MaxReconnectDelay`; a connection lost otherwise is still retried at once.
- **uasc: no data race on the request id of a server channel.** The OpenSecureChannel handler set the channel's request id without the lock that `Close` takes to draw one, so a server shutting down while a client (re)opened a channel raced on it.
- **uasc: a server closes a channel with an Error message, not a CloseSecureChannel request.** CloseSecureChannel is a client request (Part 6 §7.1.4); a server that closed its channels (on `Server.Close`, for one) sent one to each client anyway. It now sends an Error message with `Bad_SecureChannelClosed` (§7.1.5, Table 79) and closes the connection, so a client learns why its pending requests failed. The write of the old request carried the server channel's `RequestTimeout`, zero by default, as its write deadline, so it was never sent and clients only saw the connection close; the Error message gets 5 s. A go-opcua client reconnects after either, as before. Clients still send CloseSecureChannel.
- **pubsub: a writer group sends its first message once the subscriptions of its connection are in place.** The writer groups of a connection started publishing while its reader groups and discovery listener were still binding, so a group that publishes once (or rarely) could send its first NetworkMessage before the same runtime listened for it, and that message was lost. Writer groups now wait for the connection's first subscription pass, whether it succeeded or failed.
- **pubsub: a reader keeps the sequence numbers of its writers when it learns new DataSetMetaData.** It dropped them with the fields of earlier frames, so a late or duplicated copy of a message delivered before a discovery announcement or metadata message was delivered again, out of order.
- **client: the publish request test hook is atomic.** A publish loop that outlived `Client.Close` could read the hook while the next test replaced it (a data race under `-race`).

### Tests

- **Interop:** UDP and TCP ports are bound before a peer is told them and replaced when taken (testport checks the IPv6 wildcard and skips the configured ephemeral range); a container whose host port Docker finds taken starts again on other ports; each dotnet discovery probe gets its own go-opcua publisher and ports (Linux kept routing answers to a removed container) and is repeated as Part 14 §7.2.4.6.12.2 expects of a subscriber; adapter client runs are bounded by their own `--timeout-ms`; a data race on a container log buffer; event pulses, subscription recovery, queue isolation and mDNS waits no longer depend on timing.
- **Unit, chaos and conformance:** 21 timing assumptions replaced by waits on the asserted event, among them counters read once while the runtime updates them after the send (`TestChunkedUDP`, discovery), goroutine stack snapshots right after `Close`, key and token lifetimes shorter than an RSA handshake under `-race`, a UDP burst larger than Linux's default receive buffer, and fixed port 4840 in the uacp tests. The AMQP chaos test's silent broker outlasts the client idle time-out, and the test AMQP broker decides whether to withhold a disposition before it routes the message (a consumer could have it before the withholding was read) and drops the links of a connection it ends at once, requeueing their unsettled messages (it kept dealing messages to the dead link of a client that had reconnected, and the subscriber discarded them as older when they came back). The PubSub chaos checker allows for a data set handed to the handler late by the receive goroutine of a connection that was restarted, and `testport` no longer runs out of ports in long `-count` runs. The PubSub unit tests wait until the runtime called the DataSetHandler, not only until it counted the message, and the interop suite gives an adapter's `print-capabilities` 90 s and three attempts (the first container of an image on a busy runner took longer than 30 s) The test MQTT broker sends a resumed session's CONNACK and its queued QoS 1 messages before any publication routed to the session while it reconnected (MQTT §4.6; a subscriber discarded the backlog as older, `TestResumedSessionKeepsOrder`); the LDS interop test allows for the 1 s mDNS goodbye grace of an unregistered server; the rotating key group of the PubSub security conformance test keeps its past keys verifiable; the test MQTT broker sends the retained messages for a new subscription in the critical section that adds it (a retained message published right after a SUBACK reached the subscriber twice, `TestRetainedOnceToNewSubscription`), the keep-alive conformance test tells a stalled runner (measured) from a reader that times out despite keep-alives, the chaos proxy's DropAll also ends a connection it is still setting up (one accepted just before survived it, and a server meant to be cut off stayed connected), the unregistration bound of the discovery chaos test leaves room for a loaded runner, and the reverse-connect chaos storm counts as a fault that alters bytes (a blackhole lifted within the storm cuts the stream inside a message, which the receiver rejects as failed security checks).
- The interop suite runs against opcua-interop **v0.10.1**.
- `server.test`, a compiled test binary committed by mistake, is removed and `*.test` ignored.

---

## v1.9.0

**Date:** 2026-10-24
**Previous release:** v1.8.1

### Summary

PubSub (Part 14) completes its transport and message model: the Ethernet and AMQP 1.0 transports, MQTT 5.0, chunked NetworkMessages, UADP discovery, PubSub Actions and diagnostics objects in the information model.

### Added

- **pubsub, server: PubSub diagnostics objects (Part 14 §9.1.11).** `PublishSubscribe.Diagnostics` (PubSubDiagnosticsRootType, i=17409) and a Diagnostics object on every connection, writer group, reader group, DataSetWriter and DataSetReader (PubSubDiagnosticsConnectionType / WriterGroupType / ReaderGroupType / DataSetWriterType / DataSetReaderType), added and removed with the component: DiagnosticsLevel, TotalInformation, TotalError, SubError, the Reset method (through the PubSub authorizer), the state counters by cause (StateError, StateOperationalByMethod / ByParent / FromError, StatePausedByParent, StateDisabledByMethod), SentNetworkMessages, FailedTransmissions, EncryptionErrors, ReceivedNetworkMessages, ReceivedInvalidNetworkMessages, DecryptionErrors and FailedDataSetMessages, each with Active, Classification, DiagnosticsLevel and TimeFirstChange, and the LiveValues (Configured / Operational DataSetWriters and DataSetReaders, ResolvedAddress, MessageSequenceNumber, StatusCode, MajorVersion, MinorVersion, SecurityTokenID, TimeToNextTokenID). Counters and LiveValues above the DiagnosticsLevel of their object do not count and read `Bad_OutOfService`; the optional TimeFirstChange properties of the root object, which the standard nodeset leaves out, are added with their standard NodeIds.
- **pubsub: Ethernet transport (`opc.eth://`, profile pubsub-eth-uadp).** UADP NetworkMessages directly in Ethernet II frames with EtherType 0xB62C (Part 14 §7.3.3), optionally with an IEEE 802.1Q tag: `opc.eth://<MAC>[:<VID>[.<PCP>]]`. The interface (NetworkInterface) is required; the new builder `pubsub.EthernetConnection(name, url, iface, publisherID)` sets it. A multicast MAC joins the group. A NetworkMessage is at most 1500 bytes or the smaller MTU of the interface, larger ones fail with `transport.ErrMessageTooLarge`. Linux uses `AF_PACKET` raw sockets (CAP_NET_RAW or root), macOS and FreeBSD BPF devices (root or access to `/dev/bpf*`; joining a multicast group needs root on macOS); other systems get `eth.ErrNotSupported`. JSON is not defined over Ethernet and `Validate` rejects it; the server lists the profile in `SupportedTransportProfiles` where it works. go-opcua does no time-scheduled (TSN) sending.
- **pubsub: MQTT 5.0 (Part 14 §7.3.4).** `SetMQTTVersion(conn, MQTTVersion311 | MQTTVersion5 | MQTTVersionBestAvailable)` sets `0:MqttVersion` (Table 201); 3.1.1 stays the default and is unchanged on the wire, BestAvailable falls back to 3.1.1 when the broker refuses 5.0. `SetConnectionProperty` maps the Table 202 `connection-*` properties onto the CONNECT (session expiry, Receive Maximum, Maximum Packet Size, …) and sends the others as user properties; `Validate` checks them. Over MQTT 5.0 messages carry the content type of their mapping (`application/opcua+uadp`, `application/json`; §7.3.4.9) and the `UAMessageType` user property (§7.3.4.8); subscribers pick the decoder by content type and recognise metadata by UAMessageType. `transport.Message` exposes `ContentType` and `UserProperties`.
- **internal/mqtt: MQTT 5.0 client.** Properties on every packet, reason codes as errors with the broker's reason string, session expiry, Receive Maximum and Maximum Packet Size both ways, Maximum QoS, Retain and Wildcard availability, Server Keep Alive, server DISCONNECT, subscription options, and QoS 2 publishing with retransmission on both versions. Topic aliases, enhanced authentication and AUTH packets are not implemented (Topic Alias Maximum is 0).
- **pubsub/uadp, pubsub: chunked NetworkMessages (Part 14 §7.2.4.4.4).** A publisher sends a DataSetMessage larger than the MaxNetworkMessageSize of its group as chunks, each with its own GroupHeader SequenceNumber and NetworkMessageNumber and, in a secured group, its own nonce and signature. Subscribers check the security of every chunk and reassemble them per connection in bounded memory (per message, per publisher and overall, with a timeout), rejecting chunks outside their message, of another total size, duplicates and overlaps; `WithChunkReassembly` sets the limits. Codec: `uadp.EncodeChunks`, `uadp.Reassembler`, `uadp.PeekType`, `DecodeReassembled`. The layout is the one of the OPC Foundation .NET stack 2.x; open62541 1.5.9 neither sends nor accepts chunks. New counters ChunksSent, ChunksReceived, ChunkedMessagesReceived, ChunksDiscarded.
- **pubsub/uadp, pubsub: UADP discovery (Part 14 §7.2.4.6).** All probes (publisher information with every InformationType, FindApplications) and announcements (PublisherEndpoints, DataSetMetaData, DataSetWriter configuration, PubSubConnection, ApplicationInformation), in the specification layout or the .NET 2.x layout, which Decode recognises. With `WithDiscovery(DiscoveryOptions{…})` datagram publishers listen for probes on a multicast connection address and on the DiscoveryAddress, answer them rate-limited (one announcement per 500 ms, a token bucket per connection) and announce their DataSetMetaData at the DiscoveryAnnounceRate; readers without DataSetMetaData, or with a MajorVersion mismatch, probe for it after a random delay with backoff. Announcements with a bad StatusCode are ignored. New counters DiscoveryRequestsSent / Received / Ignored, DiscoveryResponsesSent / Received.
- **pubsub: AMQP 1.0 transport (Part 14 §7.3.4, Annex B.3).** Profiles `pubsub-amqp-uadp` and `pubsub-amqp-json` (`transport.ProfileAMQPUADP`, `transport.ProfileAMQPJSON`), URL schemes `amqp://` and `amqps://`, builder `pubsub.AMQPConnection`. A message carries the NetworkMessage in one data section with a UUID `message-id`, the subject `ua-data` or `ua-metadata` and the content type of the mapping (Table B.1); the Table B.2 writer group and writer properties (`message-to`, `message-correlation-id`, …) set the message properties, other properties are application properties. BestEffort and AtMostOnce are sent pre-settled, AtLeastOnce unsettled and waiting for the broker's acceptance; ExactlyOnce is downgraded to AtLeastOnce. The subject is the UAMessageType of the message (`ua-data`, `ua-metadata`, `ua-action-request`, …); received messages report their content-type, and their subject as the UAMessageType, so the subscriber picks the decoder like with MQTT 5.0. Queue names are AMQP addresses (RabbitMQ 4: `/queues/<q>`, `/exchanges/<x>/<key>`; ActiveMQ Artemis: plain addresses); AMQP has no retained messages, so metadata belongs on a queue. The server lists both profiles in SupportedTransportProfiles. Not implemented: AMQP over WebSockets, promoted fields (Table B.3).
- **internal/amqp: a dependency-free AMQP 1.0 client.** SASL ANONYMOUS, PLAIN and EXTERNAL, TLS, max-frame-size negotiation, idle time-outs with heartbeats, session and link flow control, multi-frame messages, settled and unsettled deliveries, and reconnect with backoff that attaches the links again and resends unsettled messages. Everything decoded from the network is bounded (frame size, nesting depth, counts and lengths before allocation).
- `transport.PublishOptions` has `ContentType`, `MessageType`, `MessageExpiry`, `UserProperties` (MQTT 5.0) and `Properties` (AMQP); the publisher fills them, each transport uses what it can carry.
- **pubsub: PubSub Actions (Part 14 §6.2.11.2).** A DataSetWriter of a PublishedAction (`pubsub.PublishedActions`) is a Responder whose Action targets run Go handlers (`WithActionHandler`, `SetActionHandler`, `ActionInvocationFrom`); `(*PubSub).CallAction` is the Requestor, with RequestId and CorrelationData correlation, Idle acknowledgement, timeouts (`ErrActionTimeout`) and resends for datagram transports (`ActionTarget.ResendInterval`). Actions follow the ActionState semantics of Tables 83/84 (a request runs once, duplicates get the current state, Done is repeated until Idle or the TimeoutHint), are bounded by `ActionOptions` (rate, burst, concurrent exchanges, MaxTimeout), and run over UDP, MQTT 3.1.1 / 5.0 and AMQP with the UADP mapping (secured with the group's SecurityMode) and JSON. Undecodable, misaddressed or insufficiently secured requests get no response; a datagram ResponseAddress must be the request's source host or a multicast group, so a responder cannot be used to reflect traffic. Codec: UADP ActionRequest / ActionResponse NetworkMessages (ActionHeader, DataSetMessage types 5 and 6, `uadp.PeekAction`) and JSON `ua-action-request` / `ua-action-response`, with bounded decoding. New counters ActionRequestsSent / Received / Rejected, ActionResponsesSent / Received, ActionTimeouts; configuration validation of Table 85 (PublishingInterval 0 for action-only groups, the request QueueName on brokers); helpers `ActionRequestTopic` / `ActionResponseTopic`. The server shows PublishedActions as PublishedDataSetType objects (the 1.05 nodeset has no PublishedActionType). Not implemented: binding action targets to server Methods (PublishedActionMethod), ActionMetaData / ActionResponder discovery announcements, chunked action messages.
- **pubsub: `Diagnostics`, `ResetDiagnostics`, `SetDiagnosticsLevel`, `WithDiagnosticsLevel`.** The runtime keeps the Part 14 counters per component next to the cumulative `Counters` of `Status`, which a Reset does not touch; `DiagnosticsCountersOf` lists the counters of a component kind with their classification and level.

### Tests

- `TestBrokerThatDoesNotReadIsDropped` (internal/amqp) models the broker that does not read with a client connection whose writes block, instead of a real peer that floods without reading: on Linux the full receive queue of such a peer can stall the TCP connection in both directions before the client has queued enough answers to notice, and the test hung (failed CI). The stall-based tests of the server channel writer, the MQTT client and broker and the chaos suite were checked on Linux for the same pattern and pass repeatedly.
- Runtime review: regression tests (`pubsub/runtime_regress_test.go`) for Action routing to readers (JSON and chunked), the reader stream bound, chunk expiry and chunk properties, reader security groups, Action exchange expiry and its tombstones, exchanges ending with their writer, CallAction while the send blocks, Responder readiness, unknown-writer counting, the discovery context race and nil ExtensionObject bodies; the Action tests pass at `-race -count=20 -cpu=1,4,8`. The docs say that handlers and event callbacks must not call Close or wait for CallAction.
- Interop pin update: the suite runs against opcua-interop **v0.10.0** (release run https://github.com/otfabric/opcua-interop/actions/runs/40100248770), whose UA-.NETStandard adapter has PubSub. New `interop/dotnet_pubsub_peer_test.go`: UADP and JSON codecs, UDP with the Variant, DataValue and RawData field encodings, Sign and SignAndEncrypt (Aes128 / Aes256-CTR), MQTT 3.1.1 and 5.0 with UADP and JSON, the runtime with TargetVariables, chunked NetworkMessages and UADP discovery (.NET layout), verified in both directions; new ledger capabilities `pubsub.uadp.chunk` and `pubsub.uadp.discovery`. The PubSub peer tests are parameterised by the peer adapter.
- End-to-end server to server (conformance): variables published over MQTT 5.0 and AMQP 1.0 with UADP, JSON and SignAndEncrypt, configured by an OPC UA client through the PubSub methods of the server, written to target variables of another server, with the wire checked for content types, UAMessageTypes, subjects, QoS 2 and connection properties (`TestPubSub_BrokerTransportsServerToServer`); chunked UADP over UDP (`TestPubSub_ChunkedUDPServerToServer`); a reader that learns its DataSetMetaData from a server publisher through discovery (`TestPubSub_DiscoveryServerPublisher`); the diagnostics objects read, reset and leveled through a client (`TestPubSub_DiagnosticsThroughClient`); invalid transport settings refused by AddConnection and BestAvailable falling back to 3.1.1 (`TestPubSub_RemoteConnectionValidation`); the Ethernet transport end to end over an in-memory link, lossy and with discovery (`TestE2EEthernetMemory*`).
- Chaos: MQTT 5.0 persistent sessions and AMQP 1.0 links while the broker restarts, disconnects with reason codes, detaches links, withholds dispositions and stops heartbeats, with exactly-once delivery checked; chunks and discovery over an in-memory network that drops, duplicates, reorders, truncates and corrupts, with forged chunk and probe floods; diagnostics Reset, SetDiagnosticsLevel and client reads while components come and go; five publishers and five subscribers on shared AMQP and MQTT 5.0 brokers while runtimes start and close. New fuzz targets `FuzzRuntimeReceive`, `FuzzDiscoveryRoundTrip`, `FuzzValidateConnection` and the Ethernet `FuzzParseURL`.
- `TestChaosAMQPBroker` (chaos/pubsub): the silent-broker fault lasts 2.5 s, longer than the 2 s after which a client that announces a one-second `connection-idle-time-out` gives up (it announces half its time-out), and no longer counts as a renewed connection; a run ending in withheld dispositions followed by silence left the publisher waiting for its outcomes.
- `TestBrokerClosesConnection` (internal/amqp) no longer panics when its handler stores errors of two types, and `TestRequest_SendFailures` (uasc) holds the server's answer until the duplicate request ID has been sent.
- Actions: codec round-trip, malformed-input and fuzz tests (`FuzzDecodeAction`, JSON `FuzzDecode` seeds); Responder / Requestor protocol, limit, security and lifecycle tests; end-to-end Actions over UDP (plain and SignAndEncrypt), MQTT 3.1.1 and 5.0, and AMQP 1.0. `TestV5SessionTakeover` is split from `TestV5ServerDisconnect`, whose first client took the session back while the second one dialled.
- Transport review: new fuzz targets for the AMQP connection and session state machine (`FuzzClientFrames`), MQTT 3.1.1 / 5.0 client packet handling (`FuzzClientPackets`) and the BPF record parser of the Ethernet transport (`FuzzBPFRecords`); regression tests for Close from a handler, packet-identifier exhaustion, a stalled MQTT broker, an AMQP broker that floods without reading, oversized QoS 1/2 messages and acknowledgements of unsent publications; `TestMQTT5EndToEnd` waits for the metadata announcement instead of reading it once.
- Interop through real brokers: MQTT 5.0 against open62541 1.5.9 through Mosquitto 2.0.22 in both directions (UADP and JSON; go-opcua publishes with QoS 2 and an MQTT 5.0 listener checks the content type and UAMessageType; open62541 on 3.1.1), ledger capability `pubsub.mqtt5`; AMQP 1.0 go-opcua to go-opcua through RabbitMQ 4.1.4 and ActiveMQ Artemis 2.42.0 (UADP unsecured and SignAndEncrypt, JSON, metadata learned from a queue), ledger capability `pubsub.amqp` (open62541 has no AMQP).
- AMQP: `internal/testutil/amqpbroker`, an in-process AMQP 1.0 broker with queues, topic fan-out, credit, settlement and fault injection (dropped connections, detached links, refused opens and addresses, withheld dispositions, restart); malformed-input and fuzz tests of the frame and value decoders; end-to-end runtime tests with UADP and JSON, metadata from a queue, Sign and SignAndEncrypt and a broker restart.
- Chunks and discovery: codec round trips, fuzzing of the chunk and discovery decoders, reassembly limits and every rejection, runtime tests for secured chunked messages and for probe, announcement and rate limiting. `TestPubSub_MessageSecurity` tells a message lost at a key change (an encode error of the publisher or a decode error of the subscriber) from a UDP datagram the host dropped under load; `transport.TestRegistry` can run more than once in a process.
- MQTT 5.0: the test broker speaks 5.0 and QoS 2, honours the client's limits and subscription options and can refuse or disconnect with a reason; client, transport and runtime tests cover both versions, BestAvailable fallback, content types and properties. `TestSecuredGroup` no longer reads a subscriber's counter before that subscriber has received a message.
- Ethernet transport: unit tests for the address grammar, frame building and parsing (fuzzed), receive filtering and the OS layers against replaceable system calls; real-socket tests on the loopback interface and a veth pair, including a publisher / subscriber runtime test with UADP and SignAndEncrypt, which skip without raw access. The new CI job `pubsub-eth` runs them as root and fails instead of skipping (`GO_OPCUA_ETH_REQUIRE`).
- Interop: UADP over Ethernet against open62541 1.5.9 in both directions, unsecured and SignAndEncrypt (PubSub-Aes256-CTR), new ledger capability `pubsub.uadp.eth` (C→O, O→S). The adapter runs on a Docker bridge network with a named bridge interface, on which go-opcua sends and receives raw frames; the new Interop job `ethernet` runs the tests as root on Linux, and they skip elsewhere.

### Dependency

- `golang.org/x/sys` is a direct dependency (raw sockets and BPF of the Ethernet transport).

### Fixed

- **pubsub/transport/eth: a frame reflected by the network is not delivered twice (Linux).** A publisher and a subscriber on one host each got every frame twice where the network sends a frame back to its sender (Docker's networks, a bridge in hairpin mode): once through the outgoing tap and once as received from the interface's own MAC address. On Linux, where the tap marks the frames the host sends, a received frame from the interface's own address is dropped. Found with `opcuactl pubsub publish` / `subscribe` in one container; `TestReceiveReflectedFrame`. The in-memory test segment marks the host's own frames outgoing as the OS does.
- **pubsub: one datagram could crash a subscriber.** An Action message that the quick type check missed (a JSON MessageType late in the message or escaped, an MQTT topic of another type, a reassembled chunk) reached the readers as an ActionRequest / ActionResponse DataSetMessage and panicked while the runtime's lock was held. Every decoded Action message now goes to the Action handling, and readers ignore Action DataSetMessages.
- **pubsub: a reader keeps at most 1024 publisher streams** (least recently used evicted); forged PublisherIds grew its memory without bound.
- **pubsub: incomplete chunked messages expire after the reassembly timeout** even when no further chunk arrives, counted as ChunksDiscarded; chunks carry the ContentType, MessageType and properties of unchunked messages.
- **pubsub: a reader's SecurityGroupId no longer lowers the security of its group** when the reader's own SecurityMode is Invalid or None.
- **pubsub Actions: a handler past its deadline is cancelled and answered Done with Bad_Timeout**; it counts toward MaxConcurrent until it returns, and late duplicates of an ended exchange are answered for 5 s (at most 256 exchanges) instead of running the handler again. Stopping or removing a writer ends its exchanges.
- **pubsub Actions: CallAction returns at its timeout while the transport send blocks** (MQTT QoS 1 during an outage); a Responder's writer group is Operational only once its broker request queue is subscribed; UADP requests for an unknown DataSetWriter count as ActionRequestsRejected, as documented.
- **pubsub: a data race between discovery sends and Start**, and a panic of `New` on an ExtensionObject with a nil structure pointer.
- **client: switching sessions no longer sets off a reconnect.** `ActivateSession` closes the session it replaces while that session is still the client's; a Publish of it answered with `Bad_SessionIdInvalid` or `Bad_SessionClosed` in that moment was taken as the loss of the client's session, and the client went Disconnected and Reconnecting. The session being replaced now counts as left from the moment it is closed. Found by an intermittent `TestClientCovActivateSessionRecreatesSubscriptions` failure in CI; `TestLeftSession_SessionBeingReplaced`.
- **pubsub/jsonmsg: a DataValue field whose Value has no UaType is decoded.** Opc.Ua.PubSub's JsonEncoder leaves the UaType out when the DataSetMetaData implies it (`{"Temp":{"Value":21.5,"SourceTimestamp":…}}`); jsonmsg failed such a field with `cannot decode JSON number as Variant`. The Value is now typed by the field's DataSetMetaData like a RawData field, or by its JSON form without metadata. Found by the UA-.NETStandard interop tests.
- **pubsub: a connection URL must fit its TransportProfileUri.** A URL of a built-in transport with another profile (an `amqp://` URL with the MQTT profile, `opc.udp://` with AMQP, …) was accepted by `Validate`, `AddConnection` and the AddConnection method of the server, and ran the transport of the URL under the profile of the configuration; it is now refused with `Bad_ConfigurationError`. Schemes of transports the application registers take any profile. Found by the end-to-end conformance tests.
- **ua: a nil structure in an array is written as the zero structure in XML.** It was an empty element, which decodes to the zero structure, so the XML of such a value was not a fixed point of decode and encode. Found by the codec chaos test.
- **pubsub: a message that crosses a MessageReceiveTimeout is no longer delivered twice.** The timeout made a reader forget the sequence numbers of its writers (so that a restarted publisher is not discarded), and a late or duplicated copy of the last message arriving just after it was delivered again (found by the chaos network test). The timeout now marks the sequence numbers expired: the last message again, or one up to 16 behind it, is discarded; a publisher that restarted further behind is resynchronised to. The merged delta-frame fields are still dropped.
- **pubsub/transport, internal/amqp, internal/mqtt: Close from a message handler no longer deadlocks.** Closing an AMQP, MQTT, Ethernet or UDP connection from inside its own handler waited for the handler, that is for itself; Close from another goroutine still waits for a running handler, and no handler starts after Close.
- **internal/mqtt: no hang when the packet identifiers run out.** A broker that never acknowledges QoS 1/2 publications made the client loop forever under its lock once all 65535 identifiers were in use, freezing Publish, Subscribe and Close. At most 64511 publications are now in flight; beyond that Publish returns `ErrNoPacketID`.
- **internal/mqtt: Close returns within about a second when the broker has stopped reading**, instead of waiting for a blocked write up to the keep-alive or the broker's Server Keep Alive (up to 18 hours).
- **internal/mqtt: QoS 1/2 messages dropped for exceeding the maximum packet size are acknowledged (MQTT 3.1.1)**, so the broker no longer stops delivering once its in-flight window is full or redelivers them on every reconnect.
- **internal/amqp: a broker that keeps sending without reading the client's answers is disconnected** instead of making the client queue flow and disposition frames without limit.
- **internal/mqtt: an acknowledgement for a publication that was never sent no longer completes it as delivered**, and the decoder refuses a CONNECT without a protocol name (found by fuzzing).
- **pubsub: a reader without DataSetMetaData no longer fails JSON messages that arrive before the metadata.** A reader configured without metadata holds an empty one, and the JSON decoder checked the field names of the message against it (`field "…" is not in the DataSetMetaData`), counting a decode error for every message until the announcement arrived. Such a reader now has no metadata to decode against, and the message decodes by its field names. Over MQTT the retained announcement usually came first; over AMQP, where nothing is retained, data and metadata travel on separate links.
- **pubsub: ExactlyOnce is QoS 2 over MQTT.** A `RequestedDeliveryGuarantee` of ExactlyOnce published with QoS 1; it is QoS 2 now (§7.3.4.5), with both MQTT versions.
- **server: Browse reports the type definition of a target, not its DataType.** The `TypeDefinition` of a ReferenceDescription to a Variable was the Variable's DataType (e.g. `i=6` for an Int32 variable); it is the target of the Variable's HasTypeDefinition reference, and the null NodeId for node classes other than Object and Variable (Part 4 §7.30). `MapNamespace` returned the variable itself as its type definition and its Objects folder reference had a NodeId of its own namespace as reference type; they are BaseDataVariableType, FolderType and Organizes now.

---

## v1.8.1

**Date:** 2026-10-24
**Previous release:** v1.8.0

### Summary

Interop pin update (the suite runs against opcua-interop **v0.9.0**), four new interop peers in CI next to open62541 and Milo (async-opcua, UA-.NETStandard, node-opcua, opcua-asyncio), a fix that keeps a session alive while its request waits, a fix for the first sequence number of server channels, three interoperability fixes found by UA-.NETStandard, two found by opcua-asyncio (security token renewal, Republish recovery), and the client now sends the caller's ReturnDiagnostics and AuditEntryId.

### Fixed

- **server: the first sequence number of a channel is below 1024.** The channel broker seeded new channels with 1..1023 and the first chunk carries seed+1, so about one channel in 1023 started at 1024. With the RSA security policies the first sequence number must be below 1024 (Part 6 §6.7.2.4); clients that check it (async-opcua) closed the channel with `Bad_SequenceNumberInvalid`. Found by the async-opcua interop peer.
- **uapolicy: RSA-OAEP-SHA256 plaintext block size.** Aes256_Sha256_RsaPss computed the plaintext block size of asymmetric encryption with the padding of SHA-512 (`2·64+2` instead of `2·32+2` bytes), so asymmetric messages were split into blocks 64 bytes smaller than the peer expected; UA-.NETStandard failed to verify their signatures. The client and server of this library agreed with each other, which hid it. Found by the UA-.NETStandard interop peer.
- **server: CreateSession endpoints for another host name.** CreateSession returned no `ServerEndpoints` when the client connected with a host name that no endpoint URL matches (a container name, an IP address); it now returns all endpoints of the server. UA-.NETStandard clients abort the session without a matching endpoint.
- **server: client certificate chains.** `WithClientCertificateTrustList` read only the first certificate of a client certificate chain; the leaf is verified and the rest of the chain is used as intermediates (Part 6 lets a client send its certificate chain).
- **client: the RequestHeader of the caller is kept.** The secure channel built a new RequestHeader for every request and kept only its AdditionalHeader, and `Read` and `Browse` cloned the request without its header, so a `ReturnDiagnostics` mask or an `AuditEntryId` the caller set never reached the server: no server returned DiagnosticInfos to a go-opcua client. Both are sent now (the authentication token, timestamp, request handle and timeout hint stay the channel's). Found by the server diagnostics interop tests.
- **uasc: a replaced security token is not renewed again.** When `Renew` replaced a token before its scheduled renewal fired, the timer still renewed the superseded token: the OpenSecureChannel request took that token's next sequence number, one already used on the channel (Part 6 §6.7.2.4). open62541 and Milo tolerate this; opcua-asyncio closes the channel and the request times out. The renewal of a token that is no longer active is skipped, since its successor schedules one of its own. Found by the opcua-asyncio interop peer.
- **client: a Republish answered without the requested message ends the republish loop.** The recovery loop took any NotificationMessage of a Good Republish response as the retransmission. opcua-asyncio answers a sequence number it does not hold with Good and an empty message (sequence number 0), so the client rewound the subscription's sequence numbers and asked again until recovery failed. A response that does not carry the requested sequence number is treated like `Bad_MessageNotAvailable`. Found by the opcua-asyncio interop peer.
- **server: a request keeps its session alive when it arrives.** Requests of all channels are handled one at a time, and the session timeout was restarted only when the handler got to a request, so a session whose requests waited behind slow ones (a busy server, a long method call) could be closed with `Bad_SessionIdInvalid` although its client was active. Part 4 §5.6.2 counts from the last request the server received: each channel now restarts the timeout when a request arrives. Session activity is also measured on the monotonic clock, so a step of the wall clock neither expires a session nor keeps one alive. Found by an intermittent `TestSession_TimeoutEnforced` failure under the race detector; `TestSessionTouchedWhenRequestArrives` fails without the fix. A request for a session whose timeout has already elapsed no longer revives it before the periodic reaper removes it: the session lookup and the arrival of the request leave an expired session expired, and the request gets `Bad_SessionIdInvalid` (`TestExpiredSessionNotRevived`).

### Tests

- Interop images pinned to the opcua-interop v0.9.0 multi-arch digests of all six adapters (open62541 `9c5757d5…4a811f88`, Milo `68f450b0…e34579e1`, async-opcua `6a936193…de2d405d7`, dotnet `57b41e14…2099bc6d`, node-opcua `98be675f…cecede37`, asyncua `725d9d1f…85ac471c`; release run https://github.com/otfabric/opcua-interop/actions/runs/40071233368). Since v0.8.2 the open62541 adapter re-enables PubSub components that went to Error when an MQTT send failed before the broker accepted the connection, and no longer aborts with a double free when the broker refuses connections (the intermittent `mqtt-json` failure).
- All six peers run in every interop CI run, in ten shards; `interop/coverage.json`, the peer ledgers and the coverage render name v0.9.0.
- **Interop: no test passes without checking its claim.** async-opcua and node-opcua accept a Write that carries a SourceTimestamp (Good), as Milo does: their `write.encoding-mask` rows are `unsupported` now, not `verified`. The UA-.NETStandard Write test asserts its BadWriteNotSupported instead of only logging the result, the untrusted-certificate tests fail when the Go client refuses the certificate itself (the server's trust check would go untested), and the open62541 TransferSubscriptions test requires Good instead of accepting a service error.
- **Interop:** a new peer, the FreeOpcUa async-opcua 0.19.0 Rust stack (opcua-interop v0.9.0 `async-opcua` adapter, `ASYNC_OPCUA_IMAGE`), in both directions with its own ledger `interop/testdata/ledger-async-opcua.json`, checked by `TestAsyncOpcuaLedgerValid` (see INTEROP.md). What async-opcua lacks (ECC, LDS and mDNS, PubSub, the 1.05 JSON / Part 6 XML encodings) is `unsupported` in the ledger and skipped by the tests; the stack deviations it showed (a type-mismatched Write is accepted, Browse of an unknown node is `Good`, no event queue overflow event) are skips with the reason.
- **Interop:** a new peer, the OPC Foundation UA-.NETStandard 2.0.1 C# stack (opcua-interop v0.9.0 `dotnet` adapter, `DOTNET_IMAGE`), in both directions, with the go-opcua LDS (registration, `TestMulticast_GoAndPeers`) and the JSON / XML codec, with its own ledger `interop/testdata/ledger-dotnet.json`, checked by `TestDotnetLedgerValid` (see INTEROP.md). What the dotnet adapter does not offer (reverse connect, ECC, LDS and mDNS server, PubSub) is `unsupported` in the ledger. The shared history helpers treat the end time of a raw read as exclusive.
- **Interop:** a new peer, node-opcua 2.187.12 (TypeScript / Node.js; opcua-interop v0.9.0 `node-opcua` adapter, `NODE_OPCUA_IMAGE`), in both directions with its own ledger `interop/testdata/ledger-node-opcua.json`, checked by `TestNodeOpcuaLedgerValid` (see INTEROP.md). What node-opcua lacks (ECC, AddNodes / DeleteNodes, Query and HistoryUpdate on the server, an LDS in the adapter, PubSub, the codec operation) is `unsupported` in the ledger and skipped or pinned by the tests; the stack deviations it showed (an IndexRange on a scalar is answered `Good`, the event queue is revised to at least 100 so its overflow cannot be provoked) are skips with the reason. The node-opcua LDS registration test uses a secured go-opcua LDS, the only kind node-opcua registers with.
- **Interop:** a new peer, FreeOpcUa opcua-asyncio (PyPI `asyncua` 2.1.0, Python; opcua-interop v0.9.0 `asyncua` adapter, `ASYNCUA_IMAGE`), in both directions with its own ledger `interop/testdata/ledger-asyncua.json`, checked by `TestAsyncuaLedgerValid` (see INTEROP.md), including the C→P services (chunking, SetTriggering, TransferSubscriptions identity, references, diagnostics). What asyncua lacks (ECC, reverse connect, mDNS and FindServersOnNetwork, node management for the adapter's User role, server diagnostics, PubSub, the codec operation) is `unsupported` in the ledger and skipped or pinned by the tests. The stack deviations it showed are skips with the reason (`asyncuaDeviation`) and `unsupported` rows: TimestampsToReturn and IndexRange are ignored, Write to an unknown node is `Bad_UserAccessDenied`, Browse has no continuation points, ModifySubscription / ModifyMonitoredItems / MonitoringMode Sampling are not applied, the deadband compares with the previous sample, no event queue overflow event, Republish of an unknown message is `Good`, TransferSubscriptions checks no identity, and an unregistration leaves the server listed. `assertPeerDataChangeFilter` skips only the deadband or sampling-interval case of a peer listed in `peerDataChangeDeviation`, so its trigger case is still asserted.
- **Interop: client services against every peer server** (`interop/c2p_services_peer_test.go`, 10 new capabilities). They cover: multi-chunk messages of about 200 KB over Basic256Sha256 and Aes256_Sha256_RsaPss SignAndEncrypt, sized from the negotiated limits, with the chunk counts asserted; SetTriggering and RemoveLinks with the linked item in Sampling; the TransferSubscriptions identity rules; AddReferences / DeleteReferences; ServerDiagnosticsSummary and SessionDiagnosticsArray; and a Read with ReturnDiagnostics, whose DiagnosticInfos are decoded. A JSON Verbose codec round trip runs with Milo and UA-.NETStandard in both directions. What a peer lacks is `unsupported` in the ledgers, never faked: Add/DeleteReferences on Milo, async-opcua and node-opcua; server diagnostics on Milo, async-opcua and UA-.NETStandard; operation DiagnosticInfos everywhere except UA-.NETStandard; and the Verbose form on open62541.
- `chaos/pubsub` `TestParallelStartClose`: the order check no longer spans a reader restart that fell between the runtime processing a data set and calling the handler (the handler runs after the runtime releases its lock); a restart is bounded by the Timestamp of the earlier data set instead of the handler call.
- The asyncua `monitoreditem.percent-deadband` server case skips as a stack deviation (asyncua 2.1.0 accepts a percent deadband without applying it) instead of failing on the missing adapter feature when the capabilities are required.
- The channel writer tests start with every in-flight slot free: the writer returns the slot of the setup round trip after the write, which can be after the client got the response (`TestChannelWriterCov_SendAfterClose` found a slot still taken).
- `TestPubSub_KeepAliveAndReceiveTimeout` counts the receive timeout of the stopped publisher from the moment it stops; a keep-alive delayed past the 300 ms timeout on a loaded machine (an extra Error → Operational cycle in the reader's states) no longer fails it. The comparison of the keep-alives sent and received waits for the publisher's counter, which is updated after the send returns.
- `TestCloseSemantics` (UDP transport) checks that no receive loop is left after Close instead of comparing goroutine counts, which other goroutines of the test binary change.
- `TestOpen62541LDS_GoServerRegisters` waits for the registration event as well as the FindServers listing; the LDS can list the server before the RegisterServer2 response reaches the registrant.

### Docs

- **README:** the comparison covers all six interop peers (open62541, Eclipse Milo, async-opcua, UA-.NETStandard, node-opcua, asyncua) in one feature table, followed by the interop evidence per peer ledger.
- **New [docs/interop-gaps.md](docs/interop-gaps.md):** what go-opcua does not implement and what to use instead, go-opcua behaviour you may notice, the deviations of each peer stack the interop suite found, and the go-opcua defects interop found, with the version that fixed them.
- `docs/encodings.md` lists the live codec peers per encoding, `docs/pubsub.md` what the other stacks have, and `docs/server-guide.md` what the server does not implement.

---

## v1.8.0

**Date:** 2026-10-24
**Previous release:** v1.7.1

### Summary

Security and robustness release: the server no longer accepts username or issued identity tokens that nobody validated, the secure channel keeps its sequence numbers contiguous when a send fails, and several panics on malformed server responses are now errors. Test coverage of the client, node, secure channel, server and transport code is raised to 93–100% per file.

### Behaviour changes

- **server: username tokens need a validator.** A server with `EnableAuthMode(ua.UserTokenTypeUserName)` and no `WithUsernameValidator` accepted every user name and password. It now rejects them with `Bad_UserAccessDenied`, as it does X.509 user tokens without an `X509UserValidator`. Part 4 leaves the decision to accept a user identity to the server, so this stays within the specification. **Servers that offer username login must register a validator.** The example servers and the integration test server now do; `examples/server_test` takes `-user` and `-password` and offers username login only when both are set.
- **server: warning for auth modes without a validator.** `server.New` logs a warning for every enabled UserName, Certificate or IssuedToken mode that has no validator, since every token of that type will be rejected.
- **server: issued tokens need a validator.** A server with `EnableAuthMode(ua.UserTokenTypeIssuedToken)` accepted every IssuedIdentityToken without checking it. The new `WithIssuedTokenValidator` registers a validator that receives the token as the issuer created it (decrypted where the security policy encrypts it); without one, issued tokens are rejected with `Bad_IdentityTokenRejected`, as X.509 user tokens are without an `X509UserValidator`. **Servers that use issued tokens must register a validator.**
- **uapolicy: AES rejects bad key and IV sizes.** `AES.Encrypt` zero-padded a short key while `Decrypt` did not, and an IV that is not one block long panicked in `cipher.NewCBC*`. Both now return `ErrInvalidSecurityConfig`.

### Fixed

- **uasc:** a request that failed to encode or sign, or was cancelled before a chunk was written, left its response handler behind and used up the sequence numbers of the chunks it never wrote; the peer of a secured channel refuses every chunk after such a gap. The handler is removed and the numbers of unwritten chunks are given back. A chunk whose write failed keeps its number, since part of it may have reached the peer, and an AEAD policy cannot open a chunk that reuses a number. `SendMsgWithContext` did not take the send lock, so concurrent sends could interleave sequence numbers; it does now.
- **client: no reconnect on a fault of a session the client has left.** A request still under way in the session the client had before (typically a Publish when the application activated another session, which closes the previous one) is answered with `Bad_SessionIdInvalid`. The connection monitor took that for the session in use and reconnected. The secure channel now reports such a fault as a `uasc.RequestFault` carrying the request's authentication token, and the monitor ignores faults of a session it no longer uses.
- **client: no second recreation of a subscription on a stale `Bad_NoSubscription`.** A Publish request that reached the server in the moment a subscription was being recreated (deleted, then created again) found the session without subscriptions; the monitor then marked the new subscription broken and recreated it once more, changing its id under the caller. Only the publish loop handles `Bad_NoSubscription` now, and only if no subscription was registered since the request was sent. `Bad_NoSubscription` is no longer a reconnect trigger of the secure channel (only Publish requests get it).
- **server: a channel that cannot send is closed.** The response writer took `ErrSecureChannelClosed` (no active security token) for a response that could not be encoded: it tried a ServiceFault, which failed the same way, and kept the channel instead of closing it. It is treated as a broken connection now. Seen as an intermittent CI hang of `TestChannelWriterCov_FaultOnDeadConnection`; `TestChannelWriterCov_NoActiveToken` reproduces it deterministically.
- **client:** `Node.BrowseName`, `DisplayName`, `AccessLevel` and `UserAccessLevel` panicked on an attribute value of an unexpected type, and `Browse`/`BrowseNext` on a response without exactly one result; they return an error.

### Tests

- Fault and end-to-end tests over real channels and servers: secure channel (every policy, truncated and malformed chunks, sequence gaps, bad signatures, unknown tokens, abort chunks, chunk limits, renewals), client and node APIs, server channel writer, event monitor, historian and PubSub, uacp connections and reverse connect, mDNS sockets (through replaceable OS calls, so no host multicast is needed) and the AES/HMAC/RSA-PSS primitives.
- Regression tests for both client races (`TestStaleSessionFaultIgnored` reproduces the reconnect seen in CI without the fix), and the monitor trigger tests now send `Bad_NoSubscription` on a Publish request, where servers send it.
- `chaos/pubsub` `TestParallelStartClose` no longer reports a data set the kernel delivered late to a reader that had just been restarted: a restarted reader starts over, so the order is only checked between two restarts.
- Own-package coverage per file: `client.go` 61% → 93%, `node.go` 58% → 99.6%, `uasc/secure_channel.go` 51% → 97%, `uasc/secure_channel_renew.go` 69% → 100%, `server/channel_writer.go` 47% → 94%, `server/event_monitor.go` 73% → 100%, `server/historian.go` 79% → 100%, `server/pubsub.go` 84% → 99%, `uacp/conn.go` 84% → 94%, `uacp/reverse.go` 94% → 96%, `internal/mdns/conn_udp.go` 40% → 100%, `uapolicy/crypto_aes.go`, `crypto_hmac.go`, `crypto_rsapss.go` → 100%.

---

## v1.7.1

**Date:** 2026-10-24
**Previous release:** v1.7.0

### Fixed

- **pubsub/sks:** `KeySource` refetched the keys one key change too late: after the change that left it with no future key instead of the one that leaves it with one, as documented. A fetch that took longer than one key lifetime (an SKS under load, a new SignAndEncrypt session per fetch) let the ring run out of keys, and a subscriber rejected the messages of a publisher that had fetched first. A fetch now has two key lifetimes to complete when the SKS hands out two or more future keys.
- **pubsub/sks:** a received message whose token is just ahead of the keys a `KeySource` holds (the peer fetched first) now triggers a fetch, at most once per `MinRetry`.

### Tests

- Fake-clock test of the refresh schedule for 0–5 future keys, a test against an SKS that takes a whole key lifetime to answer, and a test of the token-triggered fetch; each fails on the old schedule.

---

## v1.7.0

**Date:** 2026-10-24
**Previous release:** v1.6.0

### Summary

Feature release adding OPC UA PubSub (Part 14): publishers and subscribers over UDP and MQTT with the UADP and JSON message mappings, UADP message security with the PubSub-Aes128-CTR / PubSub-Aes256-CTR policies, the Security Key Service, the PublishSubscribe information model with its configuration methods in the server, and client helpers to configure any Part 14 server. PubSub is interoperability-tested against open62541 v1.5.9 through [opcua-interop v0.8.1](https://github.com/otfabric/opcua-interop/releases/tag/v0.8.1); Eclipse Milo 1.1.8 has no PubSub implementation. The library stays pure Go without new module dependencies (the MQTT 3.1.1 client is built in).

### Added — PubSub

- **Runtime** (package `pubsub`): `pubsub.New(*ua.PubSubConfigurationDataType, ...)` runs PubSubConnections, WriterGroups, DataSetWriters, ReaderGroups, DataSetReaders and PublishedDataSets from the standard configuration model; components can be added, removed, enabled and disabled at run time and follow the Part 14 state machine (Disabled, Paused, PreOperational, Operational, Error). Publishers: publishing interval and offset, key frames and delta frames (KeyFrameCount), keep-alive, DataSetOrdering, splitting of oversize groups, MQTT topics and retained metadata, PublishedDataItems through a `DataSource`, PublishedEvents through an `EventSource`. Subscribers: filtering by PublisherId / WriterGroupId / DataSetWriterId, sequence number checks, delta frame merging, MessageReceiveTimeout, MajorVersion checks, a `DataSetHandler`, TargetVariables (with OverrideValueHandling) and SubscribedDataSetMirror through a `TargetWriter`. Builders (`UDPConnection`, `MQTTConnection`, `WriterGroup`, `JSONWriterGroup`, `PublishedDataItems`, `DataSetReader`, `Secure`, ...) and `Validate`.
- **Message mappings:** `pubsub/uadp` (all NetworkMessage and DataSetMessage header options, Variant / DataValue / RawData field encodings, key and delta frames, keep-alive, events, DataSetMetaData announcements, message security) and `pubsub/jsonmsg` (`ua-data` with every content mask, `ua-metadata`, `ua-status`). Model in `pubsub/message`; both decoders are fuzzed.
- **Transports:** `pubsub/transport/udp` (`opc.udp://`, unicast and multicast, IPv4 and IPv6) and `pubsub/transport/mqtt` (`mqtt://`, `mqtts://`, MQTT 3.1.1 with QoS 0/1, retain, reconnect and resubscribe) on a dependency-free MQTT client.
- **Security:** `pubsub/security` with the PubSub-Aes128-CTR and PubSub-Aes256-CTR policies (byte-compatible with open62541), `KeyRing` with key rotation, and `KeyService` (SecurityGroups, GetSecurityKeys semantics, authorization: keys only over SignAndEncrypt channels and not to anonymous users by default); `pubsub/sks` with GetSecurityKeys / SetSecurityKeys calls and a key source that pulls keys from a remote SKS and refreshes them before they rotate.
- **Server:** `server.WithPubSub` runs PubSub inside the server with its address space as data source, event source and target; the PublishSubscribe information model (connections, groups, writers, readers, published data sets, status) with AddConnection, RemoveConnection, AddPublishedDataItems, AddPublishedDataItemsTemplate, RemovePublishedDataSet, AddWriterGroup, AddReaderGroup, RemoveGroup, AddDataSetWriter, RemoveDataSetWriter, AddDataSetReader, RemoveDataSetReader, Enable and Disable; `server.WithPubSubAuthorizer`; `Server.EnableSecurityKeyService` (GetSecurityKeys, Add/Remove/GetSecurityGroup) and `Server.EnableSecurityKeyPush` (SetSecurityKeys).
- **Client:** `pubsub/remote` wraps the PubSub configuration methods of any Part 14 server (tested against go-opcua and open62541).
- **Method handlers** receive the calling session and channel (`server.MethodCallerFromContext`), so they can authorize by identity and security mode.
- Examples in `examples/pubsub` (publisher, subscriber, server) and the guide [docs/pubsub.md](docs/pubsub.md).

### Behaviour changes

- **`monitor`:** `ModifyMonitorItems` returns `ErrMonitoredItemNotFound` for a node that is not monitored (it was ignored); a failed `RemoveMonitorItems` keeps the items known (they are still monitored on the server).
- **Reverse connect:** `Dialer.AcceptReverse` reports a server refused at any time since the wait began, also before a failed handshake; new `ReverseListener.Rejected`, `ReverseListener.AcceptSince` and `Dialer.AcceptReverseSince`.
- **Generated files** carry the standard marker `// Code generated ... DO NOT EDIT.` (was `DO NOT EDIT!`), so Go tooling recognises them.

### Fixed

- **Events:** a Publish request could be answered while events emitted before it were still waiting in the subscription's queue, splitting a burst over two notification messages.
- **Reverse connect:** a server refused between opening the client's listener and starting to wait was not reported; the wait ended with only "context canceled".
- **MQTT client:** a QoS 1 / QoS 2 message was handed to the application before its acknowledgement was written, so closing right after receiving it could make the broker deliver it again.
- **`monitor`:** `AddMonitorItems` left the client handles of a failed call behind; `RemoveMonitorItems` forgot its items before the call (see Behaviour changes).
- **XML:** an `XmlElement` whose top-level element had `xmlns=""` directly followed by an attribute was decoded to an element that no XML parser reads (found by fuzzing).
- **PubSub runtime** (found by the chaos and conformance suites): a secured reader accepted unsecured JSON messages and messages verified with another SecurityGroup's keys; UADP fields were placed by one reader's metadata for all readers; the strictest reader's security mode applied to all readers of a writer; a delta-frame field index could size the received DataSet (amplification); a restarted publisher was discarded until its sequence numbers caught up; equal connection names took over each other's MQTT session; a change carried by an unsent delta frame was lost until the next key frame; `Start` right after a cancelled context left the runtime stopped; a refused MQTT re-subscription was not retried.
- **PubSub runtime:** a panic in an application callback (`DataSetHandler`, `DataSource`, `TargetWriter`, event handler) or while decoding crashed the program, with `server.WithPubSub` the whole server; it is now recovered, logged and counted (`Counters.Panics`).
- **PubSub information model:** with concurrent configuration changes a component could end up without a node (its parent's event was handled after its own).
- **ExtensionObject registration:** several generated structures whose Go name differs from the OPC UA name (`UADP*/JSON*MessageDataType`, `NetworkAddressURLDataType`, `ReadValueID`, ...) were never registered; they encoded with TypeId i=0 and decoded to nil.
- **Method argument checks** accept subtypes of the declared built-in type (IntegerId, Duration, ...) and empty arrays; such calls failed with `BadTypeMismatch`.
- **Server:** `Node.DisplayName` raced with Browse when nodes were added while the server runs.

### Tests

- Every library package has at least 90% statement coverage on its own, generated code excluded (`make coverage-gate`, CI job `coverage-gate`; 94% in all).
- A goroutine leak check runs after the tests of every library package; `FuzzServerRawConnection` fuzzes a running server over TCP; chaos suite `chaos/pubsub` (network faults, security attacks, key-rotation storms, SKS outages, broker restarts, configuration churn, 70 parallel writer groups, transport fuzzing).
- The interop suite runs as six parallel CI jobs (`make interop-shard`).

### Interoperability

- Peers: open62541 v1.5.9 and Eclipse Milo 1.1.8 via opcua-interop **v0.8.1** (open62541 with PubSub, MQTT, PubSub encryption and SKS; a `--pubsub-config` server flag; NetworkMessage codec operations; an Eclipse Mosquitto broker).
- PubSub against open62541, in both directions: UADP and JSON codecs byte-exact, live data over UDP and MQTT, Sign / SignAndEncrypt with both policies, SKS pull and push, the runtime as publisher and subscriber, and the information-model methods — 52 verified ledger rows, [`interop/COVERAGE.md`](interop/COVERAGE.md) (393 verified rows in all). Milo 1.1.8 has no PubSub.
- UDP multicast is verified on Linux, with the adapter in the host's network namespace (it does not cross Docker Desktop's VM). Not interop-verified: keep-alive from open62541 (it sends none).

### Known limitations

- No Ethernet (`opc.eth://`) or AMQP transport, no chunked NetworkMessages, no UADP discovery requests; DataSetMetaData announcements over UDP are not sent (metadata is published on broker transports).
- Not implemented in the information model: Diagnostics objects, AddVariables / RemoveVariables, AddPublishedEvents, AddDataSetFolder, ReserveIds, the PubSub configuration file methods, CreateTargetVariables / CreateDataSetMirror; the optional SKS methods InvalidateKeys and ForceKeyRotation.

---

## v1.6.0

**Date:** 2026-10-11
**Previous release:** v1.5.0

### Summary

Feature release closing the largest gaps to open62541: ECC security policies, reverse connect, a Local Discovery Server with mDNS, the OPC UA JSON and XML data encodings, and server-side DataChangeFilter / sampling. Every feature is interoperability-tested against open62541 v1.5.9, and against Eclipse Milo 1.1.8 where Milo implements it, through [opcua-interop v0.7.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.7.0).

Several changes alter what existing clients and servers observe — read **Behaviour changes** before upgrading.

### Behaviour changes

- **Minimum Go version is now 1.26** (was 1.25), required by `golang.org/x/crypto` v0.58.0.
- **Unchanged values no longer notify.** A write of an identical value, or a `ChangeNotification` without a change, produces no data-change notification unless the monitored item's trigger asks for it (a timestamp-only change needs `StatusValueTimestamp`).
- **The sampling interval is enforced.** A monitored item with a sampling interval above 0 is sampled at most once per interval and keeps the latest value; previously every write was queued. Request `0` to receive every change. `RevisedSamplingInterval` is now the revised request (0 stays 0, negative means the publishing interval, otherwise 1 ms – 1 h); it used to echo the publishing interval.
- **Unusable monitored items are rejected** per item: a malformed `IndexRange` (`BadIndexRangeInvalid`), a filter on a non-Value attribute or non-numeric deadband (`BadFilterNotAllowed`), a percent deadband without `EURange` (`BadMonitoredItemFilterUnsupported`), an invalid deadband (`BadDeadbandFilterInvalid`). They were silently accepted.
- **NodeSet2 import applies variable values and attributes.** `ImportNodeSetXML` and the built-in namespace 0 now set Value, DataType, ValueRank, ArrayDimensions and (when present) AccessLevel / UserAccessLevel of variables; standard variables that used to be empty now serve their values.
- **X.509 user tokens must be signed.** On a secured channel the server requires the `UserTokenSignature` (proof of possession); a missing signature used to skip the check.
- **Non-enabled security policies are rejected at OpenSecureChannel** (`BadSecurityPolicyRejected`) instead of at CreateSession.
- **A server no longer acts on a ReverseHello it receives.** It used to close the connection and dial the announced ServerUri as a TCP address; it now answers `BadTcpMessageTypeInvalid`.
- **FindServers** applies the `serverUris` filter to the server itself and honours `endpointUrl` when choosing its discovery URLs.
- **Event monitored items** no longer receive a data notification when `ChangeNotification` is called on their node; creating a monitored item no longer re-notifies the other items on that node.
- **Secured channels reject out-of-sequence chunks** (`BadSequenceNumberInvalid`, Part 6 §6.7.2.4). A peer that does not keep sequence numbers contiguous on a secured channel loses its channel; channels without security are not checked.
- After a failed CreateSubscription the client deletes subscriptions of its own session that it does not know; `Server.Close` waits (bounded by the request timeout) for a discovery registration already on the wire; DeleteMonitoredItems is synchronous; Variant arrays are limited to 32 dimensions.

### Added — security

- **ECC security policies `ECC_nistP256` and `ECC_nistP384`** on client and server: ECDSA-signed OpenSecureChannel, ephemeral ECDH + HKDF key derivation with fresh keys on every renewal, `EccEncryptedSecret` for passwords and issued tokens, ECDSA X.509 user tokens.
- **AEAD ECC security policies `ECC_nistP256_AesGcm`, `ECC_nistP256_ChaChaPoly` and `ECC_curve25519`** (OPC UA 1.05.07, the set open62541 enables by default) on client and server: AES-128-GCM / ChaCha20-Poly1305 message protection, Ed25519 application and user certificates, X25519 key agreement, ChannelThumbprint binding, key chaining on renewal and channel-bound session signatures.
- New dependency: `golang.org/x/crypto` v0.58.0 (ChaCha20-Poly1305 only). The library remains pure Go; no cgo.
- Client options `PrivateKeySigner(crypto.Signer)` and `AuthPrivateKeySigner(crypto.Signer)`; `PrivateKeyFile` also loads ECDSA keys (PKCS#8, SEC1; PEM or DER).
- Server option `ApplicationIdentity(cert, key)`, repeatable: one application certificate per key type for servers that offer RSA and ECC endpoints.
- `opcua.SelectEndpoint(endpoints, policy, mode, certDER)` picks the best endpoint usable with the client certificate's key type; ECC endpoints rank above RSA ones, AEAD policies first, and endpoints with equal advertised SecurityLevel are ordered by the library's ranking.
- A server with ECC-only certificates can register with a discovery server; the registration client uses the certificate that fits the endpoint.
- The client and server refuse a security policy that is not implemented by name instead of failing later in the handshake.

### Added — transport

- **Reverse connect** (Part 6 §7.1.3) on client and server. Client: `opcua.ReverseConnect(listenAddr, …)`, `opcua.ReverseConnectListener(l, …)` (one listener serves many servers), `opcua.ReverseServerURI`; the announced ServerUri and EndpointUrl are validated and, with security, the ServerUri must match the server certificate. Works with `AutoReconnect` and the discovery helpers. Server: `server.WithReverseConnect(clientURL, …)`, `Server.AddReverseConnect`, `Server.ReverseConnects` and a `ReverseConnect` handle; one idle connection is kept available, with retry back-off.
- `uacp`: `ReverseDialer`, `Conn.AcceptHello`, `ListenReverse` / `NewReverseListener` / `ReverseListener`, `Dialer.AcceptReverse`; sentinel `errors.ErrReverseHelloRejected`.

### Added — discovery

- **Local Discovery Server:** `server.WithLocalDiscoveryServer` accepts RegisterServer / RegisterServer2 (validation, expiry after 60 min by default, semaphore files, registration only over a secured channel and only for the registrant certificate's URI unless opted out) and returns registered servers from FindServers.
- **Registration with a discovery server:** `server.WithDiscoveryRegistration(ldsURL, …)` registers in the background (RegisterServer2 with fallback to RegisterServer), renews, retries with back-off and unregisters on `Close`, without blocking `Start`.
- **Multicast discovery (LDS-ME):** `server.WithMulticastDiscovery` announces the server (and, on an LDS, its registered servers) with a built-in, dependency-free mDNS / DNS-SD implementation and serves FindServersOnNetwork with record ids, paging and capability filter.
- Client: `RegisterServer`, `RegisterServer2`, `FindServersWithFilter`, `FindServersOnNetworkWithFilter`, `opcua.DiscoverServers`, `opcua.DiscoveryURL` (well-known LDS port 4840).
- `server.ApplicationURI(uri)` for servers without a certificate; `Server.RegisteredServers()`, `Server.ServersOnNetwork()`; `uasc.SecureChannel.RemoteCertificate()`.

### Added — data encoding

- **OPC UA JSON (Part 6 §5.4) and XML (Part 6 §5.3) DataEncodings** in `ua`: `EncodeJSON` / `DecodeJSON` / `EncodeXML` / `DecodeXML` for all built-in types, generated structures, enumerations and registered custom structures. JSON forms: 1.05 Compact (default) and Verbose, 1.04 reversible; 1.04 non-reversible encode only. This is a data encoding — the transport stays UA-TCP / UA Binary.
- Options `WithJSONForm`, `WithNamespaceArray`, `WithServerArray`, `WithIndent`, `WithMaxDepth`, `WithMaxArrayLength`, `WithXMLRootName`, `WithoutXMLNamespace`; `RegisterDataTypeInfo` for the DataType / encoding NodeIds of custom structures; `StatusCodeDesc.Symbol`.
- Existing `MarshalJSON` display formats of `Variant`, `DataValue`, `NodeID` and friends are unchanged.

### Added — subscriptions

- **Server honours `DataChangeFilter`** on CreateMonitoredItems and ModifyMonitoredItems: triggers Status, StatusValue (default) and StatusValueTimestamp; absolute deadband on numeric scalars and arrays; percent deadband on variables with an `EURange` property.
- **Server honours the monitored item's `IndexRange`**: only the range is reported and changes outside it do not trigger.
- Client: `opcua.NewDataChangeFilter` and `SubscriptionBuilder.DataChangeFilter`.

### Fixed

Found by the new chaos and parallelism suites for the v1.6.0 features (`chaos/secure`, `chaos/datachange`, `chaos/reverse`, `chaos/discovery`, `chaos/codec`):

- **Security:** sequence numbers of secured channels were never verified — on the RSA policies and `ECC_nistP256` / `ECC_nistP384` a replayed request was executed again and a multi-chunk message with a lost or reordered chunk was accepted. Multi-chunk messages on SignAndEncrypt channels with a block cipher exceeded the peer's 65535-byte buffer by one byte and dropped the connection. Races on channel renewal (server rewrote its policy and peer certificate) and on unsolicited OpenSecureChannel messages (client). `ActivateSession` wrote the protected password into the identity token shared by all sessions.
- **Monitored item ids are stable across reconnects.** The id `Monitor` returns keeps denoting the same item after the subscription is recreated on the server; `Unmonitor`, `ModifyMonitoredItems`, `SetMonitoringMode` and `SetTriggering` translate it to the server's current id. Before, an id obtained before a reconnect could address a different item afterwards. The id returned by `Monitor` can therefore differ from the id on the wire.
- **A SecureChannel renewal cannot change the security mode.** The server refuses an OpenSecureChannel renewal that names another mode than the channel was opened with (`BadSecurityModeRejected`); it used to adopt it, so a renewal could downgrade SignAndEncrypt to Sign.
- **Subscriptions follow a session change.** When the application re-activates or replaces the session after the client's own recovery, subscriptions are recreated in the new session instead of being deleted on the server while the client still lists them; a subscription that stays silent for three keep-alive intervals while other Publish responses arrive is recreated. Before, a client could report `Connected` with a subscription that never delivered again.
- **`TransferSubscriptions` requires the owner.** The server only transfers a subscription to a session of the same user (`BadUserAccessDenied` otherwise); it used to hand any subscription to any session that asked by id.
- Publish requests queued in a session are answered when the session is closed (`BadSessionClosed`) or its subscriptions are transferred away, instead of staying unanswered until the client's request timeout.
- A notification message republished during recovery is no longer delivered a second time.
- `uacp`: an Acknowledge with buffer sizes above those of the Hello made the client slice past its buffer and panic.
- **Session AuthenticationTokens are unguessable.** The server issues an opaque NodeId with 256 bits from the cryptographic random generator; it used to be a 31-bit number from `math/rand`.
- **Client:** a response with too few results panicked `ReadValue`, `WriteValue`, `WriteAttribute`, `Browse`, `Monitor` and `Cancel` (now `BadUnknownResponse`); a subscription whose recreation failed on a healthy connection was never retried; a lost CreateSubscription response left an orphan subscription on the server; the mode set with `SetMonitoringMode` was lost on recreation; `ModifyMonitoredItems` could dereference nil when racing `Unmonitor`; a server's Error message at OpenSecureChannel could surface as `io.EOF` instead of its status code.
- **Server:** a request handled during `Close`, or a refused CreateSession, left a session behind; two samples could be taken within one sampling interval and the sampler timer stayed armed after its last item; data race in `Node.Value()`; an IndexRange write into an Uncertain array was rejected; built-in NodeSet values were shared (and raced) between all servers in a process.
- **Discovery:** `Close` abandoned an in-flight registration that the discovery server then processed after the unregistration; a registration with a lost response was not unregistered; `RegisterRequestTimeout` did not bound an attempt; overlapping registrations withdrew each other's mDNS announcement; `ServersOnNetwork()` was not empty after `Close`.
- **Data encoding:** concurrent first use, `RegisterDataTypeInfo` while coding, half-registered custom types, order-dependent lookup by name, mismatched XML metadata for ExtensionObjects; Variant dimension overflow and unbounded array allocation from a length prefix.

Other fixes:

- `ua`: nil `*Variant`, `*DataValue`, `*DiagnosticInfo` and `*GUID` pointers and body-less ExtensionObjects no longer panic or corrupt the binary stream; DateTime values outside 1678–2262 no longer overflow; `NewVariant` accepts arrays of ByteStrings of different lengths.
- Client: the endpoint re-fetch after `BadCertificateInvalid` uses the client's own connection method (dial or reverse listener).

### Interoperability

- Peers: open62541 v1.5.9 and Eclipse Milo 1.1.8 via opcua-interop **v0.7.0** (OpenSSL-based open62541 build with ECC endpoints, reverse connect, LDS / mDNS, DataChangeFilter flags and a `codec` command on both adapters).
- See [`interop/COVERAGE.md`](interop/COVERAGE.md) for the per-direction evidence of every feature above; Milo 1.1.8 has no ECC, no reverse connect and no discovery server, so those rows are open62541-only.

### Known limitations

- ECC: `Sign` mode follows open62541's key derivation, which differs from the Part 6 1.05.07 Sign-only rule implemented by the OPC Foundation .NET stack; use `SignAndEncrypt` when in doubt. Where open62541 and the specification text differ for the AEAD policies, go-opcua follows open62541 (see `docs/security.md`). Not implemented: `ECC_curve448`, Brainpool.
- mDNS: no probing / conflict resolution; real multicast is verified on Linux only.
- open62541 v1.5.9 cannot XML-encode structures, enumerations, DataValue or matrices and cannot JSON-decode a structure encoded in place in an ExtensionObject; go-opcua reads and writes the Part 6 forms.
- When registering with a discovery server its certificate is not validated unless `RegisterCertificateValidator` is set.
- An item re-enabled from `Disabled` does not report immediately; `ModifySubscription` does not re-revise items that use the default sampling interval.
- A forged mDNS announcement can stay cached for up to 24 h.
- Triggering links set with `SetTriggering` are not restored when a subscription is recreated after a reconnect.

---

## v1.5.0

**Date:** 2026-10-11
**Previous release:** v1.4.0

### Summary

Hardening release. Peer interoperability moves to open62541 v1.5.9 / Eclipse Milo 1.1.8 (opcua-interop v0.6.0) with 32 more verified ledger rows; a chaos / parallelism suite and a much larger Go↔Go conformance suite found and fixed defects in SecureChannel renewal, session handling, the publish loop and reconnect; the OPC UA schema is refreshed to UA-1.05.07; merged coverage is 91% with a 90% gate.

Several fixes change behaviour that existing deployments may have relied on — read **Behaviour changes** before upgrading.

### Behaviour changes

- **Sessions are enforced.** Services other than discovery and session management require an activated session; requests without one (or with a closed session's token) get `BadSessionIdInvalid` / `BadSessionNotActivated` instead of being served.
- **Sessions time out.** The server drops a session that is idle longer than its revised timeout, with its subscriptions.
- **Enabled security is enforced.** `CreateSession` over a policy/mode the server did not enable is rejected (`BadSecurityPolicyRejected` / `BadSecurityModeRejected`).
- **SecurityToken lifetime is revised and enforced.** The server grants at most its configured lifetime (and that value when the client asks for `0`), retires superseded tokens after lifetime + 25%, and closes a channel whose token was never renewed. Clients retire superseded tokens on the same schedule, measured on the local clock.
- **Stalled clients are disconnected.** A client that does not read a response within `WithResponseWriteTimeout` (default 15s) loses its channel.
- **Subscription ids** are monotonic from a random base and never reused; they no longer start at 1.
- **`Client.Close` waits** for the client's monitor goroutine (bounded by the context); the dial timeout now also covers the HEL/ACK handshake.
- **Attribute types:** `EventNotifier` is served as Byte (was Int16); the `DataType` of helper-created variables is a NodeId derived from the value (was `ExpandedNodeId i=267`); `NewFolderNode` no longer adds a reference back to the namespace Objects folder (the hierarchy was cyclic).
- An untrusted client certificate is answered with a transport `ERR` (`BadCertificateUntrusted`) instead of an undecodable ServiceFault.

### Added

- **Server options** `WithResponseWriteTimeout(d)` (default 15s) and `WithMaxPendingResponses(n)` (default 256).
- **`uasc.SecureChannel.Disconnected()`** and **`uasc.SecureChannel.ReleaseTokens()`**.
- **Server sends `StatusChangeNotification(BadTimeout)`** when a subscription expires; AutoReconnect clients recreate expired or deleted subscriptions (and on `BadNoSubscription`) through the existing recovery handler.
- **Panic containment in the server:** a panic in a handler or application callback fails that request with `BadInternalError`; a panic while decoding drops only that channel. Both are logged at Error with the stack.
- **AddNodes applies `VariableAttributes`** (value, data type, access levels, display name, description); an unset `SpecifiedAttributes` mask is read as "all", as open62541 clients send it.
- **Status codes** `StatusUncertainOverRange`, `StatusUncertainUnderRange`; new structures (`NumberRange`, alias-name types) and 123 NodeIds from the UA-1.05.07 schema.
- **`chaos/` package** and `make chaos`: seeded chaos monkey over a fault-injecting proxy (`internal/testutil.ChaosProxy`), parallelism tests and hostile raw-frame tests. Knobs: `CHAOS_SEED`, `CHAOS_DURATION`, `CHAOS_LOG`.
- **Conformance suite** grown from ~85 to ~200 Go↔Go tests (security matrix, identities, session and channel lifecycle, raw Publish protocol, monitored items, events, history, view, attributes, node management, query); the API matrix now also covers `Node`, `Subscription`, the builder, `Session`, `monitor` and every client/server option.
- **`.github/workflows/schema-check.yml`**: weekly check that opens a tracking issue when the upstream OPC Foundation schema changes.

### Fixed — server

- **SecureChannel renewal** reused the TokenId and swapped keys on the live instance: every peer session (open62541, Milo) failed with `could not verify signature` at its first renewal. Renewal now issues a new TokenId on a fresh instance and keeps the old token valid until it expires.
- A renewal request carrying a session `AuthenticationToken` (as open62541 sends) was rejected with `BadSecureChannelTokenUnknown`.
- Username passwords on secured endpoints were never decrypted; X509 user-token signatures were checked against the wrong nonce.
- One client that stopped reading stalled every client (responses are now written by a per-channel writer).
- A truncated 8–11 byte frame panicked `readChunk`; a silent TCP connection blocked the accept loop; a peer reset during the handshake stopped the server accepting connections.
- Lock-order deadlock between the subscription and monitored-item services; recursive read lock in Browse; data races on subscription parameters, `Node.refs` and stored `DataValue`s.
- Publish responses were sent on the channel a subscription was created on rather than the requesting one; a transferred subscription kept serving the old session; Publish without a subscription hung; a full publish queue dropped requests silently; idle subscriptions effectively never expired.
- RBAC could not be enabled through the public API; reading `RolePermissions` failed the whole Read; user-defined event types were rejected in `OfType`; MapNamespace variables could not be monitored.
- NodeSet2 import stored references declared on both ends twice and kept the `"1:"` prefix in browse names; reverse raw history reads returned the oldest values; `SoftwareVersion` was ignored in ServerStatus.
- Building the address space was quadratic in the number of references; `server.New` is several times faster.

### Fixed — client

- Reconnect closed the session it had just restored, leaving the client `Connected` with dead subscriptions; the restore path never resumed publishing; a second drop during recovery left the client stuck on a dead channel; a failed recreate dropped the subscription for good.
- A consumer that stopped reading after `Cancel` blocked the publish loop for all subscriptions; `Subscribe` / `Cancel` could block for a keep-alive period.
- The HEL/ACK handshake ignored the context and had no timeout; `Close` could race the monitor and leak a server session; a failed `Connect` left the state at `Connecting`.
- The client adopted the policy URI and certificate from every OpenSecureChannel response; token renewal rounded the lifetime to whole seconds (a tight renew loop below 1.34s).
- `Monitor` remembered items the server had rejected, which aborted subscription recreation after a reconnect.
- Encoding a nil `*LocalizedText` panicked.

### Interoperability

- Peers: **open62541 v1.5.9**, **Eclipse Milo 1.1.8** via [opcua-interop v0.6.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.6.0) (digest-pinned in `interop/harness_test.go` and `.github/workflows/interop.yml`).
- Ledger: **231 verified** rows (was 199). Newly verified: SecureChannel renewal under a live subscription (all four directions), HistoryRead continuation C→O / C→M, RegisterNodes (all four), AddNodes / DeleteNodes (C→O, O→S, M→S), ModifySubscription and ModifyMonitoredItems (C→O, C→M), SetPublishingMode and SetMonitoringMode (all four), EventFilter WhereClause comparison operators and event queue overflow (C→O, C→M).
- Recorded peer limits: the Milo reference server has no NodeManagement service set; Milo's SDK does not pass `ReleaseContinuationPoints` to its history backend.

### Changed

- **Schema** refreshed to UA-1.05.07 (2026-07-30 hotfix); `schema/update-schema.sh` now fetches the upstream `latest` branch and writes `Opc.Ua.NodeSet2.xml` to `internal/schema/`, where it is embedded.
- **Coverage gate** raised from 80% to 90% (`make coverage`, `codecov.yml`); merged coverage is 91%.

### Known limitations

- Request handling is still serial: a slow or blocking handler (for example a user method callback) delays all clients. Only the write side is decoupled.
- Reference types and browse names created through the node helpers are always in namespace 0.
- Any `BadSessionIdInvalid` / `BadSubscriptionIdInvalid` / `BadNoSubscription` service fault makes the client start recovery, including faults provoked by an application request.
- DataChangeFilter (deadband, trigger) and the sampling interval are ignored by the server; every write notifies.
- Raw history delete removes the sample at the end time (Part 11 specifies an exclusive end).
- `ServerStatus` child nodes `BuildInfo`, `ShutdownReason` and `SecondsTillShutdown` have the wrong value types; `MapNamespace` reads are not synchronised with writes.

---

## v1.4.0

**Date:** 2026-07-30
**Previous release:** v1.3.1

### Summary

Minor release: make logging silent by default (no longer delegates to `slog.Default()`), document the dual error model and lifecycle/observability contracts, and ship subscription/session correctness fixes that were staged ahead of the release.

### Added

- **ERRORS.md** — Go sentinel errors vs wire `ua.StatusCode`.
- **OBSERVABILITY.md** — silent slog default and metrics callback semantics.
- Client guide / API sections for lifecycle and concurrency.
- **Makefile `vuln`** — `govulncheck ./...`, included in `make check`.
- Unit tests for `discardHandler` (`Handle` / `WithAttrs` / `WithGroup`) on client and server, plus `WithSlogLogger(nil)`.
- **`uasc.NewCryptoChannel`** — construct a crypto-only `SecureChannel` for session/user-token helper tests (not for Open/SendRequest).
- **`export_test.go`** — testing helpers for subscription recreate paths (`TestingRecreateSubscription`, `TestingRecreateDelete`, `TestingRecreateCreate`).
- Deeper coverage for subscription notify/publish/recreate, server session service, history continuation, attribute service, and secure-channel crypto helpers.

### Changed

- **Default logger** — client (`newConfig`) and server (`New` / `newServerNoNS`) use a discard `slog.Handler` (`Enabled` always false). `WithLogger(nil)`, `SetLogger(nil)`, and `WithSlogLogger(nil)` restore that silent default.
- **API.md** / **README** — document silent logging; link ERRORS and OBSERVABILITY guides.
- **README** — note Go 1.25 floor tracks `go.mod` / CI and codegen tooling.
- **golang.org/x/sys** — bump indirect `v0.42.0` → `v0.44.0` (fixes [GO-2026-5024](https://pkg.go.dev/vuln/GO-2026-5024); Windows-only, not called by this module).

### Fixed

- **Server session timeout clamps** — `sessionTimeoutMin` / `Max` / `Default` are now proper `time.Duration` values (`100ms` / `30m` / `60s`). Previously they were bare integers compared against `time.Duration`, so the floor was effectively ~100ns rather than 100ms.
- **Subscription recreate** — after a successful standalone `recreateSubscription`, call `resumeSubscriptions` so the publish loop is not left permanently paused when the last subscription was forgotten during recreate.

### Compatibility

Behavioural change: applications that relied on the previous default of writing through `slog.Default()` must pass an explicit logger via `WithLogger` / `SetLogger`. Protocol behaviour is otherwise unchanged aside from the session-timeout clamp and subscription-recreate resume fixes above.

---

## v1.3.1

**Date:** 2026-07-25
**Previous release:** v1.3.0

### Summary

Patch release raising the **core-library coverage gate to 80%** and aligning Codecov with the local `make coverage` metric. No public API or protocol behaviour changes.

Highlights:
- **`make coverage` threshold 75% → 80%** — measured with `-coverpkg` over `COVER_PKGS` (unit + conformance)
- **Codecov aligned** — CI passes the same `COVER_PKGS` list as `coverpkg` to [`go-ci.yml@v2`](https://github.com/otfabric/.github/blob/v2/.github/workflows/go-ci.yml) ([otfabric/.github v2.0.2](https://github.com/otfabric/.github/releases/tag/v2.0.2))
- **Unit-test depth** for event WhereClause evaluation, `EmitBaseEvent`, HistoryRead/Update dispatch, historian delete/modified/aggregates, client certificate trust-list option, and package-level discovery helpers
- **`codecov.yml`** — project target 80%; ignore `examples/`, `cmd/`, `tests/`, `interop/`, `internal/testutil/`

### Testing and CI

- `server/event_monitor_test.go` — `evalEventFilter` operators (`OfType`, comparisons, `And`/`Or`/`Not`), cyclic/null passthrough, `EmitBaseEvent` delivery/filtering/disabled mode
- `server/attribute_service_test.go` — HistoryRead (raw / modified / at-time / processed / release CP) and HistoryUpdate (update / delete raw / delete at-time) with `SetHistorian`
- `server/historian_ext_test.go` — `DeleteRawModified`, `ReadModified`, Min/Max/Count aggregates
- `server/server_config_options_test.go` — `WithClientCertificateTrustList`
- `discovery_helpers_test.go` — package-level `FindServers` / `GetEndpoints` / `FindServersOnNetwork`
- `server/alarms_scaffold_test.go` — `AlarmsConditionsSupported` probe
- `.github/workflows/ci.yml` — `coverpkg` matches Makefile `COVER_PKGS`
- `codecov.yml` — status target and ignore paths

### Compatibility

No intentional breaking changes. Library behaviour is unchanged; only tests, coverage gates, and CI/Codecov configuration.

---

## v1.3.0

**Date:** 2026-07-25
**Previous release:** v1.2.0

### Summary

Minor release focused on **Part 4 correctness** for Read/Write/Browse, **subscription and monitored-item semantics**, **event subscriptions**, **subscription recovery**, and **historical access** — with matching public APIs and a large expansion of open62541 / Milo interop coverage ([opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0)). Also absorbs race-detector test timeout fixes that were prepared as an unreleased v1.2.1 patch.

Highlights:
- **IndexRange** on array and matrix Values, with Part 4 status codes and helpers in `ua`
- **Monitored-item queues** that honor `QueueSize`, `DiscardOldest`, and the Overflow InfoBit
- **Subscription lifecycle** — revise clamps, monitoring/publishing modes, `MoreNotifications`, Publish ACK, delete and lifetime expiry
- **Events** — `EventFilter` (SelectClauses / OfType / comparison WhereClauses), `EmitBaseEvent` with custom `Fields`
- **Republish / TransferSubscriptions** on server and client (`Client.Republish`, `Client.TransferSubscriptions`) plus `WithSubscriptionRecoveryHandler`
- **HistoryRead / HistoryUpdate** via pluggable `HistoryProvider`; default `*Historian` also covers update/delete/at-time/modified/processed aggregates
- **Interop evidence ledger** — **199** verified / **316** total rows; **376** interop test functions against digest-pinned adapter images
- **Public API freeze** for the v1.3.0 surface (see [`docs/api-freeze-review.md`](docs/api-freeze-review.md)); Query / NodeManagement / A&C stay out of scope
- **Server test suite under `-race`** no longer times out in CI (nodeset import cache + Query subtype recursion guard)

No intentional breaking changes for correct callers. Servers that previously ignored queue or monitoring-mode parameters now follow Part 4 — notification batches may differ.

### Read, Write, and Browse

- **IndexRange / NumericRange** — 1D (`"i"`, `"i:j"`) and multi-dimensional (`"a:b,c:d"`) Value Read/Write; ByteString IndexRange slices bytes. Scalar + IndexRange → `BadIndexRangeInvalid`; empty/out-of-range → `BadIndexRangeNoData`; write size mismatch → `BadIndexRangeDataMismatch`.
- **TimestampsToReturn** — Read and DataChange notifications honor Source / Server / Both / Neither; invalid enum → `BadTimestampsToReturnInvalid`.
- **Write EncodingMask** — value-only Writes succeed; status and/or timestamp bits → `BadWriteNotSupported`.
- **Browse ResultMask** — omitted fields are cleared on `ReferenceDescription`s (`NodeID` always kept).
- **BrowseNext** — early `ReleaseContinuationPoints` invalidates the token (`BadContinuationPointInvalid`).
- **Client certificate trust** — `WithClientCertificateTrustList` is enforced at `OpenSecureChannel` (CreateSession retained as defense-in-depth).

### Subscriptions and monitored items

- **QueueSize** revised to `max(1, requested)` (cap 100), returned as `RevisedQueueSize`.
- **DiscardOldest** — `true` keeps the newest `QueueSize` samples; `false` keeps the oldest `QueueSize-1` plus the newest (e.g. writes `1..5` / QS=3 → `[1,2,5]`).
- **Overflow** — InfoBit `0x480` when `QueueSize > 1` and the queue overflows; queues are per-item.
- **SetMonitoringMode** — Disabled (no enqueue) / Sampling (enqueue only) / Reporting (Publish).
- **SetPublishingMode** — disable holds queues; re-enable delivers the queued window.
- **Create/ModifySubscription revise** — publishing interval clamped; `RevisedLifetimeCount >= 3 × RevisedMaxKeepAliveCount`.
- **MoreNotifications** — honors `MaxNotificationsPerPublish` with partial drain.
- **Publish ACK** — Results + AvailableSequenceNumbers; keepalives do not fabricate DataChange.
- **Delete / lifetime expiry** — second delete → `BadSubscriptionIdInvalid` / `BadMonitoredItemIdInvalid`; idle lifetime removes the subscription.
- **monitor package** — zero-value `Request.MonitoringMode` means Reporting (use `SetMonitoringMode` for Disabled/Sampling).

### Events

- Event monitored items accept `EventFilter` SelectClauses and WhereClause operators (`OfType`, comparisons, `And`/`Or`/`Not`); invalid filters are rejected.
- `EmitBaseEvent` delivers a `BaseEventType`-shaped event (optional custom `Fields`) and applies each item’s filter.
- `EmitEvent` remains for raw `EventFieldList` delivery.
- `ModifyMonitoredItems` can update a live EventFilter.
- Event queues are bounded (max 50). Alarms/Conditions, historical events, and shelving are not included.

### Subscription recovery

- **Server Republish / TransferSubscriptions** — returns available sequences; missing → `BadMessageNotAvailable`; transfer reassigns session/channel under lock.
- **Client helpers** — `Client.Republish` (protocol response only; does not mutate notify channels) and `Client.TransferSubscriptions`.
- **`WithSubscriptionRecoveryHandler`** — observes Transfer → Republish → Recreate outcomes during `AutoReconnect`.
- ACK removes sequences from the retransmission set.
- `SendInitialValues` is accepted but currently a no-op. Durable subscriptions are not included.

### Historical Access

- Pluggable `HistoryProvider`; default in-memory `*Historian` (per-node ring buffer, default 1000 samples, process-lifetime only).
- Raw `ReadRawModifiedDetails` with session-bound continuation points (30s TTL, max 100 active).
- Optional interfaces on the same provider (implemented by `*Historian`): UpdateData, DeleteRawModified (`isDeleteModified=false`), DeleteAtTime, ReadAtTime, ReadModified, ReadProcessed (Average/Minimum/Maximum/Count).
- `returnBounds` is accepted but bounding/interpolation is not implemented for raw reads. Historical events are not included. HistoryRead stays unsupported until `SetHistorian` is configured.

### New and changed public APIs

#### `ua` — NumericRange and timestamp helpers

```go
type NumericRange struct {
    Start int // inclusive
    End   int // inclusive
}

func ParseNumericRange(s string) (NumericRange, error)
func ParseNumericRanges(s string) ([]NumericRange, error)
func SliceVariantRead(v *Variant, rangeStr string) (*Variant, StatusCode)
func MergeVariantWrite(current *Variant, rangeStr string, newVal *Variant) (*Variant, StatusCode)
func ApplyTimestampsToReturn(dv *DataValue, ts TimestampsToReturn) StatusCode
```

Used by the server for Value IndexRange and timestamp filtering; safe to call directly.

#### `opcua` — client recovery helpers

```go
func (c *Client) Republish(ctx context.Context, subscriptionID, sequenceNumber uint32) (*ua.RepublishResponse, error)
func (c *Client) TransferSubscriptions(ctx context.Context, subscriptionIDs []uint32, sendInitialValues bool) (*ua.TransferSubscriptionsResponse, error)
func WithSubscriptionRecoveryHandler(f func(SubscriptionRecoveryEvent)) Option
```

#### `server` — BaseEvent emission

```go
type BaseEvent struct {
    EventID    []byte
    EventType  *ua.NodeID
    SourceNode *ua.NodeID
    SourceName string
    Time       interface{} // time.Time
    Message    *ua.LocalizedText
    Severity   uint16
    Fields     map[string]*ua.Variant // custom SelectClause fields
}

func (s *Server) EmitBaseEvent(nodeID *ua.NodeID, event *BaseEvent) error
```

#### `server` — HistoryProvider / Historian

```go
type HistoryProvider interface {
    ReadRaw(nodeID *ua.NodeID, startTime, endTime time.Time, numValues uint32, returnBounds bool, continuationPoint []byte) (*ua.HistoryReadResult, error)
    ReleaseContinuation(continuationPoint []byte)
}

// Optional capabilities (type-assert; *Historian implements all):
// HistoryDataUpdater, RawHistoryDeleter, AtTimeHistoryDeleter,
// AtTimeHistoryReader, ModifiedHistoryReader, ProcessedHistoryReader

func NewHistorian() *Historian
func (h *Historian) EnableNode(nodeID *ua.NodeID, maxSamples int)
func (h *Historian) RecordValue(nodeID *ua.NodeID, dv *ua.DataValue)
func (h *Historian) IsEnabled(nodeID *ua.NodeID) bool
func (s *Server) SetHistorian(h HistoryProvider)
```

### Interoperability

Verified four-direction against open62541 and Milo for IndexRange, timestamps, Browse ResultMask / BrowseNext release, queue windows, subscription timestamps, and subscription lifecycle (revise / publishing-mode / monitoring-mode / delete). Write EncodingMask is verified in three directions; Go→Milo is `unsupported` (Milo soft-accepts). Peer capability rows on [opcua-interop v0.5.0](https://github.com/otfabric/opcua-interop/releases/tag/v0.5.0) include:

- `discovery.find-servers` / `translate.browse-path` — all applicable directions
- `event.subscription` / decode / select / `of-type` / `severity-threshold` — all four (as applicable)
- `history.read.raw` — all four; `history.read.continuation` — open62541→Go and Milo→Go
- `subscription.server.republish` / `transfer` — open62541→Go and Milo→Go
- `subscription.client.republish` / `transfer` — Go→open62541 and Go→Milo
- `subscription.recovery.reconnect` — Go→open62541 and Go→Milo (`recreated`)

| Image | Pin |
|-------|-----|
| open62541 | `ghcr.io/otfabric/opcua-interop-open62541@sha256:f2cad1899750433cf99268b59f2c9dd2747f6960d2a3ea1b736b10e77b36c084` |
| Milo | `ghcr.io/otfabric/opcua-interop-milo@sha256:88cbb7ce46a474fbfeaa7c4ab31b53bb1968e48f5593a1cdcb39c7bcaf53a0e9` |

Digests are fix-forwarded on the same `v0.5.0` tag when opcua-interop requirements change (no RC / `v0.5.1` pins). See [INTEROP.md](INTEROP.md) and [`interop/COVERAGE.md`](interop/COVERAGE.md) for the full matrix. Docs updated in `API.md`, `README.md`, and `docs/*`.

### Bug fixes and test infrastructure

Absorbed from the skipped v1.2.1 patch:

- **`server` tests: nodeset import cached across tests** — `newTestServer()` was calling `New()` (full built-in XML nodeset import, ~0.4 s each under `-race`) for every server-package test case, exceeding the 120 s CI per-package timeout. A `sync.Once` cache (`warmNS0Cache`) imports once per test binary; later servers copy the cached nodes in microseconds. Server package time under `-race`: **>120 s → ~11 s**.
- **`getSubRefs` infinite recursion guard** — `HasSubtype` expansion for `QueryFirst`/`QueryNext` could loop on the cyclic built-in type hierarchy. A `visited` map (`getSubRefsVisited`) prevents re-traversal; individual query tests now run in <50 ms instead of 41+ s.
- **`newServerNoNS()`** (package-private) — lightweight `Server` constructor that skips nodeset import; used by the test helper.

Additional hardening in this release:

- **`DefaultDialer` / UACP ACK cloning** — `ReceiveBufferSize` / `SendBufferSize` / related options no longer mutate the shared `uacp.DefaultClientACK` (previously poisoned later HEL/ACK handshakes with `message too large: 57 > 5 bytes`). `NewConn` / `Listen` / `Accept` also clone ACK templates per connection.
- **`Variant.Decode` array-length guard** — negative lengths other than `-1` (null array) return `BadEncodingLimitsExceeded` instead of panicking in `reflect.MakeSlice` (fuzz regression corpus retained).
- **Ephemeral listen port (`:0`)** — `uacp.ParseEndpoint` accepts port `0`; `Server.Start` rewrites listen/endpoint URLs to the OS-assigned port and exposes `Server.Port()`. Interop Go servers bind `:0` instead of `freePort()` pick-then-release, eliminating `address already in use` flakes under load.
- **Fuzz targets expanded** — `ua` (Variant, NodeID, ExtensionObject, ParseNodeID, NumericRange, EventFilter, ContentFilter, DecodeService, common binary shapes), `uasc` headers, `uacp` Hello/Header.
- **Lifecycle / recovery stress** — concurrent Close+subscribe, cancel-during-publish, event+data-change together, blocking recovery-handler contract, history continuation-point session close under `-race`, sequence-number rollover.
- **Interop ledger tooling** — `go generate ./interop` renders [`interop/COVERAGE.md`](interop/COVERAGE.md) / [`interop/GAPS.md`](interop/GAPS.md) from `capabilities.json` + `coverage.json`.
- **Make targets** — `make verify` runs `go vet`, unit, race, and interop; `make check` includes fmt/lint/verify/coverage.

### Known limitations

- Broad EventFilter WhereClause surface and custom event emission are **deferred**; C→ history continuation is **deferred**
- `write.encoding-mask` Go→Milo is **unsupported** (strict `BadWriteNotSupported` claim)
- No Alarms/Conditions, historical events, durable subscriptions, or full bounding/interpolation for raw HistoryRead `returnBounds`

---

## v1.2.0

**Date:** 2026-07-22
**Previous release:** v1.1.1

### Summary

Minor release focused on **X.509 security hardening**, **server API correctness**, and a large step forward in **test coverage** (50% → 81%).

Highlights:
- **ApplicationURI SAN verification** — the client now binds the server certificate to the `ApplicationURI` advertised in its `ApplicationDescription`, closing an OPC UA PKI identity gap.
- **Strict key-usage enforcement** — server certificates that declare a `KeyUsage` extension must include `DigitalSignature` (and `KeyEncipherment` for SignAndEncrypt); verification is now a hard failure instead of a warning.
- **Server-side X.509 user token validation** — the server validates the `UserTokenSignature` (signature over `serverCertificate || serverNonce`) and calls an application-provided `X509UserValidator` for trust decisions.
- **Critical server nil-pointer fixes** — 14 distinct nil-pointer panic paths in `server/` were found and fixed; the entire subscription/monitored-item service set now handles unauthenticated or malformed requests without crashing.
- **`AddObject` / `AddVariable` API fixed** — both methods were silently broken (nil back-reference on every registered node); they now work correctly and are covered by tests.
- **New documentation** — `API.md` (full public API reference with table of contents) and `INTEROP.md` (compatibility matrix against open62541 and Eclipse Milo).
- **Coverage** reaches 81%, well above the 75% threshold enforced by `make coverage`.

No breaking changes for correct existing callers. Minor version bump.

### Security hardening

#### Client — ApplicationURI SAN verification (OPC UA Part 6 §6.2.2)

`SecurityFromEndpoint` now stores the server's `ApplicationURI` from the endpoint `ApplicationDescription`. `validateServerCertificate` compares the certificate's URI SANs against this stored value. Trusting the CA alone is insufficient: the URI SAN is the OPC UA identity binding that ties a certificate to a specific application instance.

```go
// Automatic when using SecurityFromEndpoint — no API change required.
// InsecureSkipVerify() bypasses this check as before.
```

#### Client — Strict key-usage validation (OPC UA Part 6 §6.2.4)

Certificates that declare a `KeyUsage` extension are now required to include `DigitalSignature` (and additionally `KeyUsageKeyEncipherment` for `SignAndEncrypt` mode). Previously a missing bit produced a warning; it is now a rejected connection. Certificates that do not declare any `KeyUsage` extension are still accepted for interoperability with legacy deployments.

#### Server — X.509 user token validation

The server now fully validates `X509IdentityToken` presented in `ActivateSession`:
1. The token certificate must be parseable.
2. The `UserTokenSignature` (signature over `serverCertificate ‖ serverNonce`) is verified with the token certificate's public key — this prevents certificate-replay attacks.
3. An application-supplied `X509UserValidator` hook is called for trust-store and policy decisions.

```go
v := server.X509UserValidator(func(certDER []byte) error {
    // parse certDER, check trust store, enforce your policy
    return nil // or ua.StatusBadIdentityTokenRejected
})
srv, _ := server.New(
    server.WithX509UserValidator(v),
    // ...
)
```

### New server API

#### `ListenOn(addr string) Option`

Binds the server to a specific host/port without going through `EndPoint`:

```go
srv, _ := server.New(server.ListenOn("0.0.0.0:4840"))
```

#### `UsernameValidator` and `WithUsernameValidator`

Previously an internal type; now a first-class exported type and option:

```go
v := server.UsernameValidator(func(user, pass string) error {
    if user != "admin" || pass != secret {
        return ua.StatusBadUserAccessDenied
    }
    return nil
})
srv, _ := server.New(server.WithUsernameValidator(v))
```

#### `X509UserValidator` and `WithX509UserValidator`

New type and option for server-side X.509 user token trust decisions (see Security hardening above).

#### `AllowUsernameOnNone() Option`

Permits username/password authentication on `SecurityModeNone` endpoints (opt-in; disabled by default for safety).

### Bug fixes

#### Server — `AddObject` / `AddVariable` always panicked

Every node registered via `NodeNameSpace.AddNode` had its `ns` back-reference left `nil`. Any subsequent call to `Node.AddObject` or `Node.AddVariable` on that node immediately panicked. Both methods now work correctly:
- `AddNode` sets `n.ns = as`.
- `AddVariable` registers the new child node in the namespace (previously it returned the cloned child without inserting it).

#### Server — `AddNamespace` did not inject server reference

`NewNameSpace(name)` creates a `NodeNameSpace` with `srv = nil`. `AddNamespace` now sets `nns.srv = s` on any `*NodeNameSpace` instance that arrives without a server reference, so `Browse`, `ChangeNotification`, and `SetAttribute` work correctly on namespaces registered after construction.

#### Server — `Browse` nil type definition

`NodeNameSpace.Browse` called `td.DataType()` on the result of `as.srv.Node(...)` without a nil check. Any reference pointing to a node that does not exist in the server's address space panicked. The nil case is now handled gracefully.

#### Server — `node.DataType()` nil `ReferenceTypeID`

The method logged a warning about a nil `ReferenceTypeID` but then immediately called `.IntID()` on it in the next statement. The warning is now followed by a `continue`.

#### Server — `nodeset2_import.go` — nil node before `AddRef` (7 sites)

All six node-type sections of `refsImportNodeSet` called `node.AddRef(...)` after a `Warn`-but-no-`continue` nil check, or with no nil check at all. All seven call sites now skip the reference loop when the node cannot be resolved.

#### Server — subscription / monitored-item service nil panics (7 critical paths)

All service handlers that compare session tokens against a nil `Session()` result now guard with `sess == nil`:

| Method | Symptom |
|---|---|
| `SetMonitoringMode` | `!ok` check came *after* the nil dereference |
| `DeleteMonitoredItems` | Missing `continue` after `!ok`; nil `item` used on fallthrough |
| `CreateMonitoredItems` | `sess` nil, used immediately |
| `ModifyMonitoredItems` | `sess` nil, used immediately |
| `SetTriggering` | `sess` nil, used immediately |
| `DeleteSubscriptions` | `session` nil, used immediately |
| `CloseSession` | `SubscriptionService` nil before `Start()` |

#### Server — `Subscription.run()` goroutine nil session / channel panic

`CreateSubscription` sets `sub.Session = srv.Session(...)` which returns `nil` for an invalid token. The background `run()` goroutine then panicked on `s.Session.PublishRequests`. Both `Session` and `Channel` are now checked at the start of `run()` with an immediate clean shutdown. `keepalive()` also guards against a nil `Channel`.

#### Server — `ChangeNotification` before `Start()`

`MonitoredItemService` is `nil` until `initHandlers()` is called inside `Start()`. Any call to `ChangeNotification` (or `SetAttribute`, which calls it) during pre-`Start()` namespace population panicked. The method now returns early when `MonitoredItemService == nil`.

#### `uasc.SecureChannel` — new `SecurityPolicyURI()` accessor

The field was private and inaccessible to callers that need to inspect the negotiated policy URI without access to the internal `Config`. A public accessor is now exported.

### Documentation

- **`API.md`** — comprehensive public API reference for the `opcua`, `server`, `ua`, `uasc`, `uacp`, `uapolicy`, `monitor`, and `errors` packages, with a full table of contents.
- **`INTEROP.md`** — compatibility matrix showing verified behavior against open62541 and Eclipse Milo across all security policies, authentication methods, and service operations.

### Testing

Test coverage increased from ~50% to **81%** (threshold enforced at 75% via `make coverage`).

New test files and significant additions include:
- `ua/enums_all_values_test.go`, `ua/enums_string_methods_test.go` — 100% branch coverage for all generated enum `FromString` / `String` methods.
- `ua/extobjs_header_test.go` — `Header` / `SetHeader` for all generated request/response types.
- `server/server_config_options_test.go` — all server `Option` constructors.
- `server/channel_broker_test.go`, `server/query_service_test.go` — previously 0% covered.
- `server/subscription_service_test.go`, `server/monitored_item_service_test.go` — regression tests for all nil-panic fixes.
- `server/namespace_node_test.go` — `AddObject`, `AddVariable`, `AddNamespace` back-reference, `Browse` nil td, `DataType()` nil ref.
- `uasc/secure_channel_test.go` — accessors, `conditionLocker`, `mergeChunks`, `notifyMonitor`, `isReconnectTrigger`, `getActiveChannelInstance`.
- `uacp/conn_test.go` — `minNonZero`, `defaultNetDialer`, live connection accessors.
- `config_test.go` — `setCertificate` URI extraction, `loadPrivateKey` PEM/DER/PKCS#8 branches.
- `conformance/` — cross-package coverage of `uasc` and `opcua` root via in-process client/server tests.

### Compatibility

All additions are backward-compatible. The stricter certificate validation (ApplicationURI SAN, key usage) is a security fix; callers with correctly configured certificates are unaffected. `InsecureSkipVerify()` bypasses both new checks. Minor version bump.

---

## v1.1.1

**Date:** 2026-07-09
**Previous release:** v1.1.0

### Summary

Patch release focused on **interop hardening** with strict OPC UA clients and servers (certificate chains, encrypted-channel handshakes, large responses), plus **monitoring ergonomics** and **transport-layer improvements** in `uacp`.

Highlights:
- **Certificate chains** (leaf + intermediate) are parsed correctly on connect; thumbprints use the leaf certificate only.
- **Server secure-channel handshake** now includes `ReceiverCertificateThumbprint` on OpenSecureChannel responses.
- **Large server responses** (e.g. Browse of a big folder) are split across multiple chunks instead of dropping the connection.
- **`monitor.ItemError`** — batch monitored-item creation succeeds for valid nodes and reports per-item failures individually.
- **`uacp.ParseEndpoint`** and default dial timeouts for direct `uacp` package users; DNS resolution delegated to `net.Dialer`.

No breaking API changes. Patch version bump.

### Bug fixes

#### Certificate chains on connect

Servers that present their application instance certificate as a **leaf plus intermediate chain** (e.g. Siemens WinCC Unified Runtime) previously failed validation because `x509.ParseCertificate` rejects trailing DER. The client now uses `x509.ParseCertificates`, validates the leaf against the trust pool with intermediates, and `uapolicy.PublicKey` / `Thumbprint` extract the **leaf** certificate only. Session signature paths use the same chain-aware helpers.

#### Server OpenSecureChannel response missing client thumbprint

The server recorded the client's certificate on incoming OPN requests but never set `cfg.Thumbprint`, so OpenSecureChannel responses carried an empty `ReceiverCertificateThumbprint`. Strict clients (UaExpert, Prosys) reject encrypted channels against the server. The thumbprint is now derived from the client's `SenderCertificate` when the OPN request is processed.

#### Server large responses dropped the connection

`sendResponseWithContext` encoded the entire response as a single chunk. Responses larger than the negotiated buffer (common when browsing folders with many nodes) overflowed the client's receive buffer and closed the connection. Server responses now use `EncodeChunks(maxBodySize)` with per-chunk sign/encrypt/write, mirroring the client request path. `SetMaximumBodySize` is called on the server after symmetric keys are established. The UACP server handshake also negotiates send/receive buffer sizes to the **minimum** of what each side advertises.

#### Monitor batch failed on first bad node

`monitor.Subscription.AddMonitorItems` returned immediately on the first per-item `StatusCode` failure, abandoning valid items in the same batch. It now collects `ItemError` values for rejected items (recoverable via `errors.As`), cleans up speculatively registered handles, and still returns successfully created items. The server's `CreateMonitoredItems` handler rejects unknown nodes individually with `BadNodeIDUnknown` instead of failing the whole request.

### New features / improvements

#### `monitor.ItemError`

```go
type ItemError struct {
    NodeID     *ua.NodeID
    StatusCode ua.StatusCode
}
```

`AddMonitorItems` returns `(items, errors.Join(itemErrors...))` when some items fail. `errors.Is(err, ua.StatusBadNodeIDUnknown)` works via `Unwrap`.

#### `uacp` endpoint parsing and dial timeouts

- `ParseEndpoint(endpoint)` — parse and validate `opc.tcp://` URLs **without DNS**; requires a host and validates explicit ports. Hostname resolution is deferred to `net.Dialer` / `net.Listen` (standard library happy eyeballs).
- `uacp.DefaultDialTimeout` (10s); `Dial` / `DialTCP` use it by default.
- `DialWithTimeout` / `DialTCPWithTimeout` for explicit timeouts (zero = no dial timeout beyond `ctx`).
- `opcua.DefaultDialTimeout` is now an alias of `uacp.DefaultDialTimeout`.

### Testing

- `uapolicy/cert_utils_test.go` — chain thumbprint and public-key extraction.
- `config_test.go` — leaf+intermediate chain validation.
- `conformance/monitor_chunk_test.go` — partial-batch monitor (`ItemError`), multi-chunk browse with small negotiated buffer.
- `uacp/dial_timeout_test.go` — default dial timeout and zero-timeout behavior.
- `monitor/subscription_test.go` — `ItemError` unit test.

### Compatibility

No breaking API changes. All additions are new types/functions or relaxed behavior (partial monitor success, chain parsing). Patch version bump.

---

## v1.1.0

**Date:** 2026-07-09
**Previous release:** v1.0.2

### Summary

Feature and hardening release, and the first release prepared for open-source distribution under the MIT license.

Highlights:
- New **server-side Query service** (QueryFirst/QueryNext) with a full Part 4 `ContentFilter` evaluator.
- A new **client↔server conformance test suite** (conformance, adversarial, concurrency, and property-based tiers) covering the client/server API surface over a real `opc.tcp` loopback.
- **Correctness fixes** in the binary codec, the client's fault handling, and the server's fault routing.
- **Open-source preparation**: SPDX license headers across the codebase and licensing/documentation updates.

No breaking API changes. Minor version bump.

### New features

#### Server-side Query service (QueryFirst / QueryNext)

The server now implements the Query Service Set. Previously `QueryFirst`/`QueryNext` returned `Bad_ServiceUnsupported`.

- `QueryFirst` matches candidate nodes by `TypeDefinition` (with `IncludeSubTypes` via the type tree), applies the `ContentFilter` WhereClause, and builds `QueryDataSet`s by resolving each `QueryDataDescription` (`RelativePath` + attribute read). It honors `MaxDataSetsToReturn` and reports per-NodeType `ParsingResults` and a `FilterResult`.
- `QueryNext` supports pagination via a continuation-point store, releasing continuation points, and returns `Bad_ContinuationPointInvalid` for unknown tokens.
- A specified but unknown `View` returns `Bad_ViewIdUnknown`; a null view scans the whole address space. Empty `NodeTypes` returns `Bad_NothingToDo`.

The Service Support Matrix in the README now lists QueryFirst/QueryNext as supported on both client and server.

#### Full ContentFilter evaluator

New self-contained `ContentFilter` evaluator (`server/content_filter.go`) implementing full Part 4 semantics:

- All 18 `FilterOperator`s: `Equals`, `IsNull`, `GreaterThan`, `LessThan`, `GreaterThanOrEqual`, `LessThanOrEqual`, `Like`, `Not`, `Between`, `InList`, `And`, `Or`, `Cast`, `InView`, `OfType`, `RelatedTo`, `BitwiseAnd`, `BitwiseOr`.
- Three-valued logic (TRUE/FALSE/NULL) for the logical operators.
- Operand resolution for `LiteralOperand`, `ElementOperand` (with forward-only, cycle-checked element references), `AttributeOperand`, and `SimpleAttributeOperand`.
- Implicit numeric/string comparison, the OPC UA `Like` grammar (`%`, `_`, `[]`, `[^]`, `\` escaping) translated to a Go regexp, and a `Cast` conversion for the common built-in scalar types.
- A structural validation pass producing a `ContentFilterResult` with per-element/per-operand status codes.

#### Node enumeration API

New optional `Nodes()` accessors return a snapshot of a namespace's nodes:

```go
func (as *NodeNameSpace) Nodes() []*Node
func (ns *MapNamespace) Nodes() []*Node
```

The Query service uses these to scan candidate nodes; custom namespaces that implement the same signature participate automatically.

#### New and modernized examples

New runnable examples: `readmulti` (auto-chunked batch read), `history-read-simple` (`ReadHistoryAll` iterator), `serverstatus`, `metrics` (`WithMetrics`/`WithRetryPolicy`), `node-summary` (`Node.Summary`), `regread` (register-nodes), and dedicated server examples `server/node_server`, `server/map_server`, `server/NodeSet2_server`, and `server/method_server`. Existing `read`/`write`/`subscribe`/`method`/`translate`/`history-read` examples were reworked to demonstrate both the high-level convenience wrappers and the low-level service calls.

### Bug fixes

#### Binary encoder nil-pointer asymmetry

`ua/encode.go` wrote zero bytes for a nil pointer field, but the decoder always allocates and reads pointer fields. Any message that left a pointer field nil produced a stream that could not be decoded symmetrically. The encoder now writes the zero value for a nil pointer, matching decode (a nil `*NodeID` encodes as the null NodeID `0x00 0x00`). Existing messages that fully populate their pointers are unaffected. Added round-trip idempotence tests covering empty `QueryFirstRequest`/`QueryNextRequest`, `ContentFilter` with each operand type, and nil `*NodeID`.

#### Operation-level ServiceFaults no longer disconnect the client

The client's read dispatcher forwarded every failed message to the connection monitor, which treats any notification as a connection failure. A normal operation-level ServiceFault (a decoded response carrying a non-OK `ServiceResult`, e.g. a bad NodeID or an invalid filter) therefore tore down the whole connection. The dispatcher now forwards only connection/transport-level failures and the faults that actually require the channel, session, or subscriptions to be recreated (`Bad_SecureChannelIdInvalid`, `Bad_SessionIdInvalid`, `Bad_SubscriptionIdInvalid`, `Bad_NoSubscription`, `Bad_CertificateInvalid`). Ordinary faults are returned to the caller with the connection left usable. Auto-reconnect behavior is unchanged.

#### Server no longer tears down the secure channel on a per-request error

When a single request failed to decode/process, the server's channel broker closed the entire secure channel without replying, so the client blocked until its full `RequestTimeout` (and `Client.Close` then blocked too). The broker now returns a `ServiceFault` correlated to the offending `RequestID` and keeps serving the channel; only connection-level failures close it.

#### Node.Description panic

`Node.Description` could panic because the server's node constructors stored the wrong value type (a numeric NodeClass instead of a `LocalizedText`) under the Description attribute. The server constructors now store a `LocalizedText`, and the client-side `Node.Description` performs a checked type assertion and returns an error instead of panicking on unexpected types.

### Testing

#### New conformance test suite (`conformance/` package)

A new in-process client↔server test suite exercises the full client/server API surface over a real `opc.tcp` loopback:

- **Conformance** per service set (attribute, view, method, node management, subscription, events, history, query, misc).
- **Adversarial** tests for malformed/hostile inputs and edge cases.
- **Concurrency** tests (safe under `-race`).
- **Property-based** round-trip/invariance tests using `pgregory.net/rapid` (added as a dependency).
- An **API coverage matrix** (`matrix_test.go`) that reflects over the client/server APIs to guard against untested surface.
- Shared harness and a rich node `Fixture` in `internal/testutil` (scalars of every common type, arrays, access-controlled nodes, a callable method, an event source, and a typed/subtyped `VariableType` hierarchy for Query).

Unit tests were also added for the ContentFilter evaluator (`server/content_filter_test.go`: operator matrix, three-valued logic, `Like` grammar, `Cast`, validation).

### Open-source preparation / licensing

- **SPDX headers**: every first-party Go file now begins with `// SPDX-License-Identifier: MIT`. Code-generator templates (`cmd/*`) and the generation orchestrator (`internal/cmd/gen`) emit the SPDX header, and `stringer` output is post-processed so generated files stay consistent with `go generate ./...`.
- **LICENSE**: added the OT Fabric copyright line; the project remains MIT-licensed.
- **Documentation**: `README.md` badges refreshed (pkg.go.dev reference, Codecov, release), the examples table expanded, and the Query rows updated; `API.md` documents the client Query API and the new `Nodes()` accessors.

### Compatibility

No breaking API changes. All additions are new methods/behavior; the encoder change only affects previously-undecodable output; SPDX headers and licensing updates are non-functional. Minor version bump.

---

## v1.0.2

**Date:** 2026-03-24
**Previous release:** v1.0.1

### Summary

Production-grade hardening release. Makes the library fully slog-native, removes the custom logger abstraction, hardens NodeSet2 XML import against malformed input, adds generator tests and CI drift detection, and finishes the panic audit.

### Breaking changes

#### Logger package removed

The `logger/` package and `logger_alias.go` re-exports have been deleted. The library is now slog-native internally — all logging uses `*slog.Logger` directly.

```go
// Before
import "github.com/otfabric/go-opcua/logger"
opcua.WithLogger(logger.NewSlogLogger(handler))

// After
import "log/slog"
opcua.WithLogger(slog.New(handler))
```

#### `WithLogger` accepts `*slog.Logger`

The client option `WithLogger` now takes `*slog.Logger` directly instead of the former `logger.Logger` interface. The separate `WithSlogLogger` option has been removed (merged into `WithLogger`).

```go
// Before
opcua.WithSlogLogger(myLogger)

// After
opcua.WithLogger(myLogger)
```

#### `SetLogger` accepts `*slog.Logger` (server)

The server option `SetLogger` now takes `*slog.Logger` directly instead of `logger.Logger`.

#### `uacp.Dialer.Logger` and `uasc.Config.Logger` type changed

The exported `Logger` fields on `uacp.Dialer` and `uasc.Config` have changed from `logger.Logger` to `*slog.Logger`.

#### `uacp.Conn.SetLogger` accepts `*slog.Logger`

The `SetLogger` method now takes `*slog.Logger`.

#### `TypeRegistry.New(nil)` returns nil instead of panicking

`TypeRegistry.New` with a nil NodeID now returns nil instead of panicking. This protects runtime paths processing incoming messages with potentially malformed type IDs.

#### Stricter NodeSet2 XML import validation

`ImportNodeSetXML` now returns contextual errors instead of panicking when NodeSet2 XML contains invalid node IDs, reference targets, or reference types. All 29 uses of `ua.MustParseNodeID` on XML-derived data have been replaced with `ua.ParseNodeID` and error propagation.

Error messages include the import phase, node type, and offending value:
```
nodeset import: variable: parse node id "not-valid": ...
nodeset import: reference type "ns=1;i=1": parse reference target "bad-ref": ...
nodeset import: data type "ns=1;i=2": unknown reference type "NonExistent"
```

### New features

#### Slog-native logging

All internal logging now uses `*slog.Logger` with structured key-value fields. No `Debugf`/`Infof`/`Warnf`/`Errorf` format-string logging remains in production code.

The default logger is `slog.Default()`, which means the library respects any global slog configuration set by the application.

#### Generator test coverage

`internal/cmd/gen` now has focused tests covering:
- Enum type discovery (sorted, deduplicated)
- Generated file list validation (no duplicates)
- File cleanup behavior
- Missing file tolerance

#### CI generation drift detection

A new `gen-drift` CI job runs `go generate ./...` and fails if the working tree becomes dirty, ensuring generated files stay in sync with source changes.

A new `check-gen` Makefile target provides the same check locally: `make check-gen`.

#### NodeSet2 import regression tests

New test suite `TestImportNodeSetXML_BadInput` covers 12 malformed XML scenarios including invalid node IDs for each node type, invalid alias references, invalid reference targets, unknown reference types, and malformed XML.

### Improvements

#### All logging converted to structured slog

243+ log call sites across all packages (`client`, `server`, `uacp`, `uasc`) converted from printf-style format strings to structured slog calls with meaningful key-value fields.

#### Deterministic generator targets

`discoverEnumTypes` now deduplicates discovered types using `slices.Compact` after sorting, and returns errors instead of calling `log.Fatalf`.

#### Generator error propagation

All generator functions (`clean`, `generate`, `stringer`, `run`) now return errors instead of calling `log.Fatalf`, making failures actionable and testable.

#### Nil-safe map lookups in NodeSet import

Reference type lookups in NodeSet import now use the comma-ok pattern and return descriptive errors for unknown reference types instead of nil-pointer panics.

### Migration guide

1. **Logger package** — remove all imports of `"github.com/otfabric/go-opcua/logger"`. Use `*slog.Logger` directly.
2. **`WithLogger`** — change argument from `logger.Logger` to `*slog.Logger`. Remove calls to `WithSlogLogger` (use `WithLogger` instead).
3. **`SetLogger` (server)** — change argument from `logger.Logger` to `*slog.Logger`.
4. **`uacp`/`uasc` Logger fields** — update any direct assignments of `Dialer.Logger` or `Config.Logger` to use `*slog.Logger`.
5. **NodeSet import errors** — callers of `ImportNodeSetXML` should handle more granular errors from stricter validation.
6. **CI** — the new `gen-drift` job will fail PRs that modify generator inputs without regenerating. Run `make gen` before committing generated file changes.

---

## v1.0.1

**Date:** 2026-03-24
**Previous release:** v1.0.0

### Summary

Production hardening and maintainability release. Replaces shell-driven code generation with a Go-based driver, tightens package boundaries, unifies configuration patterns, eliminates avoidable panics, internalizes non-public packages, documents service support, and reduces root package sprawl.

### Breaking changes

#### `server.New` returns `(*Server, error)`

`server.New` now returns an error instead of panicking on bootstrap failures. All server option functions also return `error`, matching the client's `Option func(*Config) error` pattern.

```go
// Before
srv := server.New(opts...)

// After
srv, err := server.New(opts...)
```

#### Server options return errors instead of logging warnings

`EnableSecurity` and `EnableAuthMode` now return `fmt.Errorf` for invalid or duplicate configurations instead of silently logging warnings.

#### `schema` package moved to `internal/schema`

The `schema` package (NodeSet2 XML types and embedded spec data) is now internal. Use `server.ImportNodeSetXML(data []byte)` instead of unmarshaling into `schema.UANodeSet` directly.

```go
// Before
import "github.com/otfabric/go-opcua/schema"
var nodes schema.UANodeSet
xml.Unmarshal(data, &nodes)
srv.ImportNodeSet(&nodes)

// After
srv.ImportNodeSetXML(data)
```

#### `stats` package moved to `internal/stats`

The experimental `stats` package is now internal. It was not intended for downstream use.

#### `testutil` package moved to `internal/testutil`

The test helper package is now internal. It was not intended for downstream use.

#### Root package helpers removed

The following functions have been removed from the root `opcua` package and moved to their canonical locations:

| Function | New location |
|----------|-------------|
| `AggregateType` | `id.AggregateType` (returns `(uint32, bool)` instead of `*ua.NodeID`) |
| `ReferenceTypeDisplayName` | `ua.ReferenceTypeDisplayName` |
| `TypeDefinitionDisplayName` | `ua.TypeDefinitionDisplayName` |
| `DataTypeDisplayName` | `ua.DataTypeDisplayName` |
| `StandardNodeID` | `ua.StandardNodeID` |
| `SelectEndpoint` | `ua.SelectEndpoint` |

### New features

#### Go-based code generation driver

`generate.sh` has been replaced by `internal/cmd/gen/main.go`. The new driver:
- Cleans an explicit list of generated files (no shell globs).
- Runs each generator in dependency order.
- Discovers enum types via Go's `go/ast` parser and runs `stringer`.
- Uses `go tool stringer` (version pinned in `go.mod` via the `tool` directive).
- Does not install tools or run `go mod tidy`.

Generation is invoked via `go generate ./...` or `make gen`.

#### Pinned stringer version

`stringer` is now declared as a tool dependency in `go.mod` (`golang.org/x/tools v0.43.0`) and invoked via `go tool stringer` instead of `go install ...@latest`.

#### `server.ImportNodeSetXML`

New public API for importing custom NodeSet2 XML data without depending on schema types:

```go
data, _ := os.ReadFile("my-model.xml")
if err := srv.ImportNodeSetXML(data); err != nil {
    log.Fatal(err)
}
```

#### `WithSlogLogger` option

Both client and server now accept `WithSlogLogger(*slog.Logger)` as a convenience option for configuring structured logging without manually wrapping a handler.

#### Service support matrices

Comprehensive service support matrices added to:
- `docs/server-guide.md` — server-side service status
- `docs/client-guide.md` — client-side method coverage
- `README.md` — combined matrix with accurate unsupported-service markers

### Improvements

#### Package tiering

All packages are now explicitly classified into three tiers in `docs/architecture.md`:
- **Tier 1 (stable public):** `opcua`, `server`, `ua`, `id`, `monitor`, `errors`
- **Tier 2 (advanced public):** `uacp`, `uasc`, `uapolicy`, `logger`, `schema/` (data files), `server/attrs`, `server/refs`
- **Tier 3 (internal):** `internal/schema`, `internal/stats`, `internal/testutil`, `internal/goname`, `internal/cmd/gen`

#### Panic discipline

- Three panics in `server.New` replaced with error returns (XML unmarshal, namespace assertion, node set import).
- Panic in `monitor/subscription.go` goroutine replaced with `sendError`.
- All remaining panics audited and documented as justified (`Must*` helpers, init-time registration, or internal invariants).

#### Unified config semantics

Client and server option patterns now follow the same model: `type Option func(*config) error` with error aggregation. Invalid configurations fail explicitly instead of being silently ignored.

#### Code generation documentation

Generation flow documented in `CONTRIBUTING.md` with a table mapping each generator to its inputs and outputs.

### Migration guide

1. **`server.New`** — add error handling: `srv, err := server.New(opts...)`.
2. **`schema` import** — replace `schema.UANodeSet` + `xml.Unmarshal` + `ImportNodeSet` with `srv.ImportNodeSetXML(data)`.
3. **`stats` import** — remove direct imports of `stats`; the package is now internal.
4. **`testutil` import** — remove direct imports of `testutil`; the package is now internal.
5. **Relocated helpers** — update imports to use `id.AggregateType`, `ua.SelectEndpoint`, `ua.ReferenceTypeDisplayName`, etc. The root package wrappers have been removed.

---

## v1.0.0

**Date:** 2026-03-24
**Previous release:** v0.1.15

### Summary

Makes all generated Go identifiers fully idiomatic by removing spec-derived underscore names from exported constants, fields, and symbols. This is a **breaking change** — all exported identifiers containing underscores have been renamed to CamelCase, and `id.Name()` now returns OPC UA spec names instead of Go identifier spellings.

### Breaking changes

#### Identifier renames

All exported generated identifiers now use idiomatic Go CamelCase without underscores. Approximately 14,600 `id` package constants, plus status code constants and schema struct fields, have been renamed.

Common rename patterns:

| Old name | New name |
|----------|----------|
| `id.ServerType_ServerArray` | `id.ServerTypeServerArray` |
| `id.Server_ServerStatus_CurrentTime` | `id.ServerServerStatusCurrentTime` |
| `id.AggregateFunction_Average` | `id.AggregateFunctionAverage` |
| `id.WellKnownRole_Anonymous` | `id.WellKnownRoleAnonymous` |
| `id.FindServersRequest_Encoding_DefaultBinary` | `id.FindServersRequestEncodingDefaultBinary` |
| `StatusGoodEdited_DependentValueChanged` | `StatusGoodEditedDependentValueChanged` |

#### Go initialism normalization

Standard Go initialisms are now consistently applied across all generators:

| Token | Normalized |
|-------|-----------|
| `Id` | `ID` |
| `Uri` | `URI` |
| `Url` | `URL` |
| `Xml` | `XML` |
| `Json` | `JSON` |
| `Guid` | `GUID` |
| `Tcp` | `TCP` |
| `Tls` | `TLS` |
| `Http` | `HTTP` |
| `Https` | `HTTPS` |
| `Dns` | `DNS` |
| `Uadp` | `UADP` |

#### `id.Name()` returns spec names

`id.Name()` now returns the original OPC UA specification name (with underscores) instead of the Go identifier spelling:

```go
id.Name(2005) == "ServerType_ServerArray"  // was: "ServerTypeServerArray"
```

#### Schema struct field renames

`schema/uaNodeSet.go` struct fields and types updated to use Go initialisms:
- `NodeIdAttr` → `NodeIDAttr`
- `TransactionIdAttr` → `TransactionIDAttr`
- `UriTable` → `URITable`
- `NodeId` → `NodeID`
- `NodeIdAlias` → `NodeIDAlias`

XML tags are unchanged — wire format compatibility is preserved.

### New features

#### Shared naming formatter (`internal/goname`)

All code generators now use a single shared naming formatter (`internal/goname.Format`) that:
- Removes underscores and applies CamelCase conversion.
- Normalizes all standard Go initialisms.
- Validates generated identifiers.

#### Collision detection

The `cmd/id` generator now detects naming collisions (where distinct spec names would normalize to the same Go identifier) and fails with a clear error. No collisions exist in the current OPC UA specification.

### Lint and quality

- **ST1003 exclusion removed** — The `.golangci.yml` exclusion for `ST1003` on generated files and `schema/` has been removed. All generated code now passes staticcheck without exceptions.
- **ST1016** — Fixed inconsistent receiver name `n` → `s` on `StatusCode.Error()`.
- **ST1021** — Fixed `AttributeID` type comment format.

### Migration guide

This release contains no compatibility aliases. Update all references mechanically:

1. Replace `id.Foo_Bar_Baz` with `id.FooBarBaz` (remove all underscores).
2. Replace `StatusFoo_Bar` with `StatusFooBar`.
3. Update any code using `id.Name()` that expected Go-style names — it now returns spec-style names with underscores.
4. Update `schema.NodeIdAttr` → `schema.NodeIDAttr` and similar field references.

---

## v0.1.15

**Date:** 2026-03-24
**Previous release:** v0.1.14

## Summary

Renames the Go module from `github.com/otfabric/opcua` to `github.com/otfabric/go-opcua`, migrates CI and release workflows to shared reusable workflows, upgrades Go and all dependencies, expands the linter configuration, and fixes all lint issues across the codebase.

## Module rename

- **Go module** — `github.com/otfabric/opcua` → `github.com/otfabric/go-opcua`. All import paths across the entire codebase (source, tests, examples, commands, documentation) are updated accordingly.
- **Retract directives removed** — The `retract` block referencing old `otfabric/opcua` tags (v0.7.2, v0.2.4, v0.2.5) has been dropped since it no longer applies to the new module path.

## Go and dependency upgrades

- **Go version** — `go 1.23` → `go 1.25.0`.
- **testify** — v1.10.0 → v1.11.1.
- **golang.org/x/exp** — updated to 2026-03-12 snapshot.
- **golang.org/x/term** — v0.27.0 → v0.41.0.
- **golang.org/x/sys** — v0.28.0 → v0.42.0.

## GitHub workflows

- **CI** (`ci.yml`) — Replaced the inline multi-job workflow (test matrix, coverage, lint, integration) with a single call to the shared reusable workflow `otfabric/.github/.github/workflows/go-ci.yml@v2`. Test matrix now targets Go 1.25 and 1.26. Triggers on pushes and PRs to all branches.
- **Release** (`release.yml`) — Replaced the inline release workflow (version detection, tag creation, release notes extraction, GitHub release creation) with a call to the shared reusable workflow `otfabric/.github/.github/workflows/go-package-release.yml@v2`. Supports a `release-name-prefix` parameter (`go-opcua`).
- **goreleaser** — Removed `.goreleaser.yml` and the `make release` target. Release is now handled entirely by the shared workflow.

## Linting and code quality

- **golangci-lint** (`.golangci.yml`) — Expanded from 2 linters (`govet`, `unparam`) to 8 linters with all checks enabled: `errcheck`, `govet`, `ineffassign`, `staticcheck` (full SA/S/ST/QF), `misspell`, `godot`, `nilerr`, `exhaustive`. Added `gofmt` and `goimports` formatters. No exclusions except ST1003 on generated code (OPC UA spec names use underscores). All issues fixed at the source across code, tests, examples, and cmd/.
- **errcheck** — All unchecked error returns resolved across the entire codebase: `defer` calls wrapped in `defer func() { _ = ... }()`, cleanup `Close()`/`SetDeadline()`/`WriteByte()` calls prefixed with `_ =`, and `xml.Unmarshal`/`ImportNodeSet` in server init now panic on error.
- **godot** — Trailing periods added to all comments (production code, tests, examples, generated template).
- **misspell** — `occured` → `occurred`, `taht` → `that`.
- **ineffassign** — Removed 3 dead assignments to `action` in `client.go` reconnect logic.
- **exhaustive** — Added missing switch cases for `reconnectAction`, `ConnState`, and `crypto.Hash`.
- **goimports** — Fixed import grouping in `cmd/id/main.go` and `uacp/endpoint_test.go`.
- **staticcheck QF** — Applied 44 quickfix suggestions: removed redundant embedded field selectors (`.Header.`, `.PublicKey.`, `.MessageHeader.`, `.SequenceHeader.`, `.TCPConn.`), replaced `strings.Replace(..., -1)` with `strings.ReplaceAll`, converted untagged switches to tagged switches, and lifted loop conditions.
- **staticcheck ST1003** — Renamed 25 underscore-named variables and methods to camelCase across `client_sub.go`, `subscription.go`, `server/`, and examples (e.g. `recreate_delete` → `recreateDelete`, `matching_endpoints` → `matchingEndpoints`).
- **staticcheck ST1016** — Standardized inconsistent receiver names across 10 files (`server/namespace_map.go`, `server/namespace_node.go`, `server/nodeset2_import.go`, `ua/expanded_node_id.go`, `ua/status_gen.go`, `uapolicy/`, `uasc/`).
- **staticcheck ST1020/ST1021** — Fixed 48 exported method comments to start with the method name and 5 exported type comments to start with the type name, following Go doc conventions.
- **staticcheck ST1000** — Added package doc comments to all 11 packages that lacked them (`id`, `logger`, `monitor`, `schema`, `server`, `server/attrs`, `server/refs`, `testutil`, `tests/go`, `tests/python`, `cmd/service/goname`).
- **.gitignore** — Reorganized with categories (Python, binaries, IDE, coverage, certificates). Added `/bin/`, `cover.*`, `coverage.*`, `*.out`. Removed `vendor/`, `build/`, `dist/`, `__debug*`.
- **Makefile** — Removed the `release` target (goreleaser). Added `coverage` to the `check` target.

## Documentation

All references to `otfabric/opcua` updated to `otfabric/go-opcua` across:

- **README.md** — Title, badges, `go get` command, import paths, overview text.
- **API.md** — Module path and `pkg.go.dev` links.
- **CONTRIBUTING.md** — Title and `git clone` URL.
- **docs/architecture.md**, **docs/client-guide.md**, **docs/security.md**, **docs/server-guide.md** — Module path references and import paths in code examples.

## Files changed

196 files changed, +1130 / -1235 lines.

---

## v0.1.14

**Date:** 2026-03-12
**Previous release:** v0.1.13

## Summary

New unified github release flow.

---

## v0.1.13

**Date:** 2026-03-11
**Previous release:** v0.1.12

## Summary

Implements `fmt.Stringer` for `*ua.LocalizedText` and `*ua.QualifiedName` so that `fmt.Sprintf("%v", v)` and logging print readable text instead of struct literals (e.g. `&{3 en-US Siemens AG}`).

## LocalizedText and QualifiedName display

- **`(*ua.LocalizedText).String() string`** — Returns the text; if locale is set, returns `"locale: text"` (e.g. `"en-US: Siemens AG"`). Nil receiver returns `""`.
- **`(*ua.QualifiedName).String() string`** — Returns the name only when namespace is 0, otherwise `"ns:name"` (e.g. `"2:Temperature"`). Nil receiver returns `""`.

CLI and tools that print variant values, display names, or browse names no longer need custom formatting for these types; `%v` and default logging use the new methods.

---

## v0.1.12

**Date:** 2026-03-11
**Previous release:** v0.1.11

## Summary

Adds batch read (`ReadMulti`) and client-side recursive browse (`BrowseWithDepth`) APIs, with tests and documentation updates.

## ReadMulti (batch read)

- **`Client.ReadMulti(ctx, items []ReadItem, opts ...ReadMultiOption) ([]ReadResult, error)`** — Batch read of N node/attribute pairs in one or more OPC UA Read calls. Chunks by `DefaultReadMultiChunkSize` (32) or by `ReadMultiWithChunkSize(n)`. Results match input order; each result has `DataValue` and `StatusCode`. Use for large subtrees or bulk export to reduce round-trips.
- **`ReadItem`** — NodeID, AttributeID, optional IndexRange.
- **`ReadResult`** — DataValue and StatusCode per item.
- Empty or nil `items` returns `(nil, nil)` without sending a request.

## BrowseWithDepth (client-side recursive browse)

- **`Node.BrowseWithDepth(ctx, opts BrowseWithDepthOptions) ([]BrowseWithDepthResult, error)`** — Client-side recursive browse up to `opts.MaxDepth`. Returns a flat slice of references with depth (no iterator). Options: MaxDepth, RefType, Direction, NodeClassMask, IncludeSubtypes. Standard OPC UA Browse is single-level; recursion is implemented via multiple Browse calls (same as Walk/WalkLimit).
- **`BrowseWithDepthOptions`** — MaxDepth (-1 = unlimited), RefType (0 = HierarchicalReferences), Direction, NodeClassMask, IncludeSubtypes.
- **`BrowseWithDepthResult`** — Ref (*ua.ReferenceDescription) and Depth.

## Tests and documentation

- **Tests:** `TestReadMulti`, `TestReadMultiChunking`, `TestReadMultiEmptyItems`, `TestReadMultiMixedAttributes`, `TestNodeBrowseWithDepth`, `TestNodeBrowseWithDepthMaxDepthZero`, `TestNodeBrowseWithDepthInverse`.
- **API.md:** ReadMulti and BrowseWithDepth types and behavior; empty-items note.
- **README.md:** Reading and Browsing rows mention ReadMulti and BrowseWithDepth.
- **docs/client-guide.md:** "Batch read (ReadMulti)" and "Recursive browse (BrowseWithDepth)" sections with examples.

---

## v0.1.11

**Date:** 2026-03-11
**Previous release:** v0.1.10

## Summary

Exposes the remaining standard-node name lookups in the `id` package and adds
a type-definition display helper so browse UIs can show "PropertyType",
"FolderType", and other well-known names instead of raw NodeIDs.

## Type definition display

- **`id.VariableTypeName(id uint32) string`** — Standard name for well-known VariableTypes in namespace 0 (e.g. 68 → "PropertyType", 63 → "BaseDataVariableType"), or "" if unknown.
- **`id.ObjectTypeName(id uint32) string`** — Same for ObjectTypes (e.g. 58 → "BaseObjectType", 61 → "FolderType").
- **`TypeDefinitionDisplayName(typeDefID *ua.NodeID) string`** — Root package: tries VariableTypeName then ObjectTypeName; otherwise returns the NodeID string. Use when displaying type definition columns (e.g. browse) so "PropertyType" is shown instead of "i=68".

## id package: Object, Variable, Method names

All seven name maps used by `id.Name(id)` are now exposed as dedicated helpers:

- **`id.ObjectName(id uint32) string`** — Well-known Object nodes (e.g. 84 → "RootFolder", 85 → "ObjectsFolder", 2253 → "Server").
- **`id.VariableName(id uint32) string`** — Well-known Variable nodes (e.g. 2256 → "Server_ServerStatus", 2258 → "Server_ServerStatus_CurrentTime").
- **`id.MethodName(id uint32) string`** — Well-known Method nodes (e.g. 11492 → "Server_GetMonitoredItems").

Together with existing `DataTypeName`, `ReferenceTypeName`, `VariableTypeName`, and `ObjectTypeName`, callers can resolve standard names by node class when displaying NodeIDs (e.g. in browse or diagnostics).

---

## v0.1.10

**Date:** 2026-03-11
**Previous release:** v0.1.9

## Summary

Adds type and status display helpers, namespace-qualified path resolution,
symbolic node name lookup, TCP-only dial for diagnostics, and documentation
improvements for path semantics and CSV/JSON consistency.

## DataType display names

- **`id.DataTypeName(id uint32) string`** — Returns the standard OPC UA name for well-known DataTypes in namespace 0 (e.g. 10 → "Float", 12 → "String", 294 → "UtcTime"), or "" if unknown.
- **`DataTypeDisplayName(dataTypeID *ua.NodeID) string`** — Convenience in the root package: standard name for known ns=0 DataTypes, otherwise the NodeID string. Use to normalize type rendering (e.g. "Float" instead of "i=10").

## Status code helpers

- **`StatusCode.Symbol() string`** — Short symbolic name only (e.g. "Good", "BadServiceUnsupported"), stripping the "Status" prefix. Use for compact status rendering instead of `Error()`.
- **`StatusCode.Uint32() uint32`** — Raw 32-bit value for consistent CSV/JSON serialization.

## Variant array

- **`Variant.IsArray() bool`** — Returns true if the variant value is an array (one- or multi-dimensional). `ArrayDimensions()` was already present (returns `[]int32`).

## Connection diagnostics

- **`uacp.DialTCP(ctx, endpoint) (net.Conn, error)`** — TCP-only connect to the endpoint host:port; no OPC UA HEL/ACK or secure channel. Caller must close the returned connection. Use for TCP reachability checks (e.g. ping) without creating a session.

## Path resolution

- **Path semantics docs** — Godoc and API.md/client-guide now state start node, namespace handling, and error behavior for `NodeFromPath`, `NodeFromPathInNamespace`, `Node.TranslateBrowsePathInNamespaceToNodeID`, and `Node.TranslateBrowsePathsToNodeIDs`.
- **`Client.NodeFromQualifiedPath(ctx, path) (*Node, error)`** — Parses namespace-qualified path syntax `ns:segment.ns:segment` (e.g. `0:Server.0:ServerStatus`, `2:DeviceSet.4:PLC_Name`) and calls TranslateBrowsePathsToNodeIDs with per-segment namespace indices. Start node is Objects folder.

## Symbolic node names

- **`id.NodeIDByName(name string) (uint32, bool)`** — Reverse lookup from well-known standard node names (namespace 0) to numeric ID. Names include full spec names ("Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime") and short aliases: "CurrentTime" → 2258, "ServerStatus" → 2256, "Objects" → 85.
- **`StandardNodeID(name string) (*ua.NodeID, bool)`** — Root package helper: returns `ua.NewNumericNodeID(0, id)` when `id.NodeIDByName(name)` succeeds. Use for CLI or config that accepts symbolic names (e.g. `get value -n CurrentTime` instead of `-n i=2258`).

## CSV/JSON and canonical form

- **`ua.NodeID.String()`** — Godoc and API.md now state that output is canonical (namespace 0 omitted; round-trip with `ParseNodeID`).
- **`StatusCode.Uint32()`** — See above; supports consistent numeric serialization.

## Endpoint troubleshooting

- **Verification** — `EndpointDescription` fields `TransportProfileURI`, `ServerCertificate`, and `Server.ApplicationURI` are already exposed and used; no code change; documented for endpoint output tooling.

## Documentation

- README.md path resolution row updated with `NodeFromQualifiedPath` and symbolic names (`StandardNodeID`, `id.NodeIDByName`). Quickstart comment added for `StandardNodeID("CurrentTime")`.
- docs/client-guide.md: connection diagnostics (ping) section, path semantics table with `NodeFromQualifiedPath`, and symbolic node names (`StandardNodeID`) subsection.
- API.md: all new functions and tables (path semantics, DataType/StatusCode/Variant, uacp.DialTCP, id.NodeIDByName, StandardNodeID, NodeID canonical, StatusCode.Uint32).

---

## v0.1.9

**Date:** 2026-03-11
**Previous release:** v0.1.8

## Summary

Adds an API to resolve well-known reference type NodeIDs to their standard
names (e.g. "HasComponent", "Organizes") so tools like `opcuactl browse refs` can
show names instead of raw NodeIDs (i=47, i=46) in the reference type column.

## Reference type display names

- **`id.ReferenceTypeName(id uint32) string`** — Returns the standard OPC UA
  name for a well-known reference type in namespace 0 (e.g. 47 → "HasComponent",
  35 → "Organizes"), or "" if unknown.
- **`ReferenceTypeDisplayName(refTypeID *ua.NodeID) string`** — Convenience
  helper in the root package: returns the standard name when the NodeID is in
  namespace 0 and known, otherwise returns the NodeID string. Use when
  displaying the reference type column in browse refs or similar UIs.

Clients can call `ReferenceTypeDisplayName(ref.ReferenceTypeID)` when rendering
`ReferenceDescription` rows to show "HasComponent" instead of "i=47".

---

## v0.1.8

**Date:** 2026-03-11
**Previous release:** v0.1.7

## Summary

Adds subscription sampling interval control and a deduplicating walk API:
callers can set the server-side sampling rate for monitored items independently
of the publishing interval, and can walk the address space with each node
yielded at most once.

## Client: Subscription sampling interval

- **`SubscriptionBuilder.SamplingInterval(d time.Duration)`** — Sets the
  requested sampling interval for monitored items added by `Monitor` or
  `MonitorEvents`. The server samples at this rate (converted to milliseconds
  on the wire); the subscription's publishing interval still controls how often
  notifications are sent to the client. If not set or zero, the server uses
  the fastest practical rate (unchanged from before).

## Browsing: WalkLimitDedup

- **`Node.WalkLimitDedup(ctx, maxDepth)`** — Same as `WalkLimit` but yields
  each node at most once, keyed by NodeID. When a node is reachable via
  multiple hierarchical paths, only the first occurrence (by traversal order) is
  yielded. Callers no longer need to maintain their own visited set to avoid
  duplicate nodes.

---

## v0.1.7

**Date:** 2026-03-11
**Previous release:** v0.1.6

## Summary

Fixes a **regression introduced in v0.1.5** that broke connection establishment
(e.g. `opcuactl browse` or any client connecting with `--security-mode None`).
The generic encoder no longer skips nil optional fields; nil is now encoded as
the correct OPC UA null representation so message layout stays valid.

## Bug fix: Encoder regression (nil optional fields)

In v0.1.5 we changed `ua/encode.go` to skip nil pointer fields entirely
(return `nil, nil`) to avoid calling `BinaryEncoder.Encode()` on a nil receiver.
That broke the OPC UA binary wire format: the server expects **all fields at
fixed offsets**. Omitting bytes for nil optional fields corrupted the message
layout and caused "failed to open a new secure channel" / EOF during connect.

- **`ua/encode.go`** — Reverted the early-exit that returned no bytes for any
  nil pointer. Nil optional fields are no longer skipped.
- **`ua/qualified_name.go`** — When the receiver is nil, `Encode()` now
  returns the OPC UA null QualifiedName encoding (namespace 0 + string length
  -1), i.e. 6 bytes, so struct field offsets are preserved.
- **`ua/node_id.go`** — When the receiver is nil, `Encode()` now returns the
  OPC UA null NodeID (two-byte form, id=0), i.e. 2 bytes, so optional NodeID
  fields keep a fixed layout.

Connection establishment and all messages with optional `*QualifiedName` or
`*NodeID` fields now encode correctly.

## Other changes

- **testutil**: Test client uses longer `DialTimeout` and `RequestTimeout`
  (30s) so tests have time to connect under load (e.g. race detector).
- **examples/browse**: Test uses `testutil.NewTestServer` / `NewTestClient`
  (dynamic port, shared timeouts); removed unused `join` helper (lint).

---

## v0.1.6

**Date:** 2026-03-11
**Previous release:** v0.1.5

## Summary

Improves error messages when the server closes the connection (EOF) during
subscription or monitored-item creation. Callers (e.g. `monitor event` /
`monitor alarm` against servers that do not support event subscriptions) now
see a clear hint instead of a raw "EOF".

## Client: EOF handling in subscription path

When the server closes the connection instead of returning a service fault
(e.g. WAGO PLC not supporting OPC UA event or alarm subscriptions), the SDK
previously surfaced **io.EOF** with no context.

- **`Subscription.Monitor()`** — If the request returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  monitored items (server may not support event or alarm subscriptions)".
  Callers can still use `errors.Is(err, io.EOF)`.
- **`Client.Subscribe()`** — If `CreateSubscription` returns `io.EOF`, the
  returned error now wraps it with: "connection closed while creating
  subscription (server may not support subscriptions)".

Documentation and doc comments for `Monitor` and `SubscriptionBuilder.Start`
note that connection-close errors may wrap `io.EOF` with this hint.

---

## v0.1.5

**Date:** 2026-03-11
**Previous release:** v0.1.4

## Summary

Adds the depth-limited `WalkLimit` API for browsing the address space and fixes a
nil pointer dereference when encoding `HistoryReadRequest` with optional
`DataEncoding` (e.g. `history value` / `history event` commands).

## Client: WalkLimit (depth-limited walk)

- **`Node.WalkLimit(ctx, maxDepth)`** — Same as `Walk` but stops recursing when
  depth reaches `maxDepth`. The node at `maxDepth` is still yielded. Use for
  "find node", "find type", or "browse tree" style tools to avoid unbounded
  traversal (e.g. a `-depth` flag on the CLI). If `maxDepth < 0`, depth is
  unlimited (equivalent to `Walk`).
- **`Node.Walk(ctx)`** — Unchanged; now implemented via `WalkLimit(ctx, -1)`.

## Bug fix: HistoryReadRequest encoding with nil DataEncoding

Encoding a `HistoryReadRequest` whose `HistoryReadValueID` entries had
`DataEncoding == nil` caused a panic in `QualifiedName.Encode()` (nil pointer
dereference). This affected `HistoryReadRawModified`, `HistoryReadEvent`, and
other history read calls when the optional `DataEncoding` field was omitted.

- **`ua/encode.go`** — Nil pointer fields that implement `BinaryEncoder` are
  now encoded as no bytes instead of calling `Encode()` on a nil receiver.
- **`ua/qualified_name.go`** — `QualifiedName.Encode()` guards against a nil
  receiver and returns `(nil, nil)`.

---

## v0.1.4

**Date:** 2026-03-11
**Previous release:** v0.1.3

## Summary

Adds server certificate validation infrastructure and two new client options:
`InsecureSkipVerify()` and `TrustedCertificates()`. When `SecurityMode` is
`Sign` or `SignAndEncrypt`, the client now validates the server certificate by
default. Use `TrustedCertificates()` to trust self-signed servers or private
CAs, or `InsecureSkipVerify()` to disable validation for development.

## Client: Server Certificate Validation

The SDK previously performed no X.509 trust-chain validation of the server's
certificate — it parsed the certificate only to extract the RSA public key for
signing and encryption. This release adds opt-in validation and a deprecation
path toward secure-by-default behavior.

### New Options

| Option | Description |
|--------|-------------|
| `TrustedCertificates(certs ...*x509.Certificate)` | Add CA or self-signed certificates to the trust pool. Merged with the system CA pool. Enables full validation (chain, expiry, key usage). |
| `InsecureSkipVerify()` | Disable all server certificate validation. Certificate is still parsed for its public key. **INSECURE — development only.** |

### Validation Checks (when `TrustedCertificates` is configured)

| Check | Description |
|-------|-------------|
| **Trust chain** | Verifies the certificate chains to a trusted root CA (system pool + user-supplied certs) |
| **Expiration** | Rejects expired or not-yet-valid certificates |
| **Key usage** | Warns if `DigitalSignature` / `KeyEncipherment` bits are missing |

### Validation Points

Server certificate validation runs at two points in the connection flow:

- **`Dial()`** — validates `RemoteCertificate` (set via `SecurityFromEndpoint`
  or `RemoteCertificate` option) after `OpenSecureChannel`
- **`CreateSession()`** — validates `ServerCertificate` from the
  `CreateSessionResponse` after verifying the session signature

### Behavioral Summary

| Scenario | Certificate check | How to configure |
|----------|------------------|------------------|
| `SecurityMode == None` | No certificate exchanged, nothing to validate | Default |
| `Sign` or `SignAndEncrypt` (default) | Full validation: chain, expiry, key usage | Default |
| `Sign` or `SignAndEncrypt` + self-signed server | Fails unless cert added to trust pool | `TrustedCertificates(serverCACert)` |
| `Sign` or `SignAndEncrypt` + skip verify | No validation, just parse for public key | `InsecureSkipVerify()` |

### Config Changes

Added `serverCertValidator` to the internal `Config` struct:

```go
type serverCertValidator struct {
    insecureSkipVerify bool
    trustedCerts       *x509.CertPool
    trustedCertsList   []*x509.Certificate
}
```

## Documentation

- **API.md** — added `InsecureSkipVerify()` and `TrustedCertificates()` to the
  options table
- **docs/security.md** — new "Server Certificate Validation" section with
  usage examples, trust configuration, and dev-mode skip
- **docs/client-guide.md** — added new options to the client options table
- **README.md** — updated security feature description

## Files Changed

6 files changed. Hand-written Go: 3 files (config.go, client.go, config_test.go).

---

## v0.1.3

**Date:** 2026-03-11
**Previous release:** v0.1.2

## Summary

Patch release with a small improvement for anonymous authentication when using
the client (e.g. `--auth anonymous` in example CLIs).

## Client: anonymous auth without pre-set PolicyID

When `AuthAnonymous()` is applied before the server's endpoints are known (for
example when using `--auth anonymous` on the command line), the
`AnonymousIdentityToken` is created without a policy ID. The client now
resolves the correct anonymous user token policy from the server's advertised
endpoints after `CreateSession` and sets it on the token, so anonymous
authentication works correctly without requiring endpoint or security options
to be applied first.

---

## v0.1.2

**Date:** 2026-03-11
**Previous release:** v0.1.1

## Summary

This release brings the OPC UA schema files up to the latest OPC Foundation
specification and adds a security layer to the server: access restrictions,
role-based access control (RBAC), and session identity-to-role mapping. Three
new code generators were added and the existing service generator was hardened
to skip JSON-only types.

## Schema Update

Updated all schema files from the OPC Foundation UA-Nodeset repository:

- **NodeIds.csv** — refreshed; thousands of new/renamed node identifiers
- **StatusCode.csv** — new status codes added
- **Opc.Ua.Types.bsd** — new structured types and enumerations
- **Opc.Ua.NodeSet2.xml** — expanded node set with role permissions
- **Opc.Ua.PredefinedNodes.xml** — added (new file, used by .NET tooling)
- **AttributeIds.csv** — added (new file, 27 attribute IDs)
- **ServerCapabilities.csv** — added (new file, 39 capability identifiers)
- **Opc.Ua.NodeIds.permissions.csv** — added (new file, 557 default permission entries)

## New Code Generators

| Generator | Input | Output | Description |
|-----------|-------|--------|-------------|
| `cmd/attrid` | `AttributeIds.csv` | `ua/enums_attribute_id_gen.go` | AttributeID enum constants (replaces hand-maintained block) |
| `cmd/capability` | `ServerCapabilities.csv` | `ua/server_capabilities_gen.go` | 39 `ServerCapability*` constants, `KnownCapabilities` map, `ValidateCapability()` |
| `cmd/permissions` | `Opc.Ua.NodeIds.permissions.csv` | `server/default_permissions_gen.go` | 557 default node permission entries for RBAC |

## Code Generation Fixes

- **Service generator** (`cmd/service`): added `-nodeids` flag and
  `filterByBinaryEncoding()` to skip types that only have a JSON encoding in
  the spec — prevents generating codec registrations for types that cannot be
  serialized over OPC UA Binary.
- **`generate.sh`**: updated to run the three new generators; added descriptive
  header comment; fixed shellcheck warnings (SC2035, SC2086).

## Server Security & RBAC

### Access Restrictions (OPC UA Part 3 §5.2.11)

- `checkAccessRestrictions()` enforces `SigningRequired` and
  `EncryptionRequired` bits against the secure channel's security mode.
- `checkAccessRestrictionsForBrowse()` only enforces restrictions when the
  `ApplyRestrictionsToBrowse` bit is set.
- Wired into Read, Write, Browse, and Call service handlers.
- Added `SecurityMode()` getter on `SecureChannel`.

### Role-Based Access Control

- **`RBACAccessController`** — checks node `rolePermissions` against the
  session's assigned roles for Read, Write, Browse, and Call operations.
  Nodes without role permissions are unrestricted.
- **`RoleMapper`** function type and `DefaultRoleMapper` — maps identity tokens
  to well-known role NodeIDs (anonymous → `Anonymous`, others →
  `AuthenticatedUser`). Configurable via `WithRoleMapper()` server option.
- **Session identity tracking** — `ActivateSession` now extracts the
  `UserIdentityToken` and resolves roles through the configured `RoleMapper`.

### Well-Known Roles

- New `ua/well_known_role.go`: 12 well-known roles from the spec (Anonymous,
  AuthenticatedUser, Observer, Operator, Engineer, Supervisor, ConfigureAdmin,
  SecurityAdmin, SecurityKeyServer, SecurityKeyServerAdmin,
  SecurityKeyServerAccess, SecurityKeyServerPush).
- Each role has `String()`, `NodeID()` methods and lookup via `RoleByName` map.

### Node RolePermissions

- Server `Node` stores `[]*ua.RolePermissionType` resolved from the generated
  default permissions at import time via `resolveRolePermissions()`.
- `AttributeIDRolePermissions` and `AttributeIDUserRolePermissions` are served
  from the node as `[]*ua.ExtensionObject`.

## Server Capabilities Expansion

- `OperationalLimits` expanded from 1 field to 12 (all defaulting to 32):
  `MaxNodesPerRead`, `MaxNodesPerWrite`, `MaxNodesPerBrowse`,
  `MaxNodesPerMethodCall`, `MaxNodesPerRegisterNodes`,
  `MaxNodesPerTranslateBrowsePathsToNodeIDs`, `MaxNodesPerNodeManagement`,
  `MaxMonitoredItemsPerCall`, `MaxNodesPerHistoryReadData`,
  `MaxNodesPerHistoryReadEvents`, `MaxNodesPerHistoryUpdateData`,
  `MaxNodesPerHistoryUpdateEvents`.
- Server capability nodes generated dynamically from the struct.

## Code Quality

- Enabled `unparam` linter in `.golangci.yml` — `make check` now catches
  unused parameters.
- Fixed 4 genuine unused-parameter issues in `secure_channel.go` and
  `race_test.go`:
  - `newSecureChannel`: removed 3 dead parameters (`secureChannelID`,
    `sequenceNumber`, `securityTokenID`) — values were only used by
    `NewServerSecureChannel` which sets them on `openingInstance` directly.
  - `sendResponseWithContext`: wired up `ctx` for cancellation checks and
    write deadlines.
  - `mergeChunks`: removed always-nil error return.
  - `race_test.go`: removed unused goroutine parameter.

## Generated Code Changes

All generated files were regenerated from the updated schema:

- `id/` — NodeID constants (DataType, Method, Object, ObjectType, ReferenceType,
  Variable, VariableType)
- `ua/enums_gen.go` — updated/new enum types
- `ua/enums_strings_gen.go` — stringer output for all enums
- `ua/extobjs_gen.go` — extension object codecs
- `ua/register_extobjs_gen.go` — filtered to binary-encoded types only
- `ua/status_gen.go` — new status codes
- `connstate_strings_gen.go` — regenerated

## Files Changed

52 files changed, ~232k insertions, ~53k deletions (bulk is schema XML and
generated code). Hand-written Go: 19 files, +866 / -73 lines.
