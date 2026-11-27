// SPDX-License-Identifier: MIT

package main

// typeConfig is what the generator cannot take from the NodeSets: the Go
// names of the types package uafx exported before it was generated (its
// API must not change), and their documentation.
type typeConfig struct {
	// Go is the Go name; empty is the default: the BrowseName without the
	// suffix DataType, Enum or OptionSet, in Go form.
	Go string
	// Prefix comes before the Go form of the name of each value of an
	// enumeration or option set; the default is the Go name of the type.
	Prefix *string
	// NoString leaves out the generated String method: the type has a
	// hand-written one, or had none before it was generated.
	NoString bool
	// Doc replaces the generated documentation of the type.
	Doc string
	// Fields configure fields by their name in the definition.
	Fields map[string]fieldConfig
}

type fieldConfig struct {
	// Concrete is the BrowseName of the only subtype of the abstract
	// DataType of the field that Part 81 v1.00 defines; the field has that
	// Go type instead of an interface (the API of v1.37.0).
	Concrete string
	// Doc is the documentation of the field.
	Doc string
}

func prefix(s string) *string { return &s }

// config is keyed by namespace ("data", "ac", "cm") and BrowseName.
var config = map[string]typeConfig{
	// --- Data ---------------------------------------------------------------

	"data:FxCommandMask": {Prefix: prefix(""), NoString: true, Doc: `FxCommandMask is the FxCommandMask OptionSet of Part 81 §10.23: the
commands an EstablishConnections call runs. The bit number is not the
order the commands run in; see [FxCommandMask.Order].`},
	"data:AssetVerificationModeEnum":              {Prefix: prefix(""), NoString: true},
	"data:AssetVerificationResultEnum":            {Prefix: prefix("AssetVerification"), NoString: true},
	"data:FunctionalEntityVerificationResultEnum": {Prefix: prefix("FunctionalEntityVerification"), NoString: true},
	"data:PubSubConnectionEndpointModeEnum": {Prefix: prefix("PubSub"), NoString: true,
		Doc: `PubSubConnectionEndpointMode is the PubSubConnectionEndpointModeEnum of
Part 81 §10.41. It has no value 0.`},
	"data:FxTimeUnitsEnum": {Prefix: prefix("FxTime")},

	"data:AssetVerificationDataType":       {Go: "AssetVerification"},
	"data:AssetVerificationResultDataType": {Go: "AssetVerificationResultData"},
	"data:PubSubCommunicationConfigurationDataType": {Doc: `PubSubCommunicationConfiguration is the
PubSubCommunicationConfigurationDataType of Part 81 §10.10.3: what
SetCommunicationConfigurationCmd applies, as the CloseAndUpdate Method of
Part 14 §9.1.3.7.6 does.`},
	"data:PubSubCommunicationLinkConfigurationDataType": {Doc: `PubSubCommunicationLinkConfiguration is the
PubSubCommunicationLinkConfigurationDataType of Part 81 §10.13.3: the
DataSetReader and DataSetWriter of a ConnectionEndpoint, as references
into the PubSubConfiguration of the same EstablishConnections call.`},
	"data:ConnectionEndpointConfigurationDataType": {Fields: map[string]fieldConfig{
		"CommunicationLinks": {Concrete: "PubSubCommunicationLinkConfigurationDataType", Doc: `CommunicationLinks is nil when the call has no
SetCommunicationConfigurationCmd.`},
	}},
	"data:PubSubConnectionEndpointParameterDataType": {
		Doc: `PubSubConnectionEndpointParameter is the
PubSubConnectionEndpointParameterDataType of Part 81 §10.18.3: the
parameters of a PubSubConnectionEndpoint that EstablishConnections
creates. The fields up to IsPreconfigured are those of its abstract
supertype ConnectionEndpointParameterDataType (§10.18.2), the only other
subtype of which (Client-Server) Part 81 leaves to a future version.`,
		Fields: map[string]fieldConfig{
			"CleanupTimeout": {Doc: `CleanupTimeout is a Duration in milliseconds; negative disables the
cleanup (Part 81 §6.6.2).`},
		},
	},
	"data:NodeIdArray":     {Go: "NodeIDArray", Doc: "NodeIDArray is the NodeIdArray structure of Part 81 §10.31: a Variable,\nor elements of an array Variable."},
	"data:NodeIdValuePair": {Go: "NodeIDValuePair"},
	"data:RelatedEndpointDataType": {
		Doc: "RelatedEndpoint is the RelatedEndpointDataType of Part 81 §10.42: the\nConnectionEndpoint at the other end of a connection.",
		Fields: map[string]fieldConfig{
			"Address":                {Doc: "Address is the DiscoveryUrl of the server of the other end."},
			"ConnectionEndpointPath": {Doc: "ConnectionEndpointPath is the path from FxRoot to the\nFunctionalEntity of the other end."},
		},
	},
	"data:PubSubReserveCommunicationIdsDataType":       {Go: "PubSubReserveCommunicationIDs1"},
	"data:PubSubReserveCommunicationIdsResultDataType": {Go: "PubSubReserveCommunicationIDsResult1"},
	"data:PubSubReserveCommunicationIds2DataType": {Go: "PubSubReserveCommunicationIDs", Doc: `PubSubReserveCommunicationIDs is the
PubSubReserveCommunicationIds2DataType of Part 81 §10.44.2, which
EstablishConnections requires (§6.2.4.3.4.2). DecodeEstablishConnectionsRequest
decodes the older PubSubReserveCommunicationIdsDataType (§10.44.1,
[PubSubReserveCommunicationIDs1]) as well, with RequestTransportSpecificInfo
false.`},
	"data:PubSubReserveCommunicationIdsResult2DataType": {Go: "PubSubReserveCommunicationIDsResult",
		Fields: map[string]fieldConfig{
			"TransportSpecificInfo": {Doc: "TransportSpecificInfo is, for UDP-UADP, the UDP port of unicast\nreception as a UInt16; nil otherwise."},
		}},
	"data:ConnectionEndpointDefinitionDataType": {
		Doc: `ConnectionEndpointDefinition is the ConnectionEndpointDefinitionDataType
union of Part 81 §10.16: the parameters of a ConnectionEndpoint to create,
or the NodeId of an existing one. Exactly one field is set.`,
		Fields: map[string]fieldConfig{
			"Parameter": {Concrete: "PubSubConnectionEndpointParameterDataType"},
		},
	},

	// --- AC -----------------------------------------------------------------

	"ac:ConnectionEndpointStatusEnum": {Go: "ConnectionEndpointStatus", Prefix: prefix("ConnectionEndpoint"), NoString: true,
		Doc: "ConnectionEndpointStatus is the ConnectionEndpointStatusEnum of Part 81\n§10.17, the Status of a ConnectionEndpoint."},
	"ac:DeviceHealthOptionSet": {Prefix: prefix(""), NoString: true,
		Doc: "DeviceHealth is the DeviceHealthOptionSet of Part 81 §10.21: the\naggregated health of the Assets of an AutomationComponent."},
	"ac:OperationalHealthOptionSet": {Prefix: prefix(""), NoString: true,
		Doc: `OperationalHealth is the OperationalHealthOptionSet of Part 81 §10.34: the
operational health of a FunctionalEntity, and aggregated, of the
FunctionalEntities of an AutomationComponent. Its definition names bits
16 to 19; String shows other bits as a number.`},
	"ac:CommHealthOptionSet": {Prefix: prefix("")},
	"ac:ClampKindEnum":       {Prefix: prefix("Clamp")},
	"ac:SocketKindEnum":      {Prefix: prefix("Socket")},
	"ac:AggregatedHealthDataType": {Go: "AggregatedHealth", Fields: map[string]fieldConfig{
		"AggregatedDeviceHealth":      {Doc: "AggregatedDeviceHealth aggregates the DeviceHealth of the top-level\nAssets."},
		"AggregatedOperationalHealth": {Doc: "AggregatedOperationalHealth aggregates the OperationalHealth of the\ntop-level FunctionalEntities."},
	}},
	"ac:FxVersion": {Doc: "FxVersion is the FxVersion structure of Part 81 §10.28, the version of a\nFunctionalEntity."},

	// --- CM -----------------------------------------------------------------

	"cm:ConnectionStateEnum":                 {Prefix: prefix("")},
	"cm:FxEditEnum":                          {Prefix: prefix("")},
	"cm:FxErrorEnum":                         {Prefix: prefix("FxError")},
	"cm:FxProcessEnum":                       {Prefix: prefix("")},
	"cm:ConnectionConfigurationSetOperation": {Prefix: prefix("")},
	"cm:LastActivityMask":                    {Prefix: prefix("LastActivity")},
}
