// SPDX-License-Identifier: MIT

package uafx

import (
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// FxCommandMask is the FxCommandMask OptionSet of Part 81 §10.23: the
// commands an EstablishConnections call runs. The bit number is not the
// order the commands run in; see [FxCommandMask.Order].
type FxCommandMask uint32

// The bits of FxCommandMask (Part 81 §10.23, Table 172). Bits 9 to 31 are
// reserved.
const (
	VerifyAssetCmd                   FxCommandMask = 1 << 0
	VerifyFunctionalEntityCmd        FxCommandMask = 1 << 1
	CreateConnectionEndpointCmd      FxCommandMask = 1 << 2
	EstablishControlCmd              FxCommandMask = 1 << 3
	SetConfigurationDataCmd          FxCommandMask = 1 << 4
	ReassignControlCmd               FxCommandMask = 1 << 5
	ReserveCommunicationIDsCmd       FxCommandMask = 1 << 6
	SetCommunicationConfigurationCmd FxCommandMask = 1 << 7
	EnableCommunicationCmd           FxCommandMask = 1 << 8

	// AllFxCommands are the bits Part 81 defines.
	AllFxCommands FxCommandMask = 1<<9 - 1
)

var commandNames = []bitName{
	{0, "VerifyAsset"}, {1, "VerifyFunctionalEntity"}, {2, "CreateConnectionEndpoint"},
	{3, "EstablishControl"}, {4, "SetConfigurationData"}, {5, "ReassignControl"},
	{6, "ReserveCommunicationIds"}, {7, "SetCommunicationConfiguration"}, {8, "EnableCommunication"},
}

// String returns the names of the commands that are set, separated by "|",
// or "OK" when none is.
func (m FxCommandMask) String() string { return bitString(uint64(m), commandNames) }

// commandOrder is the order in which EstablishConnections processes the
// commands (Part 81 §6.2.4.3.1).
var commandOrder = []FxCommandMask{
	VerifyAssetCmd, VerifyFunctionalEntityCmd, ReserveCommunicationIDsCmd,
	CreateConnectionEndpointCmd, EstablishControlCmd, SetConfigurationDataCmd,
	ReassignControlCmd, SetCommunicationConfigurationCmd, EnableCommunicationCmd,
}

// Order returns the commands of m in the order EstablishConnections runs
// them (Part 81 §6.2.4.3.1): VerifyAsset, VerifyFunctionalEntity,
// ReserveCommunicationIds, CreateConnectionEndpoint, EstablishControl,
// SetConfigurationData, ReassignControl, SetCommunicationConfiguration,
// EnableCommunication.
func (m FxCommandMask) Order() []FxCommandMask {
	var out []FxCommandMask
	for _, c := range commandOrder {
		if m&c != 0 {
			out = append(out, c)
		}
	}
	return out
}

// AssetVerificationMode is the AssetVerificationModeEnum of Part 81 §10.4.
type AssetVerificationMode int32

// The values of AssetVerificationModeEnum.
const (
	AssetCompatibility            AssetVerificationMode = 0
	AssetIdentity                 AssetVerificationMode = 1
	AssetIdentityAndCompatibility AssetVerificationMode = 2
)

// AssetVerificationResult is the AssetVerificationResultEnum of Part 81
// §10.7.
type AssetVerificationResult int32

// The values of AssetVerificationResultEnum.
const (
	AssetVerificationNotSet     AssetVerificationResult = 0
	AssetVerificationMatch      AssetVerificationResult = 1
	AssetVerificationCompatible AssetVerificationResult = 2
	AssetVerificationMismatch   AssetVerificationResult = 3
)

// FunctionalEntityVerificationResult is the
// FunctionalEntityVerificationResultEnum of Part 81 §10.22.
type FunctionalEntityVerificationResult int32

// The values of FunctionalEntityVerificationResultEnum.
const (
	FunctionalEntityVerificationNotSet   FunctionalEntityVerificationResult = 0
	FunctionalEntityVerificationMatch    FunctionalEntityVerificationResult = 1
	FunctionalEntityVerificationMismatch FunctionalEntityVerificationResult = 2
)

// PubSubConnectionEndpointMode is the PubSubConnectionEndpointModeEnum of
// Part 81 §10.41. It has no value 0.
type PubSubConnectionEndpointMode int32

// The values of PubSubConnectionEndpointModeEnum.
const (
	PubSubPublisherSubscriber PubSubConnectionEndpointMode = 1
	PubSubPublisher           PubSubConnectionEndpointMode = 2
	PubSubSubscriber          PubSubConnectionEndpointMode = 3
)

// Publishes reports whether an endpoint of mode m has a DataSetWriter
// (Part 81 §6.6.3).
func (m PubSubConnectionEndpointMode) Publishes() bool {
	return m == PubSubPublisherSubscriber || m == PubSubPublisher
}

// Subscribes reports whether an endpoint of mode m has a DataSetReader
// (Part 81 §6.6.3).
func (m PubSubConnectionEndpointMode) Subscribes() bool {
	return m == PubSubPublisherSubscriber || m == PubSubSubscriber
}

// NodeIDArray is the NodeIdArray structure of Part 81 §10.31: a Variable,
// or elements of an array Variable.
type NodeIDArray struct {
	Node       *ua.NodeID
	ArrayIndex []uint32
}

// NodeIDValuePair is the NodeIdValuePair structure of Part 81 §10.32.
type NodeIDValuePair struct {
	Key   *NodeIDArray
	Value *ua.Variant
}

// AssetVerification is the AssetVerificationDataType of Part 81 §10.5.
type AssetVerification struct {
	AssetToVerify                           *ua.NodeID
	VerificationMode                        AssetVerificationMode
	ExpectedVerificationResult              AssetVerificationResult
	ExpectedVerificationVariables           []*ua.KeyValuePair
	ExpectedAdditionalVerificationVariables []*NodeIDValuePair
}

// AssetVerificationResultData is the AssetVerificationResultDataType of
// Part 81 §10.6.
type AssetVerificationResultData struct {
	VerificationStatus                    ua.StatusCode
	VerificationResult                    AssetVerificationResult
	VerificationVariablesErrors           []ua.StatusCode
	VerificationAdditionalVariablesErrors []ua.StatusCode
}

// RelatedEndpoint is the RelatedEndpointDataType of Part 81 §10.42: the
// ConnectionEndpoint at the other end of a connection.
type RelatedEndpoint struct {
	// Address is the DiscoveryUrl of the server of the other end.
	Address string
	// ConnectionEndpointPath is the path from FxRoot to the
	// FunctionalEntity of the other end.
	ConnectionEndpointPath []*ua.PortableQualifiedName
	ConnectionEndpointName string
}

// PubSubConnectionEndpointParameter is the
// PubSubConnectionEndpointParameterDataType of Part 81 §10.18.3: the
// parameters of a PubSubConnectionEndpoint that EstablishConnections
// creates. The fields up to IsPreconfigured are those of its abstract
// supertype ConnectionEndpointParameterDataType (§10.18.2), the only other
// subtype of which (Client-Server) Part 81 leaves to a future version.
type PubSubConnectionEndpointParameter struct {
	Name                     string
	ConnectionEndpointTypeID *ua.NodeID
	InputVariableIDs         []*ua.NodeID
	OutputVariableIDs        []*ua.NodeID
	IsPersistent             bool
	// CleanupTimeout is a Duration in milliseconds; negative disables the
	// cleanup (Part 81 §6.6.2).
	CleanupTimeout  float64
	RelatedEndpoint *RelatedEndpoint
	IsPreconfigured bool
	Mode            PubSubConnectionEndpointMode
}

// CleanupTimeoutDuration returns CleanupTimeout as a time.Duration, and
// false when it is negative (no cleanup).
func (p *PubSubConnectionEndpointParameter) CleanupTimeoutDuration() (time.Duration, bool) {
	if p.CleanupTimeout < 0 {
		return 0, false
	}
	return durationOf(p.CleanupTimeout), true
}

// ConnectionEndpointDefinition is the ConnectionEndpointDefinitionDataType
// union of Part 81 §10.16: the parameters of a ConnectionEndpoint to create,
// or the NodeId of an existing one. Exactly one field is set.
type ConnectionEndpointDefinition struct {
	Parameter *PubSubConnectionEndpointParameter
	Node      *ua.NodeID
}

// PubSubCommunicationLinkConfiguration is the
// PubSubCommunicationLinkConfigurationDataType of Part 81 §10.13.3: the
// DataSetReader and DataSetWriter of a ConnectionEndpoint, as references
// into the PubSubConfiguration of the same EstablishConnections call.
type PubSubCommunicationLinkConfiguration struct {
	DataSetReaderRef                 *ua.PubSubConfigurationRefDataType
	ExpectedSubscribedDataSetVersion *ua.ConfigurationVersionDataType
	DataSetWriterRef                 *ua.PubSubConfigurationRefDataType
	ExpectedPublishedDataSetVersion  *ua.ConfigurationVersionDataType
}

// ConnectionEndpointConfiguration is the
// ConnectionEndpointConfigurationDataType of Part 81 §10.14.
type ConnectionEndpointConfiguration struct {
	FunctionalEntityNode          *ua.NodeID
	ConnectionEndpoint            *ConnectionEndpointDefinition
	ExpectedVerificationVariables []*NodeIDValuePair
	ControlGroups                 []*ua.NodeID
	ConfigurationData             []*NodeIDValuePair
	// CommunicationLinks is nil when the call has no
	// SetCommunicationConfigurationCmd.
	CommunicationLinks *PubSubCommunicationLinkConfiguration
}

// ConnectionEndpointConfigurationResult is the
// ConnectionEndpointConfigurationResultDataType of Part 81 §10.15.
type ConnectionEndpointConfigurationResult struct {
	ConnectionEndpointID        *ua.NodeID
	FunctionalEntityNodeResult  ua.StatusCode
	ConnectionEndpointResult    ua.StatusCode
	VerificationResult          FunctionalEntityVerificationResult
	VerificationStatus          ua.StatusCode
	VerificationVariablesErrors []ua.StatusCode
	EstablishControlResult      []ua.StatusCode
	ConfigurationDataResult     []ua.StatusCode
	ReassignControlResult       []ua.StatusCode
	CommunicationLinksResult    ua.StatusCode
	EnableCommunicationResult   ua.StatusCode
}

// PubSubReserveCommunicationIDs is the
// PubSubReserveCommunicationIds2DataType of Part 81 §10.44.2, which
// EstablishConnections requires (§6.2.4.3.4.2). It decodes the older
// PubSubReserveCommunicationIdsDataType (§10.44.1) as well, with
// RequestTransportSpecificInfo false.
type PubSubReserveCommunicationIDs struct {
	TransportProfileURI          string
	NumReqWriterGroupIDs         uint16
	NumReqDataSetWriterIDs       uint16
	RequestTransportSpecificInfo bool
}

// PubSubReserveCommunicationIDsResult is the
// PubSubReserveCommunicationIdsResult2DataType of Part 81 §10.43.4.
type PubSubReserveCommunicationIDsResult struct {
	Result             ua.StatusCode
	DefaultPublisherID *ua.Variant
	WriterGroupIDs     []uint16
	DataSetWriterIDs   []uint16
	// TransportSpecificInfo is, for UDP-UADP, the UDP port of unicast
	// reception as a UInt16; nil otherwise.
	TransportSpecificInfo *ua.Variant
}

// PubSubCommunicationConfiguration is the
// PubSubCommunicationConfigurationDataType of Part 81 §10.10.3: what
// SetCommunicationConfigurationCmd applies, as the CloseAndUpdate Method of
// Part 14 §9.1.3.7.4 does.
type PubSubCommunicationConfiguration struct {
	PubSubConfiguration     *ua.PubSubConfiguration2DataType
	RequireCompleteUpdate   bool
	ConfigurationReferences []*ua.PubSubConfigurationRefDataType
}

// PubSubCommunicationConfigurationResult is the
// PubSubCommunicationConfigurationResultDataType of Part 81 §10.11.3.
type PubSubCommunicationConfigurationResult struct {
	Result               ua.StatusCode
	ChangesApplied       bool
	ReferenceResults     []ua.StatusCode
	ConfigurationValues  []*ua.PubSubConfigurationValueDataType
	ConfigurationObjects []*ua.NodeID
}

// EstablishConnectionsRequest are the input arguments of the
// EstablishConnections Method (Part 81 §6.2.4.2). A slice must be empty
// unless CommandMask has its command (Table 8).
type EstablishConnectionsRequest struct {
	CommandMask                      FxCommandMask
	AssetVerifications               []*AssetVerification
	ConnectionEndpointConfigurations []*ConnectionEndpointConfiguration
	ReserveCommunicationIDs          []*PubSubReserveCommunicationIDs
	// CommunicationConfigurations has one element with
	// SetCommunicationConfigurationCmd, none otherwise.
	CommunicationConfigurations []*PubSubCommunicationConfiguration
}

// EstablishConnectionsResult are the output arguments of the
// EstablishConnections Method (Part 81 §6.2.4.2) and the status of the
// call: Good, or Uncertain when a command failed and the call was aborted
// (Table 9), with the details in the results.
type EstablishConnectionsResult struct {
	Status                                 ua.StatusCode
	AssetVerificationResults               []*AssetVerificationResultData
	ConnectionEndpointConfigurationResults []*ConnectionEndpointConfigurationResult
	ReserveCommunicationIDsResults         []*PubSubReserveCommunicationIDsResult
	CommunicationConfigurationResults      []*PubSubCommunicationConfigurationResult
}
