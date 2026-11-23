// SPDX-License-Identifier: MIT

package uafx

import (
	"time"

	"github.com/otfabric/go-opcua/ua"
)

// AllFxCommands are the bits of FxCommandMask that Part 81 defines
// (§10.23, Table 172). Bits 9 to 31 are reserved.
const AllFxCommands FxCommandMask = 1<<9 - 1

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

// CleanupTimeoutDuration returns CleanupTimeout as a time.Duration, and
// false when it is negative (no cleanup).
func (p *PubSubConnectionEndpointParameter) CleanupTimeoutDuration() (time.Duration, bool) {
	if p.CleanupTimeout < 0 {
		return 0, false
	}
	return durationOf(p.CleanupTimeout), true
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
