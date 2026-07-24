// SPDX-License-Identifier: MIT

package server

import (
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/ua"
)

// AcknowledgeableConditionTypeNodeID is the well-known ObjectType NodeId for
// AcknowledgeableConditionType (Part 9). Full Alarms & Conditions support is
// an optional profile outside core Client/Server parity.
var AcknowledgeableConditionTypeNodeID = ua.NewNumericNodeID(0, id.AcknowledgeableConditionType)

// AlarmsConditionsSupported reports whether a full A&C implementation is
// available. The current library exposes the standard type NodeId in namespace 0
// via the built-in nodeset but does not implement condition state machines,
// Acknowledge/Confirm method behaviour, or alarm catalogs.
//
// This helper exists so applications and the coverage ledger can treat A&C as
// an explicitly optional / deferred profile.
func AlarmsConditionsSupported() bool {
	return false
}
