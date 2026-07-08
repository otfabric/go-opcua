// SPDX-License-Identifier: MIT

// Package refs provides OPC UA reference constructors for building node hierarchies.
package refs

import (
	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/server/attrs"
	"github.com/otfabric/go-opcua/ua"
)

// HasSubtype returns a HasSubtype reference.
func HasSubtype(typeID *ua.ExpandedNodeID) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.HasSubtype),
		TypeDefinition:  typeID,
		IsForward:       true,
	}
}

// Organizes returns an Organizes reference.
func Organizes(nid *ua.NodeID, browseName, displayName string, typeID *ua.ExpandedNodeID) *ua.ReferenceDescription {
	return &ua.ReferenceDescription{
		ReferenceTypeID: ua.NewNumericNodeID(0, id.Organizes),
		NodeID:          &ua.ExpandedNodeID{NodeID: nid},
		BrowseName:      attrs.BrowseName(browseName),
		DisplayName:     attrs.DisplayName(displayName, ""),
		TypeDefinition:  typeID,
		IsForward:       true,
	}
}
