// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import (
	"github.com/otfabric/opcua/id"
	"github.com/otfabric/opcua/ua"
)

// ReferenceTypeDisplayName returns a display string for a reference type NodeID.
// For well-known reference types in namespace 0 (e.g. HasComponent, Organizes),
// it returns the standard name; otherwise it returns the NodeID string.
// Use when displaying the reference type column in browse refs or similar UIs.
// Returns the empty string if refTypeID is nil.
func ReferenceTypeDisplayName(refTypeID *ua.NodeID) string {
	if refTypeID == nil {
		return ""
	}
	if refTypeID.Namespace() == 0 {
		if name := id.ReferenceTypeName(refTypeID.IntID()); name != "" {
			return name
		}
	}
	return refTypeID.String()
}

// TypeDefinitionDisplayName returns a display string for a type definition NodeID
// (VariableType or ObjectType in namespace 0). It tries VariableTypeName then
// ObjectTypeName; if neither matches, returns the NodeID string. Use when
// displaying type definition columns (e.g. browse) so "PropertyType" is shown
// instead of "i=68". Returns the empty string if typeDefID is nil.
func TypeDefinitionDisplayName(typeDefID *ua.NodeID) string {
	if typeDefID == nil {
		return ""
	}
	if typeDefID.Namespace() == 0 {
		if name := id.VariableTypeName(typeDefID.IntID()); name != "" {
			return name
		}
		if name := id.ObjectTypeName(typeDefID.IntID()); name != "" {
			return name
		}
	}
	return typeDefID.String()
}

// DataTypeDisplayName returns a display string for a DataType NodeID.
// For well-known DataTypes in namespace 0 (e.g. Float, String, Boolean, UtcTime),
// it returns the standard name; otherwise it returns the NodeID string.
// Use when displaying DataType attributes or type columns to normalize type
// rendering (e.g. "Float" instead of "i=10", "UtcTime" instead of "i=294").
// Returns the empty string if dataTypeID is nil.
func DataTypeDisplayName(dataTypeID *ua.NodeID) string {
	if dataTypeID == nil {
		return ""
	}
	if dataTypeID.Namespace() == 0 {
		if name := id.DataTypeName(dataTypeID.IntID()); name != "" {
			return name
		}
	}
	return dataTypeID.String()
}

// StandardNodeID returns the namespace-0 NodeID for a well-known standard node name, if known.
// Uses id.NodeIDByName and returns ua.NewNumericNodeID(0, id). Names include "Server", "ObjectsFolder",
// "Server_ServerStatus_CurrentTime", and short aliases "CurrentTime" (→ i=2258), "ServerStatus" (→ i=2256),
// "Objects" (→ i=85). Use for CLI flags like get value -n CurrentTime instead of -n i=2258.
func StandardNodeID(name string) (*ua.NodeID, bool) {
	id, ok := id.NodeIDByName(name)
	if !ok {
		return nil, false
	}
	return ua.NewNumericNodeID(0, id), true
}
