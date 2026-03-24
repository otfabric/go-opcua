package ua

import "github.com/otfabric/go-opcua/id"

// ReferenceTypeDisplayName returns a display string for a reference type NodeID.
// For well-known reference types in namespace 0 (e.g. HasComponent, Organizes),
// it returns the standard name; otherwise it returns the NodeID string.
// Returns the empty string if refTypeID is nil.
func ReferenceTypeDisplayName(refTypeID *NodeID) string {
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
// ObjectTypeName; if neither matches, returns the NodeID string.
// Returns the empty string if typeDefID is nil.
func TypeDefinitionDisplayName(typeDefID *NodeID) string {
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
// Returns the empty string if dataTypeID is nil.
func DataTypeDisplayName(dataTypeID *NodeID) string {
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
// Names include "Server", "ObjectsFolder", "Server_ServerStatus_CurrentTime",
// and short aliases "CurrentTime" (-> i=2258), "ServerStatus" (-> i=2256),
// "Objects" (-> i=85).
func StandardNodeID(name string) (*NodeID, bool) {
	nid, ok := id.NodeIDByName(name)
	if !ok {
		return nil, false
	}
	return NewNumericNodeID(0, nid), true
}
