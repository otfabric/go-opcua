// SPDX-License-Identifier: MIT

package id

import "sync"

var (
	// nameToID maps well-known standard node names (namespace 0) to numeric IDs.
	// Built from nameObject, nameVariable, nameMethod, nameDataType, nameReferenceType,
	// nameObjectType, nameVariableType; first occurrence wins on duplicate names.
	nameToID   map[string]uint32
	nameToIDMu sync.Once
)

// shortAliases are common short names for well-known nodes (namespace 0).
// These allow "CurrentTime" and "ServerStatus" in addition to the full names
// from the spec (e.g. "Server_ServerStatus_CurrentTime").
var shortAliases = map[string]uint32{
	"Objects":      ObjectsFolder,
	"CurrentTime":  ServerServerStatusCurrentTime,
	"ServerStatus": ServerServerStatus,
}

func buildNameToID() {
	nameToID = make(map[string]uint32)
	// Order matches id.Name(): object, variable, method, datatype, referenceType, objectType, variableType.
	// First occurrence wins so that e.g. "Server" (object) is preferred.
	for id, name := range nameObject {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	for id, name := range nameVariable {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	for id, name := range nameMethod {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	for id, name := range nameDataType {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	for id, name := range nameReferenceType {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	for id, name := range nameObjectType {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	for id, name := range nameVariableType {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
	// Short aliases override only if not already present (so full names take precedence when both exist).
	for name, id := range shortAliases {
		if _, ok := nameToID[name]; !ok {
			nameToID[name] = id
		}
	}
}

// NodeIDByName returns the namespace-0 numeric node ID for a well-known standard node name, if known.
// Names are the same as in the id package forward lookup (e.g. "Server", "ObjectsFolder",
// "Server_ServerStatus_CurrentTime"). Short aliases include "CurrentTime" (→ 2258),
// "ServerStatus" (→ 2256), and "Objects" (→ 85). Returns (0, false) if the name is not found.
// For a *ua.NodeID use ua.StandardNodeID(name).
func NodeIDByName(name string) (uint32, bool) {
	nameToIDMu.Do(buildNameToID)
	id, ok := nameToID[name]
	return id, ok
}
