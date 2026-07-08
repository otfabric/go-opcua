// SPDX-License-Identifier: MIT

package id

// VariableTypeName returns the standard OPC UA name for a well-known VariableType
// in namespace 0 (e.g. 68 -> "PropertyType", 63 -> "BaseVariableType"). Returns the empty
// string if the id is not in the standard VariableType set.
// Use when displaying VariableType or type definition NodeIDs.
func VariableTypeName(id uint32) string {
	return nameVariableType[id]
}
