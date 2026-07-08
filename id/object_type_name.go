// SPDX-License-Identifier: MIT

package id

// ObjectTypeName returns the standard OPC UA name for a well-known ObjectType
// in namespace 0 (e.g. 58 -> "BaseObjectType", 61 -> "FolderType"). Returns the empty
// string if the id is not in the standard ObjectType set.
// Use when displaying ObjectType or type definition NodeIDs.
func ObjectTypeName(id uint32) string {
	return nameObjectType[id]
}
