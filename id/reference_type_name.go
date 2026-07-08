// SPDX-License-Identifier: MIT

package id

// ReferenceTypeName returns the standard OPC UA name for a well-known reference type
// in namespace 0 (e.g. 47 -> "HasComponent", 35 -> "Organizes"). Returns the empty
// string if the id is not in the standard reference type set. Use when displaying
// reference type NodeIDs (e.g. browse refs) to show names instead of raw NodeIDs.
func ReferenceTypeName(id uint32) string {
	return nameReferenceType[id]
}
