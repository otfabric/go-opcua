// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package id provides well-known OPC UA node identifiers, names, and lookup functions.
package id

// DataTypeName returns the standard OPC UA name for a well-known DataType
// in namespace 0 (e.g. 10 -> "Float", 12 -> "String", 1 -> "Boolean", 294 -> "UtcTime").
// Returns the empty string if the id is not in the standard DataType set.
// Use when displaying DataType NodeIDs to show names instead of raw NodeIDs.
func DataTypeName(id uint32) string {
	return nameDataType[id]
}
