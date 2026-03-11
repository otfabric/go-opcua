// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package id

// VariableName returns the standard OPC UA name for a well-known Variable node
// in namespace 0 (e.g. 2256 -> "Server_ServerStatus", 2258 -> "Server_ServerStatus_CurrentTime").
// Returns the empty string if the id is not in the standard Variable set.
// Use when displaying Variable NodeIDs.
func VariableName(id uint32) string {
	return nameVariable[id]
}
