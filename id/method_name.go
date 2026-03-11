// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package id

// MethodName returns the standard OPC UA name for a well-known Method node
// in namespace 0 (e.g. 11492 -> "Server_GetMonitoredItems"). Returns the empty
// string if the id is not in the standard Method set.
// Use when displaying Method NodeIDs (e.g. browse or call UI).
func MethodName(id uint32) string {
	return nameMethod[id]
}
