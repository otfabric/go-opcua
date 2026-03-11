// Copyright 2018-2024 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package id

// ObjectName returns the standard OPC UA name for a well-known Object node
// in namespace 0 (e.g. 84 -> "RootFolder", 85 -> "ObjectsFolder", 2253 -> "Server").
// Returns the empty string if the id is not in the standard Object set.
// Use when displaying Object NodeIDs or for reverse lookup with NodeIDByName.
func ObjectName(id uint32) string {
	return nameObject[id]
}
