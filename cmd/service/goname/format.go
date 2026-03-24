// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Package goname delegates to the shared naming formatter.
package goname

import "github.com/otfabric/go-opcua/internal/goname"

// Format converts an OPC UA spec token into an idiomatic Go identifier.
func Format(s string) string {
	return goname.Format(s)
}
