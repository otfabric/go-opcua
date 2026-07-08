// SPDX-License-Identifier: MIT

// Package goname delegates to the shared naming formatter.
package goname

import "github.com/otfabric/go-opcua/internal/goname"

// Format converts an OPC UA spec token into an idiomatic Go identifier.
func Format(s string) string {
	return goname.Format(s)
}
