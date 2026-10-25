// SPDX-License-Identifier: MIT

// Package addrspace holds the conformance tests of the address space
// services: Read and Write of attributes, Browse and TranslateBrowsePaths,
// Call, NodeManagement, Query, role-based access control and the extended
// service set tests.
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package addrspace
