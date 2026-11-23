// SPDX-License-Identifier: MIT

// Package uafx holds the end-to-end tests of the OPC UA FX model (OPC
// 10000-81) between a go-opcua server built with uafx/fxserver and
// uafx.Inspect on a go-opcua client: over every RSA and ECC security policy
// in both secure modes, with anonymous and username identities, with UACP
// buffers small enough that every Browse and Read response spans several
// chunks, and with many clients inspecting at the same time. Every run must
// produce the report of a plain None connection.
//
// There is no independent UAFX implementation among the pinned references
// of opcua-interop, so these tests show that the two halves of go-opcua
// agree, not that they agree with Part 81 as other stacks read it.
package uafx
