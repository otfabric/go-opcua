// SPDX-License-Identifier: MIT

// Package transport holds the conformance tests of the HTTPS and WebSocket
// (opc.wss) transports.
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package transport
