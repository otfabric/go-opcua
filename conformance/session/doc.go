// SPDX-License-Identifier: MIT

// Package session holds the conformance tests of the session and secure
// channel lifecycle (activation, timeouts, transfer, renewal, metrics and
// reconnects) and of reverse connect.
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package session
