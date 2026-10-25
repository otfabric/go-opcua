// SPDX-License-Identifier: MIT

// Package discovery holds the conformance tests of discovery (Part 12 §4):
// the Local Discovery Server, registration with it and LDS-ME over mDNS.
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package discovery
