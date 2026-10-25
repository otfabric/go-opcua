// SPDX-License-Identifier: MIT

// Package certmgmt holds the conformance tests of certificate management
// (Part 12): the push model of the server's ServerConfiguration and the pull
// model of a Global Discovery Server. They are a package of their own because
// CI gives every package 120 s under the race detector; the helpers are
// shared with the other conformance packages through conformkit.
package certmgmt
