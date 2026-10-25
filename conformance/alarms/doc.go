// SPDX-License-Identifier: MIT

// Package alarms holds the conformance tests of Alarms & Conditions (Part 9).
// They are a package of their own because CI gives every package 120 s under
// the race detector; the helpers are shared with the other conformance
// packages through conformkit.
package alarms
