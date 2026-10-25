// SPDX-License-Identifier: MIT

// Package pubsub holds the conformance tests of PubSub (Part 14). They are a
// package of their own because CI gives every package 120 s under the race
// detector; the helpers are shared with the other conformance packages
// through conformkit.
package pubsub
