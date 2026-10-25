// SPDX-License-Identifier: MIT

// Package conformance holds the back-to-back client/server conformance and
// adversarial test suite for go-opcua.
//
// Every test in this package stands up an in-process OPC UA server (via
// internal/testutil) and drives it with the real go-opcua client over a
// loopback secure channel. The client encodes each request and the server
// decodes it (and vice-versa for responses), so the suite exercises both sides
// of the wire and is well suited to weeding out codec and protocol bugs.
//
// The suite is organised in three tiers:
//
//   - Conformance (attribute/view/method/subscription/events/nodemgmt/history/
//     misc) systematically covers each client API method and its server
//     handler with happy-path and error assertions.
//   - Adversarial (roundtrip/property/adversarial) fuzzes values across every
//     Variant type, generates random inputs with pgregory.net/rapid, and feeds
//     malformed/boundary requests expecting proper status codes rather than
//     panics or hangs.
//   - Concurrency runs many clients in parallel and is intended to be run under
//     the race detector.
//
// matrix_test.go keeps the suite honest as the API grows: every exported
// method of *opcua.Client, *opcua.Node, *opcua.Subscription, the subscription
// builder, *opcua.Session and the monitor package, and every client and server
// Option constructor, must be exercised by a test in this package or in one of
// the conformance packages below it.
//
// CI gives every package 120 s under the race detector, so parts of the suite
// are packages of their own: alarms (Part 9), certmgmt (Part 12), discovery,
// pubsub (Part 14) and eccext (the math/big ECC policies). They share their
// helpers through internal/testutil/conformkit.
package conformance
