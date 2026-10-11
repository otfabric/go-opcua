// SPDX-License-Identifier: MIT

// Package codec holds the parallelism and robustness suite of the OPC UA
// JSON (Part 6 §5.4) and XML (Part 6 §5.3) DataEncodings of package ua, and
// of what the server builds on them: the values of an imported NodeSet2.
//
// The package contains only tests. They are meant to be run with the race
// detector:
//
//	go test -race ./chaos/codec/
//	CHAOS_SEED=42 go test -race ./chaos/codec/            # replay a seed
//	CHAOS_DURATION=60s go test -race -run Hostile ./chaos/codec/
//
// # What is tested
//
// The codecs are functions without state of their own, but they rest on
// state that the whole process shares: the registry of extension object
// types, the JSON/XML metadata of every structure, caches that are filled on
// the first use of a Go type, and - in the server - the built-in NodeSet,
// which is parsed once and imported into every server.
//
//   - concurrent_test.go: EncodeJSON (all four forms), EncodeXML, DecodeJSON
//     and DecodeXML from many goroutines over the same values (one instance
//     of every structure the codecs know, Variants of every built-in type as
//     scalar, array and matrix, DataValues, ExtensionObjects with generated
//     and custom bodies) with the same option slices. The first use of every
//     type is made concurrent by re-executing the test binary: in a fresh
//     process the very first codec calls come from goroutines released on a
//     barrier.
//   - register_test.go: ua.RegisterExtensionObject and ua.RegisterDataTypeInfo
//     for new types while other goroutines encode and decode values of those
//     and of long-registered types in the binary, JSON and XML encoding, and
//     what a duplicate registration does.
//   - nodeset_test.go: servers created concurrently, the values of the
//     namespace-0 variables read through the server API and through clients,
//     and mutation of those values on some of the servers (in place, with
//     Node.SetAttribute, with a client Write); concurrent ImportNodeSetXML
//     of one document into several servers.
//   - hostile_test.go: concurrent decoding of mutated and of deliberately
//     exhausting documents under WithMaxDepth / WithMaxArrayLength.
//
// # Invariants
//
// No data race, no panic, no deadlock, no goroutine left behind. Every
// encoding of a value is byte for byte what a single goroutine produces, in
// the same process and in another one; every document decodes to a value
// with the binary encoding of the original; encoders and decoders do not
// modify what they are given. A type is either unknown to the codecs - in
// the documented way - or completely usable, never something in between.
// A value changed on one server is not changed on another server, nor on one
// created later. A decoder never allocates what a document merely claims,
// honours its limits, and returns errors that wrap a StatusCode.
//
// Two values are "the same" throughout if their binary encodings are equal:
// that comparison is exact and independent of the codecs under test.
//
// # Reproducing a failure
//
// Every randomized test logs its seed and the command that replays it.
// CHAOS_SEED fixes the seed of all tests of a run; CHAOS_DURATION sets the
// length of the duration based scenario (the hostile documents).
package codec
