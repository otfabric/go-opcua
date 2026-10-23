// SPDX-License-Identifier: MIT

// Package pubsubchaos holds the chaos-monkey and parallelism tests of OPC UA
// PubSub (package pubsub and its codecs, transports, message security and
// Security Key Service, and the PubSub information model of the server).
//
// The package contains only tests. They run publishers and subscribers of
// this module against each other over real UDP sockets and an in-process
// MQTT broker and are meant to be run with the race detector:
//
//	go test -race ./chaos/pubsub/
//
// # What is tested
//
// Network faults (network_test.go): a UDP relay between publisher and
// subscriber drops, duplicates, reorders, delays, truncates and - with
// message security - corrupts datagrams, and blackholes the path for longer
// than the MessageReceiveTimeout. A publisher is restarted under its
// subscriber.
//
// Message security (security_test.go): tampered and replayed messages,
// messages signed with the keys of another SKS or with an unknown token id,
// unsecured and downgraded messages, rotation storms with a key lifetime of
// a few publishing intervals, messages injected after their key left the
// past keys, and an SKS (an OPC UA server, pulled with pubsub/sks) that is
// stopped for less and for longer than its future keys last.
//
// MQTT (mqtt_test.go): the broker is restarted, stopped for a while, forgets
// its sessions, drops all connections, stops answering pings and refuses
// subscriptions (also the ones made again after a reconnect), and the
// subscriber consumes too slowly for it, for the UADP and the JSON mapping;
// a value changes during an outage under a writer that sends delta frames.
//
// Runtime churn (churn_test.go, parallel_test.go): connections, groups,
// writers, readers and published data sets are added, removed, enabled and
// disabled while traffic flows, through the Go API from several goroutines
// and through the methods of the information model from several OPC UA
// clients at once; the server is closed in the middle of it; Start, the
// cancellation of its context and Close race each other; 70 writer groups
// on six connections publish into as many reader groups while their
// components are toggled.
//
// Fuzzing (fuzz_test.go): random bytes and mutated valid messages (UADP with
// every field encoding, key and delta frames, SignAndEncrypt; JSON data and
// metadata) are fed through the real UDP and MQTT transports into
// subscribers with filtered, unfiltered, RawData and secured readers.
//
// Regression tests for the product bugs the suite found live next to the
// code they concern (pubsub/*_regress_test.go).
//
// # Invariants
//
//   - no panic, no data race, no deadlock (every operation and every Close
//     returns within a bound), no goroutine leak once all tests are done
//   - a subscriber never delivers a corrupt, duplicate or stale data set:
//     the published data sets carry a counter, a check string that repeats
//     it and a value derived from it, and the counter and the sequence
//     number of every writer only grow (checker in helpers_test.go)
//   - a secured reader only delivers what the real publisher sent: nothing
//     forged, replayed, downgraded or signed with other keys, and an
//     attack does not disturb its sequence state
//   - readers go to Error on a MessageReceiveTimeout and back to
//     Operational, and their transitions are legal
//   - the counters show what happened: discarded duplicates, decode
//     errors for corrupt and rejected messages, timeouts
//   - once the faults stop, every reader delivers again; MQTT clients
//     reconnect and subscribe again
//   - after churn, the information model shows exactly the components of
//     the runtime
//
// # Knobs
//
// CHAOS_SEED, CHAOS_DURATION and CHAOS_LOG as in package chaos. Every
// randomized test logs its seed and the command that replays it.
package pubsubchaos
