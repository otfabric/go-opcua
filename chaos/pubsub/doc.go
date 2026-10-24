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
// MQTT 5.0 (mqtt5_test.go): persistent sessions with QoS 1 and 2 while the
// broker restarts, disconnects clients with reason codes and refuses
// publications; every publication the broker took reaches the
// DataSetHandler exactly once.
//
// AMQP 1.0 (amqp_test.go): the in-process broker restarts, drops and closes
// connections, detaches links, withholds dispositions and stops sending
// heartbeats (UADP, SignAndEncrypt, JSON, metadata from a queue); every
// message a queue accepted reaches the DataSetHandler exactly once; runtimes
// close while their AMQP and MQTT connections reconnect.
//
// Chunks and discovery (chunks_test.go, discovery_test.go): over an
// in-memory datagram network (memnet_test.go, the "chaosmem" transport)
// that drops, duplicates, reorders, delays, truncates and corrupts, with
// floods of forged chunks, probes of every kind and layout and forged
// announcements. The Reassembler stays within its limits and frees the
// state of incomplete messages after the timeout; announcements stay within
// the rate limits; readers learn their DataSetMetaData.
//
// Diagnostics (diagnostics_test.go): Reset, SetDiagnosticsLevel and reads of
// the diagnostics objects through the Go API and through OPC UA clients
// while components come and go; every snapshot is consistent and the
// objects of removed components leave the address space.
//
// Many runtimes (parallel_brokers_test.go): five publishers and five
// subscribers on one AMQP and one MQTT 5.0 broker, with runtimes starting
// and closing next to them.
//
// Fuzzing (fuzz_test.go): random bytes and mutated valid messages (UADP with
// every field encoding, key and delta frames, SignAndEncrypt; JSON data and
// metadata) are fed through the real UDP and MQTT transports into
// subscribers with filtered, unfiltered, RawData and secured readers.
// fuzz_runtime_test.go has native fuzz targets: the receive path of a
// runtime (chunks, discovery, secured and RawData readers;
// FuzzRuntimeReceive), the discovery codec (FuzzDiscoveryRoundTrip) and the
// connection configurations a client can send (FuzzValidateConnection).
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
