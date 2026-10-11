// SPDX-License-Identifier: MIT

// Package reverse holds the chaos-monkey and parallelism tests that harden
// reverse connect (Part 6 §7.1.3): the connections a server opens to a
// listening client, the listener that hands them to the clients, and the
// reverse connect targets of a server.
//
// The package contains only tests. They extend the None-security scenario of
// the parent package (chaos/reverse_connect_test.go) and are meant to be run
// with the race detector:
//
//	go test -race ./chaos/reverse/
//
// # What is tested
//
// Secured reverse connections under faults (secure_test.go): a client with a
// SignAndEncrypt channel (Basic256Sha256 with RSA certificates and
// ECC_nistP256_AesGcm with ECDSA certificates), a short secure channel
// lifetime and a running subscription takes its connection from a listener
// the server reaches through internal/testutil.ChaosProxy. The proxy resets,
// half-closes, blackholes, delays, fragments, truncates and corrupts the
// connection in use, refuses new ones, and the server is restarted.
//
// Several servers on one listener (shared_test.go): servers with distinct
// ApplicationUris, with and without security, connect to one
// uacp.ReverseListener that is shared by one client per server, plus a
// server nobody waits for. The targets are removed and added again and the
// servers are restarted while the clients run a workload.
//
// The listener closed under load (listener_test.go): with servers in the
// middle of announcing themselves, announced connections nobody asked for,
// clients waiting in Connect and a client waiting to reconnect.
//
// The target life cycle (lifecycle_test.go): Server.AddReverseConnect,
// ReverseConnect.Close, Server.Start and Server.Close run concurrently while
// clients connect through the listener.
//
// Regression tests (regression_test.go) pin down the product bugs the suite
// found with small deterministic tests.
//
// # Invariants
//
//   - no panic and no data race (run with -race)
//   - no deadlock: every operation returns within a bound (watchdog)
//   - no goroutine leak after everything is closed
//   - after every fault the client returns to Connected over a new
//     connection the server opens, and its subscription delivers again
//   - a value a subscription or a read delivers is one the server-side
//     writer produced, and the values of a node never go backwards. This
//     holds in particular while the transport flips bits: on a secured
//     channel corruption is always detected
//   - a client that shares a listener only ever talks to its own server
//   - the listener holds at most one connection per server nobody is waiting
//     for, and none once the servers are gone
//   - the ConnState transitions reported to WithConnStateHandler are legal
//   - once all clients are gone a server holds no channels, sessions,
//     subscriptions or monitored items, and still serves a new client
//   - a server whose client is gone keeps trying to reach it, with back-off
//   - Server.ReverseConnects lists exactly the targets that were added and
//     not closed; closing a target or the server never blocks
//
// # Knobs
//
// CHAOS_SEED, CHAOS_DURATION and CHAOS_LOG as in the parent package. Every
// randomized scenario logs its seed together with the command that replays
// it.
package reverse
