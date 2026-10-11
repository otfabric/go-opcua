// SPDX-License-Identifier: MIT

// Package chaos holds the chaos-monkey and parallelism test suite that
// hardens the client and server state machines: the UACP connection, the
// secure channel (open, renew, close, request/response matching, chunking),
// the session (create, activate, close, timeout), the subscription publish
// loop, monitored items, and the client's automatic reconnect with
// subscription recovery.
//
// The package contains only tests. They run as part of "go test ./..." and
// are meant to be run with the race detector:
//
//	go test -race ./chaos/...
//	make chaos                      # longer fault-injection phase
//
// # What is tested
//
// Randomized scenarios (monkey_test.go) run a mixed workload on several
// clients (reads, large multi-chunk reads, writes, browses, method calls,
// subscription create/modify/delete, monitored item add/remove, long-lived
// publish streams fed by a server-side value writer) while a monkey injects
// faults through internal/testutil.ChaosProxy and through the public API:
// connection resets, half-closes, blackholes, latency, byte-level
// fragmentation, throttling, truncation in the middle of a message, an
// unreachable server, a server restart, sessions closed or detached behind
// the client's back, clients closed with calls in flight, cancelled and
// expiring contexts, short secure-channel lifetimes that force renewals, bit
// flips, and malformed or hostile raw UACP frames (raw_test.go).
//
// Parallelism tests (parallel_test.go, lifecycle_test.go) inject no faults
// and therefore accept no errors: many goroutines on one client, many
// clients on one server, concurrent subscription and monitored item churn,
// concurrent writers with subscribers, concurrent Connect/Close, server
// shutdown under load, address-space mutation during browse/read, session
// churn, and interleaved multi-chunk messages.
//
// Regression tests (regression_test.go) pin down every product bug the
// suite found with a small deterministic test.
//
// # Invariants
//
//   - no panic and no data race (run with -race)
//   - no deadlock: every operation returns within a bound (watchdog)
//   - no goroutine leak after everything is closed
//   - the server still serves a brand-new client correctly after the storm
//   - with AutoReconnect the client returns to Connected once the faults
//     stop and its subscriptions deliver again; values of a subscription
//     never go backwards
//   - the ConnState transitions reported to WithConnStateHandler are legal
//   - once all clients are gone the server holds no channels, sessions,
//     subscriptions or monitored items
//   - errors during a fault are connection-class errors (connection closed,
//     timeout, invalid session/channel/subscription); anything else fails
//     the test. Scenarios that corrupt message contents cannot make that
//     distinction and only check the invariants that do not depend on it.
//
// # Knobs
//
//	CHAOS_SEED      seed of the fault schedule and the workload. Every
//	                scenario logs its seed; the default is derived from the
//	                clock.
//	CHAOS_DURATION  length of the fault-injection phase of each randomized
//	                scenario as a Go duration (default 3s). Use e.g. 60s or
//	                10m for a soak.
//	CHAOS_LOG       debug | info | warn | error: log the server and the
//	                clients to stderr at that level.
//
// # Reproducing a failure
//
// A failing scenario prints the command to replay it, for example
//
//	CHAOS_SEED=1791716366745000000 go test -race -run '^TestChaosMonkeyNetworkFaults$' ./chaos/
//
// The seed fixes the sequence of faults, their parameters and the operations
// each worker issues. The interleaving of goroutines and the timing of the
// network are not controlled, so a seed makes a failure likely to recur, not
// certain: combine it with -count and, for rare failures, with a longer
// CHAOS_DURATION. Add -v to see the fault schedule with timestamps and
// CHAOS_LOG=debug to see what both sides did.
package chaos
