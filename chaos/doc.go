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
//	go test -race ./chaos/...       # this package and the feature suites
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
// Reverse connect (reverse_connect_test.go) puts the proxy on the path of the
// connections the server opens to a listening client: the connection in use
// and the idle one behind it are reset, half-closed and blackholed under a
// running subscription, the client is made unreachable for the server, and
// the server is restarted. Servers, targets, clients and listeners are also
// closed in every order to check that nothing is left running.
//
// Event history (history_events_test.go) pages through the event history
// of a notifier with continuation points while the server reports events on
// it, clients delete events, abandon or release their reads and close their
// sessions in the middle of one, and the proxy drops the connections; every
// page continues the previous one in time order without repeating an event.
//
// Regression tests (regression_test.go) pin down every product bug the
// suite found with a small deterministic test.
//
// # Feature suites
//
// The sub-packages apply the same method to one feature each. They are
// packages of their own so that every test binary stays well inside the
// per-package time limit of CI; internal/testutil/chaoskit holds what they
// share (knobs, watchdog, leak check, ConnState validation).
//
//   - chaos/secure: the monkey and the parallelism tests over secured
//     channels (Basic256Sha256, ECC_nistP256, ECC_nistP384,
//     ECC_brainpoolP256r1, ECC_brainpoolP384r1 and the AEAD policies
//     ECC_nistP256_AesGcm, ECC_nistP256_ChaChaPoly, ECC_curve25519,
//     ECC_curve448)
//     with token renewals and attacks on the protected messages: bit flips,
//     replayed, lost, reordered and misdirected chunks. Every value is
//     verified, also while messages are altered.
//   - chaos/datachange: DataChangeFilter, sampling intervals and index
//     ranges under concurrent writers and concurrent monitored-item
//     services, and their restoration when a subscription is recreated.
//   - chaos/reverse: secured reverse connections, several servers into one
//     listener, listeners and targets closed mid-handshake.
//   - chaos/discovery: registration loops, the Local Discovery Server and
//     mDNS (on an in-memory link) under faults.
//   - chaos/codec: the JSON and XML encodings and the shared NodeSet values
//     under concurrency.
//   - chaos/certmgmt: push certificate management (Part 12 §7): trust
//     list and certificate updates, ApplyChanges and dropped transactions
//     while clients connect, each channel validated against one complete
//     trust list.
//   - chaos/gdspull: the Global Discovery Server (package gds/gdsserver) and
//     the pull model client (Part 12 §6, §7.9): registrations, signing and
//     new key pair requests, FinishRequest races, revocations and directory
//     queries while requests are approved and rejected and the GDS is
//     restarted on the same Store.
//   - chaos/pubsub: PubSub publishers and subscribers over UDP and MQTT
//     under datagram faults, broker outages, attacks on the message
//     security, key rotation storms, SKS outages, runtime and information
//     model churn, and fuzzed messages through the real transports.
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
