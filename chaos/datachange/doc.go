// SPDX-License-Identifier: MIT

// Package datachange holds the chaos-monkey and parallelism tests of the
// data-change side of the MonitoredItem Service Set: the DataChangeFilter
// (triggers Status, StatusValue and StatusValueTimestamp; absolute and percent
// deadband on scalars and arrays), the sampling interval with its shared
// sampler timer, the monitored item's IndexRange, and the client's recreation
// of all of that after a reconnect.
//
// The package contains only tests. They talk from the Go client to the Go
// server over TCP, through internal/testutil.ChaosProxy, and are meant to be
// run with the race detector:
//
//	go test -race ./chaos/datachange/
//
// # What is tested
//
// The parallelism tests (parallel_test.go) inject no faults and accept no
// errors. Several clients with several subscriptions monitor a set of numeric
// scalar and array nodes with every trigger and deadband type, sampling
// intervals of 0, a few milliseconds, a few hundred milliseconds and "the
// publishing interval" (a negative request), and index ranges. Server-side
// writers (NodeNameSpace.SetAttribute) and client writers (Write, also with an
// IndexRange) change the nodes while other goroutines create, modify (filter,
// sampling interval, client handle), disable, enable and delete the very same
// monitored items.
//
// The fault scenario (monkey_test.go) keeps a fixed matrix of filtered and
// sampled items alive on AutoReconnect clients while a monkey resets,
// half-closes, blackholes, delays, fragments, throttles and truncates the
// connections, makes the server unreachable and restarts it. It ends with a
// server restart, so that every subscription is recreated at least once, and
// then proves with a scripted sequence of writes that the recreated items
// still have their filter, sampling interval, index range and monitoring
// mode.
//
// Regression tests (regression_test.go, and the tests next to the product
// code they name) pin down every product bug the suite found with a small
// deterministic test.
//
// # How a notification is judged
//
// The tests know the filter of every monitored item and re-implement the
// comparison the server makes (filter.changed in helpers_test.go).
//
// Without faults nothing is lost, so each notification of an item is compared
// with the previous one of that item: it must differ in status, or in value
// by more than the deadband (any element of an array), or - for
// StatusValueTimestamp without deadband - in source timestamp. The exceptions
// are exactly those the server defines: the first notification of an item
// (the initial value is always reported), the first one after the item was
// disabled (nothing is cached while disabled), and a notification carrying
// the Overflow bit (its predecessor was discarded from the item queue). The
// filter and sampling interval in effect are known for every notification
// although ModifyMonitoredItems runs concurrently: each modification gives
// the item a new client handle, which the server applies atomically with the
// new filter.
//
// With faults notifications can be lost, so the predecessor the server
// compared with may be one the client never saw. Every value is therefore
// written by the test with a source timestamp that encodes a sequence number
// and the generation of the server instance. A notification is a violation
// when no write between the previously delivered one and this one could have
// been the reference: all of them are filtered out relative to it. This is
// sound under loss and still catches a lost filter at once. A change of
// subscription id or server generation marks a recreated item, whose first
// notification is its initial value.
//
// The server stamps a sample with the server timestamp at the moment it is
// taken, so the spacing of the samples of an item is observable.
//
// # Invariants
//
//   - no panic, no data race, no deadlock (a watchdog guards every call), no
//     goroutine leak
//   - every notification satisfies the filter of its item, as described above
//   - a value is the one that was written (reduced to the IndexRange), never
//     a mix; values of an item never go backwards
//   - at most one sample per sampling interval: the number of notifications
//     of an item over a window is bounded by window/interval + 1, and two
//     consecutive samples are not closer than the interval allows
//   - the last written value is reported unless the filter suppresses it
//     relative to the last reported one - also when its sample had to wait
//     for the end of the sampling interval
//   - the sampler timer is armed only while a sample is postponed: it is
//     gone after the items are deleted or disabled, the subscription is
//     deleted, the session is closed and the server is closed
//     (internal/testhook.ServerSamplerOf)
//   - after faults: the clients return to Connected, the recreated items
//     have their filters, sampling intervals, index ranges and monitoring
//     modes, and the server holds nothing once the clients are gone
//
// # Knobs
//
// CHAOS_SEED, CHAOS_DURATION and CHAOS_LOG as in package chaos. Every
// randomized test logs its seed and the command that replays it.
package datachange
