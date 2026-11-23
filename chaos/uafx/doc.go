// SPDX-License-Identifier: MIT

// Package uafx holds the chaos and parallelism suite of uafx.Inspect and of
// the OPC UA FX model that uafx/fxserver adds to a server (OPC 10000-81).
//
// The package contains only tests. They are meant to be run with the race
// detector:
//
//	go test -race ./chaos/uafx/
//	CHAOS_SEED=42 go test -race ./chaos/uafx/              # replay a seed
//	CHAOS_DURATION=60s go test -race -run Faults ./chaos/uafx/
//
// # What is tested
//
//   - TestInspectUnderFaults: clients inspect the server through
//     internal/testutil.ChaosProxy over Basic256Sha256 SignAndEncrypt while
//     a monkey resets and half-closes connections, blackholes them, adds
//     latency, fragments and throttles the stream, truncates it and flips
//     bits. The secure channel makes a flipped bit an error instead of a
//     different value.
//   - TestInspectWhileValuesChange: clients inspect the server while it
//     changes the AggregatedHealth and AuthorAssignedVersion structures.
//   - TestInspectWhileModelChanges: clients inspect the server while it
//     adds and removes a SubFunctionalEntity.
//   - TestInspectServerClose: the server closes with inspections in flight.
//
// # Invariants
//
// No data race, no panic, no deadlock (every Inspect returns within the
// watchdog limit), no goroutine left behind. An Inspect either returns the
// report of an undisturbed run, with only what the scenario changes being
// different and then one of the values the server had, or an error that
// wraps uafx.ErrInspect and comes from the disturbed connection. Once the
// faults stop, every client gets the undisturbed report again.
//
// # Reproducing a failure
//
// Every randomized test logs its seed and the command that replays it.
// CHAOS_SEED fixes the seed, CHAOS_DURATION the length of the fault phase.
package uafx
