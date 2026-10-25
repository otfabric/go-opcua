// SPDX-License-Identifier: MIT

// Package gdspull holds the parallelism and robustness suite of the Global
// Discovery Server of package gdsserver and the pull model client of
// package gds (Part 12 §6 and §7.9).
//
// The package contains only tests. They are meant to be run with the race
// detector:
//
//	go test -race ./chaos/gdspull/
//	CHAOS_SEED=42 go test -race ./chaos/gdspull/              # replay a seed
//	CHAOS_DURATION=60s go test -race ./chaos/gdspull/         # longer churn
//
// # What is tested
//
// Clients register, update and unregister applications, ask for
// certificates by signing request and by new key pair, complete them with
// FinishRequest (several clients racing for one request), revoke them and
// query the directory, while an approver approves and rejects the requests
// and the GDS is restarted on the same Store, also while requests are in
// flight.
//
// # Invariants
//
//   - every issued certificate carries the ApplicationUri of its
//     application and is signed by a CA of the GDS
//   - a request yields at most one certificate, a rejected request none
//   - a revoked certificate stays revoked across restarts, and a
//     certificate whose revocation succeeded is reported revoked by
//     CheckRevocationStatus
//   - every application whose registration succeeded and that was not
//     unregistered is found after the last restart
//   - no panic, no data race, no deadlock, no goroutine left behind
package gdspull
