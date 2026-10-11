// SPDX-License-Identifier: MIT

// Package discovery holds the chaos-monkey and parallelism tests of the
// discovery features: the Local Discovery Server role of a server
// (RegisterServer, RegisterServer2, FindServers), the registration loop that
// keeps a server registered with a discovery server, and multicast discovery
// (mDNS and DNS-SD, FindServersOnNetwork, LDS-ME). Go clients and Go servers
// of this module are run against each other.
//
// The package contains only tests. They are meant to be run with the race
// detector:
//
//	go test -race ./chaos/discovery/
//
// # Scenarios
//
// Registration under faults (registration_test.go): internal/testutil's
// ChaosProxy sits between registering servers and their discovery server and
// resets, refuses, blackholes, stalls, delays, fragments, throttles,
// truncates and half-closes the connections; the discovery server is
// restarted; registrants are closed and replaced during the faults. A second
// test closes a server at each of the moments the discovery server swallows
// what it sends, the unregistration included.
//
// Churn with readers (churn_test.go): 18 servers register, renew, unregister,
// expire and close at one discovery server while readers call FindServers and
// FindServersWithFilter and page through FindServersOnNetwork with every
// page size, starting record id and capability filter. A model of who was
// registered when (model_test.go) tells whether a reader was handed a server
// that it could not have seen.
//
// Secured registration (secure_test.go): servers with ECC certificates
// register over ECC_nistP256 and ECC_curve25519 through the fault proxy while
// hostile applications with certificates of their own try to register,
// replace and remove servers they are not.
//
// Multicast (mdns_test.go): servers with multicast discovery, one of them a
// discovery server that announces its registered servers, join and leave an
// in-memory link (mdns.MemNetwork) that loses, duplicates, delays, truncates
// and corrupts datagrams, and on which a hostile station injects malformed
// and forged mDNS messages.
//
// Regression tests (regression_test.go) pin down the product bugs the suite
// found with small deterministic tests; two more are next to the code, in
// server/discovery_overlap_test.go.
//
// # Invariants
//
//   - no panic and no data race (run with -race)
//   - no deadlock: Start and Close of a server return within a bound, whatever
//     the discovery server and the network do (watchdog)
//   - no goroutine left behind once everything is closed (TestMain)
//   - once the faults stop, the table of a discovery server is exactly the
//     live registrants with their discovery URLs; servers that closed are
//     gone, by unregistration or by expiry
//   - a reader is only handed servers that were registered while it was
//     reading; the pages of FindServersOnNetwork are consistent and the
//     traversal ends; a record id never stands for two servers
//   - on a secured discovery server an application registers and removes
//     itself and nobody else
//   - the events of a registration loop are consistent
//   - once the faults on the link stop, and somebody asks, the ServerOnNetwork
//     table of every server is exactly what is on the link; malformed and
//     forged messages do not stay in it
//
// # Knobs
//
// The randomized scenarios log their seed and the command that replays them.
// CHAOS_SEED sets the seed, CHAOS_DURATION the length of the fault phase
// (2.5 seconds by default) and CHAOS_LOG (debug, info, warn, error) turns on
// the logs of the servers. See internal/testutil/chaoskit.
package discovery
