// SPDX-License-Identifier: MIT

// Package testhook exposes internal state of the client and server to tests in
// other packages of this module without widening the public API.
//
// The packages under test install their hooks from an init function. The
// hooks are read-only and must only be called from tests.
package testhook

// ServerResources is a snapshot of the per-client resources a server holds.
type ServerResources struct {
	// Channels is the number of registered secure channels.
	Channels int
	// Sessions is the number of sessions known to the session broker.
	Sessions int
	// Subscriptions is the number of live subscriptions.
	Subscriptions int
	// MonitoredItems is the number of live monitored items.
	MonitoredItems int
	// DiagnosticsSessionObjects is the number of SessionDiagnosticsObjects
	// (Server.ServerDiagnostics.SessionsDiagnosticsSummary).
	DiagnosticsSessionObjects int
}

// ServerResourcesOf returns the resource snapshot of a *server.Server. It is
// installed by the server package; srv is typed as any to avoid an import
// cycle.
var ServerResourcesOf func(srv any) ServerResources

// ServerMulticastTransport returns a server.Option (typed as any to avoid an
// import cycle) that makes the mDNS responder of a server use an in-memory
// link instead of the network interfaces of the machine. link must be a
// *mdns.MemNetwork. It is installed by the server package.
var ServerMulticastTransport func(link any) any

// ServerMulticastTTL returns a server.Option (typed as any to avoid an import
// cycle) that sets the TTLs, in seconds, of the mDNS records a server
// announces: hostTTL for the records that depend on the host name (SRV, A,
// AAAA) and otherTTL for the others. Tests use short TTLs to see records
// expire. It is installed by the server package.
var ServerMulticastTTL func(hostTTL, otherTTL uint32) any

// CodecStructs returns a pointer to a new zero value of every structure the
// JSON and XML codecs of package ua know by name (all generated structures
// and the registered custom ones), sorted by name. It is installed by the ua
// package.
var CodecStructs func() []any

// ServerSampler is a snapshot of the sampling machinery of a server's
// MonitoredItem service: the one timer that serves monitored items with a
// sampling interval above 0.
type ServerSampler struct {
	// Timers is the number of armed sampler timers: 1 while a postponed
	// sample is pending, 0 otherwise.
	Timers int
	// Due is the number of monitored items with a postponed sample.
	Due int
	// Running is the number of sampler callbacks in flight.
	Running int
}

// ServerSamplerOf returns the sampler snapshot of a *server.Server. It is
// installed by the server package; srv is typed as any to avoid an import
// cycle.
var ServerSamplerOf func(srv any) ServerSampler

// ServerSessionsOf describes the sessions a *server.Server holds, one line
// each: id, revised timeout, idle time, whether it was activated. It is for
// the diagnostics of leak checks. It is installed by the server package.
var ServerSessionsOf func(srv any) []string
