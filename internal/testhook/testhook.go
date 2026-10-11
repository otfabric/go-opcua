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
}

// ServerResourcesOf returns the resource snapshot of a *server.Server. It is
// installed by the server package; srv is typed as any to avoid an import
// cycle.
var ServerResourcesOf func(srv any) ServerResources
