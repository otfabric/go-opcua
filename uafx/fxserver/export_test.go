// SPDX-License-Identifier: MIT

package fxserver

import (
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
)

// SetPubSubOps replaces the runtime operations that close ConnectionEndpoints;
// a nil function keeps the current one.
func SetPubSubOps(c *Connections, disable, removeReader, removeWriter func(pubsub.ComponentID) error) {
	c.call.Lock()
	defer c.call.Unlock()
	if disable != nil {
		c.ops.disable = disable
	}
	if removeReader != nil {
		c.ops.removeReader = removeReader
	}
	if removeWriter != nil {
		c.ops.removeWriter = removeWriter
	}
}

// RuntimeOps returns the runtime operations that close ConnectionEndpoints.
func RuntimeOps(c *Connections) (disable, removeReader, removeWriter func(pubsub.ComponentID) error) {
	c.call.Lock()
	defer c.call.Unlock()
	return c.ops.disable, c.ops.removeReader, c.ops.removeWriter
}

// SetBeforeExpire sets the function the monitor runs after it found an
// expired CleanupTimeout and before it takes the call lock. Set it before
// an endpoint can expire.
func SetBeforeExpire(c *Connections, f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforeExpire = f
}

// SetRetryCleanup sets the shortest time after which a failed cleanup is
// tried again.
func SetRetryCleanup(c *Connections, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retryCleanup = d
}

// SetLockClock replaces the clock of the Locks of the ControlGroups.
func SetLockClock(c *Connections, now func() time.Time) { c.ctl.clock.Store(&now) }

// TickLocks runs one tick of the Locks as the monitor does.
func TickLocks(c *Connections) { c.tickLocks() }

// WithMaxControlled sets the most nodes an item of a ControlItemFolder
// stands for.
func WithMaxControlled(o ConnectionOptions, n int) ConnectionOptions {
	o.maxControlled = n
	return o
}

// SessionEnded tells the Guard of the Locks that the session s ended.
func SessionEnded(c *Connections, s *server.Session) { lockGuard{c}.SessionEnded(s) }

// SetCMClock replaces the clock of the set Locks of c.
func SetCMClock(c *ConnectionManager, now func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clock = now
}

// TickCMLocks runs one tick of the set Locks.
func TickCMLocks(c *ConnectionManager) { c.tickLocks() }

// CMSessionEnded tells the Guard of the ConnectionManager that s ended.
func CMSessionEnded(c *ConnectionManager, s *server.Session) { cmGuard{c}.SessionEnded(s) }

// SetPruneOps replaces the runtime operations that remove the groups,
// PubSubConnections and PublishedDataSets an EstablishConnections call
// created (prune); a nil function keeps the current one.
func SetPruneOps(c *Connections, removeGroup, removeConnection, removePDS func(pubsub.ComponentID) error) {
	c.call.Lock()
	defer c.call.Unlock()
	if removeGroup != nil {
		c.ops.removeGroup = removeGroup
	}
	if removeConnection != nil {
		c.ops.removeConnection = removeConnection
	}
	if removePDS != nil {
		c.ops.removePDS = removePDS
	}
}

// SetBeforeUpdate sets the function SetCommunicationConfigurationCmd runs
// right before it applies the PubSub configuration.
func SetBeforeUpdate(c *Connections, f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.beforeUpdate = f
}
