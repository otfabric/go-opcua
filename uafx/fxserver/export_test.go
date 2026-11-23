// SPDX-License-Identifier: MIT

package fxserver

import (
	"time"

	"github.com/otfabric/go-opcua/pubsub"
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
