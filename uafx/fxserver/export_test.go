// SPDX-License-Identifier: MIT

package fxserver

import (
	"time"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxcm"
)

// LogEvent records e in the ConnectionManagerLog of c as apply does.
func LogEvent(c *ConnectionManager, e fxcm.Event) { c.logEvent(e) }

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

// WithFailCapabilities makes the setting of SupportsPersistence in
// EnableConnections fail with err.
func WithFailCapabilities(o ConnectionOptions, err error) ConnectionOptions {
	o.failCapabilities = err
	return o
}

// ModificationTime returns the ModificationTime the connections keep for
// the endpoint n (Part 81 Table 74), also of one without the Variable.
func ModificationTime(c *Connections, n *ua.NodeID) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.endpoints[n.String()]; e != nil {
		return e.modifiedAt
	}
	return time.Time{}
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

// ApplyCMEvent applies e to the address space as the loop does: a test
// replays an event the loop has not drained yet.
func ApplyCMEvent(c *ConnectionManager, e fxcm.Event) { c.apply(e) }

// SetCrashPoint sets the function the persistence protocols run at each of
// their named points; nil removes it.
func SetCrashPoint(c *Connections, f func(point string)) {
	if f == nil {
		c.crash.Store(nil)
		return
	}
	c.crash.Store(&f)
}

// WithLateNode returns the endpoint record v with one more NodeId, name in
// the namespace uri, which the record then needs: as a record written by a
// server that had the namespace.
func WithLateNode(v []byte, uri, name string) ([]byte, error) {
	idn, body, err := decodeEndpoint(v)
	if err != nil {
		return nil, err
	}
	idn.Namespaces = append(idn.Namespaces, uri)
	idn.Nodes = append(idn.Nodes, ua.NewStringNodeID(uint16(len(idn.Namespaces)-1), name))
	return encodeEndpoint(idn, body)
}

// WithLateComponent returns the component record v with its NodeIds
// outside namespace 0 moved to a new namespace uri: as a record written
// by a server that had it. ok is false when the record has none.
func WithLateComponent(v []byte, uri string) (out []byte, ok bool, err error) {
	cr, err := decodeComponent(v)
	if err != nil {
		return nil, false, err
	}
	late := uint16(len(cr.Namespaces))
	cr.Namespaces = append(cr.Namespaces, uri)
	r := &remapper{m: map[uint16]uint16{0: 0}, miss: map[uint16]bool{}}
	for i := 1; i < int(late); i++ {
		r.m[uint16(i)] = late
	}
	before, _ := encodeComponent(cr)
	if err := r.remap(cr); err != nil {
		return nil, false, err
	}
	out, err = encodeComponent(cr)
	return out, err == nil && string(out) != string(before), err
}

// RemovePending returns the endpoint record v in the state RemovePending.
func RemovePending(v []byte) ([]byte, error) {
	idn, body, err := decodeEndpoint(v)
	if err != nil {
		return nil, err
	}
	body.State = stateRemovePending
	return encodeEndpoint(idn, body)
}

// NotOwner returns the endpoint record v of the endpoint name with
// OwnReader and OwnWriter cleared, as the record of an endpoint that
// linked a component another call created; ok reports whether v is the
// record of name.
func NotOwner(v []byte, name string) (out []byte, ok bool, err error) {
	idn, body, err := decodeEndpoint(v)
	if err != nil || idn.Name != name {
		return nil, false, err
	}
	body.OwnReader, body.OwnWriter = false, false
	out, err = encodeEndpoint(idn, body)
	return out, err == nil, err
}

// SetAfterChange sets the function that runs after each PubSub transaction
// of the package's runtime changes, outside the transaction, with its
// result; nil removes it.
func SetAfterChange(c *Connections, f func(error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.afterChange = f
}
