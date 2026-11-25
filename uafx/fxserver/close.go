// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"errors"
	"slices"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

func (c *Connections) closeHandler(ac *automationComponent) server.MethodHandler {
	return func(ctx context.Context, obj, method *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		out, sc := c.closeCall(ctx, ac, args)
		c.auditCall(ctx, ac, method, args, out, sc)
		return out, sc
	}
}

// closeCall runs a CloseConnections call (Part 81 §6.2.5): it returns
// Uncertain when an element fails (Table 23) and one StatusCode per element
// (Table 24).
func (c *Connections) closeCall(ctx context.Context, ac *automationComponent, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
	if len(args) != 2 || args[0] == nil || args[1] == nil {
		return nil, ua.StatusBadArgumentsMissing
	}
	var nodes []*ua.NodeID
	switch v := args[0].Value().(type) {
	case []*ua.NodeID:
		nodes = v
	case nil:
	default:
		return nil, ua.StatusBadTypeMismatch
	}
	remove, ok := args[1].Value().(bool)
	if !ok {
		return nil, ua.StatusBadTypeMismatch
	}
	c.call.Lock()
	defer c.call.Unlock()
	scope := map[string]bool{}
	for _, fe := range c.functionalEntities(ac) {
		scope[fe.String()] = true
	}
	results := make([]ua.StatusCode, len(nodes))
	status := ua.StatusOK
	for i, n := range nodes {
		results[i] = c.closeOne(ctx, n, remove, scope)
		if results[i] != ua.StatusOK {
			status = ua.StatusUncertain
		}
	}
	c.refreshAll()
	return []*ua.Variant{ua.MustVariant(results)}, status
}

func (c *Connections) closeOne(ctx context.Context, n *ua.NodeID, remove bool, scope map[string]bool) ua.StatusCode {
	if isNull(n) {
		return ua.StatusBadNodeIDInvalid
	}
	if c.node(n) == nil {
		return ua.StatusBadNodeIDUnknown
	}
	c.mu.Lock()
	e := c.endpoints[n.String()]
	c.mu.Unlock()
	switch {
	case e != nil && scope[e.fe.String()]:
		if remove {
			// Remove releases the ControlGroups e controls (§6.2.5.2):
			// the ControlAuthorizer decides, before anything changes.
			for _, g := range c.endpointGroups(e) {
				if sc := c.authorize(ctx, ControlRequest{Operation: ControlCloseRemove, Group: g, Endpoint: e.id}); sc != ua.StatusOK {
					return sc
				}
			}
		}
		return c.closeEndpoint(e, remove)
	case e != nil || c.isA(n, fxacid.ConnectionEndpointType):
		// A ConnectionEndpoint of another AutomationComponent.
		return ua.StatusBadNodeIDUnknown
	}
	return ua.StatusBadInvalidArgument
}

// closeEndpoint disables the DataSetReader and DataSetWriter of e that no
// other endpoint references and stops its CleanupTimeout processing (Part
// 81 §6.2.5.2). With remove it also removes what EstablishConnections
// created for it: the reader and writer its calls configured, unless another
// endpoint references them, and e itself unless it is preconfigured, which
// keeps its nodes, loses its References to the removed reader and writer
// and its RelatedEndpoint, and can be used again. A group, PubSubConnection
// or PublishedDataSet an EstablishConnections call added for the removed
// reader or writer goes too once nothing uses it ("all related
// communication model Objects if not referenced from other
// ConnectionEndpoints"); preconfigured ones stay (prune).
//
// It returns Good, or the status of the first PubSub operation that failed:
// Table 24 has no code for that, so it is the StatusCode the runtime gives,
// or Bad_InternalError. A failure leaves e and its References to what is
// left in place, so that the caller sees the endpoint and can close it
// again. A reader or writer that is disabled already, or no longer exists,
// is not a failure.
func (c *Connections) closeEndpoint(e *endpoint, remove bool) ua.StatusCode {
	c.mu.Lock()
	e.cleanupOff = true
	e.deadline = timeZero
	reader, writer, ownReader, ownWriter := e.reader, e.writer, e.ownReader, e.ownWriter
	c.mu.Unlock()
	status := ua.StatusOK
	fail := func(op string, cid pubsub.ComponentID, err error) {
		c.log.Warn("uafx: CloseConnections: "+op, "endpoint", e.id, "component", cid, "error", err)
		if status == ua.StatusOK {
			status = badStatusOf(err)
		}
	}
	for _, x := range []struct {
		n      *ua.NodeID
		own    bool
		reader bool
	}{{reader, ownReader, true}, {writer, ownWriter, false}} {
		if x.n == nil || c.shared(e, x.n) {
			continue
		}
		cid, ok := c.componentOf(x.n)
		if !ok {
			// Gone already: nothing to disable or remove.
			if remove && x.own {
				c.setLinkLocked(e, x.reader, nil, false)
			}
			continue
		}
		derr := c.ops.disable(cid)
		if errors.Is(derr, ua.StatusBadInvalidState) {
			derr = nil // disabled already
		}
		if !remove || !x.own {
			if derr != nil {
				fail("disable", cid, derr)
			}
			continue
		}
		// Removing stops the component as well: a failed disable matters
		// only if the removal fails too.
		remover := c.ops.removeWriter
		if x.reader {
			remover = c.ops.removeReader
		}
		group, pds := c.related(cid, x.reader)
		if err := remover(cid); err != nil && !errors.Is(err, ua.StatusBadNotFound) {
			fail("remove", cid, errors.Join(derr, err))
			continue
		}
		c.setLinkLocked(e, x.reader, nil, false)
		c.prune(e, group, pds)
	}
	if status != ua.StatusOK {
		return status
	}
	switch {
	case remove && e.created:
		c.deleteEndpoint(e)
	case remove:
		// A preconfigured endpoint stays; the RelatedEndpoint the call set
		// goes, so that it is no longer in use (Part 81 Table 12), and so
		// do its ControlGroups (§6.2.5.2).
		c.write(c.childID(e.id, "RelatedEndpoint"), &ua.Variant{})
		c.releaseEndpoint(e)
	}
	return ua.StatusOK
}

// related returns the group of the DataSetReader or DataSetWriter cid and,
// for a writer, the name of its PublishedDataSet.
func (c *Connections) related(cid pubsub.ComponentID, reader bool) (group pubsub.ComponentID, pds string) {
	rt := c.srv.PubSub()
	if info, err := rt.Component(cid); err == nil {
		group = info.Parent
	}
	if !reader {
		if dw, err := rt.DataSetWriterConfig(cid); err == nil {
			pds = dw.DataSetName
		}
	}
	return group, pds
}

// prune removes, after the removal of a DataSetReader or DataSetWriter of
// e, its group and then the group's PubSubConnection when an
// EstablishConnections call added them and they are empty, and the
// PublishedDataSet pds when a call added it and no DataSetWriter uses it
// (Part 81 §6.2.5.2). Preconfigured components stay. The endpoint is
// closed either way: a failure is logged, and the component stays.
func (c *Connections) prune(e *endpoint, group pubsub.ComponentID, pds string) {
	rt := c.srv.PubSub()
	created := func(id pubsub.ComponentID) bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return id != 0 && c.created[id]
	}
	children := func(id pubsub.ComponentID) bool {
		for _, ci := range rt.Components() {
			if ci.Parent == id && ci.Kind != pubsub.KindPublishedDataSet {
				return true
			}
		}
		return false
	}
	remove := func(id pubsub.ComponentID, op string, f func(pubsub.ComponentID) error) bool {
		if err := f(id); err != nil && !errors.Is(err, ua.StatusBadNotFound) {
			c.log.Warn("uafx: CloseConnections: "+op, "endpoint", e.id, "component", id, "error", err)
			return false
		}
		c.mu.Lock()
		delete(c.created, id)
		c.mu.Unlock()
		return true
	}
	if created(group) && !children(group) {
		conn := pubsub.Root
		if info, err := rt.Component(group); err == nil {
			conn = info.Parent
		}
		if remove(group, "remove group", c.ops.removeGroup) && created(conn) && !children(conn) {
			remove(conn, "remove connection", c.ops.removeConnection)
		}
	}
	if pds == "" {
		return
	}
	pid, ok := rt.Lookup(pubsub.KindPublishedDataSet, pubsub.Root, pds)
	if !ok || !created(pid) {
		return
	}
	for _, conn := range rt.Configuration().Connections {
		if conn == nil {
			continue
		}
		for _, g := range conn.WriterGroups {
			if g == nil {
				continue
			}
			if slices.ContainsFunc(g.DataSetWriters, func(w *ua.DataSetWriterDataType) bool { return w != nil && w.DataSetName == pds }) {
				return
			}
		}
	}
	remove(pid, "remove PublishedDataSet", c.ops.removePDS)
}

// badStatusOf returns the Bad StatusCode err carries, or Bad_InternalError.
func badStatusOf(err error) ua.StatusCode {
	if sc := pubsub.StatusCodeOf(err); sc.Uint32()&0x80000000 != 0 {
		return sc
	}
	return ua.StatusBadInternalError
}
