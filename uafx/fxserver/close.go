// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"

	"github.com/otfabric/go-opcua/server"
	"github.com/otfabric/go-opcua/ua"
	"github.com/otfabric/go-opcua/uafx/fxacid"
)

func (c *Connections) closeHandler(ac *automationComponent) server.MethodHandler {
	return func(ctx context.Context, obj, method *ua.NodeID, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
		out, sc := c.closeCall(ac, args)
		c.auditCall(ctx, ac, method, args, out, sc)
		return out, sc
	}
}

// closeCall runs a CloseConnections call (Part 81 §6.2.5): it returns
// Uncertain when an element fails (Table 23) and one StatusCode per element
// (Table 24).
func (c *Connections) closeCall(ac *automationComponent, args []*ua.Variant) ([]*ua.Variant, ua.StatusCode) {
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
		results[i] = c.closeOne(n, remove, scope)
		if results[i] != ua.StatusOK {
			status = ua.StatusUncertain
		}
	}
	c.refreshAll()
	return []*ua.Variant{ua.MustVariant(results)}, status
}

func (c *Connections) closeOne(n *ua.NodeID, remove bool, scope map[string]bool) ua.StatusCode {
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
		c.closeEndpoint(e, remove)
		return ua.StatusOK
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
// and its RelatedEndpoint, and can be used again. The groups and
// connections stay.
func (c *Connections) closeEndpoint(e *endpoint, remove bool) {
	rt := c.srv.PubSub()
	c.mu.Lock()
	e.cleanupOff = true
	e.deadline = timeZero
	reader, writer, ownReader, ownWriter := e.reader, e.writer, e.ownReader, e.ownWriter
	c.mu.Unlock()
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
			continue
		}
		if err := rt.Disable(cid); err != nil {
			c.log.Debug("uafx: CloseConnections: disable", "component", cid, "error", err)
		}
		if !remove || !x.own {
			continue
		}
		var err error
		if x.reader {
			err = rt.RemoveDataSetReader(cid)
		} else {
			err = rt.RemoveDataSetWriter(cid)
		}
		if err != nil {
			c.log.Warn("uafx: CloseConnections: remove", "component", cid, "error", err)
			continue
		}
		c.setLinkLocked(e, x.reader, nil, false)
	}
	switch {
	case remove && e.created:
		c.deleteEndpoint(e)
	case remove:
		// A preconfigured endpoint stays; the RelatedEndpoint the call set
		// goes, so that it is no longer in use (Part 81 Table 12).
		c.write(c.childID(e.id, "RelatedEndpoint"), &ua.Variant{})
	}
}
