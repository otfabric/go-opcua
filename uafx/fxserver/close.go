// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"errors"

	"github.com/otfabric/go-opcua/pubsub"
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
// and its RelatedEndpoint, and can be used again. The groups and
// connections stay.
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
		if err := remover(cid); err != nil && !errors.Is(err, ua.StatusBadNotFound) {
			fail("remove", cid, errors.Join(derr, err))
			continue
		}
		c.setLinkLocked(e, x.reader, nil, false)
	}
	if status != ua.StatusOK {
		return status
	}
	switch {
	case remove && e.created:
		c.deleteEndpoint(e)
	case remove:
		// A preconfigured endpoint stays; the RelatedEndpoint the call set
		// goes, so that it is no longer in use (Part 81 Table 12).
		c.write(c.childID(e.id, "RelatedEndpoint"), &ua.Variant{})
	}
	return ua.StatusOK
}

// badStatusOf returns the Bad StatusCode err carries, or Bad_InternalError.
func badStatusOf(err error) ua.StatusCode {
	if sc := pubsub.StatusCodeOf(err); sc.Uint32()&0x80000000 != 0 {
		return sc
	}
	return ua.StatusBadInternalError
}
