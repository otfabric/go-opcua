// SPDX-License-Identifier: MIT

package fxserver

import (
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// change runs fn in the PubSub transaction of the server
// (Server.ChangePubSubConfiguration) and returns its result, which is fn's
// error or the refusal of the PubSub configuration hook. A refusal comes
// after fn changed the runtime: the server reconciles the runtime back to
// the configuration before the change, by name, so that what fn removed or
// changed is back under a new ComponentID and node. What this package
// keeps of those components follows them by path: the provenance
// (c.created), what the endpoints have left to prune, and their
// ToDataSetReader and ToDataSetWriter References. The endpoints are then as consistent with the restored
// configuration as they were with the one before.
func (c *Connections) change(fn func(rt *pubsub.PubSub) error) error {
	var before map[string]pubsub.ComponentID
	var links map[string]pubsub.ComponentID
	ran := false
	err := c.srv.ChangePubSubConfiguration(func(rt *pubsub.PubSub) error {
		before, links, ran = runtimePaths(rt), c.links(), true
		return fn(rt)
	})
	if err != nil && ran {
		c.follow(before, runtimePaths(c.srv.PubSub()), links)
	}
	return err
}

// links returns the components the endpoints reference, by node.
func (c *Connections) links() map[string]pubsub.ComponentID {
	c.mu.Lock()
	var nodes []*ua.NodeID
	for _, e := range c.endpoints {
		for _, n := range [...]*ua.NodeID{e.reader, e.writer} {
			if n != nil {
				nodes = append(nodes, n)
			}
		}
	}
	c.mu.Unlock()
	out := make(map[string]pubsub.ComponentID, len(nodes))
	for _, n := range nodes {
		if cid, ok := c.srv.PubSubComponentID(n); ok {
			out[n.String()] = cid
		}
	}
	return out
}

// follow moves the provenance and the References of the components of
// before to the components at the same paths in after.
func (c *Connections) follow(before, after, links map[string]pubsub.ComponentID) {
	moved := map[pubsub.ComponentID]pubsub.ComponentID{}
	for path, old := range before {
		if cur, ok := after[path]; ok && cur != old {
			moved[old] = cur
		}
	}
	if len(moved) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for old, cur := range moved {
		if c.created[old] {
			delete(c.created, old)
			c.created[cur] = true
		}
	}
	for _, e := range c.endpoints {
		for i, it := range e.pending {
			if cur, ok := moved[it.group]; ok {
				e.pending[i].group = cur
			}
			if cur, ok := moved[it.conn]; ok {
				e.pending[i].conn = cur
			}
		}
		for _, reader := range []bool{true, false} {
			n, own := e.writer, e.ownWriter
			if reader {
				n, own = e.reader, e.ownReader
			}
			if n == nil {
				continue
			}
			// The old node is gone from the model: links knows what
			// it was.
			old, ok := links[n.String()]
			if !ok {
				continue
			}
			cur, ok := moved[old]
			if !ok {
				continue
			}
			if node, ok := c.srv.PubSubNodeID(cur); ok {
				c.setLink(e, reader, node, own)
			}
		}
	}
}

// runtimePaths returns the components of rt by path.
func runtimePaths(rt *pubsub.PubSub) map[string]pubsub.ComponentID {
	comps := rt.Components()
	byID := make(map[pubsub.ComponentID]pubsub.ComponentInfo, len(comps))
	for _, ci := range comps {
		byID[ci.ID] = ci
	}
	out := make(map[string]pubsub.ComponentID, len(comps))
	for _, ci := range comps {
		var names []string
		for x, ok := ci, true; ok; x, ok = byID[x.Parent] {
			names = append([]string{x.Name}, names...)
			if x.Parent == pubsub.Root {
				break
			}
		}
		out[componentPath(ci.Kind, names...)] = ci.ID
	}
	return out
}
