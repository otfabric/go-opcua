// SPDX-License-Identifier: MIT

package fxserver

import (
	"context"
	"slices"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/server"
)

// The boundary between the persistence of the ConnectionEndpoints and that
// of the PubSub configuration of the server (server.WithPubSubStore): each
// PubSub component has one store that restores it. The Connections own the
// components their EstablishConnections calls created, the PubSub
// configuration store of the server leaves them out, and they live as long
// as their ConnectionEndpoint: with ConnectionOptions.Store and IsPersistent
// the component records restore them (design §4), otherwise they are gone
// after a restart, as the endpoint is (Part 81 §5.5.5). The components an
// endpoint references but did not create, preconfigured or added by
// another mechanism, are the server's: its store restores them first, and
// the restore of the endpoint adopts them when they are equal (design §5).

var _ server.PubSubComponentOwner = (*Connections)(nil)

// OwnsPubSubComponent reports whether the component of kind at path is the
// Connections': it is added by a change of an EstablishConnections call
// itself (until the call ends: PersistPubSubConfiguration then hands what
// no endpoint uses over to the store of the server), it is a
// PubSubConnection, group or PublishedDataSet a call created, or a
// DataSetReader or DataSetWriter an endpoint owns, or a component record
// says a call created it. It is called in the PubSub transaction.
func (c *Connections) OwnsPubSubComponent(ch *server.PubSubChange, kind pubsub.ComponentKind, path []string) bool {
	if ownCall(ch.Context) && addedBy(ch, componentPath(kind, path...)) {
		return true
	}
	if cid, ok := lookupComponent(c.srv.PubSub(), &compRecord{Kind: uint8(kind), Path: path}); ok {
		switch kind {
		case pubsub.KindDataSetReader, pubsub.KindDataSetWriter:
			if c.ownedByCall(cid) {
				return true
			}
		default:
			c.mu.Lock()
			created := c.created[cid]
			c.mu.Unlock()
			if created {
				return true
			}
		}
	}
	p := c.pers
	if p == nil {
		return false
	}
	// A record restored, or being restored, that a call created: the
	// restore marks the component created after it added it.
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cr := range p.comps {
		if cr.Provenance == provCreated && !cr.Removed && pubsub.ComponentKind(cr.Kind) == kind && slices.Equal(cr.Path, path) {
			return true
		}
	}
	return false
}

// addedBy reports whether the change ch adds the component at path.
func addedBy(ch *server.PubSubChange, path string) bool {
	return slices.ContainsFunc(addedComponents(ch.Before, ch.After), func(a added) bool { return a.path == path })
}

// persistServerPubSub writes the PubSub configuration of the server to its store
// (server.WithPubSubStore) after an EstablishConnections or
// CloseConnections call: the components the call added that no endpoint
// uses, and those its endpoints no longer own, are the server's now.
func (c *Connections) persistServerPubSub(ctx context.Context) {
	if err := c.srv.PersistPubSubConfiguration(ctx); err != nil {
		c.log.Warn("uafx: the PubSub configuration store of the server is not written", "error", err)
	}
}
