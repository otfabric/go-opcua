// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// PubSubConfigurationStore persists the PubSub configuration of a server:
// "The latest configuration shall be persisted by the OPC UA Server and
// shall be available after a restart of the OPC UA Server. PubSub
// components are not persisted, if the component has the optional
// NotPersisted property set with a value of true" (OPC 10000-14 §9.1.2).
// Package server/pubsubstore implements it on a directory.
//
// The server calls StorePubSubConfiguration in the PubSub transaction
// after each change, whatever makes it (the Methods of Part 14 §9.1.3,
// CloseAndUpdate, [Server.UpdatePubSubConfiguration],
// [PubSubConfigurationUpdate.Revert], [Server.ChangePubSubConfiguration]
// and [Server.PersistPubSubConfiguration]), and LoadPubSubConfiguration
// once, before the PubSub information model is built ([WithPubSubStore]).
type PubSubConfigurationStore interface {
	// LoadPubSubConfiguration returns the stored configuration with its
	// NodeIds in the namespaces of namespaces, the NamespaceArray of the
	// server, or nil when the store holds no configuration. An error, a
	// NodeId in a namespace the server does not have included, fails the
	// restore: the server does not start with a configuration other than
	// the latest one.
	LoadPubSubConfiguration(ctx context.Context, namespaces []string) (*ua.PubSubConfigurationDataType, error)
	// StorePubSubConfiguration makes cfg, whose NodeIds are in the
	// namespaces of namespaces, the stored configuration, all or nothing.
	// It returns nil when cfg is durable. On an error the server does not
	// apply the change: it undoes it and fails it with
	// Bad_InternalError. After an error the store must hold the
	// configuration it held before, or refuse later writes until it does,
	// so that a restarted server never starts with a change it did not
	// apply. cfg leaves out the components with 0:NotPersisted TRUE and
	// those a [PubSubComponentOwner] keeps; the store does not keep it.
	StorePubSubConfiguration(ctx context.Context, cfg *ua.PubSubConfigurationDataType, namespaces []string) error
}

// WithPubSubStore persists the PubSub configuration of [WithPubSub] in st
// (OPC 10000-14 §9.1.2). Once st holds a configuration it is the
// configuration of the server: the server restores it before it builds
// the PubSub information model ([Server.BuildPubSubModel] or Start, or the
// first [Server.ChangePubSubConfiguration] before them), in place of the
// configuration given to WithPubSub, which is the configuration of an
// empty store only. A store that cannot be loaded, or a configuration that
// is not valid, fails the restore: BuildPubSubModel and Start return the
// error and the server does not start (fail closed). Register the
// namespaces the configuration uses before.
//
// Every change of the configuration made in the PubSub transaction is
// written in one call of st before the Method or function that made it
// returns; a write that fails undoes the change and fails it with
// Bad_InternalError. A change made on the runtime directly
// ([Server.PubSub]) is outside the transaction: it is written with the
// next change made in it, or by [Server.PersistPubSubConfiguration].
//
// A restored WriterGroup, ReaderGroup or DataSetReader with a
// SecurityMode above None gates its SecurityGroup in the runtime
// ([pubsub.PubSub.GateSecurityGroup]): it neither secures nor accepts
// messages under a key that may have been in use before the restart
// (Part 14 §7.2.3, §7.2.4.4.3).
//
// It needs WithPubSub.
func WithPubSubStore(st PubSubConfigurationStore) Option {
	return func(c *serverConfig) error {
		if st == nil {
			return errors.New("server: WithPubSubStore: nil store")
		}
		c.pubsubStore = st
		return nil
	}
}

// PubSubComponentOwner is a part of the application that persists some
// PubSub components itself, or keeps them in memory on purpose: the
// [PubSubConfigurationStore] of the server leaves them out, with what is
// below them. The persistent ConnectionEndpoints of OPC UA FX (package
// uafx/fxserver) own the components their EstablishConnections calls
// created, so that each component has one store that restores it.
type PubSubComponentOwner interface {
	// OwnsPubSubComponent reports whether the owner keeps the component of
	// kind at path: the names from its PubSubConnection down (a
	// PublishedDataSet: its Name), in the configuration ch.After. It is
	// called in the PubSub transaction, after the PubSubConfigurationHook
	// accepted ch; it must not change the configuration.
	OwnsPubSubComponent(ch *PubSubChange, kind pubsub.ComponentKind, path []string) bool
}

type pubsubOwnerBox struct{ o PubSubComponentOwner }

// reconcileTo is reconcilePubSub for the restore of the store and the undo
// of a change it refused; the tests replace it to make it fail.
var reconcileTo = reconcilePubSub

// SetPubSubComponentOwner sets the owner of components the store of
// [WithPubSubStore] leaves out; nil removes it. One owner at a time: a
// second call replaces the first.
func (s *Server) SetPubSubComponentOwner(o PubSubComponentOwner) {
	s.ps.txn.Lock()
	defer s.ps.txn.Unlock()
	if o == nil {
		s.ps.owner.Store(nil)
		return
	}
	s.ps.owner.Store(&pubsubOwnerBox{o: o})
}

func (s *Server) pubsubOwner() PubSubComponentOwner {
	if b := s.ps.owner.Load(); b != nil {
		return b.o
	}
	return nil
}

// PersistPubSubConfiguration writes the PubSub configuration of the
// runtime to the store of [WithPubSubStore] now, in the PubSub
// transaction: for changes made on the runtime directly ([Server.PubSub]),
// and for components a [PubSubComponentOwner] no longer keeps. It restores
// the store first when that has not happened yet. It does nothing without
// a store, and returns ua.StatusBadNotSupported without PubSub. An error
// changes nothing in the runtime: the store follows it with the next
// write.
func (s *Server) PersistPubSubConfiguration(ctx context.Context) error {
	rt := s.PubSub()
	if rt == nil {
		return ua.StatusBadNotSupported
	}
	if s.cfg.pubsubStore == nil {
		return nil
	}
	s.ps.txn.Lock()
	defer s.ps.txn.Unlock()
	if err := s.restorePubSubLocked(); err != nil {
		return err
	}
	cfg := rt.Configuration()
	return s.storePubSubLocked(&PubSubChange{Context: ctx, Before: cfg, After: cfg})
}

// restorePubSub is restorePubSubLocked in the PubSub transaction.
func (s *Server) restorePubSub() error {
	s.ps.txn.Lock()
	defer s.ps.txn.Unlock()
	return s.restorePubSubLocked()
}

// restorePubSubLocked brings the runtime to the configuration of the store
// once (WithPubSubStore). It fails, and is tried again by the next call,
// when the store cannot be loaded or its configuration cannot be applied;
// the runtime then keeps the configuration it had. The caller holds the
// PubSub transaction.
func (s *Server) restorePubSubLocked() error {
	st := s.cfg.pubsubStore
	if st == nil || s.ps.restored {
		return nil
	}
	rt := s.PubSub()
	cfg, err := st.LoadPubSubConfiguration(context.Background(), s.namespaceURIs())
	if err != nil {
		return fmt.Errorf("server: pubsub: load the configuration store: %w", err)
	}
	if cfg != nil {
		if err := pubsub.Validate(cfg); err != nil {
			return fmt.Errorf("server: pubsub: the stored configuration: %w", err)
		}
		before := rt.Configuration()
		if err := reconcileTo(rt, cfg); err != nil {
			if rerr := reconcileTo(rt, before); rerr != nil {
				s.cfg.logger.Error("pubsub: restoring the configuration before the restore failed", "error", rerr)
			}
			return fmt.Errorf("server: pubsub: restore the stored configuration: %w", err)
		}
		gateRestored(rt, cfg)
	}
	s.ps.restored = true
	return nil
}

// gateRestored gates the SecurityGroup of every secured WriterGroup,
// ReaderGroup and DataSetReader of a restored configuration (Part 14
// §7.2.3, §7.2.4.4.3): the runtime then neither secures nor accepts
// messages under a key that may predate the restart.
func gateRestored(rt *pubsub.PubSub, cfg *ua.PubSubConfigurationDataType) {
	gate := func(mode ua.MessageSecurityMode, group string) {
		if mode > ua.MessageSecurityModeNone && group != "" {
			rt.GateSecurityGroup(group)
		}
	}
	for _, c := range cfg.Connections {
		for _, g := range c.WriterGroups {
			gate(g.SecurityMode, g.SecurityGroupID)
		}
		for _, g := range c.ReaderGroups {
			gate(g.SecurityMode, g.SecurityGroupID)
			for _, r := range g.DataSetReaders {
				gate(r.SecurityMode, r.SecurityGroupID)
			}
		}
	}
}

// storePubSubLocked writes what ch.After persists to the store. The error
// carries the StatusCode of the change: Bad_ConfigurationError when the
// configuration to persist is not valid, Bad_InternalError when the store
// failed. The caller holds the PubSub transaction.
func (s *Server) storePubSubLocked(ch *PubSubChange) error {
	cfg := s.persistedConfig(ch)
	if err := pubsub.Validate(cfg); err != nil {
		// A component may need one that is not persisted (an Action
		// WriterGroup without a PublishingInterval its writers): the
		// configuration a restart would bring back must be valid (library
		// interpretation).
		s.cfg.logger.Warn("pubsub: the configuration to persist is not valid without the components that are not persisted", "error", err)
		return fmt.Errorf("%w: server: pubsub: the configuration to persist: %w", ua.StatusBadConfigurationError, err)
	}
	if err := s.cfg.pubsubStore.StorePubSubConfiguration(ch.Context, cfg, s.namespaceURIs()); err != nil {
		s.cfg.logger.Warn("pubsub: storing the configuration failed", "error", err)
		return fmt.Errorf("%w: server: pubsub: store the configuration: %w", ua.StatusBadInternalError, err)
	}
	return nil
}

// persistedConfig returns the part of ch.After that is persisted: without
// the components with 0:NotPersisted TRUE (Part 14 §6.2.2 Table 4, §9.1.2)
// and those the PubSubComponentOwner keeps, and without what is below
// them, which cannot be restored without them; a DataSetWriter of a
// PublishedDataSet that is not persisted is left out too. The components
// are shallow copies: the caller does not change them.
func (s *Server) persistedConfig(ch *PubSubChange) *ua.PubSubConfigurationDataType {
	o := s.pubsubOwner()
	skip := func(props []*ua.KeyValuePair, kind pubsub.ComponentKind, path ...string) bool {
		return notPersisted(props) || o != nil && o.OwnsPubSubComponent(ch, kind, path)
	}
	in := ch.After
	out := &ua.PubSubConfigurationDataType{Enabled: in.Enabled}
	pds := map[string]bool{}
	for _, d := range in.PublishedDataSets {
		if skip(nil, pubsub.KindPublishedDataSet, d.Name) {
			continue
		}
		out.PublishedDataSets = append(out.PublishedDataSets, d)
		pds[d.Name] = true
	}
	for _, c := range in.Connections {
		if skip(c.ConnectionProperties, pubsub.KindConnection, c.Name) {
			continue
		}
		cc := *c
		cc.WriterGroups, cc.ReaderGroups = nil, nil
		for _, g := range c.WriterGroups {
			if skip(g.GroupProperties, pubsub.KindWriterGroup, c.Name, g.Name) {
				continue
			}
			gg := *g
			gg.DataSetWriters = nil
			for _, w := range g.DataSetWriters {
				if w.DataSetName != "" && !pds[w.DataSetName] || skip(w.DataSetWriterProperties, pubsub.KindDataSetWriter, c.Name, g.Name, w.Name) {
					continue
				}
				gg.DataSetWriters = append(gg.DataSetWriters, w)
			}
			cc.WriterGroups = append(cc.WriterGroups, &gg)
		}
		for _, g := range c.ReaderGroups {
			if skip(g.GroupProperties, pubsub.KindReaderGroup, c.Name, g.Name) {
				continue
			}
			gg := *g
			gg.DataSetReaders = nil
			for _, r := range g.DataSetReaders {
				if skip(r.DataSetReaderProperties, pubsub.KindDataSetReader, c.Name, g.Name, r.Name) {
					continue
				}
				gg.DataSetReaders = append(gg.DataSetReaders, r)
			}
			cc.ReaderGroups = append(cc.ReaderGroups, &gg)
		}
		out.Connections = append(out.Connections, &cc)
	}
	return out
}

// notPersisted reports whether the configuration properties props have
// 0:NotPersisted TRUE: "Indicates if the component configuration is
// persisted. If this property is not present the default value is false
// and the component configuration is persisted" (Part 14 §6.2.2 Table 4).
// Its DataType is Boolean (§6.2.2); a value of another type is not TRUE.
func notPersisted(props []*ua.KeyValuePair) bool {
	for _, kv := range props {
		if kv != nil && kv.Key != nil && kv.Key.NamespaceIndex == 0 && kv.Key.Name == "NotPersisted" {
			if kv.Value == nil {
				return false
			}
			b, _ := kv.Value.Value().(bool)
			return b
		}
	}
	return false
}
