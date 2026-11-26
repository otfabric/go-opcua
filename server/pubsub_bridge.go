// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/otfabric/go-opcua/id"
	"github.com/otfabric/go-opcua/pubsub"
	"github.com/otfabric/go-opcua/ua"
)

// The functions here let a Method of a companion specification configure
// PubSub as its caller would with the PubSubConfiguration object of Part 14
// §9.1.3.7: the EstablishConnections Method of OPC UA FX (OPC 10000-81
// §6.2.4.3.4, §6.2.4.3.9) reserves ids as ReserveIds does and applies a
// configuration as CloseAndUpdate does. They run with the session of the
// Method call in ctx and check what a call of ReserveIds or CloseAndUpdate
// by that session would: the AccessController (CheckCall) and the
// AccessRestrictions of that Method node, the PubSubAuthorizer, and for an
// update the TargetVariables of the readers (see [WithPubSubAuthorizer]).
// They share the reservations, limits and locks of the PubSubConfiguration
// object.

// PubSubIDReservation is what [Server.ReservePubSubIDs] reserved.
type PubSubIDReservation struct {
	// DefaultPublisherID is the PublisherId of the server.
	DefaultPublisherID *ua.Variant
	WriterGroupIDs     []uint16
	DataSetWriterIDs   []uint16
}

// PubSubConfigurationUpdate is the result of
// [Server.UpdatePubSubConfiguration]: the output arguments of
// CloseAndUpdate (Part 14 §9.1.3.7.4).
type PubSubConfigurationUpdate struct {
	ChangesApplied       bool
	ReferenceResults     []ua.StatusCode
	ConfigurationValues  []*ua.PubSubConfigurationValueDataType
	ConfigurationObjects []*ua.NodeID

	f             *configFile
	before, after *ua.PubSubConfigurationDataType
	created       map[pubsub.ComponentID]bool
}

// Created reports whether the update added the component id to the PubSub
// runtime: a PubSubConnection, WriterGroup, ReaderGroup or
// PublishedDataSet its own reconciliation created, not one it found there
// (one an ElementMatch matched, or one that had the Name already). It is
// recorded as the update applies the configuration, from the ids the
// runtime returned, so a component another client adds meanwhile is never
// the update's. A component the update replaced because its parameters
// changed (ElementModify) counts as created.
func (u *PubSubConfigurationUpdate) Created(id pubsub.ComponentID) bool {
	return u != nil && u.created[id]
}

// ErrPubSubChanged reports that the PubSub configuration changed after an
// update, which Revert therefore does not undo.
var ErrPubSubChanged = errors.New("server: the PubSub configuration changed after the update")

// Revert restores the configuration the update replaced, provided the
// configuration is still the one the update applied: else it changes
// nothing and returns ErrPubSubChanged. It does nothing for an update that
// applied no changes. The ids the update used stay released.
//
// Revert is safe for concurrent use: calls run one after the other in the
// PubSub transaction, and those after the first that restored the
// configuration do nothing.
func (u *PubSubConfigurationUpdate) Revert() error {
	if u == nil || !u.ChangesApplied || u.f == nil {
		return nil
	}
	f := u.f
	f.m.s.ps.txn.Lock()
	defer f.m.s.ps.txn.Unlock()
	if u.before == nil {
		return nil // reverted already
	}
	if !reflect.DeepEqual(f.m.rt.Configuration(), u.after) {
		return ErrPubSubChanged
	}
	h := f.m.s.pubsubHook()
	ids := f.m.s.restorerSnapshot(h)
	if err := reconcilePubSub(f.m.rt, u.before); err != nil {
		return fmt.Errorf("server: revert the PubSub configuration: %w", err)
	}
	if h != nil {
		if err := f.m.s.pubsubChanged(h, &PubSubChange{Context: context.Background(), Before: u.after, Revert: true, ids: ids}); err != nil {
			return fmt.Errorf("server: revert the PubSub configuration: %w", err)
		}
	}
	u.before = nil
	f.modified.Store(time.Now().UnixNano())
	go f.changed()
	return nil
}

// ChangePubSubConfiguration calls fn with the PubSub runtime of the server
// inside the transaction that CloseAndUpdate, UpdatePubSubConfiguration,
// PubSubConfigurationUpdate.Revert and the PubSub Methods that change the
// configuration (AddConnection, AddWriterGroup, RemoveGroup, Enable and the
// others of Part 14 §9.1.3) hold, and returns its error. Changes made
// through it are never lost to a CloseAndUpdate that read the
// configuration before them, nor resurrected by one. fn must not call
// those functions or Methods itself. A server without PubSub ([WithPubSub])
// returns ua.StatusBadNotSupported without calling fn.
func (s *Server) ChangePubSubConfiguration(fn func(rt *pubsub.PubSub) error) error {
	return s.ChangePubSubConfigurationThen(fn, nil)
}

// ChangePubSubConfigurationThen is [Server.ChangePubSubConfiguration] with
// then, which it calls with the runtime and the result in the same
// transaction once the change is complete: after the
// [PubSubConfigurationHook], and, when the hook refused the change, after
// the runtime was reconciled back to the configuration before it. then
// sees the runtime as the change left it, before any other change of the
// configuration; it is not called when fn is not (no PubSub). Like fn, it
// must not call the functions and Methods that change the configuration.
func (s *Server) ChangePubSubConfigurationThen(fn func(rt *pubsub.PubSub) error, then func(rt *pubsub.PubSub, err error)) error {
	rt := s.PubSub()
	if rt == nil {
		return ua.StatusBadNotSupported
	}
	s.ps.txn.Lock()
	defer s.ps.txn.Unlock()
	err := s.changeLocked(rt, fn)
	if then != nil {
		then(rt, err)
	}
	return err
}

// changeLocked is ChangePubSubConfiguration in the PubSub transaction.
func (s *Server) changeLocked(rt *pubsub.PubSub, fn func(rt *pubsub.PubSub) error) error {
	h := s.pubsubHook()
	if h == nil {
		return fn(rt)
	}
	before, ids := rt.Configuration(), s.restorerSnapshot(h)
	if err := fn(rt); err != nil {
		// What fn changed before it failed is the hook's to see too.
		if herr := s.pubsubChanged(h, &PubSubChange{Context: context.Background(), Before: before, ids: ids}); herr != nil {
			return errors.Join(err, herr)
		}
		return err
	}
	return s.pubsubChanged(h, &PubSubChange{Context: context.Background(), Before: before, ids: ids})
}

// PubSubConfigurationHook follows the changes of the PubSub configuration of
// a server, whatever makes them: CloseAndUpdate and the other Methods of
// Part 14 §9.1.3, [Server.UpdatePubSubConfiguration],
// [PubSubConfigurationUpdate.Revert] and [Server.ChangePubSubConfiguration].
// A companion specification that keeps durable records of components (the
// persistent ConnectionEndpoints of OPC UA FX, OPC 10000-81 §6.6.2) uses it
// to keep them in line with the configuration in the same transaction
// (Part 14 §9.1.2).
type PubSubConfigurationHook interface {
	// PubSubConfigurationChanged is called in the PubSub transaction after
	// a change was applied to the runtime, before the Method or function
	// that made it returns. An error undoes the change (the runtime is
	// reconciled back to ch.Before, by name: a component the change
	// removed or changed comes back under a new ComponentID and node) and
	// fails it with the error's ua.StatusCode, or Bad_InternalError. It
	// must not change the PubSub configuration itself.
	PubSubConfigurationChanged(ch *PubSubChange) error
	// HeldPubSubIDs returns WriterGroupIds and DataSetWriterIds that
	// ReserveIds does not hand out and CloseAndUpdate does not assign to
	// new components, and refuse, which makes ReserveIds fail with
	// Bad_ResourceUnavailable. It is called in the PubSub transaction.
	HeldPubSubIDs() (writerGroups, dataSetWriters []uint16, refuse bool)
}

// PubSubChange is a change of the PubSub configuration a
// [PubSubConfigurationHook] sees.
type PubSubChange struct {
	// Context is the context of the Method call or of the
	// [Server.UpdatePubSubConfiguration] call that made the change;
	// context.Background() for [Server.ChangePubSubConfiguration] and
	// [PubSubConfigurationUpdate.Revert].
	Context context.Context
	// Before and After are the configuration before and after the change.
	Before, After *ua.PubSubConfigurationDataType
	// Revert: the change is [PubSubConfigurationUpdate.Revert] undoing an
	// update.
	Revert bool

	// ids are the components before the change by path, for a
	// PubSubConfigurationRestorer; nil for another hook.
	ids map[string]componentAt
}

// PubSubConfigurationRestorer is a [PubSubConfigurationHook] that follows
// the components a refused change brings back. The runtime is reconciled
// back to the configuration before the change by name, so a component the
// change removed or changed comes back under a new ComponentID and node:
// PubSubConfigurationRestored is called with those moves, in the PubSub
// transaction, after the runtime was reconciled back and before anything
// else changes the configuration. It must not change the configuration.
type PubSubConfigurationRestorer interface {
	PubSubConfigurationHook
	PubSubConfigurationRestored(ch *PubSubChange, moved []PubSubComponentMove)
}

// PubSubComponentMove is a component a refused change brought back under a
// new ComponentID and node: the same kind and path of names (its
// PubSubConnection, group and own Name; a PublishedDataSet's Name).
type PubSubComponentMove struct {
	From, To         pubsub.ComponentID
	FromNode, ToNode *ua.NodeID // nil when the component has no node
}

// componentAt is a component of the runtime at a path.
type componentAt struct {
	id   pubsub.ComponentID
	node *ua.NodeID
}

// restorerSnapshot returns the components of the runtime by path when h is
// a PubSubConfigurationRestorer, else nil.
func (s *Server) restorerSnapshot(h PubSubConfigurationHook) map[string]componentAt {
	if _, ok := h.(PubSubConfigurationRestorer); !ok {
		return nil
	}
	return s.componentsByPath()
}

// componentsByPath returns the components of the runtime by kind and path
// of names.
func (s *Server) componentsByPath() map[string]componentAt {
	rt := s.PubSub()
	comps := rt.Components()
	byID := make(map[pubsub.ComponentID]pubsub.ComponentInfo, len(comps))
	for _, ci := range comps {
		byID[ci.ID] = ci
	}
	out := make(map[string]componentAt, len(comps))
	for _, ci := range comps {
		path := fmt.Sprint(ci.Kind)
		for x, ok := ci, true; ok && x.ID != pubsub.Root; x, ok = byID[x.Parent] {
			path += "\x00" + x.Name
		}
		n, _ := s.PubSubNodeID(ci.ID)
		out[path] = componentAt{id: ci.ID, node: n}
	}
	return out
}

type pubsubHookBox struct{ h PubSubConfigurationHook }

// SetPubSubConfigurationHook sets the hook that follows the changes of the
// PubSub configuration; nil removes it. One hook at a time: a second call
// replaces the first.
func (s *Server) SetPubSubConfigurationHook(h PubSubConfigurationHook) {
	s.ps.txn.Lock()
	defer s.ps.txn.Unlock()
	if h == nil {
		s.ps.hook.Store(nil)
		return
	}
	s.ps.hook.Store(&pubsubHookBox{h: h})
}

func (s *Server) pubsubHook() PubSubConfigurationHook {
	if b := s.ps.hook.Load(); b != nil {
		return b.h
	}
	return nil
}

// pubsubChanged runs the hook h after the change ch, whose After it sets,
// in the PubSub transaction; when it fails, the runtime goes back to
// ch.Before. Nothing changed: no call.
func (s *Server) pubsubChanged(h PubSubConfigurationHook, ch *PubSubChange) error {
	rt := s.PubSub()
	ch.After = rt.Configuration()
	if reflect.DeepEqual(ch.Before, ch.After) {
		return nil
	}
	err := h.PubSubConfigurationChanged(ch)
	if err == nil {
		return nil
	}
	if rerr := reconcilePubSub(rt, ch.Before); rerr != nil {
		s.cfg.logger.Error("pubsub: restoring the configuration a hook refused failed", "error", rerr)
	}
	if r, ok := h.(PubSubConfigurationRestorer); ok && ch.ids != nil {
		var moved []PubSubComponentMove
		for path, cur := range s.componentsByPath() {
			if old, ok := ch.ids[path]; ok && old.id != cur.id {
				moved = append(moved, PubSubComponentMove{From: old.id, To: cur.id, FromNode: old.node, ToNode: cur.node})
			}
		}
		if len(moved) > 0 {
			r.PubSubConfigurationRestored(ch, moved)
		}
	}
	var sc ua.StatusCode
	if !errors.As(err, &sc) {
		err = fmt.Errorf("%w: %w", ua.StatusBadInternalError, err)
	}
	return err
}

// heldPubSubIDs adds the ids the hook holds to groups and writers.
func (s *Server) heldPubSubIDs(groups, writers map[uint16]bool) (refuse bool) {
	h := s.pubsubHook()
	if h == nil {
		return false
	}
	g, w, refuse := h.HeldPubSubIDs()
	for _, x := range g {
		groups[x] = true
	}
	for _, x := range w {
		writers[x] = true
	}
	return refuse
}

// ReservePubSubIDs reserves WriterGroupIds and DataSetWriterIds for the
// session of the Method call in ctx, as the ReserveIds Method of
// PublishSubscribe.PubSubConfiguration (Part 14 §9.1.3.7.5) does. The
// transport profile does not matter: the server has one id space.
//
// It returns Bad_NotSupported when the server has no PubSub information
// model ([WithPubSub]) and Bad_SessionIDInvalid without a session.
func (s *Server) ReservePubSubIDs(ctx context.Context, writerGroups, dataSetWriters uint16) (*PubSubIDReservation, ua.StatusCode) {
	f, sc := s.pubsubBridge(ctx, id.PublishSubscribePubSubConfigurationReserveIDs, "ReserveIds")
	if sc != ua.StatusOK {
		return nil, sc
	}
	return f.reserve(ctx, writerGroups, dataSetWriters)
}

// UpdatePubSubConfiguration applies cfg to the PubSub configuration of the
// server for the session of the Method call in ctx, as the CloseAndUpdate
// Method of PublishSubscribe.PubSubConfiguration (Part 14 §9.1.3.7.4) does
// with a file holding cfg: requireCompleteUpdate and refs have the meaning
// of its arguments of the same name.
//
// It returns Bad_NotSupported when the server has no PubSub information
// model ([WithPubSub]), Bad_NothingToDo without refs, and Bad_TypeMismatch
// without cfg.
func (s *Server) UpdatePubSubConfiguration(ctx context.Context, cfg *ua.PubSubConfiguration2DataType, requireCompleteUpdate bool, refs []*ua.PubSubConfigurationRefDataType) (*PubSubConfigurationUpdate, ua.StatusCode) {
	f, sc := s.pubsubBridge(ctx, id.PublishSubscribePubSubConfigurationCloseAndUpdate, "CloseAndUpdate")
	if sc != ua.StatusOK {
		return nil, sc
	}
	if cfg == nil {
		return nil, ua.StatusBadTypeMismatch
	}
	if len(refs) == 0 {
		return nil, ua.StatusBadNothingToDo
	}
	f.m.s.ps.txn.Lock()
	defer f.m.s.ps.txn.Unlock()
	return f.applyLocked(ctx, cfg, requireCompleteUpdate, refs)
}

// pubsubBridge returns the PubSubConfiguration object after the checks a
// call of its Method method (BrowseName name) by the caller of ctx passes.
func (s *Server) pubsubBridge(ctx context.Context, method uint32, name string) (*configFile, ua.StatusCode) {
	s.ps.mu.Lock()
	m := s.ps.model
	s.ps.mu.Unlock()
	if m == nil || m.file == nil {
		return nil, ua.StatusBadNotSupported
	}
	f := m.file
	caller, ok := MethodCallerFromContext(ctx)
	if !ok || caller.SessionID == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
	sess, _ := f.m.callerSession(ctx)
	if sess == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}
	mid := ua.NewNumericNodeID(0, method)
	if sc := s.cfg.accessController.CheckCall(ctx, sess.handle(), mid); sc != ua.StatusOK {
		return nil, sc
	}
	if n := s.Node(mid); n != nil {
		if sc := accessRestrictionsFor(caller.SecurityMode, n); sc != ua.StatusOK {
			return nil, sc
		}
	}
	if a := s.cfg.pubsubAuth; a != nil {
		if sc := a(ctx, caller, name); sc != ua.StatusOK {
			return nil, sc
		}
	}
	return f, ua.StatusOK
}
