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
func (u *PubSubConfigurationUpdate) Revert() error {
	if u == nil || !u.ChangesApplied || u.before == nil {
		return nil
	}
	f := u.f
	f.m.s.ps.txn.Lock()
	defer f.m.s.ps.txn.Unlock()
	if !reflect.DeepEqual(f.m.rt.Configuration(), u.after) {
		return ErrPubSubChanged
	}
	if err := reconcilePubSub(f.m.rt, u.before); err != nil {
		return fmt.Errorf("server: revert the PubSub configuration: %w", err)
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
	rt := s.PubSub()
	if rt == nil {
		return ua.StatusBadNotSupported
	}
	s.ps.txn.Lock()
	defer s.ps.txn.Unlock()
	return fn(rt)
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
